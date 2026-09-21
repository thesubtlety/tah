// Command tah: collect a per-host behavioral memory and investigate it.
// All commands share ~/.tah/tah.db by default (override with --db).
//
//	tah collect   [--stdin]              # the daemon: eslogger + net/DNS + PII scan
//	tah snapshot                         # seed pre-existing processes (cold start)
//	tah status                           # counts + last activity (is it capturing?)
//	tah report    [--since 24h]          # all investigation questions at once
//	tah rank      [--since 24h]          # processes ranked by behavioral change
//	tah watch     [--interval 5s]        # live view
//	tah scan                             # drain the PII content-scan queue
//	tah query <readers|net> | caps
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/thesubtlety/tah/internal/dnslog"
	"github.com/thesubtlety/tah/internal/eslogger"
	"github.com/thesubtlety/tah/internal/event"
	"github.com/thesubtlety/tah/internal/netpoll"
	"github.com/thesubtlety/tah/internal/recognize"
	"github.com/thesubtlety/tah/internal/scan"
	"github.com/thesubtlety/tah/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "collect":
		cmdCollect(args)
	case "snapshot":
		cmdSnapshot(args)
	case "scan":
		cmdScan(args)
	case "net-poll":
		cmdNetPoll(args)
	case "dns-stream":
		cmdDNSStream(args)
	case "query":
		cmdQuery(args)
	case "rank":
		cmdRank(args)
	case "report":
		cmdReport(args)
	case "watch":
		cmdWatch(args)
	case "caps":
		cmdCaps(args)
	case "status":
		cmdStatus(args)
	case "recognize":
		cmdRecognize(args)
	default:
		usage()
	}
}

// cmdRecognize runs content credential recognition over files (a manual probe;
// the daemon will run this automatically on novel reads).
func cmdRecognize(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tah recognize <file>...")
		os.Exit(2)
	}
	for _, path := range args {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("%s: %v\n", path, err)
			continue
		}
		creds := recognize.Creds(string(b))
		if len(creds) == 0 {
			fmt.Printf("%s: no credentials recognized\n", path)
			continue
		}
		for _, c := range creds {
			fmt.Printf("%s: %s (line %d) %s\n", path, c.Type, c.Line, redactSecret(c.Secret))
		}
	}
}

func redactSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "…" + s[len(s)-2:]
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tah <collect|snapshot|scan|recognize|status|query|rank|report|watch|caps> ...")
	os.Exit(2)
}

func flagVal(args []string, name, def string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--"+name {
			return args[i+1]
		}
	}
	return def
}
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "--"+name {
			return true
		}
	}
	return false
}

// defaultDBPath is a stable absolute location so `collect` and `report` share
// one database regardless of the directory each is run from.
func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "tah.db"
	}
	dir := filepath.Join(home, ".tah")
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, "tah.db")
}

func openDB(args []string) *store.Store {
	st, err := store.Open(flagVal(args, "db", defaultDBPath()))
	must(err)
	return st
}
func window(args []string) (int64, string) {
	since := flagVal(args, "since", "24h")
	d, err := time.ParseDuration(since)
	if err != nil {
		d = 24 * time.Hour
	}
	return time.Now().Add(-d).UnixMilli(), since
}

func cmdCollect(args []string) {
	host := flagVal(args, "host", "localhost")
	st := openDB(args)
	defer st.Close()
	must(st.InitDefaultCaps())

	var src io.Reader = os.Stdin
	if !hasFlag(args, "stdin") && runtime.GOOS == "darwin" {
		cmd := exec.Command("eslogger", "exec", "fork", "exit", "open")
		out, err := cmd.StdoutPipe()
		must(err)
		must(cmd.Start())
		src = out
		defer cmd.Wait()
		fmt.Fprintln(os.Stderr, "collecting from eslogger (needs root + Full Disk Access)...")
		// Network + DNS aren't in Endpoint Security: run the pollers alongside.
		startNetDNS(st, host, args)
	}
	// One daemon does it all: collection + periodic PII scan of queued files.
	startScanLoop(st, args)
	n := 0
	must(eslogger.ParseStream(host, src, func(ev event.Event) error {
		n++
		return st.Apply(ev)
	}))
	fmt.Fprintf(os.Stderr, "applied %d events\n", n)
}

// startScanLoop drains the content-recognition queue on an interval: credential
// recognition always runs (in-process), PII runs too if Presidio is importable.
func startScanLoop(st *store.Store, args []string) {
	pii := piiScanner(args)
	if pii == nil {
		fmt.Fprintln(os.Stderr, "note: Presidio not installed — credentials still recognized; PII off until installed")
	}
	iv := flagVal(args, "scan-interval", "30s")
	d, err := time.ParseDuration(iv)
	if err != nil {
		d = 30 * time.Second
	}
	go func() {
		for {
			time.Sleep(d)
			_, _, _ = scan.Drain(st, pii, 200)
		}
	}()
	fmt.Fprintf(os.Stderr, "content-recognition loop every %s (creds%s)\n", iv, map[bool]string{true: " + PII", false: ""}[pii != nil])
}

// piiScanner returns a Presidio scanner if importable, else nil.
func piiScanner(args []string) scan.Scanner {
	python := flagVal(args, "python", "python3")
	script := flagVal(args, "script", "presidio/presidio_scan.py")
	if exec.Command(python, "-c", "import presidio_analyzer").Run() != nil {
		return nil
	}
	return scan.PresidioScanner{Python: python, Script: script}
}

// startNetDNS launches the macOS network (lsof poll) and DNS (mDNSResponder log
// stream) collectors as background goroutines feeding the same store.
func startNetDNS(st *store.Store, host string, args []string) {
	iv := flagVal(args, "net-interval", "10s")
	d, err := time.ParseDuration(iv)
	if err != nil {
		d = 10 * time.Second
	}
	go func() {
		for {
			evs, err := netpoll.Poll(host)
			if err == nil {
				for _, ev := range evs {
					_ = st.Apply(ev)
				}
			}
			time.Sleep(d)
		}
	}()
	go func() {
		cmd := exec.Command("log", "stream", "--predicate", `process == "mDNSResponder"`, "--info", "--style", "ndjson")
		out, err := cmd.StdoutPipe()
		if err != nil || cmd.Start() != nil {
			return
		}
		_ = dnslog.Stream(host, out, func(ev event.Event) error { return st.Apply(ev) })
	}()
	fmt.Fprintf(os.Stderr, "net poll every %s + DNS stream started\n", iv)
}

func cmdNetPoll(args []string) {
	st := openDB(args)
	defer st.Close()
	evs, err := netpoll.Poll(flagVal(args, "host", "localhost"))
	must(err)
	n := 0
	for _, ev := range evs {
		if st.Apply(ev) == nil {
			n++
		}
	}
	fmt.Printf("net-poll: applied %d connections\n", n)
}

func cmdDNSStream(args []string) {
	st := openDB(args)
	defer st.Close()
	host := flagVal(args, "host", "localhost")
	cmd := exec.Command("log", "stream", "--predicate", `process == "mDNSResponder"`, "--info", "--style", "ndjson")
	out, err := cmd.StdoutPipe()
	must(err)
	must(cmd.Start())
	fmt.Fprintln(os.Stderr, "streaming DNS from mDNSResponder (needs Sensitive-level profile for cleartext names)...")
	must(dnslog.Stream(host, out, func(ev event.Event) error { return st.Apply(ev) }))
}

// cmdSnapshot seeds currently-running processes as pre-existing (prov_tier
// "snapshot"), so day-one queries don't treat the whole box as novel.
func cmdSnapshot(args []string) {
	st := openDB(args)
	defer st.Close()
	st.ProvTier = "snapshot"
	ts := time.Now().UnixMilli()
	out, err := exec.Command("ps", "ax", "-o", "pid=,ppid=,command=").Output()
	must(err)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	n := 0
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		pid, e1 := strconv.Atoi(fields[0])
		ppid, e2 := strconv.Atoi(fields[1])
		if e1 != nil || e2 != nil {
			continue
		}
		path := fields[2]
		ev := event.Event{
			TS: ts, Sensor: "snapshot", Fidelity: "high", Kind: event.Exec,
			Actor:    event.Actor{PID: pid},
			Parent:   &event.Actor{PID: ppid},
			Identity: event.Identity{ExecPath: path},
		}
		if err := st.Apply(ev); err == nil {
			n++
		}
	}
	fmt.Fprintf(os.Stderr, "snapshot: seeded %d running processes as pre-existing\n", n)
}

func cmdScan(args []string) {
	st := openDB(args)
	defer st.Close()
	limit, _ := strconv.Atoi(flagVal(args, "limit", "1000"))
	processed, failed, err := scan.Drain(st, piiScanner(args), limit)
	must(err)
	fmt.Printf("scanned %d queued files (%d failed)\n", processed, failed)
}

func cmdQuery(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tah query <readers|net> ...")
		os.Exit(2)
	}
	sub := args[0]
	rest := args[1:]
	st := openDB(rest)
	defer st.Close()
	win, since := window(rest)
	switch sub {
	case "readers":
		fs, err := st.UnexpectedCredentialReaders(win)
		must(err)
		fmt.Printf("unexpected readers of sensitive classes (last %s): %d\n", since, len(fs))
		for _, f := range fs {
			fmt.Printf("  %-26s read %-46s [%s/%s, %s]\n", f.Reader, f.File, f.Class, f.Family, f.Fidelity)
		}
	case "net":
		fs, err := st.NewNetworkUsers(win)
		must(err)
		fmt.Printf("processes that newly used the network (last %s): %d\n", since, len(fs))
		for _, f := range fs {
			fmt.Printf("  %-26s -> %s [%s]\n", f.Reader, f.File, f.Fidelity)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown query:", sub)
		os.Exit(2)
	}
}

func cmdRank(args []string) {
	st := openDB(args)
	defer st.Close()
	win, since := window(args)
	rows, err := st.RankLineages(win)
	must(err)
	fmt.Printf("processes by behavioral change (last %s):\n", since)
	for _, r := range rows {
		tag := ""
		if r.Interpreter {
			tag = " (host/interpreter)"
		}
		fmt.Printf("  %-30s score=%-3d classes=%-2d sensitive=%d%s\n", r.Display, r.Score, r.NovelClasses, r.SensitiveClasses, tag)
	}
}

func cmdReport(args []string) {
	st := openDB(args)
	defer st.Close()
	win, since := window(args)
	fmt.Printf("=== tah report (last %s) ===\n", since)
	printReport(st, win)
}

func printReport(st *store.Store, win int64) {
	readers, _ := st.UnexpectedCredentialReaders(win)
	fmt.Printf("[unexpected readers of sensitive classes] %d\n", len(readers))
	for _, f := range readers {
		fmt.Printf("  %-26s read %-46s [%s/%s]\n", f.Reader, f.File, f.Class, f.Family)
	}
	newprocs, _ := st.NewProcessIdentities(win)
	fmt.Printf("[new executable identities] %d\n", len(newprocs))
	for _, r := range newprocs {
		fmt.Printf("  %s\n", r.Display)
	}
	spawns, _ := st.NewParentChild(win)
	fmt.Printf("[new parent->child] %d\n", len(spawns))
	for _, f := range spawns {
		fmt.Printf("  %s -> %s\n", f.Reader, f.File)
	}
	net, _ := st.NewNetworkUsers(win)
	fmt.Printf("[newly networked] %d\n", len(net))
	for _, f := range net {
		fmt.Printf("  %-26s -> %s [%s]\n", f.Reader, f.File, f.Fidelity)
	}
	rank, _ := st.RankLineages(win)
	fmt.Printf("[biggest behavioral change]\n")
	for i, r := range rank {
		if i >= 10 {
			break
		}
		tag := ""
		if r.Interpreter {
			tag = " (host/interpreter)"
		}
		fmt.Printf("  %-30s score=%-3d classes=%-2d sensitive=%d%s\n", r.Display, r.Score, r.NovelClasses, r.SensitiveClasses, tag)
	}
}

func cmdWatch(args []string) {
	st := openDB(args)
	defer st.Close()
	iv := flagVal(args, "interval", "5s")
	d, err := time.ParseDuration(iv)
	if err != nil {
		d = 5 * time.Second
	}
	cursor, _ := window(args)
	fmt.Fprintf(os.Stderr, "watching (interval %s)...\n", iv)
	for {
		now := time.Now().UnixMilli()
		readers, _ := st.UnexpectedCredentialReaders(cursor)
		rank, _ := st.LineageChangeRank(cursor)
		if len(readers) > 0 || len(rank) > 0 {
			fmt.Printf("--- %s ---\n", time.Now().Format(time.Kitchen))
			for _, f := range readers {
				fmt.Printf("  ALERT unexpected read: %s read %s [%s/%s]\n", f.Reader, f.File, f.Class, f.Family)
			}
			for i, r := range rank {
				if i >= 5 {
					break
				}
				fmt.Printf("  change: %-26s new-edges=%d sensitive=%d\n", r.Display, r.NewEdges, r.Sensitive)
			}
		}
		cursor = now
		time.Sleep(d)
	}
}

func cmdCaps(args []string) {
	st := openDB(args)
	defer st.Close()
	caps, err := st.Capabilities()
	must(err)
	if len(caps) == 0 {
		fmt.Println("no capabilities recorded yet (run collect once)")
		return
	}
	fmt.Println("relation      available  fidelity  source")
	for _, c := range caps {
		fmt.Printf("%-12s  %-9v  %-8s  %s\n", c.Relation, c.Available, c.Fidelity, c.Source)
	}
}

func cmdStatus(args []string) {
	st := openDB(args)
	defer st.Close()
	s, err := st.Stats()
	must(err)
	fmt.Printf("db: %s\n", flagVal(args, "db", defaultDBPath()))
	fmt.Printf("nodes:   %d proc, %d file, %d ip, %d domain\n", s.Procs, s.Files, s.IPs, s.Domains)
	fmt.Printf("edges:   %d total, %d sensitive reads flagged\n", s.Edges, s.SensitiveReads)
	fmt.Printf("scan:    %d files queued, %d PII findings recorded\n", s.QueuedScans, s.NotifyFindings)
	if s.LastSeenMS == 0 {
		fmt.Println("activity: none yet — is `tah collect` running against this db?")
		return
	}
	last := time.UnixMilli(s.LastSeenMS)
	fmt.Printf("activity: first %s, last %s (%s ago)\n",
		time.UnixMilli(s.FirstSeenMS).Format("15:04:05"), last.Format("15:04:05"),
		time.Since(last).Round(time.Second))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
