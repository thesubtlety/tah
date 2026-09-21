package store_test

import (
	"os"
	"testing"

	"github.com/thesubtlety/tah/internal/eslogger"
	"github.com/thesubtlety/tah/internal/event"
	"github.com/thesubtlety/tah/internal/scan"
	"github.com/thesubtlety/tah/internal/store"
)

type fakeScanner struct{}

func (fakeScanner) Scan(path string) ([]scan.Finding, error) {
	return []scan.Finding{{EntityType: "US_SSN", Count: 3, MaxScore: 0.9}}, nil
}

// TestPlumbingEndToEnd: the whole chain holds together — parse -> update path ->
// classify -> scan queue -> content scan -> every query runs without error.
func TestPlumbingEndToEnd(t *testing.T) {
	st := open(t)
	if err := st.InitDefaultCaps(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("testdata/eslogger_sample.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := eslogger.ParseStream("h", f, st.Apply); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scan.Drain(st, fakeScanner{}, 100); err != nil {
		t.Fatal(err)
	}
	win := int64(0)
	readers, err := st.UnexpectedCredentialReaders(win)
	if err != nil || len(readers) < 2 {
		t.Fatalf("readers: %d err=%v", len(readers), err)
	}
	if procs, err := st.NewProcessIdentities(win); err != nil || len(procs) < 2 {
		t.Fatalf("new procs: %d err=%v", len(procs), err)
	}
	if _, err := st.NewParentChild(win); err != nil {
		t.Fatal(err)
	}
	if r, err := st.RankLineages(win); err != nil || len(r) == 0 {
		t.Fatalf("rank: %d err=%v", len(r), err)
	}
	if caps, err := st.Capabilities(); err != nil || len(caps) != 5 {
		t.Fatalf("caps: %d err=%v", len(caps), err)
	}
}

// TestMessyDevHostRanking: on a noisy developer box (interpreter with 60 edges, a
// browser resolving 42 domains), a low-volume attack lineage must still surface.
// The improved class-based ranker puts the attack #1; the naive edge-count order
// buries it under the interpreter — the whole point of the rank rework.
func TestMessyDevHostRanking(t *testing.T) {
	st := open(t)
	// browser is a known reader of its own session store.
	if err := st.AddExpectedReader("browser_state", "com.google.Chrome", "prior", 0); err != nil {
		t.Fatal(err)
	}

	// benign python: huge raw volume, few behavioral classes.
	ex(t, st, 100, 1, "/usr/bin/python3", "")
	for i := 0; i < 30; i++ {
		rd(t, st, 100, "/usr/bin/python3", "/tmp/build/obj"+itoa(i))
	}
	for i := 0; i < 20; i++ {
		conn(t, st, 100, "/usr/bin/python3", "10.0.0."+itoa(i))
	}
	for i := 0; i < 10; i++ {
		ex(t, st, 1100+i, 100, "/tmp/pychild"+itoa(i), "")
	}

	// benign chrome: 42 new domains + reads its own login store (expected).
	ex(t, st, 200, 1, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "com.google.Chrome")
	for i := 0; i < 42; i++ {
		dns(t, st, 200, "com.google.Chrome", "cdn"+itoa(i)+".example.com")
	}
	rd(t, st, 200, "com.google.Chrome", "/Users/x/Library/Application Support/Google/Chrome/Default/Login Data")

	// benign updater.
	ex(t, st, 300, 1, "/Library/Sparkle/Updater", "com.sparkle")
	rd(t, st, 300, "com.sparkle", "/tmp/dl/pkg1")
	conn(t, st, 300, "com.sparkle", "93.184.216.34")

	// THE ATTACK: unsigned tool, few edges, but reads a credential class it isn't
	// an expected reader of, connects out, and spawns.
	ex(t, st, 900, 1, "/tmp/vendorupdater", "")
	rd(t, st, 900, "/tmp/vendorupdater", "/Users/x/.aws/credentials")
	conn(t, st, 900, "/tmp/vendorupdater", "203.0.113.7")
	ex(t, st, 901, 900, "/tmp/attackchild", "")

	attackKey := "/tmp/vendorupdater"

	improved, err := st.RankLineages(0)
	if err != nil {
		t.Fatal(err)
	}
	if r := store.RankOf(improved, attackKey); r != 1 {
		t.Fatalf("improved ranker should surface attack at #1, got rank %d in %+v", r, improved)
	}

	// naive raw edge-count order buries the attack under the interpreter.
	rawRank := rawEdgeCountRank(t, st, attackKey)
	if rawRank <= 1 {
		t.Fatalf("expected raw edge-count order to bury the attack (>1), got %d", rawRank)
	}
	t.Logf("attack rank: improved=1, naive-raw=%d", rawRank)
}

// helpers ---------------------------------------------------------------

func open(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/tah.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func ex(t *testing.T, st *store.Store, pid, ppid int, path, signing string) {
	t.Helper()
	must(t, st.Apply(event.Event{
		TS: 1, Sensor: "eslogger", Fidelity: "high", Kind: event.Exec,
		Actor: event.Actor{PID: pid}, Parent: &event.Actor{PID: ppid},
		Identity: event.Identity{ExecPath: path, SigningID: signing},
	}))
}
func rd(t *testing.T, st *store.Store, pid int, path, file string) {
	t.Helper()
	must(t, st.Apply(event.Event{
		TS: 1, Sensor: "eslogger", Fidelity: "high", Kind: event.Open,
		Actor: event.Actor{PID: pid}, Identity: event.Identity{ExecPath: path}, Path: file, Read: true,
	}))
}
func conn(t *testing.T, st *store.Store, pid int, path, ip string) {
	t.Helper()
	must(t, st.Apply(event.Event{
		TS: 1, Sensor: "lsof", Fidelity: "low", Kind: event.Connect,
		Actor: event.Actor{PID: pid}, Identity: event.Identity{ExecPath: path}, RemoteIP: ip, RemotePort: 443,
	}))
}
func dns(t *testing.T, st *store.Store, pid int, path, domain string) {
	t.Helper()
	must(t, st.Apply(event.Event{
		TS: 1, Sensor: "mdns", Fidelity: "med", Kind: event.DNS,
		Actor: event.Actor{PID: pid}, Identity: event.Identity{ExecPath: path}, QName: domain,
	}))
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// rawEdgeCountRank returns the 1-based rank of key under a naive "most new edges
// wins" ordering — the failure mode the improved ranker is meant to beat.
func rawEdgeCountRank(t *testing.T, st *store.Store, key string) int {
	t.Helper()
	rows, err := st.DB().Query(`
SELECT pn.key, COUNT(*) c
FROM edge e JOIN node pn ON pn.node_id=e.subj_node_id AND pn.kind='proc'
GROUP BY e.subj_node_id ORDER BY c DESC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	rank := 0
	for rows.Next() {
		rank++
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			t.Fatal(err)
		}
		if k == key {
			return rank
		}
	}
	return 0
}
