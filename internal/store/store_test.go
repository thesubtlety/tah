package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thesubtlety/tah/internal/eslogger"
	"github.com/thesubtlety/tah/internal/event"
)

func TestFlagshipUnexpectedReader(t *testing.T) {
	db := filepath.Join(t.TempDir(), "tah.db")
	st, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// The "ask" side: ssh is a known reader of private keys.
	if err := st.AddExpectedReader("private_key", "com.apple.ssh", "prior", 0); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open("testdata/eslogger_sample.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	if err := eslogger.ParseStream("host1", f, func(ev event.Event) error { n++; return st.Apply(ev) }); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("expected 5 mapped events, got %d", n)
	}

	fs, err := st.UnexpectedCredentialReaders(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 unexpected-reader findings, got %d: %+v", len(fs), fs)
	}
	files := map[string]string{}
	for _, x := range fs {
		files[x.File] = x.Class
		if x.Reader != "/tmp/stealer" {
			t.Errorf("unexpected reader identity: %q", x.Reader)
		}
	}
	if _, ok := files["/Users/noah/.aws/credentials"]; !ok {
		t.Error("missing .aws/credentials finding")
	}
	if !hasSuffixKey(files, "Login Data") {
		t.Error("missing Chrome Login Data finding")
	}
	for k := range files {
		if strings.HasSuffix(k, "id_rsa") {
			t.Error("ssh/id_rsa should be excluded (expected reader)")
		}
	}

	// spawn lineage: ssh -> stealer edge recorded.
	var spawn int
	_ = st.DB().QueryRow(`SELECT COUNT(*) FROM edge WHERE relation='spawned'`).Scan(&spawn)
	if spawn != 1 {
		t.Errorf("expected 1 spawn edge, got %d", spawn)
	}

	// sensitive flag set on the flagged reads.
	var flagged int
	_ = st.DB().QueryRow(`SELECT COUNT(*) FROM edge WHERE relation='opened_read' AND (flags & 1)<>0`).Scan(&flagged)
	if flagged != 2 {
		t.Errorf("expected 2 sensitive-flagged read edges, got %d", flagged)
	}

	// scan_requested queued for the flagged files (Presidio hook).
	var queued int
	_ = st.DB().QueryRow(`SELECT COUNT(*) FROM file_object WHERE scan_requested=1`).Scan(&queued)
	if queued != 2 {
		t.Errorf("expected 2 files queued for content scan, got %d", queued)
	}
}

func TestNewNetworkUser(t *testing.T) {
	db := filepath.Join(t.TempDir(), "tah.db")
	st, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// stealer makes its first-ever connection (network is not an eslogger event;
	// this is the polled net_connect adapter's shape, fidelity low).
	ev := event.Event{
		TS: 1000, HostID: "h", Sensor: "nettop", Fidelity: "low", Kind: event.Connect,
		Actor:    event.Actor{PID: 900, PIDVersion: 1},
		Identity: event.Identity{ExecPath: "/tmp/stealer"},
		Proto:    "tcp", RemoteIP: "203.0.113.7", RemotePort: 443,
	}
	if err := st.Apply(ev); err != nil {
		t.Fatal(err)
	}
	fs, err := st.NewNetworkUsers(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Fidelity != "low" {
		t.Fatalf("expected 1 low-fidelity new-network finding, got %+v", fs)
	}
}

func hasSuffixKey(m map[string]string, suffix string) bool {
	for k := range m {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return false
}
