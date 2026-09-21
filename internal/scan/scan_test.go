package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thesubtlety/tah/internal/event"
	"github.com/thesubtlety/tah/internal/store"
)

type fakeScanner map[string][]Finding

func (f fakeScanner) Scan(path string) ([]Finding, error) { return f[path], nil }

// TestContentCredentialRecognition proves the full new path: an unexpected process
// reads an UNKNOWN file (no catalog match) that contains a token; content
// recognition catches it and the flagship surfaces it — sensitivity from content,
// not path.
func TestContentCredentialRecognition(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "tah.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	secretFile := filepath.Join(t.TempDir(), "config.txt")
	if err := os.WriteFile(secretFile, []byte("gh_token = ghp_012345678901234567890123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.Apply(event.Event{
		TS: 1, Sensor: "eslogger", Fidelity: "high", Kind: event.Open,
		Actor:    event.Actor{PID: 700, PIDVersion: 1},
		Identity: event.Identity{ExecPath: "/tmp/curl"},
		Path:     secretFile, Read: true,
	}); err != nil {
		t.Fatal(err)
	}

	if q, _ := st.QueuedScans(10); len(q) != 1 {
		t.Fatalf("expected the unknown file queued for recognition, got %+v", q)
	}
	if _, _, err := Drain(st, nil, 10); err != nil { // nil = no PII scanner; creds still run
		t.Fatal(err)
	}
	var n int
	_ = st.DB().QueryRow(`SELECT COUNT(*) FROM object_class WHERE source='geiger' AND family='rotate'`).Scan(&n)
	if n == 0 {
		t.Fatal("expected a recognized credential class recorded from content")
	}
	fs, err := st.UnexpectedCredentialReaders(0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.File == secretFile {
			found = true
		}
	}
	if !found {
		t.Fatalf("flagship should surface the content-recognized file, got %+v", fs)
	}
}

func TestDrainRecordsPIIAndMarksScanned(t *testing.T) {
	db := filepath.Join(t.TempDir(), "tah.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// An unexpected reader touches an UNKNOWN (non-catalogued) file → it queues for
	// content recognition. (Path-known files don't queue; they're already classified.)
	docPath := "/Users/noah/Documents/quarterly.txt"
	if err := st.Apply(event.Event{
		TS: 1, Sensor: "eslogger", Fidelity: "high", Kind: event.Open,
		Actor:    event.Actor{PID: 900, PIDVersion: 1},
		Identity: event.Identity{ExecPath: "/tmp/stealer"},
		Path:     docPath, Read: true,
	}); err != nil {
		t.Fatal(err)
	}

	q, _ := st.QueuedScans(10)
	if len(q) != 1 || q[0].Path != docPath {
		t.Fatalf("expected 1 queued file, got %+v", q)
	}

	sc := fakeScanner{docPath: {{EntityType: "US_SSN", Count: 12, MaxScore: 0.85}, {EntityType: "CREDIT_CARD", Count: 3, MaxScore: 0.99}}}
	processed, failed, err := Drain(st, sc, 100)
	if err != nil || processed != 1 || failed != 0 {
		t.Fatalf("drain: processed=%d failed=%d err=%v", processed, failed, err)
	}

	// notify-family PII rows recorded with counts.
	var ssnCount int
	if err := st.DB().QueryRow(`SELECT count FROM object_class
WHERE source='presidio' AND class='US_SSN' AND family='notify'`).Scan(&ssnCount); err != nil {
		t.Fatalf("SSN row: %v", err)
	}
	if ssnCount != 12 {
		t.Errorf("expected SSN count 12, got %d", ssnCount)
	}

	// queue drained, state advanced.
	var reqd, scanned int
	_ = st.DB().QueryRow(`SELECT COUNT(*) FROM file_object WHERE scan_requested=1`).Scan(&reqd)
	_ = st.DB().QueryRow(`SELECT COUNT(*) FROM file_object WHERE scan_state='content_scanned'`).Scan(&scanned)
	if reqd != 0 || scanned != 1 {
		t.Errorf("expected queue empty and 1 scanned, got requested=%d scanned=%d", reqd, scanned)
	}
}
