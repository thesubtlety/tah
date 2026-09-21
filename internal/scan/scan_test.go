package scan

import (
	"path/filepath"
	"testing"

	"github.com/puck-security/tah/internal/event"
	"github.com/puck-security/tah/internal/store"
)

type fakeScanner map[string][]Finding

func (f fakeScanner) Scan(path string) ([]Finding, error) { return f[path], nil }

func TestDrainRecordsPIIAndMarksScanned(t *testing.T) {
	db := filepath.Join(t.TempDir(), "tah.db")
	st, err := store.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// An unexpected reader touches a credentials file → queues a content scan.
	docPath := "/Users/noah/.aws/credentials"
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
