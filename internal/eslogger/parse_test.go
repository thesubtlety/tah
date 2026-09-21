package eslogger

import (
	"testing"

	"github.com/thesubtlety/tah/internal/event"
)

func TestParseOpen(t *testing.T) {
	line := []byte(`{"time":"2026-09-18T21:05:01Z","process":{"audit_token":{"pid":900,"pidversion":2},"executable":{"path":"/tmp/x"},"signing_id":""},"event":{"open":{"fflag":1,"file":{"path":"/Users/noah/.aws/credentials"}}}}`)
	ev, ok, err := ParseLine("h", line)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.Kind != event.Open || ev.Path != "/Users/noah/.aws/credentials" {
		t.Fatalf("bad event: %+v", ev)
	}
	if !ev.Read || ev.Write {
		t.Fatalf("expected read-only intent: %+v", ev)
	}
	if ev.Actor.PID != 900 || ev.Actor.PIDVersion != 2 {
		t.Fatalf("bad actor: %+v", ev.Actor)
	}
	if ev.Sensor != "eslogger" || ev.Fidelity != "high" {
		t.Fatalf("bad provenance: %+v", ev)
	}
}
