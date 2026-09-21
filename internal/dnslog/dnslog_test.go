package dnslog

import "testing"

func TestParseDNSLine(t *testing.T) {
	line := `{"timestamp":"2022-07-24 18:46:48.130384-0000","eventMessage":"[R2114] DNSServiceQueryRecord(15000, 0, api.onedrive.com, Addr) START PID[9153](rclone)","processID":221}`
	ev, ok := ParseLine("h", []byte(line))
	if !ok {
		t.Fatal("expected a DNS event")
	}
	if ev.QName != "api.onedrive.com" || ev.QType != "Addr" {
		t.Errorf("bad query: %+v", ev)
	}
	if ev.Actor.PID != 9153 || ev.Identity.ExecPath != "rclone" {
		t.Errorf("bad querying process: %+v", ev)
	}
}

func TestParseDNSRedacted(t *testing.T) {
	line := `{"timestamp":"2022-07-24 18:46:48.130384-0000","eventMessage":"[R2076] DNSServiceQueryRecord(15000, 0, qefxZtfJBc5Xm4i7BNS+3Q==, AAAA) START PID[9063](rclone)"}`
	ev, ok := ParseLine("h", []byte(line))
	if !ok || ev.QName != "<redacted>" {
		t.Errorf("expected redacted qname, got ok=%v %+v", ok, ev)
	}
}
