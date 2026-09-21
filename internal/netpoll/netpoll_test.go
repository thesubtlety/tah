package netpoll

import "testing"

func TestParseLsofFields(t *testing.T) {
	sample := `p5356
cfirefox
f94u
tIPv4
PTCP
n192.168.254.212:52429->55.65.117.34:443
TST=ESTABLISHED
f95u
tIPv4
PTCP
n192.168.254.212:52510->140.82.113.26:443
TST=ESTABLISHED
p640
cmDNSResponder
f18u
tIPv4
PUDP
n*:5353
`
	evs := Parse("h", []byte(sample))
	if len(evs) != 2 {
		t.Fatalf("expected 2 connect events (listener skipped), got %d: %+v", len(evs), evs)
	}
	if evs[0].Actor.PID != 5356 || evs[0].Identity.ExecPath != "firefox" {
		t.Errorf("bad actor: %+v", evs[0])
	}
	if evs[0].RemoteIP != "55.65.117.34" || evs[0].RemotePort != 443 || evs[0].Proto != "tcp" {
		t.Errorf("bad remote: %+v", evs[0])
	}
	if evs[1].RemoteIP != "140.82.113.26" {
		t.Errorf("bad second remote: %+v", evs[1])
	}
}
