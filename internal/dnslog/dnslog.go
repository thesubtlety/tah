// Package dnslog is a per-process DNS collector for macOS. It streams
// `log stream --predicate 'process=="mDNSResponder"' --info --style ndjson` and
// extracts the querying pid + qname from each DNSServiceQueryRecord START line.
//
// The querying process is in the eventMessage text as PID[..](..), NOT the log
// entry's own processID (which is mDNSResponder). Query names are redacted to a
// salted hash unless an mDNSResponder profile sets Privacy-Enable-Level=Sensitive
// (private_data:on is NOT enough); redacted names are emitted as "<redacted>".
package dnslog

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"time"

	"github.com/thesubtlety/tah/internal/event"
)

var queryRe = regexp.MustCompile(`DNSServiceQueryRecord\(\s*\d+,\s*\d+,\s*([^,]+?),\s*(\w+)\)\s+START\s+PID\[(\d+)\]\(([^)]*)\)`)
var redactedRe = regexp.MustCompile(`^[A-Za-z0-9+/]{16,}={0,2}$`)

type logLine struct {
	Timestamp    string `json:"timestamp"`
	EventMessage string `json:"eventMessage"`
}

// ParseLine parses one NDJSON log entry into a DNS event. ok=false for lines
// that aren't a query START.
func ParseLine(host string, data []byte) (event.Event, bool) {
	var l logLine
	if err := json.Unmarshal(data, &l); err != nil {
		return event.Event{}, false
	}
	m := queryRe.FindStringSubmatch(l.EventMessage)
	if m == nil {
		return event.Event{}, false
	}
	qname, qtype, pidStr, proc := m[1], m[2], m[3], m[4]
	if redactedRe.MatchString(qname) {
		qname = "<redacted>"
	}
	var pid int
	for _, c := range pidStr {
		pid = pid*10 + int(c-'0')
	}
	return event.Event{
		TS: parseTime(l.Timestamp), HostID: host, Sensor: "mdns", Fidelity: "med", Kind: event.DNS,
		Actor:    event.Actor{PID: pid},
		Identity: event.Identity{ExecPath: proc},
		QName:    qname,
		QType:    qtype,
	}, true
}

// Stream reads NDJSON log lines and calls emit for each DNS query.
func Stream(host string, r io.Reader, emit func(event.Event) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		if ev, ok := ParseLine(host, sc.Bytes()); ok {
			if err := emit(ev); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

func parseTime(s string) int64 {
	if t, err := time.Parse("2006-01-02 15:04:05.000000-0700", s); err == nil {
		return t.UnixMilli()
	}
	return time.Now().UnixMilli()
}
