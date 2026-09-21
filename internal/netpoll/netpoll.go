// Package netpoll is a polling per-process network collector for macOS. It shells
// to `lsof -nP -i -FpcntPT` (field output) and emits Connect events. It is a
// SNAPSHOT poller: short-lived connections between polls are missed (fidelity low).
// A lossless feed needs a NetworkExtension content filter, out of POC scope.
package netpoll

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/thesubtlety/tah/internal/event"
)

// Parse converts `lsof -FpcntPT` field output into Connect events (one per
// connected socket that has a remote endpoint; listeners are skipped).
func Parse(host string, data []byte) []event.Event {
	var out []event.Event
	var curPID int
	var curCmd string
	// in-progress connection record
	var proto, name string
	ts := time.Now().UnixMilli()

	flush := func() {
		if name == "" || !strings.Contains(name, "->") {
			proto, name = "", ""
			return
		}
		parts := strings.SplitN(name, "->", 2)
		lip, lport := splitAddr(parts[0])
		rip, rport := splitAddr(parts[1])
		_ = lip
		out = append(out, event.Event{
			TS: ts, HostID: host, Sensor: "lsof", Fidelity: "low", Kind: event.Connect,
			Actor:      event.Actor{PID: curPID},
			Identity:   event.Identity{ExecPath: curCmd},
			Proto:      strings.ToLower(proto),
			RemoteIP:   rip,
			RemotePort: rport,
			LocalPort:  lport,
		})
		proto, name = "", ""
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		tag, val := line[0], line[1:]
		switch tag {
		case 'p':
			flush()
			curPID, _ = strconv.Atoi(val)
			curCmd = ""
		case 'c':
			curCmd = val
		case 'f':
			flush() // new file set -> finish the previous connection
		case 'P':
			proto = val
		case 'n':
			name = val
		}
	}
	flush()
	return out
}

// splitAddr splits "ip:port" (IPv4) or "[ip]:port" (IPv6) into (ip, port).
func splitAddr(s string) (string, int) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, ":"); i >= 0 {
		ip := strings.Trim(s[:i], "[]")
		port, _ := strconv.Atoi(s[i+1:])
		return ip, port
	}
	return strings.Trim(s, "[]"), 0
}

// Poll runs lsof once and returns the current connections (macOS).
func Poll(host string) ([]event.Event, error) {
	out, err := exec.Command("lsof", "-nP", "-i", "-FpcntPT").Output()
	if err != nil {
		return nil, err
	}
	return Parse(host, out), nil
}
