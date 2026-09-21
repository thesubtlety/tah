// Package eslogger maps Apple eslogger NDJSON into the normalized event contract.
//
// Field paths are confirmed against two independent open-source parsers
// (tstromberg/esl, nubcoxyz/ESLogger) plus the eslogger(1) man page: audit_token
// is a named object (process.audit_token.pid/.pidversion), event is a single-key
// map, open.fflag is kernel FFLAGS (FREAD=0x1), exit.stat is a wait-status.
// eslogger fields are version-gated, so give it one confirming run on the target
// macOS build; the pipeline downstream of this parser is OS-independent and tested.
package eslogger

import (
	"bufio"
	"encoding/json"
	"io"
	"strconv"
	"time"

	"github.com/puck-security/tah/internal/event"
)

// fflag bits (fcntl-style, as ES reports them).
const (
	fRead  = 0x0001
	fWrite = 0x0002
)

type auditToken struct {
	PID        int `json:"pid"`
	PIDVersion int `json:"pidversion"`
}

type esFile struct {
	Path string `json:"path"`
}

type esProcess struct {
	AuditToken  auditToken  `json:"audit_token"`
	PPID        int         `json:"ppid"`
	Responsible *auditToken `json:"responsible_audit_token"`
	Executable  esFile      `json:"executable"`
	CDHash      string      `json:"cdhash"`
	SigningID   string      `json:"signing_id"`
	TeamID      string      `json:"team_id"`
	IsPlatform  bool        `json:"is_platform_binary"`
}

func (p esProcess) identity() event.Identity {
	return event.Identity{
		ExecPath:   p.Executable.Path,
		CDHash:     p.CDHash,
		SigningID:  p.SigningID,
		TeamID:     p.TeamID,
		IsPlatform: p.IsPlatform,
	}
}
func (p esProcess) actor() event.Actor {
	return event.Actor{PID: p.AuditToken.PID, PIDVersion: p.AuditToken.PIDVersion}
}

type esMessage struct {
	Time    string                     `json:"time"`
	SeqNum  uint64                     `json:"seq_num"`
	Process esProcess                  `json:"process"`
	Event   map[string]json.RawMessage `json:"event"`
}

// ParseLine converts one eslogger JSON line into an Event. ok=false means the
// line was a well-formed message of an event type we don't map (skip it).
func ParseLine(host string, line []byte) (event.Event, bool, error) {
	var m esMessage
	if err := json.Unmarshal(line, &m); err != nil {
		return event.Event{}, false, err
	}
	ts := parseTime(m.Time)
	base := event.Event{
		TS: ts, HostID: host, Sensor: "eslogger", Fidelity: "high",
		Actor: m.Process.actor(),
	}
	for name, raw := range m.Event {
		switch name {
		case "exec":
			var e struct {
				Target esProcess `json:"target"`
				Args   []string  `json:"args"`
				CWD    esFile    `json:"cwd"`
			}
			_ = json.Unmarshal(raw, &e)
			base.Kind = event.Exec
			// Post-exec the process IS the target; use the target's audit token
			// so later events for this pid+pidversion attribute to one instance.
			base.Actor = e.Target.actor()
			base.Identity = e.Target.identity()
			base.Argv = e.Args
			base.CWD = e.CWD.Path
			base.Parent = &event.Actor{PID: m.Process.PPID}
			if m.Process.Responsible != nil {
				base.Responsible = &event.Actor{PID: m.Process.Responsible.PID, PIDVersion: m.Process.Responsible.PIDVersion}
			}
			return base, true, nil
		case "fork":
			var e struct {
				Child esProcess `json:"child"`
			}
			_ = json.Unmarshal(raw, &e)
			base.Kind = event.Fork
			base.Identity = m.Process.identity()
			c := e.Child.actor()
			base.Child = &c
			return base, true, nil
		case "exit":
			var e struct {
				Stat int `json:"stat"`
			}
			_ = json.Unmarshal(raw, &e)
			base.Kind = event.Exit
			base.Identity = m.Process.identity()
			base.ExitCode = (e.Stat >> 8) & 0xff // WEXITSTATUS(wait-status)
			return base, true, nil
		case "open":
			var e struct {
				FFlag int    `json:"fflag"`
				File  esFile `json:"file"`
			}
			_ = json.Unmarshal(raw, &e)
			base.Kind = event.Open
			base.Identity = m.Process.identity()
			base.Path = e.File.Path
			base.Read = e.FFlag&fRead != 0
			base.Write = e.FFlag&fWrite != 0
			if !base.Read && !base.Write {
				base.Read = true
			}
			return base, true, nil
		}
	}
	return event.Event{}, false, nil
}

// ParseStream reads NDJSON and calls emit for each mapped event.
func ParseStream(host string, r io.Reader, emit func(event.Event) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		ev, ok, err := ParseLine(host, b)
		if err != nil || !ok {
			continue
		}
		if err := emit(ev); err != nil {
			return err
		}
	}
	return sc.Err()
}

func parseTime(s string) int64 {
	if s == "" {
		return time.Now().UnixMilli()
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UnixMilli()
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return time.Now().UnixMilli()
}
