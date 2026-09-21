// Package scan runs content classification over files the store has queued.
// The Scanner interface keeps Presidio (a Python subprocess, macOS/anywhere with
// Python) swappable with a fake for tests.
package scan

import (
	"encoding/json"
	"os/exec"
	"time"

	"github.com/puck-security/tah/internal/store"
)

// Finding is one content-classification result: an entity type with a count.
type Finding struct {
	EntityType string  `json:"type"`
	Count      int     `json:"count"`
	MaxScore   float64 `json:"max_score"`
}

// Scanner inspects a file's contents and returns entity findings.
type Scanner interface {
	Scan(path string) ([]Finding, error)
}

// Drain processes every queued file through the scanner, records its content
// classes (PII → family "notify"), and marks it scanned. A scan error still
// marks the file scanned so it is not retried forever; the error is returned
// aggregated via the count of failures for the caller to log.
func Drain(st *store.Store, sc Scanner, limit int) (processed, failed int, err error) {
	q, err := st.QueuedScans(limit)
	if err != nil {
		return 0, 0, err
	}
	for _, f := range q {
		ts := time.Now().UnixMilli()
		fs, serr := sc.Scan(f.Path)
		if serr != nil {
			failed++
		} else {
			for _, x := range fs {
				if x.Count <= 0 {
					continue
				}
				if e := st.RecordContentClass(f.NodeID, "presidio", x.EntityType, "notify", x.MaxScore, x.Count, ts); e != nil {
					return processed, failed, e
				}
			}
		}
		if e := st.MarkScanned(f.NodeID, ts); e != nil {
			return processed, failed, e
		}
		processed++
	}
	return processed, failed, nil
}

// PresidioScanner shells out to the bundled presidio_scan.py.
type PresidioScanner struct {
	Python string // e.g. "python3"
	Script string // path to presidio_scan.py
}

type presidioOut struct {
	Entities []Finding `json:"entities"`
	Error    string    `json:"error"`
}

func (p PresidioScanner) Scan(path string) ([]Finding, error) {
	py := p.Python
	if py == "" {
		py = "python3"
	}
	out, err := exec.Command(py, p.Script, path).Output()
	if err != nil {
		return nil, err
	}
	var r presidioOut
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, err
	}
	return r.Entities, nil
}
