// Package scan runs content classification over files the store has queued.
// The Scanner interface keeps Presidio (a Python subprocess, macOS/anywhere with
// Python) swappable with a fake for tests.
package scan

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/thesubtlety/tah/internal/recognize"
	"github.com/thesubtlety/tah/internal/store"
)

const maxScanBytes = 1 << 20 // 1 MiB read cap for content recognition

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxScanBytes))
}

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

// Drain processes every queued file: it recognizes credentials in the content
// (in-process, always) and, if a PII scanner is supplied, PII entities too, then
// records the classes and marks the file scanned. A file read or scan failure
// still marks it scanned so it is not retried forever.
//
//   - credentials → object_class(source "geiger", family "rotate")
//   - PII         → object_class(source "presidio", family "notify")
//
// pii may be nil (e.g. Presidio not installed); credential recognition still runs.
func Drain(st *store.Store, pii Scanner, limit int) (processed, failed int, err error) {
	q, err := st.QueuedScans(limit)
	if err != nil {
		return 0, 0, err
	}
	for _, f := range q {
		ts := time.Now().UnixMilli()

		// credentials (in-process, no external dependency)
		if content, rerr := readCapped(f.Path); rerr == nil {
			seen := map[string]bool{}
			for _, c := range recognize.Creds(string(content)) {
				if seen[c.Type] {
					continue
				}
				seen[c.Type] = true
				if e := st.RecordContentClass(f.NodeID, "geiger", c.Type, "rotate", 1.0, 1, ts); e != nil {
					return processed, failed, e
				}
			}
		}

		// PII (optional)
		if pii != nil {
			if fs, serr := pii.Scan(f.Path); serr != nil {
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
