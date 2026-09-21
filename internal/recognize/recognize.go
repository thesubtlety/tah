// Package recognize does content-based credential recognition — "does this file's
// bytes contain a credential-shaped string" — using the gitleaks detection
// library (the same engine geiger uses for its broad net; MIT). Recognition
// only: it identifies typed secrets and validates checksummed prefixes offline.
// It does NOT validate liveness or reach — that is geiger's job, not tah's.
package recognize

import (
	"sync"

	"github.com/zricethezav/gitleaks/v8/detect"
)

// Cred is one recognized credential in a blob of content.
type Cred struct {
	Type   string // gitleaks rule id, e.g. "aws-access-token", "github-pat"
	Secret string // the matched value (kept for redaction/labeling, not stored raw)
	Line   int    // 1-based line
}

var (
	once sync.Once
	det  *detect.Detector
)

func detector() *detect.Detector {
	once.Do(func() {
		if d, err := detect.NewDetectorDefaultConfig(); err == nil {
			det = d
		}
	})
	return det
}

// Creds recognizes credential-shaped strings in content.
func Creds(content string) []Cred {
	d := detector()
	if d == nil {
		return nil
	}
	var out []Cred
	for _, f := range d.DetectString(content) {
		out = append(out, Cred{Type: f.RuleID, Secret: f.Secret, Line: f.StartLine + 1})
	}
	return out
}
