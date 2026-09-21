// Package classify is the POC sensitive-object classifier: path + glob only
// (cascade layers 1-2). Magic-byte and Presidio content layers are deferred;
// this classifies purely on the object's path and caches nothing itself (the
// store caches by file node). Reads no file content.
package classify

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
)

//go:embed catalog.json
var catalogJSON []byte

// Label is one classification verdict for an object.
type Label struct {
	Class      string // puck category, e.g. "credentials", "browser_state"
	Family     string // "rotate" | "invalidate" | "notify"
	Source     string // "catalog" | "glob" | ...
	Confidence float64
}

type entry struct {
	Class  string   `json:"class"`
	Family string   `json:"family"`
	Source string   `json:"source"`
	Globs  []string `json:"globs"`
	res    []*regexp.Regexp
}

type Classifier struct{ entries []entry }

// New loads the embedded catalog and compiles its globs.
func New() (*Classifier, error) {
	var doc struct {
		Entries []entry `json:"entries"`
	}
	if err := json.Unmarshal(catalogJSON, &doc); err != nil {
		return nil, err
	}
	for i := range doc.Entries {
		for _, g := range doc.Entries[i].Globs {
			doc.Entries[i].res = append(doc.Entries[i].res, regexp.MustCompile(globToRegex(g)))
		}
	}
	return &Classifier{entries: doc.Entries}, nil
}

// Classify returns every matching label for a path (multi-label by design).
func (c *Classifier) Classify(path string) []Label {
	var out []Label
	for _, e := range c.entries {
		for _, re := range e.res {
			if re.MatchString(path) {
				out = append(out, Label{Class: e.Class, Family: e.Family, Source: e.Source, Confidence: 1.0})
				break
			}
		}
	}
	return out
}

// globToRegex translates a **/* glob into an anchored regexp. ** spans /,
// * spans a single path segment.
func globToRegex(g string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); {
		if strings.HasPrefix(g[i:], "**") {
			b.WriteString(".*")
			i += 2
			continue
		}
		c := g[i]
		switch c {
		case '*':
			b.WriteString("[^/]*")
		default:
			if strings.ContainsRune(`.+()|[]{}^$\`, rune(c)) {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		}
		i++
	}
	b.WriteString("$")
	return b.String()
}
