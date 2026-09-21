package store

import (
	"path/filepath"
	"sort"
	"strings"
)

// Improved lineage ranking for the messy-host case. The naive "count new edges"
// ranker is dominated by interpreters and browsers (dependency-explosion / long
// tail). This scores by:
//   - count of novel relationship CLASSES (a browser's 42 new domains = 1 class,
//     not 42 points), so volume doesn't win;
//   - a bonus per distinct sensitive object class actually read by a NON-expected
//     reader (the high-value signal);
//   - a discount for interpreter / host-process identities whose broad
//     neighborhood is expected (python, node, powershell, svchost, browser helpers).
// Only prov_tier='learned' edges count, so prior/snapshot-vouched novelty is
// suppressed.

type ScoredRow struct {
	Display          string
	Key              string
	Score            int
	NovelClasses     int
	SensitiveClasses int
	Interpreter      bool
}

func (s *Store) RankLineages(windowStartMS int64) ([]ScoredRow, error) {
	expected := s.loadExpectedReaders()

	rows, err := s.db.Query(`
SELECT e.subj_node_id, pn.display, pn.key, e.relation, on2.kind,
       COALESCE(oc.family,''), COALESCE(oc.class,'')
FROM edge e
JOIN node pn ON pn.node_id = e.subj_node_id AND pn.kind='proc'
JOIN node on2 ON on2.node_id = e.obj_node_id
LEFT JOIN object_class oc ON oc.node_id = e.obj_node_id
WHERE e.first_seen > ? AND e.prov_tier='learned'`, windowStartMS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type acc struct {
		display    string
		key        string
		categories map[string]bool
		sensitive  map[string]bool
	}
	bySubj := map[string]*acc{}
	for rows.Next() {
		var subj, display, key, relation, objKind, family, class string
		if err := rows.Scan(&subj, &display, &key, &relation, &objKind, &family, &class); err != nil {
			return nil, err
		}
		a := bySubj[subj]
		if a == nil {
			a = &acc{display: display, key: key, categories: map[string]bool{}, sensitive: map[string]bool{}}
			bySubj[subj] = a
		}
		sensitiveRead := (relation == relOpenedRead) && (family == "rotate" || family == "invalidate")
		if sensitiveRead {
			if expected[class+"\x00"+key] {
				continue // an expected reader touching its own class is not novel signal
			}
			a.categories["sensitive_read"] = true
			a.sensitive[class] = true
			continue
		}
		// Non-sensitive: collapse to one category per relation kind (volume-proof).
		switch relation {
		case relSpawned:
			a.categories["spawn"] = true
		case relConnected:
			a.categories["network"] = true
		case relResolved:
			a.categories["dns"] = true
		case relOpenedWr:
			a.categories["write"] = true
		default:
			a.categories["read"] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var out []ScoredRow
	for _, a := range bySubj {
		interp := isInterpreter(a.display, a.key)
		score := len(a.categories) + 2*len(a.sensitive)
		if interp {
			score -= 3
		}
		out = append(out, ScoredRow{
			Display: a.display, Key: a.key, Score: score,
			NovelClasses: len(a.categories), SensitiveClasses: len(a.sensitive), Interpreter: interp,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].SensitiveClasses > out[j].SensitiveClasses
	})
	return out, nil
}

// RankOf returns the 1-based rank of a lineage key (0 = not present) — the
// Quality-of-Attribution number: candidates an analyst inspects before reaching it.
func RankOf(rows []ScoredRow, key string) int {
	for i, r := range rows {
		if r.Key == key {
			return i + 1
		}
	}
	return 0
}

func (s *Store) loadExpectedReaders() map[string]bool {
	m := map[string]bool{}
	rows, err := s.db.Query(`SELECT object_class, reader_key FROM expected_reader`)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var cls, key string
		if rows.Scan(&cls, &key) == nil {
			m[cls+"\x00"+key] = true
		}
	}
	return m
}

var interpreterNames = map[string]bool{
	"python": true, "python3": true, "node": true, "ruby": true, "perl": true,
	"java": true, "bash": true, "zsh": true, "sh": true, "osascript": true,
	"powershell": true, "pwsh": true, "svchost.exe": true, "svchost": true,
	"rundll32.exe": true, "cmd.exe": true, "wscript.exe": true, "cscript.exe": true,
}

func isInterpreter(display, key string) bool {
	base := strings.ToLower(filepath.Base(display))
	if interpreterNames[base] {
		return true
	}
	l := strings.ToLower(display + " " + key)
	return strings.Contains(l, "helper") // "Google Chrome Helper", "Electron Helper"
}
