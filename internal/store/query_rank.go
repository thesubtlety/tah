package store

// Ranking / "what changed" queries — the how.md investigation questions, the
// entry point for the watch/report subcommand.

// NodeRow is a simple node result.
type NodeRow struct {
	Key     string
	Display string
	FirstMS int64
}

// NewProcessIdentities: question 1 — executable identities first seen in window.
func (s *Store) NewProcessIdentities(windowStartMS int64) ([]NodeRow, error) {
	return s.nodeRows(`SELECT key, display, first_seen FROM node
WHERE kind='proc' AND first_seen > ? ORDER BY first_seen DESC`, windowStartMS)
}

// NewParentChild: question 2 — parent→child relationships first seen in window.
func (s *Store) NewParentChild(windowStartMS int64) ([]Finding, error) {
	rows, err := s.db.Query(`
SELECT pp.display, pp.key, cc.display, '', e.fidelity, e.first_seen
FROM edge e
JOIN node pp ON pp.node_id=e.subj_node_id
JOIN node cc ON cc.node_id=e.obj_node_id
WHERE e.relation='spawned' AND e.first_seen > ?
ORDER BY e.first_seen DESC`, windowStartMS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.Reader, &f.ReaderID, &f.File, &f.Class, &f.Fidelity, &f.FirstMS); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RankRow ranks a process identity by how much its behavioral neighborhood changed.
type RankRow struct {
	Display   string
	Key       string
	NewEdges  int
	Sensitive int
}

// LineageChangeRank: question 10 — rank process identities by count of new edges
// in the window, surfacing sensitive-object touches first.
func (s *Store) LineageChangeRank(windowStartMS int64) ([]RankRow, error) {
	rows, err := s.db.Query(`
SELECT n.display, n.key,
       COUNT(*) AS new_edges,
       SUM(CASE WHEN (e.flags & 1)<>0 THEN 1 ELSE 0 END) AS sensitive
FROM edge e
JOIN node n ON n.node_id = e.subj_node_id AND n.kind='proc'
WHERE e.first_seen > ?
GROUP BY e.subj_node_id
ORDER BY sensitive DESC, new_edges DESC`, windowStartMS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RankRow
	for rows.Next() {
		var r RankRow
		if err := rows.Scan(&r.Display, &r.Key, &r.NewEdges, &r.Sensitive); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) nodeRows(q string, args ...any) ([]NodeRow, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeRow
	for rows.Next() {
		var r NodeRow
		if err := rows.Scan(&r.Key, &r.Display, &r.FirstMS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
