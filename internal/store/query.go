package store

// Queries over the behavioral memory. Each returns leads for an analyst; the
// data is alert-shaped (novelty, class, fidelity, lineage all on the row).

// Finding is one unexpected-reader lead.
type Finding struct {
	Reader   string // exec path of the reading process
	ReaderID string // proc node key
	File     string
	Class    string
	Family   string
	Fidelity string
	FirstMS  int64
}

// UnexpectedCredentialReaders is the flagship question: a not-yet-learned-normal
// process read a rotate/invalidate-class object in the window and is not a known
// expected reader of that class.
func (s *Store) UnexpectedCredentialReaders(windowStartMS int64) ([]Finding, error) {
	rows, err := s.db.Query(`
SELECT pn.display, pn.key, fn.key, oc.class, COALESCE(oc.family,''), e.fidelity, e.first_seen
FROM edge e
JOIN node pn ON pn.node_id = e.subj_node_id AND pn.kind='proc'
JOIN node fn ON fn.node_id = e.obj_node_id AND fn.kind='file'
JOIN object_class oc ON oc.node_id = e.obj_node_id
WHERE e.relation='opened_read'
  AND e.first_seen > ?
  AND oc.family IN ('rotate','invalidate')
  AND e.prov_tier='learned'
  AND NOT EXISTS (
    SELECT 1 FROM expected_reader er
    WHERE er.object_class = oc.class AND er.reader_key = pn.key
  )
ORDER BY e.first_seen DESC`, windowStartMS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.Reader, &f.ReaderID, &f.File, &f.Class, &f.Family, &f.Fidelity, &f.FirstMS); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// NewNetworkUsers answers "which processes began using the network when they
// historically did not" (question 3): a connected/resolved edge first seen in
// the window for a process identity that has no such edge from before it.
func (s *Store) NewNetworkUsers(windowStartMS int64) ([]Finding, error) {
	rows, err := s.db.Query(`
SELECT pn.display, pn.key, e.obj_node_id, on2.kind, e.fidelity, e.first_seen
FROM edge e
JOIN node pn ON pn.node_id=e.subj_node_id AND pn.kind='proc'
JOIN node on2 ON on2.node_id=e.obj_node_id
WHERE e.relation IN ('connected','resolved')
  AND e.first_seen > ?
  AND NOT EXISTS (
    SELECT 1 FROM edge e2 WHERE e2.subj_node_id=e.subj_node_id
      AND e2.relation IN ('connected','resolved') AND e2.first_seen <= ?
  )
ORDER BY e.first_seen DESC`, windowStartMS, windowStartMS)
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
