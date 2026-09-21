package store

// Scan-queue support: the Presidio content-classification worker drains files
// flagged scan_requested, records per-entity classes, and marks them scanned.

type QueuedFile struct {
	NodeID string
	Path   string
}

// QueuedScans returns files awaiting a content scan (scan_requested=1).
func (s *Store) QueuedScans(limit int) ([]QueuedFile, error) {
	rows, err := s.db.Query(`
SELECT fo.node_id, n.key
FROM file_object fo JOIN node n ON n.node_id = fo.node_id
WHERE fo.scan_requested = 1
ORDER BY fo.path_class_ts
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QueuedFile
	for rows.Next() {
		var q QueuedFile
		if err := rows.Scan(&q.NodeID, &q.Path); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// RecordContentClass writes a content-derived classification (e.g. a Presidio
// entity type with a count).
func (s *Store) RecordContentClass(nodeID, source, class, family string, confidence float64, count int, ts int64) error {
	_, err := s.db.Exec(`
INSERT INTO object_class(node_id, source, class, family, confidence, count, detected_ts)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(node_id, source, class) DO UPDATE SET
  count=excluded.count, confidence=MAX(object_class.confidence, excluded.confidence), detected_ts=excluded.detected_ts`,
		nodeID, source, class, family, confidence, count, ts)
	return err
}

// MarkScanned clears the queue flag and advances the file's scan state.
func (s *Store) MarkScanned(nodeID string, ts int64) error {
	_, err := s.db.Exec(`UPDATE file_object
SET scan_requested=0, scan_state='content_scanned', content_scan_ts=?
WHERE node_id=?`, ts, nodeID)
	return err
}
