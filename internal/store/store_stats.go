package store

// Stats is a quick "is this thing capturing?" snapshot for `tah status`.
type Stats struct {
	Procs, Files, IPs, Domains int
	Edges                      int
	SensitiveReads             int
	QueuedScans                int
	NotifyFindings             int
	FirstSeenMS, LastSeenMS    int64
}

func (s *Store) Stats() (Stats, error) {
	var st Stats
	q := func(dst *int, sql string, args ...any) error {
		return s.db.QueryRow(sql, args...).Scan(dst)
	}
	if err := q(&st.Procs, `SELECT COUNT(*) FROM node WHERE kind='proc'`); err != nil {
		return st, err
	}
	_ = q(&st.Files, `SELECT COUNT(*) FROM node WHERE kind='file'`)
	_ = q(&st.IPs, `SELECT COUNT(*) FROM node WHERE kind='ip'`)
	_ = q(&st.Domains, `SELECT COUNT(*) FROM node WHERE kind='domain'`)
	_ = q(&st.Edges, `SELECT COUNT(*) FROM edge`)
	_ = q(&st.SensitiveReads, `SELECT COUNT(*) FROM edge WHERE relation='opened_read' AND (flags & 1)<>0`)
	_ = q(&st.QueuedScans, `SELECT COUNT(*) FROM file_object WHERE scan_requested=1`)
	_ = q(&st.NotifyFindings, `SELECT COUNT(*) FROM object_class WHERE source='presidio'`)
	_ = s.db.QueryRow(`SELECT COALESCE(MIN(first_seen),0), COALESCE(MAX(last_seen),0) FROM edge`).Scan(&st.FirstSeenMS, &st.LastSeenMS)
	return st, nil
}
