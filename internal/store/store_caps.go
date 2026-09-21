package store

// Sensor capability descriptor: what this host's adapters can actually observe,
// so the ranker can gate/label the ten questions.

type Capability struct {
	Relation  string
	Available bool
	Fidelity  string
	Source    string
}

func (s *Store) SetCapability(c Capability) error {
	_, err := s.db.Exec(`
INSERT INTO sensor_capability(relation, available, fidelity, source)
VALUES(?,?,?,?)
ON CONFLICT(relation) DO UPDATE SET available=excluded.available, fidelity=excluded.fidelity, source=excluded.source`,
		c.Relation, b2i(c.Available), c.Fidelity, c.Source)
	return err
}

func (s *Store) Capabilities() ([]Capability, error) {
	rows, err := s.db.Query(`SELECT relation, available, fidelity, source FROM sensor_capability ORDER BY relation`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Capability
	for rows.Next() {
		var c Capability
		var av int
		if err := rows.Scan(&c.Relation, &av, &c.Fidelity, &c.Source); err != nil {
			return nil, err
		}
		c.Available = av != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// InitDefaultCaps records what the macOS eslogger + polling adapters can see.
func (s *Store) InitDefaultCaps() error {
	defs := []Capability{
		{"spawned", true, "high", "eslogger"},
		{"opened_read", true, "high", "eslogger"},
		{"opened_write", true, "high", "eslogger"},
		{"connected", true, "low", "nettop"}, // polled: misses short-lived
		{"resolved", true, "med", "mdns"},    // unified log; DoH blind
	}
	for _, c := range defs {
		if err := s.SetCapability(c); err != nil {
			return err
		}
	}
	return nil
}
