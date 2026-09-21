// Package store owns the SQLite tables and the event->tables update path.
package store

import (
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/thesubtlety/tah/internal/classify"
	"github.com/thesubtlety/tah/internal/event"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// Edge relations.
const (
	relSpawned    = "spawned"
	relOpenedRead = "opened_read"
	relOpenedWr   = "opened_write"
	relConnected  = "connected"
	relResolved   = "resolved"
)

// Edge flag bits.
const (
	flagSensitive = 1 << 0
	flagCrossProc = 1 << 1
	flagDormant   = 1 << 2
)

type Store struct {
	db       *sql.DB
	cl       *classify.Classifier
	ProvTier string // "learned" (default) | "snapshot" | "prior"
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// SQLite is single-writer; serialize so concurrent collectors (eslogger +
	// net/dns pollers) don't hit "database is locked".
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	cl, err := classify.New()
	if err != nil {
		return nil, err
	}
	return &Store{db: db, cl: cl, ProvTier: "learned"}, nil
}

func (s *Store) DB() *sql.DB  { return s.db }
func (s *Store) Close() error { return s.db.Close() }

func nodeID(kind, key string) string {
	h := sha256.Sum256([]byte(kind + "\x00" + key))
	return hex.EncodeToString(h[:16])
}

func procKey(id event.Identity) string {
	switch {
	case id.SigningID != "":
		return id.SigningID
	case id.ExecPath != "":
		return id.ExecPath
	default:
		return "unknown"
	}
}

// Apply runs one normalized event through the update path.
func (s *Store) Apply(ev event.Event) error {
	switch ev.Kind {
	case event.Exec:
		return s.applyExec(ev)
	case event.Fork:
		return s.applyFork(ev)
	case event.Exit:
		return s.applyExit(ev)
	case event.Open:
		return s.applyOpen(ev)
	case event.Connect:
		return s.applyConnect(ev)
	case event.DNS:
		return s.applyDNS(ev)
	default:
		return nil
	}
}

func (s *Store) upsertNode(kind, key, display string, ts int64, attrs any) (string, error) {
	id := nodeID(kind, key)
	var aj []byte
	if attrs != nil {
		aj, _ = json.Marshal(attrs)
	}
	_, err := s.db.Exec(`
INSERT INTO node(node_id, kind, key, display, first_seen, last_seen, attrs)
VALUES(?,?,?,?,?,?,?)
ON CONFLICT(node_id) DO UPDATE SET last_seen=excluded.last_seen, display=excluded.display`,
		id, kind, key, display, ts, ts, string(aj))
	return id, err
}

// ensureProc upserts the process identity node and a running instance, returning
// the proc node id and instance id. If the instance for (pid,pidversion) already
// exists it is reused.
func (s *Store) ensureProc(a event.Actor, id event.Identity, ts int64) (string, int64, error) {
	key := procKey(id)
	procNode, err := s.upsertNode("proc", key, id.ExecPath, ts, id)
	if err != nil {
		return "", 0, err
	}
	var instID int64
	err = s.db.QueryRow(`SELECT inst_id FROM process_instance
WHERE pid=? AND pidversion=? ORDER BY start_ts DESC LIMIT 1`, a.PID, a.PIDVersion).Scan(&instID)
	if err == sql.ErrNoRows {
		res, e := s.db.Exec(`
INSERT INTO process_instance(pid,pidversion,proc_node_id,start_ts,argv,cwd,cdhash,signing_id,team_id,is_platform,exec_path)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			a.PID, a.PIDVersion, procNode, ts, "", "", id.CDHash, id.SigningID, id.TeamID, b2i(id.IsPlatform), id.ExecPath)
		if e != nil {
			return "", 0, e
		}
		instID, _ = res.LastInsertId()
	} else if err != nil {
		return "", 0, err
	}
	return procNode, instID, nil
}

// resolveProcNode prefers the identity eslogger already established for this pid
// (so a weak poller identity like a short command name doesn't fork the graph),
// falling back to ensureProc when the pid is unknown.
func (s *Store) resolveProcNode(a event.Actor, id event.Identity, ts int64) (string, error) {
	if pn, _, ok := s.instanceProcNode(a.PID); ok {
		return pn, nil
	}
	pn, _, err := s.ensureProc(a, id, ts)
	return pn, err
}

// instanceProcNode finds the proc node of the newest instance for a pid.
func (s *Store) instanceProcNode(pid int) (string, int64, bool) {
	var pn string
	var iid int64
	err := s.db.QueryRow(`SELECT proc_node_id, inst_id FROM process_instance
WHERE pid=? ORDER BY start_ts DESC LIMIT 1`, pid).Scan(&pn, &iid)
	if err != nil {
		return "", 0, false
	}
	return pn, iid, true
}

func (s *Store) upsertEdge(subj, rel, obj string, ts int64, fidelity, source string, addFlags int) error {
	tier := s.ProvTier
	_, err := s.db.Exec(`
INSERT INTO edge(subj_node_id, relation, obj_node_id, first_seen, last_seen, count_ever, prov_tier, fidelity, source, flags)
VALUES(?,?,?,?,?,1,?,?,?,?)
ON CONFLICT(subj_node_id, relation, obj_node_id) DO UPDATE SET
  last_seen=excluded.last_seen,
  count_ever=edge.count_ever+1,
  fidelity=excluded.fidelity,
  source=excluded.source,
  flags=edge.flags | excluded.flags`,
		subj, rel, obj, ts, ts, tier, fidelity, source, addFlags)
	if err != nil {
		return err
	}
	day := ts / 86400000
	_, err = s.db.Exec(`
INSERT INTO edge_daycount(subj_node_id, relation, obj_node_id, day, count)
VALUES(?,?,?,?,1)
ON CONFLICT(subj_node_id, relation, obj_node_id, day) DO UPDATE SET count=edge_daycount.count+1`,
		subj, rel, obj, day)
	return err
}

func (s *Store) applyExec(ev event.Event) error {
	childNode, childInst, err := s.ensureProc(ev.Actor, ev.Identity, ev.TS)
	if err != nil {
		return err
	}
	if ev.Parent != nil {
		if parentNode, parentInst, ok := s.instanceProcNode(ev.Parent.PID); ok {
			_, _ = s.db.Exec(`UPDATE process_instance SET parent_inst=? WHERE inst_id=?`, parentInst, childInst)
			if err := s.upsertEdge(parentNode, relSpawned, childNode, ev.TS, "high", ev.Sensor, 0); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) applyFork(ev event.Event) error {
	if ev.Child == nil {
		return nil
	}
	// Child inherits the parent's identity until it execs.
	if _, _, err := s.ensureProc(*ev.Child, ev.Identity, ev.TS); err != nil {
		return err
	}
	return nil
}

func (s *Store) applyExit(ev event.Event) error {
	_, err := s.db.Exec(`UPDATE process_instance SET exit_ts=?, exit_code=?
WHERE pid=? AND pidversion=? AND exit_ts IS NULL`, ev.TS, ev.ExitCode, ev.Actor.PID, ev.Actor.PIDVersion)
	return err
}

// ensureFile upserts a file node + file_object row and eager path/glob classification.
func (s *Store) ensureFile(path string, ts int64) (string, []classify.Label, error) {
	fileNode, err := s.upsertNode("file", path, path, ts, nil)
	if err != nil {
		return "", nil, err
	}
	labels := s.cl.Classify(path)
	state := "unknown"
	if len(labels) > 0 {
		state = "path_classified"
	}
	if _, err := s.db.Exec(`
INSERT INTO file_object(node_id, scan_state, path_class_ts)
VALUES(?,?,?)
ON CONFLICT(node_id) DO UPDATE SET scan_state=CASE WHEN file_object.scan_state='content_scanned' THEN 'content_scanned' ELSE excluded.scan_state END`,
		fileNode, state, ts); err != nil {
		return "", nil, err
	}
	for _, l := range labels {
		if _, err := s.db.Exec(`
INSERT INTO object_class(node_id, source, class, family, confidence, detected_ts)
VALUES(?,?,?,?,?,?)
ON CONFLICT(node_id, source, class) DO NOTHING`,
			fileNode, l.Source, l.Class, l.Family, l.Confidence, ts); err != nil {
			return "", nil, err
		}
	}
	return fileNode, labels, nil
}

func (s *Store) isExpectedReader(class, readerKey string) bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM expected_reader
WHERE object_class=? AND reader_key=?`, class, readerKey).Scan(&n)
	return n > 0
}

func (s *Store) applyOpen(ev event.Event) error {
	procNode, _, err := s.ensureProc(ev.Actor, ev.Identity, ev.TS)
	if err != nil {
		return err
	}
	fileNode, labels, err := s.ensureFile(ev.Path, ev.TS)
	if err != nil {
		return err
	}
	rel := relOpenedRead
	if ev.Write && !ev.Read {
		rel = relOpenedWr
	}
	flags := 0
	if ev.Read {
		switch {
		case len(labels) > 0:
			// Path fast-path: a known-sensitive file. Flag an unexpected reader
			// immediately; no need to read its content.
			readerKey := procKey(ev.Identity)
			for _, l := range labels {
				if !s.isExpectedReader(l.Class, readerKey) {
					flags |= flagSensitive
				}
			}
		case s.cl.Scannable(ev.Path):
			// Unknown file: queue content recognition (creds + PII). This is how
			// an arbitrarily-named secret file gets caught — by what it contains,
			// not by an enumerated path list.
			_, _ = s.db.Exec(`UPDATE file_object SET scan_requested=1
WHERE node_id=? AND scan_state<>'content_scanned'`, fileNode)
		}
	}
	return s.upsertEdge(procNode, rel, fileNode, ev.TS, ev.Fidelity, ev.Sensor, flags)
}

func (s *Store) applyConnect(ev event.Event) error {
	procNode, err := s.resolveProcNode(ev.Actor, ev.Identity, ev.TS)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s:%d", ev.RemoteIP, ev.RemotePort)
	ipNode, err := s.upsertNode("ip", key, key, ev.TS, nil)
	if err != nil {
		return err
	}
	fid := ev.Fidelity
	if fid == "" {
		fid = "low"
	}
	return s.upsertEdge(procNode, relConnected, ipNode, ev.TS, fid, ev.Sensor, 0)
}

func (s *Store) applyDNS(ev event.Event) error {
	procNode, err := s.resolveProcNode(ev.Actor, ev.Identity, ev.TS)
	if err != nil {
		return err
	}
	domNode, err := s.upsertNode("domain", ev.QName, ev.QName, ev.TS, nil)
	if err != nil {
		return err
	}
	fid := ev.Fidelity
	if fid == "" {
		fid = "med"
	}
	return s.upsertEdge(procNode, relResolved, domNode, ev.TS, fid, ev.Sensor, 0)
}

// AddExpectedReader seeds a prior/exception (the "ask" side).
func (s *Store) AddExpectedReader(class, readerKey, source string, ts int64) error {
	_, err := s.db.Exec(`INSERT INTO expected_reader(object_class, reader_key, match_kind, source, added_ts)
VALUES(?,?,?,?,?)`, class, readerKey, "exact", source, ts)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
