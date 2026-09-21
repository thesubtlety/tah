PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS node (
  node_id    TEXT PRIMARY KEY,
  kind       TEXT NOT NULL,
  key        TEXT NOT NULL,
  display    TEXT,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  attrs      TEXT,
  UNIQUE (kind, key)
);

CREATE TABLE IF NOT EXISTS process_instance (
  inst_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  pid          INTEGER NOT NULL,
  pidversion   INTEGER NOT NULL,
  proc_node_id TEXT NOT NULL REFERENCES node(node_id),
  parent_inst  INTEGER REFERENCES process_instance(inst_id),
  resp_inst    INTEGER REFERENCES process_instance(inst_id),
  start_ts     INTEGER NOT NULL,
  exit_ts      INTEGER,
  exit_code    INTEGER,
  argv         TEXT,
  cwd          TEXT,
  cdhash       TEXT,
  signing_id   TEXT,
  team_id      TEXT,
  is_platform  INTEGER,
  exec_path    TEXT,
  UNIQUE (pid, pidversion, start_ts)
);

CREATE TABLE IF NOT EXISTS edge (
  subj_node_id TEXT NOT NULL REFERENCES node(node_id),
  relation     TEXT NOT NULL,
  obj_node_id  TEXT NOT NULL REFERENCES node(node_id),
  first_seen   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  count_ever   INTEGER NOT NULL DEFAULT 0,
  prov_tier    TEXT NOT NULL DEFAULT 'learned',
  fidelity     TEXT NOT NULL DEFAULT 'high',
  source       TEXT,
  flags        INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (subj_node_id, relation, obj_node_id)
);

CREATE TABLE IF NOT EXISTS edge_daycount (
  subj_node_id TEXT NOT NULL,
  relation     TEXT NOT NULL,
  obj_node_id  TEXT NOT NULL,
  day          INTEGER NOT NULL,
  count        INTEGER NOT NULL,
  PRIMARY KEY (subj_node_id, relation, obj_node_id, day)
);

CREATE TABLE IF NOT EXISTS file_object (
  node_id         TEXT PRIMARY KEY REFERENCES node(node_id),
  dev             INTEGER,
  inode           INTEGER,
  size            INTEGER,
  mtime           INTEGER,
  scan_state      TEXT NOT NULL DEFAULT 'unknown',
  scan_requested  INTEGER NOT NULL DEFAULT 0,
  path_class_ts   INTEGER,
  content_scan_ts INTEGER
);

CREATE TABLE IF NOT EXISTS object_class (
  node_id     TEXT NOT NULL REFERENCES node(node_id),
  source      TEXT NOT NULL,
  class       TEXT NOT NULL,
  family      TEXT,
  confidence  REAL NOT NULL DEFAULT 1.0,
  count       INTEGER,
  detected_ts INTEGER NOT NULL,
  PRIMARY KEY (node_id, source, class)
);

CREATE TABLE IF NOT EXISTS expected_reader (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  object_class TEXT NOT NULL,
  reader_key   TEXT NOT NULL,
  match_kind   TEXT NOT NULL DEFAULT 'exact',
  source       TEXT NOT NULL,
  added_ts     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sensor_capability (
  relation  TEXT PRIMARY KEY,
  available INTEGER NOT NULL,
  fidelity  TEXT NOT NULL,
  source    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS host_meta ( k TEXT PRIMARY KEY, v TEXT );

CREATE INDEX IF NOT EXISTS idx_edge_obj     ON edge(obj_node_id, relation);
CREATE INDEX IF NOT EXISTS idx_edge_first   ON edge(first_seen);
CREATE INDEX IF NOT EXISTS idx_node_kind_fs ON node(kind, first_seen);
CREATE INDEX IF NOT EXISTS idx_class_class  ON object_class(class);
CREATE INDEX IF NOT EXISTS idx_class_family ON object_class(family);
CREATE INDEX IF NOT EXISTS idx_inst_pidver  ON process_instance(pid, pidversion);
CREATE INDEX IF NOT EXISTS idx_fileobj_queue ON file_object(scan_requested) WHERE scan_requested = 1;
