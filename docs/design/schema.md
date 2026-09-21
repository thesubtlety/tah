# POC schema: event contract + edge/object tables

macOS-first POC. Go core, SQLite store, eslogger adapter. Sensor-agnostic: adapters emit the
normalized event below; the core owns the tables. The edge model is untouched by Presidio;
Presidio lives entirely in the object-classification tables.

## 1. Normalized event (the adapter → core contract)

Every adapter (eslogger now; osquery/Sysmon/ETW later) emits this shape. `sensor`+`fidelity`
is where a low-quality source (polled network) declares itself, so edges can inherit it.

```jsonc
{
  "ts":       1726690000000,        // epoch ms
  "host_id":  "…",
  "sensor":   "eslogger",           // eslogger | nettop | mdns | osquery | sysmon
  "fidelity": "high",               // high | med | low
  "kind":     "file_open",
  "actor":    { "pid": 501, "pidversion": 3 },   // pid+pidversion = the real key
  // kind-specific below:
}
```

| kind | extra fields |
|---|---|
| `process_exec` | `ppid{pid,pidversion}`, `responsible{pid,pidversion}`, `identity{exec_path,cdhash,signing_id,team_id,is_platform}`, `argv[]`, `cwd` |
| `process_fork` | `child{pid,pidversion}` |
| `process_exit` | `exit_code` |
| `file_open` | `path`, `read`(bool), `write`(bool)  — from ES `fflag` |
| `file_close` | `path`, `modified`(bool) |
| `net_connect` | `proto`, `remote_ip`, `remote_port`, `local_port`  — fidelity `low` (polled) |
| `dns_query` | `qname`, `qtype`, `answers[]`  — fidelity `med` |

Optionally persisted to a short-retention `event` ring for lineage rebuild / window recompute;
the durable memory is the edge DB.

## 2. Nodes and process instances

Unified **typed node** table for anything an edge can touch (processes-as-identity, files,
domains, IPs). Separate **process_instance** for runtime lineage and to attribute an event's
`pid+pidversion` to a stable identity node.

```sql
CREATE TABLE node (
  node_id    TEXT PRIMARY KEY,   -- hash(kind || 0x00 || key)
  kind       TEXT NOT NULL,      -- 'proc' | 'file' | 'domain' | 'ip'
  key        TEXT NOT NULL,      -- canonical identity string for the kind
  display    TEXT,
  first_seen INTEGER NOT NULL,   -- epoch ms
  last_seen  INTEGER NOT NULL,
  attrs      TEXT,               -- JSON, kind-specific
  UNIQUE (kind, key)
);

CREATE TABLE process_instance (
  inst_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  pid          INTEGER NOT NULL,
  pidversion   INTEGER NOT NULL,     -- ES audit_token; disambiguates pid reuse
  proc_node_id TEXT NOT NULL REFERENCES node(node_id),  -- the stable identity this instance is
  parent_inst  INTEGER REFERENCES process_instance(inst_id),
  resp_inst    INTEGER REFERENCES process_instance(inst_id),
  start_ts     INTEGER NOT NULL,
  exit_ts      INTEGER,              -- NULL while alive
  exit_code    INTEGER,
  argv         TEXT,                 -- JSON
  cwd          TEXT,
  -- identity attributes captured at exec, so edges can be re-keyed at another level later
  cdhash       TEXT,
  signing_id   TEXT,
  team_id      TEXT,
  is_platform  INTEGER,              -- 0/1
  exec_path    TEXT,
  UNIQUE (pid, pidversion, start_ts)
);
```

**POC identity keying:** `proc` node `key` = `team_id/signing_id` if signed, else normalized
`exec_path`, else filename. The instance row keeps cdhash/signing_id/team_id/path, so we can
re-key edges at hash- or family-level later without re-collecting. (readme wants several
identity levels at once; POC records one, keeps the raw material for the rest.)

## 3. Edges (the memory) + rolling windows

```sql
CREATE TABLE edge (
  subj_node_id TEXT NOT NULL REFERENCES node(node_id),
  relation     TEXT NOT NULL,   -- 'spawned'|'opened_read'|'opened_write'|'connected'|'resolved'|'loaded'
  obj_node_id  TEXT NOT NULL REFERENCES node(node_id),
  first_seen   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  count_ever   INTEGER NOT NULL DEFAULT 0,
  prov_tier    TEXT NOT NULL DEFAULT 'learned',  -- 'prior'|'snapshot'|'learned' (cold-start tier)
  fidelity     TEXT NOT NULL DEFAULT 'high',      -- inherited from the observing sensor
  source       TEXT,                              -- last sensor to observe it
  flags        INTEGER NOT NULL DEFAULT 0,        -- bitset: SENSITIVE_OBJ|CROSS_PROC|DORMANT
  PRIMARY KEY (subj_node_id, relation, obj_node_id)
);

-- rolling C_1d/7d/30d without keeping raw events: one bucket per active day, GC'd past 30d.
CREATE TABLE edge_daycount (
  subj_node_id TEXT NOT NULL,
  relation     TEXT NOT NULL,
  obj_node_id  TEXT NOT NULL,
  day          INTEGER NOT NULL,   -- ts / 86400000
  count        INTEGER NOT NULL,
  PRIMARY KEY (subj_node_id, relation, obj_node_id, day)
);
```

`prov_tier` + `fidelity` + `flags` are what make the data **alert-shaped**: a downstream
alerter reads novelty (`first_seen`), recency (`last_seen`), how vouched (`prov_tier`), how
trustworthy (`fidelity`), and lineage (via `process_instance`) straight off the row.

## 4. Object classification (the Presidio-shaped holes)

Classification is a **separate, multi-label, versioned, count-bearing** side. An edge can point
at a file whose deep class is still `unknown`.

```sql
CREATE TABLE file_object (
  node_id         TEXT PRIMARY KEY REFERENCES node(node_id),  -- the file node
  dev             INTEGER,
  inode           INTEGER,
  size            INTEGER,
  mtime           INTEGER,
  scan_state      TEXT NOT NULL DEFAULT 'unknown',  -- unknown|path_classified|content_scanned
  scan_requested  INTEGER NOT NULL DEFAULT 0,       -- job-queue flag (set by an unexpected read)
  path_class_ts   INTEGER,
  content_scan_ts INTEGER
);  -- reclassify when (dev,inode,mtime) changes

CREATE TABLE object_class (
  node_id     TEXT NOT NULL REFERENCES node(node_id),
  source      TEXT NOT NULL,   -- 'catalog'|'glob'|'magic'|'presidio_id'|'presidio_ner'
  class       TEXT NOT NULL,   -- puck category ('credentials','browser_state') OR presidio entity ('US_SSN','PERSON')
  family      TEXT,            -- 'rotate'|'invalidate'|'notify' (derived; nullable)
  confidence  REAL NOT NULL DEFAULT 1.0,
  count       INTEGER,         -- PII entity count; NULL for path classes
  detected_ts INTEGER NOT NULL,
  PRIMARY KEY (node_id, source, class)
);
```

- Path/glob classes land eagerly at first sight → `scan_state='path_classified'`.
- An unexpected read of an unscanned file sets `scan_requested=1`; a worker runs Presidio and
  writes `presidio_*` rows (with `count`), then `scan_state='content_scanned'`.

## 5. Priors, exceptions, capabilities, meta

```sql
-- expected readers: the "ask" side (shipped prior) + human calibration (analyst exceptions)
CREATE TABLE expected_reader (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  object_class TEXT NOT NULL,
  reader_key   TEXT NOT NULL,                 -- proc node key or identity glob
  match_kind   TEXT NOT NULL DEFAULT 'exact', -- 'exact'|'glob'
  source       TEXT NOT NULL,                 -- 'prior'|'snapshot'|'analyst'
  added_ts     INTEGER NOT NULL
);

-- gate the ten questions: what can THIS host's sensor actually see?
CREATE TABLE sensor_capability (
  relation  TEXT PRIMARY KEY,   -- 'spawned','opened_read','connected','resolved'
  available INTEGER NOT NULL,
  fidelity  TEXT NOT NULL,      -- high|med|low|none
  source    TEXT NOT NULL
);

CREATE TABLE host_meta ( k TEXT PRIMARY KEY, v TEXT );  -- install_ts, host_id, os, os_version
```

## 6. Indexes

```sql
CREATE INDEX idx_edge_obj      ON edge(obj_node_id, relation);   -- "who touched this object"
CREATE INDEX idx_edge_first    ON edge(first_seen);              -- novelty scans
CREATE INDEX idx_node_kind_fs  ON node(kind, first_seen);        -- "new binary identities"
CREATE INDEX idx_class_class   ON object_class(class);
CREATE INDEX idx_class_family  ON object_class(family);
CREATE INDEX idx_inst_pidver   ON process_instance(pid, pidversion);
CREATE INDEX idx_fileobj_queue ON file_object(scan_requested) WHERE scan_requested = 1;
```

## 7. Update path (event → tables)

1. `process_exec` → upsert `node(proc)` for the identity; insert `process_instance` (link
   parent via pid+pidversion → inst); upsert `edge(parent_proc, 'spawned', child_proc)`.
2. `file_open{read}` → resolve actor inst → proc_node; upsert `node(file)` + `file_object`;
   if file unclassified, run path/glob classifier (eager); upsert
   `edge(proc, 'opened_read', file)`; if class is sensitive and reader not in
   `expected_reader`, set `file_object.scan_requested=1` and flag the edge.
3. `net_connect` / `dns_query` → upsert `node(ip|domain)`; upsert
   `edge(proc,'connected'|'resolved',obj)` with `fidelity='low'`.
4. every observation bumps `edge.last_seen`, `count_ever`, and `edge_daycount[today]`, and
   `node.last_seen`.

## 8. Flagship query (validates the schema): unexpected reader of a credential class

```sql
SELECT pi.exec_path, fn.key AS file, oc.class, oc.family
FROM edge e
JOIN node pn ON pn.node_id = e.subj_node_id AND pn.kind = 'proc'
JOIN node fn ON fn.node_id = e.obj_node_id AND fn.kind = 'file'
JOIN object_class oc ON oc.node_id = e.obj_node_id
JOIN process_instance pi ON pi.proc_node_id = pn.node_id
WHERE e.relation = 'opened_read'
  AND e.first_seen > :window_start
  AND oc.family = 'rotate'
  AND e.prov_tier = 'learned'          -- not vouched by prior/snapshot
  AND NOT EXISTS (
    SELECT 1 FROM expected_reader er
    WHERE er.object_class = oc.class AND er.reader_key = pn.key
  );
```

`object_class` is populated from both the path catalog and content recognition
(credentials via gitleaks, PII via Presidio), so this query surfaces a
content-recognized secret with no catalog entry — sensitivity is ranked, not gated
on the path list.

C_1d/7d/30d for any edge = `SELECT SUM(count) FROM edge_daycount WHERE …edge… AND day >= :cut`.
