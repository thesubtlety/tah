# tah POC

A per-host behavioral provenance memory. macOS-first. Go core, SQLite store,
`eslogger` sensor adapter. Watches process lineage and reads of sensitive files,
records typed (subject → relation → object) edges, and ranks discontinuities.
Observe-only; the data is shaped so an alert is derivable.

## Layout
```
cmd/tah/              collect | query CLI
internal/event/       normalized event contract (sensor-agnostic)
internal/eslogger/    eslogger NDJSON -> event  (PROVISIONAL field mapping; validate on a Mac)
internal/classify/    path/glob sensitive-object classifier + catalog.json seed
internal/store/       SQLite schema + event->tables update path + queries
docs/design/          collection.md, classifier.md, schema.md (design notes)
```

## Build & test (needs Go 1.27+)
```
go build ./...
go test ./...
go build -o tah ./cmd/tah
```

## Run
```
# macOS (real): spawns eslogger — needs root + Full Disk Access
sudo ./tah collect --db tah.db

# any OS: feed eslogger NDJSON on stdin
cat events.ndjson | ./tah collect --db tah.db --stdin

./tah snapshot --db tah.db                     # seed running procs as pre-existing (cold start)
./tah scan     --db tah.db                     # drain the content-scan queue through Presidio
./tah report   --db tah.db --since 24h         # all investigation questions at once
./tah rank     --db tah.db --since 24h         # processes by behavioral-neighborhood change
./tah watch    --db tah.db --interval 5s       # live: alert on unexpected reads + change
./tah query readers|net --db tah.db            # single questions
./tah caps     --db tah.db                     # what this host's sensors can observe
```

Quick local demo (no macOS): `make demo`.

## What's real vs stubbed
Real & tested here on Linux (via fixtures + unit tests, all green):
- event contract; eslogger parser (mapped to the confirmed on-device JSON);
- path/glob classifier; full update path (nodes, instances, edges, day-count windows,
  multi-label object classification, scan-request queue, capability descriptor);
- investigation queries: unexpected-reader (flagship), new identities, new parent/child,
  newly-networked, behavioral-change rank; snapshot cold-start;
- network collector (`lsof -F` parser) and DNS collector (mDNSResponder log parser);
- Presidio scan worker: Go->python subprocess->object_class notify rows, validated end to end
  (real script handles Presidio-absent; entity path proven with a stub).

Needs a real macOS box to exercise (code is written, not run here):
- live `eslogger` capture, the `lsof`/`log` pollers actually spawning, Full Disk Access.
- eslogger field mapping is built to two independent parsers' schemas but should get one
  confirming run on-device (fields are version-gated).

Deferred (see docs/design/classifier.md skip-list): the shipped global prior, magic-byte
classifier layer, Presidio `--server` mode for throughput, Windows adapter, DoH visibility.
