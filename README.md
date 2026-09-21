# tah — typed activity history

A per-host behavioral memory for incident response. It records what a machine
normally does — process lineage, reads of sensitive files, network, DNS — as
typed `subject → relation → object` edges, and ranks what changed. macOS first,
Windows second. Go + SQLite, no kernel driver.

## What it is, and isn't

A search-space reducer for a human already investigating a host: *rank the
process relationships that changed most, especially around sensitive resources,
and show the evidence.* **Not a detector** — behavioral change isn't malice and
malice isn't always change. See [risks & eval](docs/design/risks-and-eval.md).

## Build

```
go build -o bin/tah ./cmd/tah      # Go 1.27+
go test ./...
make demo                          # end-to-end on the bundled fixture, no macOS needed
```

## Run (macOS)

```
scripts/bootstrap.sh                       # Go build + Presidio
sudo ./bin/tah snapshot --db tah.db        # seed pre-existing state (cold start)
sudo ./bin/tah collect  --db tah.db        # eslogger + net/DNS pollers (root + Full Disk Access)
./bin/tah watch  --db tah.db               # live: unexpected reads + behavioral change
./bin/tah report --db tah.db               # every investigation question once
./bin/tah rank   --db tah.db               # lineages by behavioral-neighborhood change
./bin/tah scan   --db tah.db               # Presidio content classification over queued files
```

## How it works

Sensor adapters emit one normalized event shape (eslogger now; osquery/Sysmon
later). The core keeps a compact SQLite edge store — nodes, process lineage,
rolling day-count windows, multi-label object classification. Ranking scores a
lineage by its count of *novel relationship classes* (so a browser's 42 new
domains count once), plus a bonus per sensitive class read by a non-expected
reader, minus a discount for interpreters and host processes. PII content
classification runs lazily via Presidio only on files an unexpected reader touched.

## Layout

```
cmd/tah            CLI
internal/event     normalized event contract
internal/eslogger  eslogger NDJSON adapter
internal/netpoll   lsof network collector
internal/dnslog    mDNSResponder DNS collector
internal/classify  path/glob sensitive-object classifier
internal/scan      Presidio content-scan worker
internal/store     SQLite schema, update path, queries, ranking
presidio/          presidio_scan.py + requirements
docs/design/       collection, classifier, schema, risks-and-eval (+ genesis, naming)
```

## Status

Builds and tests green on Linux. Live `eslogger` capture needs a macOS box.
Network/DNS are best-effort pollers (short-lived flows missed; DNS needs a
Sensitive-level profile for cleartext names). The open question the project must
falsify: *does local behavioral memory materially cut an investigator's search
space?* See [risks & eval](docs/design/risks-and-eval.md).
