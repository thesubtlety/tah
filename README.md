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

One daemon collects everything (eslogger + network + DNS + PII scan); the rest
are read-only queries you run whenever, no sudo, no extra daemon. All commands
share one database at `~/.tah/tah.db` by default (override with `--db`).

```
scripts/bootstrap.sh              # build (+ optional Presidio)
sudo ./bin/tah snapshot           # once: seed pre-existing state (cold start)
sudo ./bin/tah collect            # THE daemon; leave it running
./bin/tah status                  # is it capturing? counts + last activity
./bin/tah report                  # every investigation question once
./bin/tah watch                   # live view
./bin/tah rank                    # lineages by behavioral-neighborhood change
```

Quick known-bad check (no daemon, no root): `./bin/tah selftest` plants a
credential by content and by path, runs an unexpected read through the real
pipeline, and confirms both are flagged. Use it to verify detection works on this
machine. For a live check, with `collect` running: `cat ~/.aws/credentials`, then
`./bin/tah report`.

Full Disk Access (eslogger needs it) is a GUI or MDM grant — there is no
pure-CLI way. Headless/remote: screen-share once to add the binary in System
Settings → Privacy & Security → Full Disk Access, or push a PPPC profile via MDM.

## How it works

Sensor adapters emit one normalized event shape (eslogger now; osquery/Sysmon
later). The core keeps a compact SQLite edge store — nodes, process lineage,
rolling day-count windows, multi-label object classification. Ranking scores a
lineage by its count of *novel relationship classes* (so a browser's 42 new
domains count once), plus a bonus per sensitive class read by a non-expected
reader, minus a discount for interpreters and host processes. Content recognition
runs lazily on files an unexpected reader touched: credentials via the gitleaks
library (the same in-process engine geiger uses — recognition only, no liveness),
PII via Presidio. Sensitivity is decided by what a file *contains*, not only its path.

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
