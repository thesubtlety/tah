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

## Example

A signed updater spawns an unsigned child that reads your AWS keys, the Chrome
login store, and a file in Downloads that happens to contain a token. `tah report`:

```
[unexpected readers of sensitive classes] 3
  /tmp/.cache/xpdate  read  ~/.aws/credentials                         [cloud_auth/rotate]
  /tmp/.cache/xpdate  read  ~/…/Chrome/Default/Login Data              [browser_state/invalidate]
  /tmp/.cache/xpdate  read  ~/Downloads/notes.txt                      [github-pat/rotate]
[new parent->child] 1
  /Applications/SoftUpdate.app/…/SoftUpdate  ->  /tmp/.cache/xpdate
[biggest behavioral change]
  /tmp/.cache/xpdate  score=7  classes=1  sensitive=3
  SoftUpdate          score=1  classes=1  sensitive=0
```

The Downloads file was in no catalog — it was flagged by its *contents* (a
recognized GitHub token). The unsigned child ranks first: three distinct sensitive
classes read (`sensitive=3`) versus the signed parent's one benign new relationship
(`score = novel-classes + 2·sensitive-classes − interpreter-discount`).
`tah selftest` runs this shape as a built-in check:

```
  [PASS] content recognition  ~/loot.txt                   [github-pat/rotate]
  [PASS] path catalog         ~/.aws/credentials            [cloud_auth/rotate]
selftest OK — detection pipeline works
```

## Getting started

Requires Go 1.27+ (`brew install go`). Live capture is macOS; the detection logic
runs anywhere.

```
scripts/bootstrap.sh        # build ./bin/tah  (PII/Presidio optional, off by default)
./bin/tah selftest          # verify detection works here (no root, no daemon)
sudo ./bin/tah snapshot     # once: seed pre-existing state (cold start)
sudo ./bin/tah collect      # the daemon: eslogger + net/DNS + content recognition; leave running
./bin/tah status            # is it capturing?  (no sudo)
./bin/tah report            # findings: what changed, unexpected readers, ranked  (no sudo)
```

- **Full Disk Access** (eslogger needs it) is a GUI or MDM grant — there is no
  pure-CLI way. Headless/remote: screen-share once to add the binary in System
  Settings → Privacy & Security → Full Disk Access, or push a PPPC profile via MDM.
- One database at `~/.tah/tah.db`, shared between the `sudo` daemon and your
  non-root queries.
- **PII (optional):** `scripts/bootstrap.sh --presidio` installs it into a venv;
  credentials are recognized without it.
- Poke at it: `./bin/tah recognize <file>…` (content recognition on demand),
  `./bin/tah watch` (live), `./bin/tah rank`. Run tests: `go test ./...`.

## How it works

Sensor adapters emit one normalized event shape (eslogger now; osquery/Sysmon
later). The core keeps a compact SQLite edge store — nodes, process lineage,
rolling day-count windows, multi-label object classification. Ranking scores a
lineage by its count of *novel relationship classes* (so a browser's 42 new
domains count once), plus a bonus per sensitive class read by a non-expected
reader, minus a discount for interpreters and host processes.

Sensitivity is decided by what a file **contains**, not only its path. When an
unexpected process reads an unknown file, content recognition runs lazily:
credentials via the gitleaks library (the in-process engine geiger uses —
recognition only, no liveness), and PII via Presidio when installed. A small
catalog of known credential locations is just the cheap fast path.

## Layout

```
cmd/tah            CLI
internal/event     normalized event contract
internal/eslogger  eslogger NDJSON adapter
internal/netpoll   lsof network collector
internal/dnslog    mDNSResponder DNS collector
internal/classify  sensitive-object classifier (path/glob + scan eligibility)
internal/recognize credential recognition (gitleaks, in-process)
internal/scan      content-recognition worker (credentials + optional Presidio PII)
internal/store     SQLite schema, update path, queries, ranking
presidio/          optional Presidio PII scanner (venv)
docs/design/       concept, collection, classifier, schema, risks-and-eval
```

## Status

Builds and tests green on Linux. Live `eslogger` capture needs a macOS box.
Network/DNS are best-effort pollers (short-lived flows missed; DNS needs a
Sensitive-level profile for cleartext names). The open question the project must
falsify: *does local behavioral memory materially cut an investigator's search
space?* See [risks & eval](docs/design/risks-and-eval.md).
