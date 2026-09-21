# Risks, scope, and the falsification experiment

## The core claim we are allowed to make

Two non-implications kill this as a primary detector:

- large discontinuity ⇏ attack (an update storm dwarfs any infostealer)
- attack ⇏ large discontinuity (a browser-extension session thief is nearly invisible)

So the only defensible claim is a **search-space reduction** one:

> "I'm already looking at this host. Rank the process relationships that changed
> most, especially around sensitive resources, and show the evidence."

The metric is **Quality of Attribution**, not detection accuracy:
- rank of the true attack lineage in the output
- number of candidates an analyst inspects before reaching it

NOT TPR / FPR / AUC. An answer can be 80% benign in its top-5 and still win if
item 4 is the compromised updater.

## How our current POC stands against the eight threats

| # | Threat | Where our code stands |
|---|---|---|
| 1 | Attacker borrows an already-normal actor (browser, updater, interpreter) | **Exposed, by design.** Our flagship `UnexpectedCredentialReaders` fires on a *new* reader; injection into an expected reader (browser reads its own store) is invisible. We already flag this as the expected loss — it must be published, not hidden. |
| 2 | Provenance ≠ information flow (dependency explosion) | **Inoculated by construction.** We store `proc→read→file` and `proc→connect→ip` as separate edges and NEVER synthesize `file→network`. The read→stage→exfil "sequence" is co-occurrence within a lineage/time window, explicitly not causal taint. Keep it that way. |
| 3 | Benign long tail is enormous (updates, browsing, dev tools) | **Exposed.** `LineageChangeRank` currently ranks by raw new-edge count — on a dev box the noisiest interpreter/updater sorts to the top, i.e. the "489/1281" failure. The `prov_tier` (prior/snapshot/learned) column exists to suppress authentic-but-benign novelty but the ranker doesn't yet use it. This is the #1 thing to fix before any eval means anything. |
| 4 | Sensitive-object semantics cut both ways | **Exposed.** Backup/indexer/security/password-manager/sync tools legitimately read credential classes → false positives; secrets also live in env vars, memory, pipes, caches, unknown config formats → misses. The `expected_reader` prior is the only lever, and it's only as good as its contents. |
| 5 | Rich telemetry isn't free | Handled honestly: catalog-scoped reads keep event volume near zero; the cost is on the collection side (documented in collection.md), not the tens-of-MB store. |
| 6 | Normalization is a monster | **Partially exposed.** Identity keys on signing_id-or-path (single level), raw attrs kept for re-keying. Unhandled: host-process collapse — svchost, browser renderers, python/node/PowerShell/Electron are ONE identity for many unrelated activities, so their edge counts explode and dominate rank. Needs an interpreter/host-process discount. |
| 7 | Graph machinery may be the wrong representation (AIRTAG: 96% of time in graph construction) | **On the favored side.** We store compact typed edges + counters answered by keyed lookups, not a reconstructed causal graph traversed at query time. Resist drifting into graph reconstruction; the ten questions are indexed feature lookups. |
| 8 | Evaluation lies (2025 USENIX: 8 SOTA PIDS reimplemented, none deployable; rewarded "neighborhood contains attack" not "found the attack") | **Unaddressed — the biggest gap.** We emit ranked findings but have NO scorer for rank-of-attack / candidates-to-reach. Our green fixture demo is the easy case (unsigned /tmp/stealer reads .aws); it validates plumbing, proves nothing about the hypothesis. |

## The experiment, mapped to this repo

Build the measurement before adding anything else. No ML.

1. **Benign baseline.** Run collect on a spread of real workloads (ordinary
   workstation, dev box, admin box) for weeks. Record **discontinuities per
   host-day**, developer vs non-developer. This is data nobody else has.
2. **Scenario injection + labels.** Encode the hostile cases as ground-truth
   fixtures (extend `internal/store/testdata/`): malicious browser extension,
   injection into a networked process, compromised signed updater, PowerShell/
   node dev endpoint, malware reusing an existing cloud service, install/update
   storm, credential access through an expected accessor, and post-compromise
   (weeks-old) start. Include the ones we expect to LOSE.
3. **Scorer (the missing piece).** Given a labeled run, compute rank of the
   attack lineage and candidates-inspected-before-reach across scenarios. Report
   those, not ROC.
4. **Kill criteria.** If the attack lineage generally ranks in the first ~10-20
   an investigator would inspect → continue. If it ranks in the hundreds →
   kill or re-represent. Publish the losses either way.

## What to build next (in order), given all this

1. **Eval harness**: scenario runner + labeler + QoA scorer. This, not more collectors.
2. **Rank fix** so it can survive #3/#6: rank by *count of novel relationship
   CLASSES* per lineage (not raw edge count), weight by sensitivity, subtract a
   discount for interpreter/host-process identities, and use `prov_tier` to
   suppress prior/snapshot-vouched novelty. Then re-measure.
3. **Scenario fixtures** including expected-loss cases.
4. **Scope discipline**: present as a hunting/IR primitive, never a detector.
   Do not add ML until the dumb baseline's QoA is clearly positive.

## The uncomfortable honest line

It is very plausible the simple prototype works brilliantly on obvious
infostealers and ordinary workstations, then collapses on sophisticated
compromise and power-user endpoints — the cases you most want it for. The
project must be built so a month of experimentation can falsify:

> Does local behavioral memory materially reduce the search space for a human
> investigator?

If that isn't clearly yes, stop before any AI.

## Status (built)

Done, tested on Linux:
- **QoA scorer**: `store.RankOf(rows, key)` returns rank of a lineage — the
  candidates-to-reach number.
- **Rank rework**: `store.RankLineages` scores by novel relationship CLASSES (not
  raw edge count), +2 per non-expected sensitive class read, minus an
  interpreter/host-process discount, over `prov_tier='learned'` edges only. It is
  now the default for `tah rank` and `tah report`.
- **Messy-dev-host test** (`TestMessyDevHostRanking`): a noisy box (Python with 60
  edges, Chrome resolving 42 domains, a benign updater) plus one low-volume attack
  lineage. The attack ranks **#1** under the class scorer and **#3** under naive
  edge count — the rework earns its place.
- **Plumbing test** (`TestPlumbingEndToEnd`): parse → update path → classify → scan
  queue → content scan → every query, in one pass.
- **Content recognition (addresses threat #4)**: sensitivity is decided by what a
  file contains — credentials via the gitleaks library in-process, PII via Presidio —
  not by an enumerated path list. The flagship ranks on `object_class` (any source),
  so it no longer gates on the catalog. `tah selftest` proves both content and path
  paths end to end.

Still needs real hosts (can't fake on Linux):
- benign baseline: discontinuities per host-day across real workloads over weeks.
- the hostile scenarios as first-class labeled runs, including the expected-loss
  cases (injection into an expected reader).
