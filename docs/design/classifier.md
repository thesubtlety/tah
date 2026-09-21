# Sensitive-object classifier & cold start

## Classifier: a cached cascade

Not one classifier — a cheap-to-expensive cascade, run once per object, cached by
path+inode, producing two axes: **class** (`credentials`, `browser_state`,
`private_key`, `notify` PII…) and **how-decided** (catalog → glob → magic →
content). Stop at the first hit. The ranker weights on both.

1. **Exact-path catalog** — enumerated credential locations. Certain; ships as data.
2. **Path/name globs** — `**/.ssh/**`, `**/.env*`, `**/*.pem|*.kdbx`, `**/credentials`.
3. **Magic bytes** — first ~64 bytes: SQLite header, PEM markers, PKCS#12, Office/zip.
4. **Content keys** — small files: gitleaks/TruffleHog token shapes (`AKIA`, `ghp_`…).
5. **Entropy/detector** — last resort, size-gated.

POC ships layers 1–2 only. Rules that matter more than the layers:

- **Classify the object, not the event** — cache by path+inode; the hot path stays metadata.
- **Reading content to classify is fine** — just exclude the daemon's own pid so its
  classification reads aren't recorded as edges.
- **Provenance is free** — `com.apple.quarantine` (macOS) / `Zone.Identifier` (Windows)
  ⇒ came from the internet; separates `user.download` (low weight) from credentials.

## Vendored from puck / geiger (never loaded at runtime)

Copied FROM once to build tah's self-contained catalog. tah has no runtime
dependency on puck — `internal/classify/catalog.json` is checked in.

| source | What it is | Use |
|---|---|---|
| `brain/.../pathfinder/artifact-catalog.ts` | 8 object classes, Unix+Windows paths, MITRE refs | Vendored into `catalog.json`; class vocabulary adopted |
| `.../pathfinder/geiger-modules.json` | 175 providers, `file_store` flag | Infostealer-target taxonomy |
| `.../parse/detectors/library.ts` + `puck-egress/.../detectors.rs` | gitleaks/trufflehog regexes | Content-scan layer (portable to Go) |
| `shared/secret-corpus.json` | labeled samples | Classifier eval set |
| `agent/docs/cred-breach-radius.md` | blast-radius taxonomy | Ties "what was read" → "what to rotate" |

`geiger` (public Go) is the downstream: we say "X read a credential class", it says
"and that key is live with reach into prod". `puck-scout` (public Go, read-only MCP
investigation) is a candidate consumer, not code we call.

## Three IR families

| Family | Action | puck coverage |
|---|---|---|
| **Rotate** | credentials/secrets | Strong (artifact-catalog + detectors + blast-radius) |
| **Invalidate** | live sessions (cookies, tokens, keychains) | Partial (`browser_state`, geiger) |
| **Notify** | PII / ePHI / PCI | The gap → integrate Presidio |

## PII (integrate Presidio, don't reimplement)

Run Presidio as a Python subprocess; use the **full** entity set including NER
(PERSON/LOCATION/medical) — names and addresses are what make a document sensitive.
Cost is a *when*, not a *whether*: NER loads a model, so run it **lazily on candidate
files** (a file an unexpected reader touched), while regex/checksum entities
(CREDIT_CARD/Luhn, US_SSN, IBAN, ~40 country IDs) run cheaply. `presidio_scan.py`
degrades to regex-only if no spaCy model is installed.

## Cold start: ask, or populate

`first_seen` = "since install", so everything looks new for weeks. Solve three ways,
tagging each edge with which tier vouches for it:

- **Populate** — snapshot running processes, autostart, installed apps, catalog files
  at install as `pre-existing` (kills day-one noise).
- **Ask** — ship a global prior (browser reads its own store; backup/EDR read everything).
- **Learn** — local counters fill over weeks and eventually outrank the prior.

Confidence ladder: prior → snapshot → learned → (none + post-baseline = interesting).
A baseline-maturity signal leans on prior/snapshot early, counters later. During IR an
analyst can confirm/deny an expected-reader relationship → a tenant exception (same table).

## What the POC skips

- **[data]** No enforcement (watch, not block) — but edges carry novelty/class/tier/
  fidelity/lineage, so an alert is derivable. "Not detection" is positioning, not a limit.
- **[scope]** Native ES client (using eslogger), real net/DNS sensors (using pollers),
  Windows, magic-byte + PII layers in the classifier, ML, the shipped global prior.
- **[gap]** DoH/DoT & app-embedded resolvers — DNS blind spot on both OSes, unfixable.
