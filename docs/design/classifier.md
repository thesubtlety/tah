# Sensitive-object classifier & cold-start

Status: design notes, POC-phase.

## Classifier: a cascade, run once per object, cached

Not one classifier — a cascade of cheap-to-expensive signals, stopping at the first hit,
producing two axes:
- **class**: `browser.auth`, `browser.session`, `os.credential`, `private.key`,
  `cloud.auth`, `vpn.auth`, `password.store`, `developer.secret`, `mail.store`,
  `auth.config`, `user.document`, `user.download`, …
- **confidence / how-decided**: catalog → pattern → magic → content.

The ranker weights on both. Classify the object on first sight (or via the install scan),
cache the verdict keyed by **path + inode**, and never re-sniff on the hot path.

### Layers (cheapest first)
1. **Exact-path catalog** — enumerated credential locations. Certain. Ships as versioned
   per-OS data, updated independently of the binary. Seed from LaZagne / HackBrowserData /
   SharpChrome location lists.
2. **Path + name patterns** — globs where directory context carries meaning: `**/.ssh/**`,
   `**/.env*`, `**/*.pem|*.key|*.p12|*.pfx`, `**/*.kdbx`, `**/credentials`, `**/.netrc`.
   Catches un-enumerated dotfiles/config files.
3. **Magic-byte sniff** — bounded read of first ~64 bytes: SQLite header
   (`SQLite format 3\0`) → db class; PEM markers (`-----BEGIN OPENSSH PRIVATE KEY-----`);
   PKCS#12 DER; Office/PDF/zip for documents.
4. **Structured-content keys** — small config/db/doc files only: token shapes and key names
   from the gitleaks / TruffleHog / detect-secrets corpus (`AKIA…`, `ghp_…`, `xoxb-…`,
   `aws_access_key_id`, `client_secret`). This is what generalizes to novel secret files.
5. **Entropy / detector** — last resort for novel secrets in downloads/documents; gated hard
   by size.

### Three rules that matter more than the layers
- **Classify the object, not the event.** Cache by path+inode; the hot path (open → edge
  upsert) stays pure metadata.
- **Reading file content to classify is fine** (per decision). The only care: **exclude the
  daemon's own pid** from the provenance graph so its classification reads don't register as
  edges (self-exclusion, which we do anyway). Classification can freely sniff magic bytes and
  content; it just isn't a recorded reader.
- **Provenance is a free cross-platform signal.** `com.apple.quarantine` xattr (macOS) or a
  `Zone.Identifier` ADS (Windows) ⇒ came from the internet. Separates `user.download`
  (exfil target, low weight) from credentials (rotate target, high weight).

### Two sensitivities, two uses
- **Credentials** feed the "unexpected reader of a credential class" query (rotate-by-what-
  was-read).
- **Documents/downloads** feed the staging→exfil **sequence** detection, not the reader
  query. Lower weight, different purpose.

## Cold start: "ask, or populate"

`first_seen` = "since install", so for weeks everything reads as new. Solve three ways at
once and tag every edge with which tier vouches for it.

1. **Populate — snapshot at install.** One-time enumeration seeding current state as
   `pre-existing` (distinct from first-seen-after-baseline). Cheap sources:
   - running processes + open handles + sockets (`lsof`/`nettop`/proc)
   - autostart inventory (launchd plists, LaunchAgents/Daemons, login items; Windows Run
     keys, services, scheduled tasks)
   - installed apps + signing identities
   - filesystem pass over catalog paths (which sensitive objects exist here; pre-classify).
   Not claiming they're old — marking them pre-existing, enough to kill day-one noise. On
   macOS this matters more, since stock boxes can't stream exec in real time.
2. **Ask — ship a global prior.** Relationships normal on a stock OS + common software
   (browser reads its own store; backup agents/EDR read everything; package managers hit
   their CDNs; Office phones Microsoft). Day one, "expected reader?" has answers with zero
   local history.
3. **Learn — local counters.** Rolling first/last/count fills over weeks and eventually
   outranks the prior for this host.

### The confidence ladder on any edge
in global prior (normal everywhere) → in install snapshot (pre-existing here) → in local
counters (learned normal here) → none + post-baseline = **the interesting case**.

Plus a **baseline-maturity** signal (host age, edge count, catalog coverage) so the ranker
leans on prior+snapshot early, local counters later. That is the literal answer to "good
enough now vs wait a few weeks."

### "Ask" has a second meaning
During an IR engagement the analyst can confirm/deny an expected-reader relationship; that
becomes a **tenant exception** — human-approved, then deterministic. Same table as the prior,
sourced from a person. Build the exception store from the start.

## Reuse from puck (don't rebuild the catalog)

The readme's "you already own the hard half" is literally true. Reuse, don't fork:

| puck asset | What it is | How we use it |
|---|---|---|
| `brain/src/core/pathfinder/artifact-catalog.ts` | ~45KB `export const CATALOG`, 8 object classes (`credentials`, `persistence`, `network_c2`, `shadow_ai`, `vulnerable_software`, `incident_compromise`, `kill_chain`, `browser_state`), each with Unix `paths[]` + Windows `winPaths[]` + MITRE/Atomic refs. Plus `CATEGORY_MATCHERS` keyword classifier. | **Our path catalog, layers 1-2.** Adopt its category vocabulary instead of inventing `browser.auth`-style strings. |
| `brain/src/core/pathfinder/geiger-modules.json` | 175 credential providers, `file_store:true` (21) = plaintext cred store on disk | **Infostealer-target taxonomy.** `file_store` is exactly "what a stealer grabs off disk." |
| `brain/src/core/parse/detectors/library.ts` (TS) + `agent-rs/crates/puck-egress/src/scrubber/detectors.rs` (Rust) | 48 gitleaks/trufflehog-lifted regexes, ReDoS-audited (PEM, `AKIA`, `ghp_`, `xoxb-`, JWT, DSNs, SSH-key posture) | **Content-scan layer 4-5**, if/when we sniff content. Data is portable to Go. |
| `shared/secret-corpus.json` | One labeled sample per credential class + benign look-alikes to preserve | **Labeled eval set** for the classifier. |
| `agent/docs/cred-breach-radius.md` (CBRM) | Credential/Identity/Resource + `transitive_reach` taxonomy (`aws.assume_role`, `github.oidc_federation`, …) | **Blast-radius vocabulary** — ties "what was read" → "what to rotate." |

Mechanics: `artifact-catalog.ts` is TypeScript; export `CATALOG` to JSON at build time and
ship that JSON with the Go daemon. `geiger-modules.json` and `secret-corpus.json` are already
JSON. **Align our object classes to puck's existing `CategoryName` union, not new strings.**

Product synergy (post-POC): `geiger` is an external Go binary that live-validates ~166
credential types with blast-radius scoring (`geiger --live --min-footprint --json`). Our tool
says "process X read a credential-class object"; geiger says "and that key is live with
assume-role reach into prod." Natural handoff, not a POC concern.

## The three IR families (and the one real gap)

"Sensitive" splits by what the analyst *does*:

| Family | Action | puck coverage |
|---|---|---|
| **Rotate** | credentials/secrets | Strong — artifact-catalog `credentials` + detectors + CBRM blast-radius. |
| **Invalidate** | live session material (cookies, Discord/Slack/Telegram tokens, keychains) | Partial — `browser_state` + geiger session types. |
| **Notify** | PII / ePHI / PCI (breach-notification) | **Weak — the real gap.** |

**PII is the net-new build.** puck treats PII/ePHI as a *finding class* emitted upstream by
path/keyword matching (`pii-redact.ts` only masks filenames keyed on `pii_`/`ephi_` prefixes).
There is **no SSN / credit-card / DOB content detector** in the repo. The "notify" family
is covered by integrating Presidio (below), not a hand-rolled detector.
Also net-new (minor): magic-byte/format sniffing (SQLite header, PEM, Office/zip) — puck is
path+regex only, no format sniffer.

## POC scope for the classifier
Layers 1-2 only (catalog + globs), sourced from `artifact-catalog.ts` exported to JSON, class
strings aligned to puck's categories. Skip PII-content and magic-byte layers for the POC; they
are the first post-POC extensions (PII being the one with no upstream to lean on).

## Presidio for PII content (integrate, don't reimplement)

For the POC, **integrate Presidio directly** (run it as a Python service/subprocess) instead
of porting regexes to Go. Use the **full** entity set, NER included: `PERSON`, `LOCATION`, and
the `MEDICAL_*` narrative entities are exactly what make a document sensitive, so we want them,
not just structured identifiers. Names, addresses, and clinical text in a file ARE the signal.

The only real constraint is cost, and it's a *when*, not a *whether*: NER loads a model and
runs per file, so don't run it on every `open()`. Run it **lazily on candidate files** (a file
an unexpected process just read, or one the cheap path/glob layer already flagged). Structured
identifiers (CREDIT_CARD/Luhn, US_SSN, IBAN, US_NPI, ~40 country IDs) are cheap regex+checksum
and can run eagerly. Porting regexes to Go and keeping NER as a service is a *packaging*
concern for later, not a POC one.

## geiger & puck-scout: what they are, and the fit

Both are public MIT Go repos — reuse and integrate, don't reinvent.

- **geiger** (`puck-security/geiger`, Go 1.26+): read-only blast-radius triage — "pipe
  credential-bearing text, it recognizes creds, runs read-only recon, ranks by what they
  reach." This is the **downstream** of our tool, not a competitor: we say "process X read
  `cloud.auth`"; geiger says "and that key is live with assume-role reach into prod." Its
  `Cap*` reach vocabulary (CapSecretsRead, CapCloudControl, CapDestructive, CapExec, …) and
  blast-radius scoring are the reach taxonomy to align to.
- **puck-scout** (`puck-security/puck-scout`, Go MCP + Rust agent): "autonomous, read-only
  endpoint investigation via MCP." This is a candidate **consumer** of our output. Reuse:
  its `skills/` names (access-history, credential-exposure, cloud-compromise, shadow-ai,
  ir-triage) are just a naming reference for which questions matter — prose playbooks, not
  code we call; `skills/_reference/
  os-adaptation.md` = cross-OS notes worth reading for our macOS/Windows split; its
  read-only `policy.toml` = a reference for keeping the collector read-only, if we ever want
  that. (No deployment/approval story here — this is a local research utility.)

## What the POC deliberately skips (and why)

This is a local academic POC utility. Category: **[scope]** = fine, do later · **[data]** =
data model constraint · **[gap]** = genuinely unsolved.

- **[data]** No enforcement — we watch, we don't block. But the data model is deliberately
  rich enough that a finding or alert is *derivable* from it: every edge carries the novelty,
  class, confidence, and lineage a downstream alerter would need. "Not detection" is just
  positioning; the data is alert-shaped on purpose.
- **[scope]** Native ES client → using `eslogger` (firehose, no in-kernel scoping, no
  network). Defers the entitlement + notarization work.
- **[scope]** Real network/DNS sensor → `nettop`/`lsof` + `mDNSResponder` log polling. Misses
  short-lived connections; DNS needs private-data enable.
- **[scope]** Windows — second priority, not in the POC.
- **[scope]** Classifier magic-byte/entropy layers — POC path/glob is eager; Presidio NER runs
  lazily on candidate files (above), not on every open.
- **[scope]** ML novelty layer — explicitly deferred (how.md: strong dumb baseline first).
- **[scope]** Global prior content — mechanism described, actual "normal on stock macOS +
  common software" data not authored; cold start leans on the install snapshot first.
- **[scope]** Identity-ladder normalization (cdhash/signer/family) and rolling-counter
  eviction/GC — described, not built.
- **[gap]** DoH/DoT & app-embedded resolvers — DNS blind spot on both OSes, unfixable.
