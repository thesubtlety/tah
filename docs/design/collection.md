# Collection: capability, audit config, and network/DNS

Status: design notes, POC-phase. macOS first, Windows second. Go core, thin
per-OS sensor adapters feeding one shared provenance store.

## The organizing fact: the two OSes are mirror images

| | Sensitive-file **reads** | **Network + DNS** |
|---|---|---|
| **macOS** | Free. ES `NOTIFY_OPEN` gives read-intent, with full process identity, and in-kernel path scoping. | The wall. ES covers neither in a shippable way; needs a separate NetworkExtension system extension. |
| **Windows** | The wall. Sysmon has no read event; only route is SACL + Event 4663 on a curated path set, or a Kernel-File ETW firehose. | Free. Sysmon EID 3 / EID 22, or the Kernel-Network / DNS-Client ETW providers, all with per-process attribution. |

So the sensor adapter must **advertise a capability descriptor** per host — which relation
types it can emit and at what fidelity — and the ranker gates the ten investigation
questions on it. A question that leans on network edges is high-confidence on Windows and
weak on a macOS POC box; the reverse for credential-read edges. Never present a question
the current sensor can't actually answer.

## macOS (as-of 2026-09, macOS 15 Sequoia / 26 Tahoe)

### Process lifecycle
- `NOTIFY_EXEC` / `NOTIFY_FORK` / `NOTIFY_EXIT`. eslogger short names `exec`/`fork`/`exit`.
- Every event carries full `es_process_t`: `audit_token` (use **pid+pidversion** as the key, not bare pid), `responsible_audit_token` (attributes GUI/XPC work to the responsible app), `cdhash`, `signing_id`, `team_id`, `is_platform_binary`, `codesigning_flags`, and on macOS 15+ `cs_validation_category` (clean PLATFORM/APP_STORE/DEVELOPER_ID/… enum). Exec adds **argv, envp** (full environment — many EDRs drop it), `cwd`, opened FDs.
- This is most of our multi-level identity ladder for free.

### File reads
- Read/write model is `NOTIFY_OPEN` (`fflag` = requested `O_*`/`FREAD`/`FWRITE` bitmask) plus `NOTIFY_CLOSE` (`modified` bool). **There is no `NOTIFY_READ` and no `NOTIFY_WRITE`, and no byte/offset event.** Open-intent is the granularity; infer writes from `OPEN(FWRITE)` + `CLOSE.modified`. Also subscribe `NOTIFY_MMAP` to catch read-via-mmap that bypasses open-then-read.
- Our edge relation is therefore **opened-for-read** (intent at open time), not bytes-touched. Note the fidelity difference vs Windows 4663 (access exercised).
- OPEN is a firehose. A native ES client scopes it **in-kernel** via inverted target-path muting (`es_invert_muting` + `es_mute_path`, `ES_MUTE_INVERSION_TYPE_TARGET_PATH`), delivering only opens under watched dirs (`~/.ssh`, `~/Library/Keychains`, browser stores). eslogger **cannot** do this — it's a firehose, filter in userspace.

### Network + DNS
- ES historically has **zero** connect events. macOS 26.4 added undocumented `RESERVED_5/6` slots (types 153/154) carrying hostname + originating process, but they are reverse-engineered, unstable, **not exposed by eslogger**, and Objective-See warns against production use. Watch it; do not build on it.
- Shippable per-process connect telemetry = **`NEFilterDataProvider`** (NetworkExtension content filter): per-flow source app + signing id. Costs the `networkextension` entitlement, a system extension, and user-or-MDM approval; only one system-wide content filter allowed.
- Per-process DNS: cheapest is **unified log, `mDNSResponder` subsystem** — log lines carry `PID(procname)` + query name, but names are private-data-redacted until `log config --mode private_data:on` (push via MDM). Structured/tamper-resistant capture = `NEDNSProxyProvider` (another sysext).
- Cheap POC fallback for socket→process: `nettop` / `lsof` / `libproc` polling. Gives pid + proto + local/remote IP:port, **no hostname**, and **sampling gaps** on short-lived connections. Enrichment layer, not a primary sensor.

### Approvals
- eslogger POC = **root + Full Disk Access** only (grant FDA to the launchd daemon via MDM PPPC so it survives headless). eslogger sidesteps the ES entitlement and notarization because it's an Apple platform binary.
- Native ES client = restricted `com.apple.developer.endpoint-security.client` entitlement (manual Apple approval) + notarization.
- **Two separate approval pipelines** for a full macOS product: the ES client, and the NetworkExtension sysext. Budget for both.

## Windows (as-of 2026, Windows 11)

### Assume a stock box has nothing on
Process-creation auditing, Object Access, WFP auditing, and the DNS-Client operational
channel are all **off** on a clean unmanaged client. Probe with `auditpol /get /category:*`
and degrade; domain machines under a CIS/MS baseline may already have some enabled.

### Process + command line
- Native: Event 4688 requires the *Detailed Tracking → Process Creation* subcategory **and** the registry key `ProcessCreationIncludeCmdLine_Enabled=1` for the command line.
- Sysmon EID 1 is strictly richer (hashes, signature, integrity level, non-reusable `ProcessGuid`) and is the higher-value single source.

### File reads — the gap
- **Sysmon has no file-read event at any version.** Its file events are create/delete/metadata only (EID 11/2/23/26).
- Only cheap native route: *Object Access → Audit File System* subcategory **plus a SACL** (audit ACE for ReadData, principal Everyone) on **each** curated credential path → Event 4663 fires, kernel does the filtering.
- `Microsoft-Windows-Kernel-File` ETW can see reads (READ keyword `0x100`) but it's a system-wide firehose handing you a file-object pointer, not a path; you rebuild path correlation at line rate. Real engineering; reserve for targeted tracing.
- USN journal is **writes-only** — not a read source.

### Network + DNS — solved
- Sysmon EID 3: per-process connect (image, pid, ProcessGuid, 5-tuple, protocol).
- Sysmon EID 22: DNS query name + resolved results + pid (wraps `Microsoft-Windows-DNS-Client`).
- No-Sysmon path: consume `Microsoft-Windows-Kernel-Network` (per-process connect, PID only — join yourself) and `Microsoft-Windows-DNS-Client` (3006/3008) ETW providers directly, all user-mode, no driver.
- WFP 5156/5157 give allow/block 5-tuple + pid natively but are very noisy.

### Recommended "turn it on" (shortest high-value set)
```
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"File System"      /success:enable   # only useful with SACLs
auditpol /set /subcategory:"Logon"            /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" \
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```
Plus SACLs on a small credential set (DPAPI master keys `%APPDATA%\Microsoft\Protect\`,
browser login-data, `%LOCALAPPDATA%\Microsoft\Credentials`, `.aws\credentials`, `.azure`,
kube config, SSH keys). If an agent is allowed, deploy **Sysmon** (Olaf Hartong
`sysmon-modular`, pinned version) and consume its ETW provider `Microsoft-Windows-Sysmon`
directly rather than scraping the event log.

## Shared blind spot
**DoH / DoT and app-embedded resolvers** bypass DNS-client telemetry on both OSes (Sysmon
EID 22, DNS-Client ETW, and macOS `NEDNSProxyProvider` alike). You'll see the connect to the
resolver, not the query. State it as an inherent limit, not a config gap.

## Consequences for the build
1. **Capability descriptor per adapter** is a first-class type, not an afterthought. It records, per relation type, {available, fidelity, source} so the ranker can label and gate.
2. **eslogger is POC-only with a hard ceiling.** It can't do network at all, and can't scope the reads firehose in-kernel. The moment we need scoped reads at scale or any network, we're writing a native ES client (entitlement + notarization) *and* a NetworkExtension. Don't over-architect around eslogger.
3. **Edge-relation fidelity differs by OS.** macOS `opened-for-read` (intent) vs Windows 4663 (exercised). Store the source/fidelity on the edge.
4. **On stock macOS, even exec is racy** (polling only). So the install-time snapshot matters more on macOS than Windows for the day-one picture.

## Network depth needed: shallow (connect-attempt only)
`how.md` is entirely edge-level — "began using network", "new destination", "process →
domain/IP/port is new". We need only: **originating process + remote endpoint + first-seen**,
plus DNS name-to-IP correlation. No payloads, no byte inspection, not inline/blocking. This
lowers the macOS bar a lot: the hard part of a firewall (being in the data path, deciding
allow/deny) is exactly what we don't need.

- **LuLu** (Objective-See, open source) is the reference for how you'd do it *properly*: a
  `NEFilterDataProvider` system extension (older versions used a socket-filter kext). It sees
  each new outbound flow with the originating app (audit token → pid → signing id) and
  allow/denies. We want the *observe* half of that, not the enforce half.
- **POC:** skip the sysext. `nettop`/`lsof`/`libproc` polling gives process → remote IP:port
  (misses short-lived flows), and `mDNSResponder` log scraping gives the DNS name → pid. Same
  edge shape, low fidelity, clearly labeled. Enough to prove "never networked, now does" and
  "new destination". Graduate to a LuLu-style NEFilterDataProvider only for the real product.

## Confirmed implementation facts (2026-09, from on-format research)

**eslogger JSON** (verified against two independent open-source parsers + Apple forums):
- `event` is a single-key map: `{"open":{...}}`. Dispatch on the key, not the integer `event_type`.
- Acting pid/pidversion: `process.audit_token.pid` / `.pidversion` (a named object, NOT a raw 8-int array). `ppid` is `process.ppid`. Responsible: `process.responsible_audit_token.pid`.
- Identity: `process.executable.path`, `signing_id`, `team_id` (may be null), `cdhash` (40-hex string), `is_platform_binary`. Exec's new image at `event.exec.target.*`; `event.exec.args` is a string array.
- `open.fflag` is kernel FFLAGS (FREAD=0x1, FWRITE=0x2), so O_RDONLY reads as 1 — read-intent = `fflag&1`, no O_RDONLY==0 ambiguity. It's intent (fires before the permission decision).
- `exit.stat` is wait-status; exit code = `(stat>>8)&0xff`.
- `time` is RFC3339. Fields are version-gated — gate optional ones. Invoke: `sudo eslogger exec fork exit open`, NDJSON one object per line.

**Network (lsof)**: use `lsof -nP -i -FpcntPT` field mode (stateful: `p`=pid, `c`=cmd, `f`=new socket, `P`=proto, `n`=local->remote, `T`=state). Gotcha: `nettop -P` DROPS remote addresses — don't use `-P`; add `-n` for raw IPs. Snapshot poller: misses short-lived flows.

**DNS (unified log)**: `log stream --predicate 'process=="mDNSResponder"' --info --style ndjson`. The querying pid is in the `eventMessage` text as `PID[..](..)`, NOT the entry's `processID` (that's mDNSResponder). Names are redacted to a salted hash unless an **mDNSResponder profile sets `Privacy-Enable-Level=Sensitive`** — `private_data:on` alone is NOT enough (2025 Apple DTS), and it's not retroactive. We emit redacted names as `<redacted>`.
