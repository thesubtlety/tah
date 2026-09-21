# Collection: capability, audit config, network/DNS

Sensor-agnostic core; thin per-OS adapters. Each adapter advertises a **capability
descriptor** (per relation: available, fidelity, source) so the ranker gates and
labels the ten questions per host.

## The organizing fact: the two OSes are mirror images

| | Sensitive-file **reads** | **Network + DNS** |
|---|---|---|
| **macOS** | Free — ES `NOTIFY_OPEN`, full identity, in-kernel path scoping | The wall — needs a separate NetworkExtension sysext |
| **Windows** | The wall — SACL + Event 4663 on curated paths (Sysmon has no read event) | Free — Sysmon EID 3/22 or Kernel-Network/DNS-Client ETW, no driver |

So macOS-first leads with the credential-read story; network lags. Reverse on Windows.

## macOS (macOS 15/26)

- **Process**: `NOTIFY_EXEC/FORK/EXIT`. Every event carries pid+pidversion, cdhash,
  signing_id, team_id, is_platform_binary, and (exec) argv+envp — most of the identity
  ladder for free.
- **File reads**: `NOTIFY_OPEN` (`fflag` = read-intent) + `NOTIFY_CLOSE.modified`. No
  per-read or per-write event. OPEN is a firehose; a native ES client scopes it in-kernel
  via inverted target-path muting. **eslogger can't** — it's a firehose, filter in userspace.
- **Network/DNS**: not in ES in any shippable form (macOS 26.4's undocumented RESERVED
  slots aside). Shippable = `NEFilterDataProvider` sysext (network) + `NEDNSProxyProvider`
  or mDNSResponder log (DNS) — a second approval pipeline. POC fallback: `lsof`/`nettop`
  + mDNSResponder log scraping, low fidelity.
- **Approvals**: eslogger = root + Full Disk Access only (sidesteps the ES entitlement +
  notarization a native client needs). For a local POC, grant FDA by hand.

## Windows 11

Assume a stock box has **nothing** on (probe `auditpol /get`). Recommended minimum:

```
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"File System"      /success:enable   # only useful with SACLs
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" \
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

- **Reads**: only cheap native route is SACLs on a curated credential set → Event 4663.
  Kernel-File ETW can see reads but it's a firehose needing path correlation. USN is writes-only.
- **Network/DNS**: Sysmon EID 3 (connect) + EID 22 (DNS), or Kernel-Network + DNS-Client
  ETW direct. If an agent is allowed, deploy Sysmon (Olaf Hartong `sysmon-modular`, pinned).

## Network depth needed: shallow

`genesis.md` is edge-level only — "began networking", "new destination". We need just
originating process + remote endpoint + first-seen (+ DNS name), no payloads, not inline.
**LuLu** is the reference for doing it properly (`NEFilterDataProvider` sysext, observe half
only); POC fakes the same edge with `lsof`/mDNSResponder polling.

## Shared blind spot

DoH/DoT and app-embedded resolvers bypass DNS-client telemetry on both OSes — you see the
connect to the resolver, not the query. A limit, not a config gap.

## Confirmed implementation facts (2026-09)

- **eslogger JSON** (verified vs two parsers + Apple forums): `event` is a single-key map;
  pid at `process.audit_token.pid`/`.pidversion` (named object, not an int array); ppid at
  `process.ppid`; identity at `process.executable.path`/`signing_id`/`team_id`(nullable)/
  `cdhash`(40-hex). `open.fflag` is kernel FFLAGS (FREAD=0x1) so read-intent = `fflag&1`;
  `exit.stat` is wait-status, code = `(stat>>8)&0xff`; `time` is RFC3339. Fields are
  version-gated. Invoke `sudo eslogger exec fork exit open`, NDJSON per line.
- **Network (lsof)**: use `lsof -nP -i -FpcntPT` field mode. `nettop -P` DROPS remote
  addresses — don't use `-P`; add `-n` for raw IPs. Snapshot poller: misses short-lived flows.
- **DNS**: `log stream --predicate 'process=="mDNSResponder"' --info --style ndjson`. The
  querying pid is in the message text `PID[..](..)`, not the entry's `processID`. Names are
  redacted unless an mDNSResponder profile sets `Privacy-Enable-Level=Sensitive`
  (`private_data:on` is NOT enough, not retroactive); we emit redacted names as `<redacted>`.
