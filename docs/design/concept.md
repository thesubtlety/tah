# Concept

## The idea

An endpoint's most useful security baseline isn't means and standard deviations —
it's a compact **behavioral memory**: what this machine has done, and which
relationships recently appeared, disappeared, or changed. The goal isn't to prove
maliciousness; it's to expose **behavioral discontinuities** that give an analyst
leverage.

Processes, files, sensitive resources, domains, IPs, ports, users, and modules are
nodes; spawning, reading, connecting, resolving, loading, and accessing are edges.
For each edge the host cheaply keeps first/last-seen, counts, and rolling windows —
so it can tell "never seen" from "not seen recently" from "historically common"
without keeping years of raw logs.

Two ideas make it sharper:

- **Relationship novelty beats entity novelty.** `chrome` and `microsoft.com` can
  both be familiar while a *new relationship* between two familiar entities still
  matters. Baseline A→B, not just whether A and B exist.
- **Security semantics.** Knowing an object is browser-credential / cloud-auth /
  private-key material turns `unknown → READ → random.db` into
  `unknown → READ → browser.auth`, with context: expected reader? seen before?
  ever touched secrets? ever used the network?

Neither alone identifies an attack. Together — novelty + semantics + short-window
sequence — they rank what an investigator should look at first.

## Why an IR primitive, not an alerter

As an alert generator, novelty drowns you: normal systems produce endless
first-seen events (updates, new domains, new binaries). But an investigator already
looking at a host is glad to be handed "the 15 strongest behavioral changes around
the time of compromise," even if ten are benign. The interface is *"show me how this
endpoint changed,"* not *"anomaly detected: score 87."* See
[risks & eval](risks-and-eval.md) for where this holds and where it breaks.

## The ten questions

1. Which executable identities appeared for the first time?
2. Which parent→child process relationships are new?
3. Which processes began using the network when they historically did not?
4. Which process→domain/IP/port relationships are new or dormant?
5. Which cross-process access relationships are new?
6. Which processes began interacting with unfamiliar file-location classes?
7. Which process→registry relationships changed?  (Windows)
8. Which process→module relationships changed?
9. Which lineages accumulated several categories of novelty in a short window?
10. Which processes changed most in their overall behavioral neighborhood?

Question 10 is the entry point: rank processes by how far recent behavior differs
from history, instead of hunting a known IOC. tah answers 1, 2, 3/4, and 9/10 today
(`tah report` / `tah rank`); 5–8 are model extensions.
