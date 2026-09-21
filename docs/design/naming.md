Name:
semantic → typed or labeled
provenance → history or activity history
baselining → learning normal or remembering normal
attribution → attack tracing or finding the cause

Put together:

Typed Activity History
Typed Host History
Labeled History for Attack Tracing
Learning Normal from Typed History
Endpoint History for Attack Tracing
Typed History Baselines

Shortest that still says the idea: Typed Activity History. Three words, all plain. "Typed" carries the nodes-know-what-they-are part. "History" is provenance without the word. "Activity" covers processes, files, sockets without naming a unit.

Typed Activity History for Attack Tracing.
-----
Rank of the malicious lineage in the discontinuity list — top-1 and top-5 across scenarios.
Rows an analyst reads before reaching it.
Discontinuities per host-day on benign boxes, developer vs. non-developer. This comes from your own rollouts and nobody else has it. Record it like first-sweep findings.

Ablation: novelty-only → +sensitivity → +sequence. If the catalog doesn't move rank, it isn't earning anything, and you want to know that before it's on a slide. Baseline to beat: the executable-name/path allowlist from that August preprint. If it ties you, your scenarios reward lexical novelty and need fixing.

Scenarios: infostealer with fast egress (OTRF APT29 Sysmon data; Atomic T1555.003 and T1552 in a lab), compromised known updater (no new binary — allowlist is blind), LOLBin-only credential access (same), and one you expect to lose: injection into an expected reader, so the browser reads its own store. Publish the loss. Measure box cost alongside: edge-store size, ETW/ES consumer CPU, event rate with catalog-scoped reads.

No public benchmark carries your object semantics, so the ablation needs your own generated ground truth. DARPA TC is useful for scale only, with the preprint's caveat attached.
