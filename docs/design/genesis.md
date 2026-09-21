## Genesis

The conversation started with a broad question about **baselining in computing systems**: what it means to establish “normal,” how anomaly detection works, how much historical data is enough, and whether confidence intervals are the right way to think about deviations.

The key pivot was moving away from generic statistical monitoring and into **endpoint security**. In that context, the goal is not to perfectly characterize the probability distribution of everything a machine does. The more useful question became:

> **What has this device historically done, and what meaningful relationships or behaviors have recently appeared, disappeared, or changed?**

That reframing avoids the perfection trap. A security baseline does not need to prove that something is malicious. It only needs to expose **behavioral discontinuities** that give an analyst leverage.

## Main conclusions

For endpoint security, the most useful baseline is probably not a collection of means, standard deviations, and confidence intervals. It is closer to a **behavioral memory or provenance graph**.

Processes, files, sensitive resources, registry locations, modules, domains, IPs, ports, users, and other objects become nodes. Actions such as spawning, reading, writing, connecting, resolving, loading, modifying, and accessing become edges.

The endpoint remembers things like:

```text
process A -> spawned -> process B
process A -> contacted -> domain C
process A -> accessed -> process D
process A -> read -> sensitive-object-class E
process A -> modified -> registry-area F
```

For those relationships it can cheaply retain:

```text
first_seen
last_seen
count
count_1d
count_7d
count_30d
possibly count_ever
```

The useful security question then becomes less:

> Is `foo.exe` anomalous?

and more:

> **How did the behavioral neighborhood around `foo.exe` change?**

That distinction matters enormously for supply-chain attacks and living-off-the-land activity. An executable can be familiar and trusted while suddenly acquiring completely new relationships.

For example:

```text
Updater.exe
    -> browser credential material       NEW
    -> powershell.exe                    NEW
    -> temp archive                      NEW
    -> previously unseen destination     NEW
```

The identity isn't necessarily anomalous. The **behavioral graph is**.

Another important conclusion was that **relationship novelty is much more informative than entity novelty**.

`chrome.exe` and `microsoft.com` can both be completely familiar while a new relationship involving two otherwise normal entities can still matter. Therefore, baseline:

$$
A \rightarrow B
$$

not merely whether \(A\) and \(B\) individually exist.

## Security semantics make the model much stronger

The next significant step was adding knowledge about **what objects represent**.

Not all files, processes, registry keys, or memory objects should have equal weight.

The endpoint can know, often without deep content inspection, that certain objects belong to categories such as:

```text
browser credentials
browser session state
OS credential material
private keys
cloud authentication
VPN authentication
password manager stores
developer/API secrets
mail stores
authentication configuration
```

That transforms:

```text
unknown.exe -> READ -> random.db
```

into something more useful:

```text
unknown.exe
    -> READ
    -> browser.auth
```

with contextual facts such as:

```text
expected reader?            no
seen before?                no
process touched secrets?    never
process used network?       never before
```

A single sensitive access may still be benign. But the sequence:

```text
new process
   ↓
sensitive credential access
   ↓
multiple other sensitive classes
   ↓
staging file
   ↓
new DNS/network behavior
   ↓
outbound transfer
```

is a highly useful investigative discontinuity.

This suggests combining three forms of information:

$$
\boxed{
\text{behavioral novelty}
+
\text{security semantics}
+
\text{temporal/causal correlation}
}
$$

rather than expecting any one of those to identify maliciousness alone.

## Why existing EDR anomaly detection often feels disappointing

EDR vendors do perform behavioral analysis, anomaly detection, rare-process detection, process-tree correlation, and related modeling.

The conceptual idea is not new.

The problem is often **how it is operationalized**.

When anomaly detection is used primarily to create alerts, false positives become intolerable. Normal systems constantly generate novelty:

```text
new binaries after updates
new domains
new PowerShell command lines
new compiler output
new modules
new browser behavior
new software
```

If each novel event becomes an alarm, the model quickly loses credibility.

But incident response has a very different cost function.

An investigator already examining a machine may be delighted by:

> “Here are the 15 strongest behavioral changes around the time of compromise.”

even if ten of those turn out to be benign.

That led to one of the central conclusions of the conversation:

> **An imperfect anomaly detector may be a mediocre alert generator but an excellent forensic indexing system.**

The product interface should therefore perhaps be less:

> “Anomaly detected: score 87.”

and more:

> **“Show me how this endpoint changed.”**

## Ten useful questions a device should be able to answer

The discussion converged on roughly ten investigation questions that a device could answer from its rolling behavioral memory:

1. Which executable identities appeared for the first time?
2. Which parent→child process relationships are new?
3. Which processes began using the network when they historically did not?
4. Which process→domain/IP/port relationships are new or dormant?
5. Which cross-process access relationships are new?
6. Which processes began creating or interacting with unfamiliar file-location classes?
7. Which process→registry relationships changed?
8. Which process→module relationships changed?
9. Which process lineages accumulated several categories of novelty in a short period?
10. Which processes experienced the largest overall change in their behavioral neighborhood?

The tenth question is arguably the most important.

Instead of searching for a known IOC:

> **Rank the processes whose recent behavior differs most substantially from their historical behavior.**

That becomes a powerful entry point for IR and hunting.

## Data retention is probably tractable

Another conclusion was that **raw telemetry retention and behavioral memory retention are fundamentally different problems**.

Raw Sysmon/EDR telemetry can become large, particularly with verbose event classes such as module loads, registry activity, process access, or richer kernel provenance.

But the long-term baseline doesn't need to retain every original event.

A normalized relationship might look like:

```text
subject_id
relation_type
object_id
first_seen
last_seen
count
recent counters
flags
```

Even hundreds of thousands of distinct relationships can plausibly fit in tens of megabytes before database/index overhead. A million compact edges might still be in the tens to low hundreds of MB per host depending on implementation and how much temporal history is attached.

That suggests a retention hierarchy:

```text
raw detailed telemetry       short retention
normalized event history     medium retention
behavioral relationship DB   long retention
```

The system could maintain simultaneously:

$$
C_{24h}, C_{7d}, C_{30d}, C_{ever}
$$

plus first- and last-seen timestamps.

That allows useful distinctions between:

```text
never observed
not observed recently
historically rare
historically common
```

without retaining years of raw logs.

## Sensor limitations remain important, but are not fatal

Sysmon was used as the concrete example.

It provides useful telemetry around process creation, process ancestry, DNS, network connections, process access, registry activity, file creation, image loading, WMI, named pipes, and related activity.

It does **not** provide a generic stream of every Win32 API call or every filesystem read.

That means some credential theft may happen partially outside Sysmon's visibility.

But that does not weaken the baselining concept. It simply defines the limits of the sensor.

Additional endpoint instrumentation could selectively capture higher-value observations, especially accesses to known sensitive objects. Windows file auditing, kernel/minifilter instrumentation, ETW, or a purpose-built EDR sensor could provide richer signals.

Importantly, the discussion favored **selective semantic instrumentation** rather than trying to record every operation on the machine.

## AI is optional, not foundational

Another important conclusion was that the initial implementation probably should not start with a large ML system.

A useful V1 can potentially be built from:

```text
normalization
hash tables / compact graph storage
first/last/count state
recency
edge novelty
neighborhood comparison
short-window correlation
security-sensitive object classification
```

A simple score could already rank process lineages by how many meaningful new relationships appeared.

Machine learning can be layered on later.

One promising architecture is:

$$
\text{global Windows prior}
+
\text{local endpoint adaptation}.
$$

A model trained against clean/default Windows installations and common software could establish generic priors:

```text
common Windows relationships
expected process behaviors
common system destinations
typical module relationships
expected readers of sensitive resources
```

The local endpoint would then personalize those expectations:

```text
this user uses PowerShell constantly
this host runs WSL
this application normally accesses this secret store
this service normally contacts these domains
```

The model need not be large. Small sequence models, graph embeddings, compact transformers, or even traditional statistical models could potentially add value after the simple baseline is established.

A particularly useful research question is therefore:

> **How far can a simple explicit behavioral model get before ML materially improves analyst outcomes?**

## What is and is not novel

Most of the primitives have substantial prior research.

The closest umbrella field is **provenance-based intrusion detection (PIDS)** or, in endpoint terminology, **provenance-based EDR**.

Related research areas include:

* host behavioral anomaly detection,
* whole-system/system provenance,
* provenance graph anomaly detection,
* dynamic information-flow tracking and taint tracking,
* attack reconstruction,
* tactical provenance,
* provenance triage,
* graph summarization,
* quality of attribution.

Relevant systems/papers discussed included **NoDoze, UNICORN, ProvDetector, SLEUTH, HOLMES, RapSheet/Tactical Provenance, ATLAS, DISTDET, KAIROS, NODLINK, and ORTHRUS**.

The historical lineage goes back at least to Forrest et al.'s 1990s work on learning normal system-call sequences.

So none of these ideas individually should be presented as novel:

```text
learning normal endpoint behavior
building process/file/network provenance graphs
detecting rare/new edges
tracking sensitive information
compressing provenance history
local + global behavioral models
reconstructing attack paths
```

What may be more interesting is the **particular product/research framing** developed here:

> Maintain a deliberately simple, compact, semantically enriched, per-host behavioral provenance memory whose primary purpose is **interactive incident investigation**, not autonomous anomaly alerting.

Then optimize it for:

> **How quickly can an analyst identify the smallest set of changed relationships that explains the endpoint's behavioral discontinuity?**

That overlaps the emerging research idea of **Quality of Attribution** more than conventional anomaly-detection accuracy.

## Potential proof-of-concept

A good POC does not need an EDR kernel driver initially.

Start with Windows telemetry and build a local relationship store.

The core pipeline could be:

```text
Sysmon / Windows events
        ↓
normalize identities
        ↓
construct semantic relationships
        ↓
update compact per-host graph
        ↓
first/last/count + rolling counts
        ↓
compute relationship novelty
        ↓
correlate by process lineage/time
        ↓
rank behavioral discontinuities
```

Process identities should probably exist at several levels simultaneously:

```text
exact hash
normalized path
filename
signer/publisher
product/original filename
process family
```

Likewise objects should have normalized semantic classes.

A first POC could use SQLite, DuckDB, RocksDB, LMDB, or another embedded key/value/column store rather than a graph database. The core operation is mostly keyed lookups and counters; a heavyweight graph platform isn't initially necessary.

The POC should answer questions such as:

```text
show first-seen process relationships in last hour

show processes that contacted destinations they never previously contacted

show processes that historically never networked but now do

show new parent-child relationships

show processes newly touching sensitive object classes

show processes with the largest behavioral neighborhood change

show lineages that acquired >=3 new edge categories within 2 minutes

compare this process's current behavior with its previous 30 days
```

For visualization, an analyst should be able to select one process and see:

```text
Historical neighborhood
        versus
Incident neighborhood
```

with new edges highlighted.

That is probably a more informative initial POC than building an anomaly-classification model.

## Good research follow-ups

The most useful next research questions are not “can ML detect malware?” They are narrower and more measurable:

**Attribution quality.** Can the system reduce a million raw events to 5–20 relationships that actually explain what changed?

**Baseline representation.** Which representations provide the most investigative value: exact edges, normalized process families, path classes, sensitive-object classes, short sequences, or neighborhood embeddings?

**Retention economics.** Measure actual distinct-edge growth per endpoint over 7/30/90/365 days under realistic Windows workloads.

**Semantic sensitivity.** Determine how accurately endpoint objects can be classified as credential/session/private-key/cloud-auth/etc. using only metadata versus bounded content inspection.

**Expected-reader modeling.** Learn which process families normally touch each sensitive class and quantify how much this improves ranking.

**Behavioral neighborhood distance.** Compare simple metrics—new-edge count, weighted Jaccard, recency-weighted novelty, graph edit distance—against learned embeddings.

**Sequence correlation.** Determine how much value comes from sequences such as:

$$
sensitive\ access
\rightarrow staging
\rightarrow new\ network
$$

versus individual-edge novelty.

**Global/local learning.** Test clean-Windows/global priors against host-specific adaptation and measure cold-start improvement.

**Simple versus ML.** Establish a strong “dumb baseline” first and require every ML model to demonstrate meaningful incremental analyst value.

**IR evaluation rather than classifier evaluation.** Measure analyst time-to-root-cause, number of events/nodes inspected, attack-path completeness, and benign distractions—not just ROC/AUC/F1.

The strongest formulation that came out of the conversation is probably this:

> **Build a compact semantic memory of how an endpoint normally behaves, then use it during investigation to identify and explain the smallest meaningful set of new relationships that constitutes a behavioral discontinuity.**

That is not a new security theory. But it may be a very productive way to turn several established research ideas into a simpler and more useful IR capability.

