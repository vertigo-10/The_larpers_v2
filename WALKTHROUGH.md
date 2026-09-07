# SENTRY — full technical walkthrough

Everything this system does, why it does it that way, and what it cannot do.
Written to be read aloud at a demo. Numbers come from `backend/artifacts/metrics.json`
and the source files cited beside each claim.

---

## 1. The one-paragraph version

SENTRY watches network traffic, turns it into **flows**, scores every flow with a
neural network, and shows the result on a live dashboard. It ships as two front
ends over one backend: an **enterprise console** for a security team, and a
**household version** for a home network. Detection is identical in both — only
the vocabulary and the amount of detail change.

> **Flow** — one conversation between two machines, summarised. Not a packet: a
> packet is a single envelope, a flow is "this address talked to that port for
> 4.2 seconds, 180 packets, 240 KB". Flows are the standard unit in network
> monitoring because storing every packet is impossible at any real scale.

---

## 2. Stack

| Layer | Choice | Why |
|---|---|---|
| API | **FastAPI** (Python) | Async, and generates its own OpenAPI schema |
| ORM | **SQLAlchemy 2.0** | Typed models, `Mapped[...]` style |
| DB | **Postgres** via psycopg3 (SQLite in dev) | See §11 on persistence |
| ML | **PyTorch 2.2.2** | The model is 4 layers; the framework is the boring part |
| Front end | **Vanilla JS + Chart.js 4.4.1** | No build step. Edit a file, refresh |
| Transport | **REST + WebSocket** | REST for state, WebSocket for live push |

> **ORM (Object-Relational Mapper)** — lets you write `db.get(User, 3)` instead
> of SQL. The Python class *is* the table definition.

There is no framework  on the front end and no bundler. Every page is a plain
`.html` file loading plain `.js`. That is a deliberate constraint: the whole
client is readable without tooling.

---

## 3. The spine: life of a flow

This is the single most useful thing to explain, because every page is a view
onto some stage of it.

```
  packets on the wire
        │
        ▼
  ① collector aggregates          agent/sentry_collector.py
        │                          (scapy sniffs headers, never payloads)
        ▼
  ② POST /api/ingest              authenticated with an API key
        │
        ▼
  ③ flow_to_features()            6 numbers                backend/app/ml/features.py
        │
        ▼
  ④ signed_log1p → StandardScaler → MLP → softmax          backend/app/ml/infer.py
         │
        ▼
  ⑤ threshold + severity          backend/app/severity.py
        │
        ▼
  ⑥ incident correlation          backend/app/engine.py:479
        │
        ▼
  ⑦ escalation tier               backend/app/mitigation.py
        │
        ▼
  ⑧ persist + WebSocket broadcast → every open dashboard
```

### ① The collector

`agent/sentry_collector.py` runs on a machine you want watched. It uses **scapy**
to sniff packet headers and accumulates them into flows using standard NetFlow
expiry rules:

- **Idle timeout, 15s** — a conversation that has gone quiet is finished.
- **Active timeout, 60s** — a long download is reported in chunks, so an
  hour-long transfer does not surface as one flow when it finally ends.

Two deliberate refusals, both in the module docstring:

- **It never reads payloads.** Only headers — addresses, ports, sizes, timings.
  A compromised collector leaks metadata, not your messages.
- **It never takes the key as a command-line argument**, because arguments are
  visible in `ps` to every user on the machine. Environment variable or a
  mode-600 file only.

### ③ The six features

`backend/app/ml/features.py` reduces a flow to exactly six numbers:

| # | Feature | What it captures |
|---|---|---|
| 1 | `duration` | seconds the conversation lasted |
| 2 | `packets` | how many packets |
| 3 | `total_bytes` | how much data |
| 4 | `packets_per_sec` | rate — derived |
| 5 | `bytes_per_packet` | **average packet size — derived** |
| 6 | `dst_port` | which service was addressed |

Features 4 and 5 are derived, not measured. They matter because they are
*scale-invariant*: a flood is defined by its shape, not its size.

**`bytes_per_packet` is the one that does the work.** A flood is thousands of
tiny packets — 40–80 bytes, just enough for a TCP header with no real payload,
because the attacker's goal is to exhaust the target's ability to *respond*, not
to send data. Ordinary browsing runs 300–1200 bytes per packet. This is measurable
live: a real HTTPS session scored `normal` at 738 B/pkt while a flood scored
`dos_ddos` at 60 B/pkt.

> **Why the ordering is fragile.** `features.py` and `FEATURE_NAMES` in `net.py`
> must stay in sync. If they drift, the model keeps returning confident
> predictions that are quietly nonsense — feeding `duration` into the slot
> trained for `dst_port` produces no error, just wrong answers. The file carries
> a comment saying exactly this.

### ④ Preprocessing, then the network

```
signed_log1p  →  StandardScaler  →  MLP 6-64-32-3  →  softmax
```

> **`signed_log1p`** — `sign(x) · log(1+|x|)`. Compresses wildly different
> magnitudes onto a comparable range.

This is not cosmetic. `total_bytes` reaches 5×10⁸ in CIC-IDS2017 while `duration`
sits under a minute. Standardising raw values leaves the heavy-tailed columns
dominated by a handful of enormous flows and the network never recovers.
**Measured: plain standardisation 86%, with this transform 97%.**

> **StandardScaler** — rescales each feature to mean 0, standard deviation 1, so
> no feature dominates purely because its units are bigger.

Fitted **on the training split only**. Fitting on all data first would let the
test set influence the scaling — **data leakage**, which inflates your reported
score without improving the model.

> **MLP (Multi-Layer Perceptron)** — the plainest neural network. Layers of
> numbers, each fully connected to the next, with a nonlinearity between them.

**6 → 64 → 32 → 3**, ReLU activations. Six inputs, two hidden layers, three
outputs. That is about 2,500 parameters — tiny, and deliberately so: the input
is six numbers, so a larger network would memorise rather than generalise.

> **ReLU** — `max(0, x)`. Without a nonlinearity, stacked layers collapse
> mathematically into a single layer and the depth buys nothing.

> **Softmax** — turns three raw scores into three probabilities summing to 1.
> This is where "94% confident" comes from.

Three classes, in this order because `LabelEncoder` sorts alphabetically:
**`dos_ddos`, `normal`, `scan`**.

### ⑤ Threshold and severity

Confidence must clear the org's **threshold** (τ, default 0.85, adjustable
50–99% in Settings) before a non-benign prediction counts. `severity.py`:

```python
if label == "dos_ddos":
    if confidence >= 0.95 and bps > 5_000_000:  return "critical"
    return "high" if confidence >= 0.9 else "medium"
# scan
return "medium" if confidence >= 0.9 else "low"
```

A flood is graded on **confidence *and* volume**; a scan tops out at medium
because a scan is reconnaissance, not damage.

### ⑥ Incident correlation

`engine.py:479`. A thousand flows from one attacker is **one incident**, not a
thousand alerts. Flows are attached to an open incident matching the same
`src_ip` + same `label` within a **10-minute window**; otherwise a new incident
opens. This is what stops the alerts page becoming unreadable during an actual
attack — which is precisely when it needs to be readable.

### ⑦ Escalation tiers

`mitigation.py`, lowest first:

| Tier | Automatic? | Meaning |
|---|---|---|
| `throttle` | yes | rate limit proportional to severity |
| `repeat_offender` | yes | tripped throttle repeatedly inside the org's window |
| `ban` | **never** | an operator chooses it, with a duration |

Rate-limit ceilings by severity: low 1000, medium 500, high 100, critical 10 rps.

**Two refusals worth saying out loud, because they are the honest part:**

1. **SENTRY does not enforce anything.** It watches traffic and has no path to
   the router. A tier is *a decision recorded*, not an action performed.
   `enforced` is `false` on every response and the UI says "recorded, not yet
   enforced" in as many words.
2. **It never auto-promotes to `ban`.** An automatic ban is the one action that
   could take a household off the internet on a false positive at 3am with
   nobody awake to undo it. The engine raises the alarm; a person pulls the cord.

---

## 4. The model, honestly

### Training data

| | |
|---|---|
| Source | **CIC-IDS2017** + generated SENTRY-shaped flows |
| CIC rows available | 2,830,743 |
| Sampled per class | 150,000 |
| Final mix | 60,000 CIC + 60,000 synthetic |
| Train / test | 96,000 / 24,000 |
| Epochs | 30 |

> **CIC-IDS2017** — a labelled packet capture of five working days of real
> traffic recorded by the Canadian Institute for Cybersecurity in July 2017.
> Real machines, real attacks, ground-truth labels. A standard benchmark.

**Why both sources?** CIC supplies real labelled attack traffic, but its flows
are **per-TCP-connection** while SENTRY's collector aggregates **per peer**.
A model trained on CIC alone detects *none* of the traffic this system actually
receives. That is not a hypothesis — a CIC-only model was trained, scored 97.5%,
detected **0%** of real floods and **0%** of real scans, and was rejected. It is
kept locally as evidence and git-ignored.

### Results

**Overall accuracy: 94.92%.** Reported per domain, never averaged into one
flattering number:

| Domain | Accuracy | What it means |
|---|---|---|
| CIC-IDS2017 | **93.11%** | real captured traffic |
| SENTRY shapes | **96.72%** | what the collector actually produces |

Per class (precision / recall / F1):

| Class | Precision | Recall | F1 |
|---|---|---|---|
| `dos_ddos` | 94.56 | 96.72 | 95.63 |
| `normal` | 93.77 | 92.35 | 93.06 |
| `scan` | 96.41 | 95.68 | 96.04 |

> **Precision** — of everything flagged as an attack, how much really was.
> Low precision = false alarms.
> **Recall** — of all real attacks, how many were caught. Low recall = misses.
> They trade off. F1 is their harmonic mean.

### The label leak — the best story in the project

`dst_port` is feature #6, and it nearly destroyed the model twice.

**First, in the synthetic generator.** The original script hardcoded port 443 for
every `normal` sample and port 80 for every `dos_ddos` sample. The network never
had to learn anything about traffic shape — "port 80" was a sufficient statistic
for "attack".

**Then, in the real data.** CIC ran every DoS/DDoS capture against a single web
server, so ~100% of attack rows carry destination port 80. The same leak,
arriving independently from a public dataset.

> **Label leak** — when a feature accidentally encodes the answer. The model
> learns the shortcut instead of the phenomenon.

This is invisible on a held-out split, because the split inherits the same leak.
That is why the reported accuracy looked excellent. In deployment it is
catastrophic **in the most damaging possible direction**: every ordinary HTTP
request gets called a DDoS, and a real flood aimed at port 443 reads as normal.

**The fix:** attack rows get their port resampled from the *benign* port
distribution. Benign and scan ports are untouched — a scan genuinely does sweep
arbitrary ports, so that is real signal, not leakage.

**Measured effect** — accuracy of a model given *only* the port:

| | Port-only accuracy |
|---|---|
| Before decorrelation | **95.05%** |
| After decorrelation | **67.15%** |

### The ablation table — how to prove it is not a lookup table

Linear probes on feature subsets, same split:

| Features given | Accuracy |
|---|---|
| Port only | **54.02%** |
| Shape only, no port | **73.65%** |
| Everything (full model) | **94.92%** |

The note in `metrics.json` states the test plainly: *"If the headline accuracy is
close to port_only, the model is a port lookup rather than a traffic
classifier."* 94.92% vs 54.02% is the evidence that it is not.

This is the answer to "how do you know it learned anything?"

### What it cannot do

The capture has **fifteen** labels. The model has **three classes**. Rows for
FTP-Patator, SSH-Patator, Bot, Infiltration, Heartbleed, and the three Web Attack
families — **18,028 rows** — were excluded from training and scoring.

**SENTRY cannot detect those families.** Traffic of that kind will be scored as
one of three classes that do not describe it. This is stated on the model page in
the product, not just here.

Also: 115 malformed rows dropped. Mean confidence 93.43%.

---

## 5. Enterprise pages

### `index.html` — Live Operations

The main console. Four charts:

**① Main throughput/threat chart** (Chart.js line, dual Y-axis)
- Left axis: **throughput in Mbps**. Right axis: **threat score 0–100**.
- Range selector: 5m / 15m / 30m / 1h — literally 30 / 90 / 180 / 360 data
  points, one per collection tick.
- Two series on one chart on purpose: **you are looking for divergence**.
  Throughput up *and* threat up is a volumetric attack. Threat up while
  throughput stays flat is a scan — quiet, but hostile.
- Updates by **pushing one point and shifting one off** on each WebSocket
  message, not by re-fetching. Redrawing the whole series every 1.2s would
  visibly stutter.
- The camera button flattens the transparent canvas onto the panel colour before
  export — otherwise a screenshot comes out with a black hole where the chart was.

**② Class distribution** (doughnut) — `normal` / `dos_ddos` / `scan` proportions.
The shape of the mix at a glance.

**③ Per-node** (bar) — which collection points are carrying the traffic.

**④ Top ports** (bar) — which services are being addressed. Reads as a services
inventory when calm and as a target list during a scan.

Below: the **live flow table**, newest first, with a pause button (you cannot
read a table that reorders under your cursor), a CSV export, class filters, and
a τ slider that re-scores the view immediately.

### `alerts.html` — Incidents
Correlated incidents, not raw flows. Status tabs (open / acknowledged /
resolved), severity chips, and the **ban modal** — the only place a human action
is taken. Duration is mandatory, because an indefinite ban is how someone ends up
permanently blocked by an incident nobody remembers.

### `traffic.html` — Analysis
**Top talkers** (which addresses account for the most traffic), **protocol
breakdown**, **port breakdown**, over a selectable window. This is the forensics
page: *who* rather than *what*.

### `baseline.html` — Behavioural baselining
See §6. The most conceptually interesting page.

### `nodes.html` — Collection points
Each node's throughput and status. A node turns **amber** after more than eight
flagged flows in five minutes.

### `model.html` — The model, exposed
Architecture, feature list, confusion matrix, per-class metrics, the ablation
table, the port-decorrelation numbers, and an explicit limitations panel naming
the eight undetectable attack families.

**Putting your model's weaknesses in the product is the strongest thing in this
build.** Most projects hide them.

### `reports.html` — Periodic summary
Date-ranged rollup, CSV and print export. Print-specific stylesheet so it is
usable on paper.

### `team.html` / `settings.html` / `profile.html` — Shared
Reworded per account type rather than duplicated. `team.html` is "Team" for a
company and "Household" for a home.

---

## 6. Baselining — the second detector

`backend/app/baseline.py`. Worth its own section because it answers a question
the neural network structurally cannot.

**The gap:** the model scores one flow on its own shape. That makes it blind to
traffic that is individually unremarkable but collectively wrong. *Ten thousand
well-formed HTTP requests from ten thousand addresses is a botnet, and every
single flow looks benign.* And a link that goes silent at 2am — dead collector or
severed uplink — produces **no flows at all to classify**.

So this module asks a different question: **is this normal *for this network*?**

It watches non-overlapping **5-minute windows** across three metrics — `flows`,
`bytes`, `sources` — and compares each against a learned baseline, flagging
**|z| > 4**.

> **z-score** — how many standard deviations from the mean. z=4 means "this
> would happen by chance roughly 1 time in 16,000".

Three failure modes it is explicitly built to avoid:

**1. Learning the attack.** A self-updating baseline that folds in whatever it
sees will, during a sustained attack, quietly decide the attack is normal and
stop reporting it. Observations are **winsorized to mean + 3σ** before updating,
so an attack *nudges* the baseline instead of dragging it. A genuine permanent
shift is still learned — over days rather than minutes, which is the correct
trade for a security tool.

> **Winsorize** — clamp outliers to a ceiling instead of discarding them.

**2. Firing while still learning.** Each bucket needs **30 observations** before
it has an opinion. The API reports how warm each bucket is so the UI says *"still
learning"* rather than *"all clear"* — those are very different statements.

**3. Firing on a quiet network.** On a link doing three flows per window, σ is
almost zero and every flicker is a fifty-sigma event. σ is floored both
relatively (**15% of the mean**) and absolutely (flows 5, bytes 50,000,
sources 3). This is what stops a home connection filling the page with nonsense.

**Buckets:** 48 of them — (weekend?, hour-of-day). Not 168 hour-of-week slots,
because 168 buckets each needing 30 samples takes weeks to warm up. Tuesday 3pm
and Thursday 3pm genuinely do look alike; Saturday 3pm does not.

---

## 7. The consumer UI

### The design rule
> The verdict is derived from **the same data the enterprise dashboard renders**,
> not from a separate friendlier endpoint. *"A softer summary computed by a
> different rule is how a home account ends up being told everything is fine
> during something that is not."*

### `home-index.html` — the verdict
One hero answer to one question: *is anything wrong with my network?*

Five states, in priority order (`ui.js:620`):

| State | Trigger | Says |
|---|---|---|
| 🔴 bad | any outstanding **critical/high** | "Something serious needs your attention" |
| 🟡 warn | outstanding, none serious | "Worth a look, but nothing urgent" |
| 🟡 warn | **`flows_per_min == 0`** | "Not seeing any traffic" |
| 🟢 ok | serious things, all handled | "Handled without you" |
| 🟢 ok | genuinely clear | all clear |

**The third state is the most important design decision in the consumer UI.**
No traffic means *nothing is being checked*. Reporting that as green would be
the single most misleading thing this page could do — it looks identical to
safety and means the opposite.

The fourth exists because green must not be a lie either: it would be wrong to
say the network "looks fine" on a day something tried to knock a device offline
and got stopped. The reader should know it happened.

The verdict is judged on **all** open incidents and only the *display* is
trimmed to eight. An earlier version judged on the most recent eight and showed
a green banner while nineteen older incidents were still open.

### `home-alerts.html` / `home-devices.html`
Same incidents and same nodes as the enterprise pages, in plain language.
"Device" not "node". Technical detail is behind a disclosure — never removed,
because a household member who wants to know which port something was talking on
deserves an answer. It is just never the first thing on screen.

### How the split is enforced
`<body data-org-scope="consumer">`, checked by `ui.js` against the signed-in
user's `org_type`. A mismatch redirects to `landingFor(user)`.

Guarded by `backend/tests/test_ui_split.py`, including a test that **fails when
anyone adds a new page** without assigning it a scope — because the failure is
silent otherwise: nothing throws, the page just quietly becomes visible to both
account types.

Feature differences (`backend/app/features.py`) are a **table, not scattered
`if` statements**:

| Capability | Company | Household |
|---|---|---|
| roles, audit log, invites | ✅ | ❌ |
| API keys | ✅ multiple | ✅ **exactly one** |
| model tuning, export, reports | ✅ | ❌ |

Gated elements are **removed from the DOM**, not hidden — *"a hidden control is
still tabbable, still reachable by querySelector, and still looks to a reader
like it might be the security boundary."* The API enforces the same table
independently.

---

## 8. Auth and multi-tenancy

- **bcrypt** password hashing — deliberately slow, so guessing is expensive.
- **Signed session cookie**, `HttpOnly`, `Secure` in production, `SameSite=Lax`.
- Signed with `SENTRY_SECRET_KEY`. **In production the app refuses to boot
  without it** rather than falling back to a guessable default — that key is the
  only thing making sessions unforgeable.
- Roles: **admin** (settings + people), **analyst** (mitigate + work incidents),
  **viewer** (read only).
- **Every query is scoped by `org_id`.** Two households on the same deployment
  cannot see each other's traffic.
- Failed logins and signups are **rate-limited per address** over a 5-minute
  window.
- The WebSocket authenticates its cookie **at handshake**, then trusts the
  connection for its lifetime — noted in the source, since HTTP routes
  re-authenticate per request and this one does not.
- Login says **"Incorrect email or password"** — never which one was wrong.
  Saying "no such account" turns the form into a **user-enumeration oracle**.

---

## 9. Live updates

WebSocket at `/ws`, broadcast per org. On each message the dashboard pushes one
point and shifts one off. Falls back to polling if the socket drops.

**Known gap, stated honestly:** `/api/ingest` does not currently broadcast over
the WebSocket. Flows arriving from a real collector are scored and persisted
correctly but only appear on the *next* poll rather than instantly.

---

## 10. Data retention

Every table here is written on a timer or on ingest, so without a cap they grow
without bound and the only symptom is a full disk weeks later.

| Table | Cap per org |
|---|---|
| flows | 5,000 |
| metrics | 20,000 (~7h at one point/1.2s) |
| anomalies | 2,000 |
| audit | 10,000 |

Retention sweeps every 300s. **Incidents are deliberately uncapped** — they are
the durable record everything else is evidence for.

---

## 11. Deployment notes

- Hosted on **Render**, auto-deploys from `main`.
- **Postgres**, not SQLite. The default `sqlite:///./sentry.db` lives *inside the
  container*, which is rebuilt on every deploy — every account created since the
  last deploy would silently vanish. Nothing errors; signup keeps working; people
  simply cannot log in with credentials that worked yesterday. The app now prints
  a loud boot warning if it detects this.
- URL must begin `postgresql+psycopg://`, not `postgresql://` — SQLAlchemy 2.0
  reads the bare form as a request for psycopg2, which is not installed.
- **`SENTRY_ENV=production` must be set**, which turns the traffic simulator off.
  Otherwise synthetic flows appear alongside real ones and an operator cannot
  tell a fabricated incident from a real one.
- **340 automated tests**, `.venv/bin/python -m pytest backend/tests -q`.

---

## 12. Likely questions

**"Is this real or a simulation?"**
Both exist, and they are labelled. The simulator generates synthetic flows for
development so a fresh checkout does not look broken. In production it is off,
and flows arrive from a real collector sniffing a real interface. Every flow
carries `source: "live"` or `source: "sim"`.

**"How do you know the model learned anything?"**
The ablation table. Port-only 54%, shape-only 73.6%, full model 94.9%. And the
port-decorrelation numbers: a port-only model scored 95% *before* the fix and 67%
*after*, which is what tells you the original score was a leak.

**"What is your false positive rate?"**
`normal` recall is 92.35%, so roughly 7.65% of benign traffic is misclassified.
On a busy network that is a lot of noise — which is why the threshold is
adjustable, why flows correlate into incidents rather than firing individually,
and why `ban` is never automatic.

**"Why only three classes?"**
Because that is what the data supports. Fifteen labels exist in the capture; the
eight that do not map to these three were excluded rather than forced into a
class that does not describe them. The model page names them.

**"Can it stop an attack?"**
No, and it says so. SENTRY has no path to the router. It records a decision and
a recommended rate limit; enforcement would be a separate integration. Claiming
otherwise would be the easiest lie in the project and the least defensible.

**"What happens if the collector dies?"**
The consumer verdict goes amber with "Not seeing any traffic" rather than green.
A monitoring tool that shows all-clear when it has gone blind is worse than no
tool at all.
