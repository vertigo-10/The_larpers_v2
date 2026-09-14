# SENTRY — The Complete Rundown

**Everything, technical and business, in one document.**

Current as of commit `8048b81` ("Give the slow-DoS detector something to detect").
Codebase: ~9,100 lines of backend Python, ~6,400 lines of tests (468 passing),
~6,700 lines of frontend JavaScript, ~2,400 lines of HTML, ~1,200 lines of CSS,
plus a 370-line standalone collector agent.

---

## How to read this

There are three documents in this repository and they do different jobs:

| Document | What it is for |
| --- | --- |
| `README.md` | Getting it running. Install, deploy, feed it traffic. Operator-facing. |
| `WALKTHROUGH.md` | The engineering defence — why each decision was made, written for a technical judge. Note it predates the NetFlow work and says "340 tests"; that number is stale. |
| **This document** | The exhaustive one. Every page, every chart, every button, plus the whole business side, which neither of the others covers at all. |

Where this document and `WALKTHROUGH.md` disagree on a count, this one is newer.

---

# PART I — THE BUSINESS

## 1. What SENTRY is, in one paragraph

SENTRY is a network threat detection console. A neural network scores every
network flow crossing a customer's network, a correlation engine groups the
malicious ones into incidents an analyst can actually work, and a live dashboard
shows the whole thing as it happens. It is multi-tenant, self-serve, and ships as
a single deployable container that serves the model, the API and the dashboard
from one origin. Customers feed it traffic either by pointing existing network
hardware at it (NetFlow/IPFIX, ten minutes of setup) or by running a small
capture agent on a machine they want watched.

## 2. The problem

Network monitoring splits badly into two camps and leaves a large middle
unserved.

**The enterprise camp** — Darktrace, Vectra, ExtraHop, Corelight. These work, and
they cost six figures a year, require a sales cycle measured in months, a
proof-of-concept, a deployment engineer, and usually a hardware appliance. They
are sold to organisations that already have a security team to operate them.

**The free camp** — Suricata, Zeek, Snort, ntopng, pfSense dashboards. These also
work, and they are free, and they produce raw signal that assumes you already
know what a flow record is. Standing up Zeek plus Elastic plus a dashboard plus
tuned rules is a project, not a product. The output is a firehose, not a verdict.

Between those sits everyone who has a network worth watching and nobody whose job
it is to watch it: the 20–200 person company with an IT person rather than a SOC,
the managed service provider running networks for thirty small clients, the
school, the clinic, the regional manufacturer. They currently have a firewall
with logs nobody reads.

The specific gap SENTRY targets: **time-to-first-verdict**. Every incumbent
either takes months to deploy or takes weeks to tune. SENTRY's bet is that you
can go from "I have a firewall" to "I am seeing scored traffic on a dashboard" in
under fifteen minutes, without talking to a salesperson, without new hardware, and
without knowing what a flow record is.

## 3. Who it is for

The product ships **two distinct user interfaces** off one codebase, selected at
signup by `Org.org_type`. This is not a pricing tier with features removed — it
is two different products sharing an engine, because a household and a company
are protecting different things and the same screen serves neither well.

### Segment A — Companies (`org_type = "company"`)

The primary commercial segment. Characteristics: multiple people with different
levels of trust, an obligation to answer "who turned that off", more than one
site or collector, and someone accountable for detection tuning.

They get: role-based access (admin / analyst / viewer), an audit trail, invite
codes and email-domain joining, multiple revocable collector keys, a tunable
detection threshold, a retention policy, CSV/report export, and node metadata.

Nav reads like a SOC tool: *Live Overview, Alerts & Incidents, Traffic Analysis,
Baseline & Anomalies, Network Nodes, Flow Sources, Model Performance, Reports.*

### Segment B — Households (`org_type = "consumer"`)

A beachhead and a distribution channel more than a profit centre. A family
running one collector on one router has no compliance obligation, no rota of
analysts and no retention policy — surfacing those makes the product harder to
use without making anyone safer.

They get: a single verdict sentence with a ring gauge, a device list in plain
language, an alert list phrased as "what we've spotted", and one collector key
presented as "connect a device" rather than as credential management. Roles
collapse to two (can change things / can only look). No audit log, no threshold
slider, no export.

Nav reads like a consumer app: *Home, Alerts, My Devices, Router Setup.*

**Why carry both.** The consumer build is where the word-of-mouth is. A security
engineer who runs it at home and finds it pleasant is the person who brings it up
at work. It also forces the product to be genuinely self-serve — a UI that a
non-technical household member can use is a UI that does not need an onboarding
call, and that is what makes the company tier sellable without a sales team.

The split is enforced in exactly one place, `backend/app/features.py`, which both
the API and the frontend read. The API re-checks with `require_feature` on every
gated route, because a hidden button has never been a permission.

## 4. The honest boundary — what SENTRY does not do

This is a deliberate positioning choice and arguably the most commercially
distinctive thing about the product, so it goes near the top rather than in a
footnote.

**SENTRY does not block traffic.** It has no path to any router, firewall or
upstream provider. There is no outbound enforcement integration of any kind.

When an operator clicks "Record a ban", the modal says so in the interface, in
plain words: *"SENTRY records this ban — it does not apply it. Nothing here
reaches your router or firewall, so the traffic keeps arriving until you add the
block there yourself."* The escalation tiers (`throttle`, `repeat_offender`,
`ban`) with their rate-limit recommendations (1000 / 500 / 100 / 10 rps by
severity) are decisions the system recorded and stands behind, not actions it
performed.

Three reasons this is the right call, in order of how much they matter:

1. **A security tool that lies about its own scope is worse than no tool.** An
   operator who believes traffic was stopped and goes home is in a worse position
   than one who knows they have to go add the block. The failure mode of
   overclaiming is silent and catastrophic; the failure mode of underclaiming is
   an extra click.
2. **Inline enforcement is a different product with a different risk profile.**
   Anything that can drop traffic can drop the wrong traffic, and the blast radius
   of a false positive goes from "a red row on a dashboard" to "the payment
   processor is unreachable". That needs a maturity of detection the model does
   not yet have.
3. **It shortens the sale.** "Read-only, sees a mirror port, cannot break
   anything" gets through a change-approval board far faster than anything
   inline.

The same honesty applies elsewhere and is worth cataloguing because it is a
pattern, not an accident:

- **The webhook field is stored but does not fire**, and the settings page carries
  a `not delivering yet` tag next to it. It is unimplemented on purpose: a server
  fetching a user-supplied URL is an SSRF vector, and a webhook pointed at
  `169.254.169.254` would read the host's cloud credentials. It needs a
  private-range blocklist and DNS-rebinding protection before it ships.
- **The model page never prints a bare accuracy figure.** It shows CIC-IDS2017
  accuracy and SENTRY-shape accuracy separately and never averaged, publishes the
  port-only ablation that proves the number is not a label leak, and lists the
  eight attack families it cannot detect by name.
- **The simulator warns loudly at boot** if enabled in production, because a
  fabricated incident is indistinguishable from a real one to the operator
  looking at it.
- **The baseline page shows a warm-up percentage** rather than pretending a
  cold baseline is a confident one.

## 5. Competitive position

| | Deploy time | Price | Verdicts or signal | Enforces |
| --- | --- | --- | --- | --- |
| Darktrace / Vectra | Weeks–months | $50k–250k/yr | Verdicts | Some |
| ExtraHop / Corelight | Weeks | $40k+/yr | Signal + verdicts | No |
| Zeek / Suricata + ELK | Weeks of engineering | Free + labour | Raw signal | No |
| ntopng | Hours | ~$300/yr | Metrics, not verdicts | No |
| Firewall's own logs | Already there | Included | Raw logs | Yes (manually) |
| **SENTRY** | **~15 minutes** | **Target $0–200/mo** | **Verdicts** | **No, and says so** |

The defensible claim is not "better detection than Darktrace" — that would be
false and everyone in the room would know it. The claim is **"a real verdict on
your real traffic, today, for a price you can put on a card"**, aimed at a
segment the incumbents do not call on.

## 6. Business model

**Self-serve SaaS, seat-independent, priced on ingest volume and retention.**

Seat-independent is deliberate: charging per analyst punishes exactly the
behaviour you want (more people looking at the dashboard) and it is the reason
small teams share a login on competing tools, which destroys the audit trail that
makes the product worth having.

A plausible ladder, not yet committed:

| Tier | Who | Shape |
| --- | --- | --- |
| Home | Households | Free, or ~$5/mo. One collector, 7-day retention, consumer UI. |
| Team | 20–200 person companies | ~$99/mo. Unlimited seats, 3 collectors, 30-day retention, full company UI, export. |
| Business | Multi-site, MSP-adjacent | ~$299/mo. Unlimited collectors, 90-day retention, scheduled reports, API access. |
| Self-hosted | Regulated / air-gapped | Annual licence. The whole thing already runs from one container. |

**Why self-hosted matters more than it looks.** The image serves API, model and
dashboard from one origin with a single Postgres dependency and `--workers 1`. It
is genuinely deployable by a customer's own IT team in an afternoon, which opens
the segment that cannot send flow metadata off-premises — healthcare, defence
adjacency, anyone with a data residency clause. That segment pays annually and
does not churn.

**The MSP channel is the highest-leverage one.** A managed service provider
running networks for thirty small clients is thirty deployments from one sale,
and SENTRY is already multi-tenant to the row level — every query is scoped by
`org_id` and that isolation is covered by tests rather than by convention. The
missing piece for MSPs is a cross-org roll-up view, which does not exist yet.

## 7. Go-to-market

**Wedge:** the NetFlow path. Most competitors need an agent installed or a
hardware tap. Nearly every managed switch, router and firewall already speaks
NetFlow v5, v9 or IPFIX and is not currently pointed at anything. "Change one
config line on hardware you already own" is a fundamentally shorter sentence than
"deploy an agent fleet", and it is the single most important distribution fact
about this product.

The collector agent covers the case where there is no capable hardware — a
laptop, a Raspberry Pi on a mirror port, a cloud VM.

**Sequence:**

1. Consumer tier free, no card, shipped where security-adjacent people already
   are. The goal is not revenue, it is a population of people who have seen it
   work on their own traffic.
2. Company tier self-serve from the same signup screen. The third option on that
   screen — *Join a company already using SENTRY* — means the second person at a
   company does not need a sales conversation either.
3. MSP partnerships once the cross-org view exists.
4. Self-hosted licence, inbound only, no outbound enterprise sales motion.

**What is already built for this and what is not:**

Built: signup with three paths (company / household / join), email-domain
discovery so an employee can find their employer without an invite, single-use
expiring invite codes, an admin approval queue that distinguishes "someone
invited this person" from "this address merely matches our domain", per-org
collector keys, and a self-serve exporter registration page that answers the
commonest support ticket ("I configured it and see nothing") on screen.

Not built: billing, email delivery of any kind (invites are copy-paste today),
password reset, cross-org MSP roll-up, and a public marketing site.

## 8. Cost structure

The hosting plan agreed earlier and currently deferred until the bugs and UI are
finished:

- **Production: Hetzner CX22** (~€4/mo, 2 vCPU / 4 GB). Runs the container plus
  Postgres comfortably. The workload is not CPU-bound — a 2,500-parameter MLP
  forward pass is nothing, and inference is batched.
- **Demo / live-demo: Oracle Cloud free tier.** Permanently free ARM instances,
  which is the right place for an always-on demo with the simulator turned on.
  Keeping the demo physically separate from production is what makes it safe to
  run fabricated traffic at all.
- **Currently: Render**, auto-deploying from `main`, with managed Postgres.

Marginal cost per customer is close to zero until ingest volume is real. The
scaling constraint is not compute, it is that **three pieces of state live in the
process rather than the database** — the WebSocket connection registry, the
failed-login throttle, and the simulator. The Dockerfile pins `--workers 1`
deliberately. Scaling out means more containers behind a sticky-session load
balancer, or moving that state to Redis. That is the first real infrastructure
bill and it arrives later than the first revenue.

## 9. Defensibility

Honest assessment: the model architecture is not a moat. A 6→64→32→3 MLP is
reproducible by a competent engineer in a weekend.

What is actually hard to copy:

1. **The training-domain insight.** A model trained on CIC-IDS2017 alone scores
   97.5% on its own test split and then detects **0% of the floods and 0% of the
   port scans this system actually produces**. That is measured, not assumed. The
   reason is that a CIC "flow" is one TCP connection while SENTRY's collector
   aggregates per peer, so a flood arrives as one 50,000-packet flow rather than
   several thousand nine-packet ones. Anybody who trains on the public dataset and
   ships it has a calm green dashboard that catches nothing, and will not find out
   until a customer does. Knowing to train on the union of both domains — and
   knowing to report the two accuracies separately — is the hard-won part.
2. **The label-leak treatment.** CIC ran every DoS/DDoS capture against one web
   server, so destination port alone predicts the label 95.05% of the time.
   Untreated, the network learns "port 80 = attack" and inverts the moment it
   meets real traffic. After resampling attack ports from the benign
   distribution, port alone scores 67.15%, and the ablation is published on the
   model page rather than buried.
3. **The NetFlow parser.** v5, v9 and IPFIX with template caching, uptime-wrap
   handling, sampling-rate normalisation and per-source resource caps is a
   genuinely fiddly piece of protocol work, and it is the thing that makes the
   ten-minute setup possible.
4. **The honesty posture as a brand.** Harder to copy than it sounds, because
   copying it means a competitor publishing their own blind spots.
5. **Multi-tenancy done properly from row one.** Retrofitting `org_id` scoping
   onto a single-tenant product is a rewrite.

## 10. Risks

| Risk | Severity | Mitigation |
| --- | --- | --- |
| Three classes do not cover real attacks | High | Named openly on the model page. Roadmap: more classes, more rule-based aggregate detectors. The slow-DoS rule is the template. |
| False positives destroy trust fast | High | Threshold is tunable per org; incidents require correlation not single flows; `MIN_FLOWS_FOR_FULL_RESPONSE = 5` stops a three-packet blip presenting as critical. |
| "Detects but does not block" reads as half a product | Medium | Reframe as the safety property it is. Long term, an optional enforcement integration. |
| Incumbents move down-market | Medium | They have tried. Their cost structure carries an enterprise sales team. |
| NetFlow has no authentication | Medium | Registration-based trust model, documented as weaker than a signed agent. Unclaimed senders are quarantined in their own table, never scored. |
| Single-worker state | Low now, Medium later | Known and documented. Redis migration is a day of work. |
| Model was a competition entry, not a research programme | Medium | The measurement discipline is real and reproducible; the ablations exist. |

## 11. Roadmap

**Now — finish the product.** Fix bugs, finish the UI, close the gaps below.

1. **Alembic migrations.** `alembic==1.14.0` is in requirements but there is no
   migrations directory; a hand-rolled additive column-adder in `db.py` is doing
   the job. It only handles additive changes. The first time a column needs
   renaming or a type needs changing in production, this becomes urgent.
2. **Blocking sync DB calls inside `async def engine_loop` and `baseline_loop`.**
   Under real load this stalls the event loop and stutters the live WebSocket.
3. **Email delivery.** Invites are copy-paste today. No password reset exists.
   This is the single biggest self-serve gap.
4. **Billing.**
5. **CSRF tokens.** Defence-in-depth only — `SameSite=Lax` already blocks the
   classic cross-site POST vector. It matters if the dashboard ever moves to a
   different origin from the API.

**Next — the hosting move** (Hetzner prod + Oracle demo), then the MSP cross-org
view, then scheduled report delivery.

**Later — more detection.** Every new aggregate detector follows the slow-DoS
template: a rule the per-flow model structurally cannot learn, because the model
sees one flow in isolation and the evidence only exists across flows.

## 12. Team and IP

The neural network and `backend/sentryv1.py` are **Sai Adheep Addala's** work,
credited in the README. The serving layer, API, authentication, multi-tenancy,
detection engine, NetFlow stack, collector agent and the entire dashboard are
built around it.

`backend/sentryv1.py` must not be modified — it is the original artifact and the
provenance of the model.

Repository history: 30 commits, from `408e2e1` on 2026-08-07 ("Add AEGIS DDoS
detection dashboard UI") through `8048b81`. The project was renamed AEGIS →
SENTRY at `0813f23`, and rebuilt from a static dashboard into a deployable
full-stack application at `5bdcf26`.

## 13. Metrics that would matter

Not instrumented yet — worth building before the first paying customer.

- **Time to first scored flow** from account creation. The single number that
  tells you whether the self-serve promise is real. Target: under 15 minutes.
- **Activation rate**: accounts that ever ingest a real (non-simulated) flow.
- **Exporters registered per account**, and the ratio of registered to unclaimed
  — a high unclaimed count means the setup instructions are failing.
- **Incidents acknowledged / incidents opened**. If this trends to zero the
  product has become noise.
- **Mean time to acknowledge.**
- **Flows scored per org per day** — the pricing axis.

---

# PART II — THE TECHNICAL SYSTEM

## 14. Architecture

```
                       ┌──────────────── browser ────────────────┐
                       │  17 HTML pages · 20 JS modules · no build │
                       └───────┬────────────────────┬──────────────┘
                        REST (cookie)         WebSocket /ws
                               │                    │
┌──────────────────────────────▼────────────────────▼──────────────────────┐
│                        FastAPI (one process, one worker)                  │
│                                                                           │
│  routers/auth   routers/team   routers/api   routers/exporters            │
│                                                                           │
│  engine.py ── scoring loop, incident correlation, WebSocket fan-out       │
│  baseline.py ─ aggregate anomaly detection + slow-DoS rule               │
│  mitigation.py ─ escalation ladder (records, never enforces)             │
│  ml/infer.py ── model.pt + scaler.joblib + labels.joblib                 │
│  netflow/collector.py ── UDP 2055/4739 → parser → flows                  │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ SQLAlchemy 2.0
                    ┌──────────▼──────────┐
                    │ Postgres (psycopg3) │   or SQLite+WAL in dev
                    └─────────────────────┘
          ▲                    ▲                     ▲
   POST /api/ingest     UDP NetFlow/IPFIX      simulator (dev only)
   (collector agent,    (switches, routers,
    Bearer API key)      firewalls — registered by source IP)
```

Three things arrive at the same place by three different routes, and all three
are scored by the same model through the same code path. That symmetry is
deliberate: it means the demo exercises the production path.

## 15. The model

| | |
| --- | --- |
| Architecture | MLP, `6 → 64 → 32 → 3`, ReLU, PyTorch 2.2.2 |
| Parameters | ~2,500 |
| Classes | `dos_ddos`, `normal`, `scan` |
| Pipeline | `signed_log1p → StandardScaler → MLP → softmax` |
| Training data | CIC-IDS2017 (60k rows) ∪ SENTRY-shaped synthetic (60k rows) |
| Split | 96k train / 24k test |
| Epochs | 30 |
| Artifacts | `model.pt`, `scaler.joblib`, `labels.joblib`, `metrics.json` |

### The six features

`duration`, `packets`, `total_bytes`, `packets_per_sec`, `bytes_per_packet`,
`dst_port`.

Every one of them describes **one flow in isolation**. No address is a feature —
deliberately, because learning that "traffic to 10.0.0.7 is bad" is memorising a
host rather than recognising an attack.

This constraint is the single most important fact about the detection design, and
it is the direct reason the aggregate detectors in §19 have to exist as rules
rather than as more model. A slow DoS is thirty connections that are each
individually unremarkable; there is no per-flow feature vector that can express
"and there are twenty-nine others like me aimed at the same port".

`signed_log1p` rather than plain normalisation because these features span orders
of magnitude — a flow can be 40 bytes or 40 megabytes — and a linear scaler makes
the entire benign range indistinguishable from zero.

### Measured performance

Overall held-out accuracy: **94.92%**.

| Domain | Accuracy |
| --- | --- |
| CIC-IDS2017 (real capture) | **93.11%** |
| SENTRY flow shapes | **96.72%** |

Reported separately and **never averaged**, because one blended figure describes
neither.

| Class | Precision | Recall | F1 |
| --- | --- | --- | --- |
| `dos_ddos` | 94.56% | 96.72% | 95.63% |
| `normal` | 93.77% | 92.35% | 93.06% |
| `scan` | 96.41% | 95.68% | 96.04% |

Mean confidence: **93.43%**.

### The ablation that proves the number

| Trained on | Accuracy |
| --- | --- |
| Destination port only | **54.02%** |
| Flow shape only (no port) | **73.65%** |
| All six features | **94.92%** |

Port alone is barely better than the majority class. Shape alone is substantially
worse than the whole. The model is genuinely using the shape of traffic, and the
port is a contributing signal rather than a shortcut.

### The label leak, and its treatment

CIC-IDS2017 ran every DoS/DDoS capture against a single web server, so nearly
every attack row carries destination port 80. **Destination port alone predicted
the label 95.05% of the time.** A model trained on that learns "port 80 = attack",
which inverts the instant it meets real traffic where port 80 is the busiest
benign port on the network.

Attack ports are resampled from the benign port distribution during loading.
After treatment, port alone scores **67.15%**. Both numbers are published on the
model page in the *What the accuracy rests on* panel.

### Known blind spots

Three classes do not cover the fifteen labels in the capture. **18,028 rows across
8 attack families** are excluded from training: Patator (FTP and SSH), Bot,
Infiltration, Heartbleed, and the web attacks (Brute Force, XSS, SQL Injection).

Flows from those families are still scored, because every flow gets a verdict, and
they will usually come back `normal`. The *Known blind spots* panel on the model
page lists them by name, directly next to the accuracy figure, so the caveat
travels with the number.

### Why not CIC-IDS2017 alone

Measured, not assumed: a model trained on CIC alone scores **97.5%** on its own
test split and detects **0% of the floods and 0% of the port scans** this system
produces. A calm green dashboard while nothing at all is caught.

The cause is aggregation granularity. A CIC flow is one TCP connection. SENTRY's
collector aggregates per peer. A flood that CIC records as several thousand
nine-packet connections arrives here as a single 50,000-packet flow. The two do
not look alike to a classifier.

### Retraining

```bash
python -m backend.app.ml.train                      # default: CIC ∪ synthetic
python -m backend.app.ml.train --dataset synthetic  # no download needed
python -m backend.app.ml.train --dataset cicids     # see above
```

CIC-IDS2017 CSVs go in `data/cicids2017/` and are not in the repo (~884 MB).
`--dataset synthetic` prints an accuracy near 100% for the reason above, and the
dashboard labels it as such.

## 16. Backend modules

| File | Lines of responsibility |
| --- | --- |
| `main.py` | App factory, security headers, WebSocket endpoint, static mounts, background loops |
| `config.py` | Environment-driven settings, startup safety checks |
| `db.py` | Engine, session factory, additive migration shim |
| `models.py` | 13 ORM models |
| `schemas.py` | Pydantic request/response contracts, `MITIGATION_TIERS` |
| `security.py` | bcrypt, JWT sessions, role guards, revocation, API keys |
| `features.py` | The org-type capability table |
| `severity.py` | `severity_for(label, confidence, bps)` → low/medium/high/critical |
| `mitigation.py` | Escalation ladder, repeat-offender detection, expiry sweep |
| `baseline.py` | EWMA baselines, z-score anomalies, slow-DoS rule |
| `engine.py` | Scoring loop, incident correlation, simulator, retention, WebSocket fan-out |
| `ml/features.py` | The one flow→vector function, shared by train and serve |
| `ml/cicids.py` | Streams CIC CSVs into the 6-feature vector |
| `ml/train.py` | Trains, evaluates per domain, writes artifacts |
| `ml/net.py` | The MLP definition |
| `ml/infer.py` | Loads artifacts, batched inference |
| `netflow/parser.py` | v5 / v9 / IPFIX packet parsing, template cache |
| `netflow/collector.py` | UDP listener, exporter registry, org attribution, buffering |
| `routers/auth.py` | signup, join, login, logout, profile, password, features, bootstrap |
| `routers/team.py` | members, invites, pending approvals, collector keys, audit |
| `routers/api.py` | flows, ingest, analytics, incidents, anomalies, baseline, nodes, settings, reports, model |
| `routers/exporters.py` | exporter CRUD, unclaimed list, collector status |

`severity.py` is its own module for a specific reason worth recording: `engine`
scores flows and `mitigation` decides how hard to respond, and mitigation is
called *from* engine, so they cannot import each other. Left in `engine.py`, the
response tiers would have had to re-derive severity from confidence and bps, and
the two copies would have drifted the first time a threshold was tuned — the
dashboard calling something critical while the escalation ladder treated it as
medium.

## 17. The database

13 tables. Every table carrying data has an `org_id` and every query is scoped by
it.

### `orgs`
`name`, `org_type` (`company` | `consumer`), `email_domain`, `created_at`.

`email_domain` is stored lowercase and bare (`acme.com`, no `@`). It is a
**discovery** mechanism, not an authentication one — nothing verifies that a
person controls the address they signed up with, so a domain match never grants
access. It places the joiner in a pending state and the approving admin is shown
that the address is unverified.

### `users`
`email` (globally unique), `password_hash` (bcrypt cost 12), `name`, `role`,
`title`, `is_active`, `status`, `join_method`, `created_at`, `last_login_at`,
`token_version`.

`is_active` and `status` are deliberately separate. `is_active = false` means "an
admin turned this person off"; `status = pending` means "this person asked to
join and nobody has decided yet". Collapsing them would make a brand-new joiner
indistinguishable from a suspended employee in the team list, which is exactly the
distinction an admin needs in order to act.

`token_version` is server-side session revocation. Every JWT embeds the version it
was minted against; bumping the counter kills every token at once. It is an
integer rather than a timestamp because `iat` is only second-resolution, so any
time-based cutoff either leaves a sub-second window open or has to future-date the
replacement token, which PyJWT then rejects as immature.

### `org_settings`
`threshold` (0.85), `auto_mitigate` (true), `webhook_url`, `notify_browser`,
`min_severity` (high), `poll_interval_ms` (2000), `max_table_rows` (45),
`repeat_offender_window_minutes` (60).

The repeat-offender window is per-org because "three times in an hour" means
something very different on a home router than on an edge segment where scans are
background noise.

### `api_keys`
`label`, `prefix` (stored clear, for identification), `key_hash` (SHA-256),
`scope` (`ingest`), `created_at`, `created_by_id`, `last_used_at`, `revoked_at`.

SHA-256 rather than bcrypt, and the reasoning is specific: bcrypt's cost exists to
slow guessing of low-entropy human passwords. These are 32 random bytes, so brute
force is not the threat and a per-request bcrypt verify would add latency to every
ingested batch. What matters is that a database leak does not hand over usable
keys, which a plain digest already achieves.

Scope is deliberately not a full `Role` — a collector needs to submit flows and
nothing else. Revocation is soft so the audit trail still resolves which key
performed past actions.

### `invites`
`prefix`, `code_hash` (SHA-256), `invitee_email`, `role`, `expires_at`,
`used_at`, `used_by_id`, `revoked_at`. `state()` returns one of
`used` / `revoked` / `expired` / `open`, in that precedence order.

The `sentry_inv_` prefix is distinct from the collector key's `sentry_ak_` on
purpose: collector keys live unattended on capture devices, invite codes create
user accounts. If they shared a prefix, a key scraped off a Raspberry Pi would be
indistinguishable from a credential that mints logins.

`invitee_email` is **enforced at redemption**, not merely recorded — `/api/auth/join`
refuses a code presented by any other address. An invite is a decision about one
named person, so a forwarded code must not work for whoever ends up holding it.

### `nodes`
`label` (unique per org), `description`, `status`, `mbps`, `updated_at`.

Created lazily by the engine. Any node label arriving on an ingested flow that
does not already exist is added automatically.

Company default topology: `EDGE-01`, `EDGE-02`, `DC-LB-01`, `VPN-GW`, `API-TIER`,
`DB-TIER`, `CDN-POP`, `IOT-SEG`.
Consumer default topology: `HOME-ROUTER`, `IOT-DEVICES`, `PERSONAL-DEVICES`.

### `flows`
`flow_ref`, `ts`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `node`, `duration`,
`packets`, `total_bytes`, `bytes_per_sec`, `prediction`, `confidence`,
`mitigated`, `source` (`live` | `simulated`), `truth`, `incident_id`.

`dst_ip` is **not a model feature** — the classifier never sees an address. It is
stored because the aggregate detectors need to know what a group of flows is
converging *on*. Slow-DoS is the clearest case: thirty idle connections spread
across thirty servers is a quiet afternoon; the same thirty aimed at one of them
is an outage in progress. Without this column those two are the same row set.

Empty string rather than NULL means "we were never told" — ingest makes it
optional and flows recorded before the column existed genuinely have no answer.
Detectors skip those rather than grouping them all under a shared blank, which
would invent a target that does not exist.

`truth` is the behaviour the simulator actually intended. The model never sees it;
it exists so the model page can show a live agreement rate. NULL for ingested
flows, where no ground truth exists.

### `incidents`
`src_ip`, `label`, `node`, `opened_at`, `last_seen_at`, `resolved_at`,
`flow_count`, `peak_confidence`, `peak_bps`, `severity`, `detail`, `status`,
`mitigated`, `mitigation_tier`, `rate_limit_rps`, `mitigation_expires_at`,
`acknowledged_by_id`.

Flows are ephemeral and high-volume; incidents are what an analyst actually works.

`detail` exists because not every incident comes from the classifier. A model
detection is self-describing — the label is the finding and `peak_confidence` says
how sure it was. A rule-based aggregate detection is not: "slow_dos from
203.0.113.9" leaves out the only facts an operator needs, which are how many
connections, against what, and how idle they were. NULL reads as "nothing further
to add" and the UI shows the line only when there is one.

`mitigation_expires_at` being NULL means two different things depending on tier —
no ban at all, or a permanent one. It must be read together with
`mitigation_tier`, never alone.

### `metric_points`
`ts`, `throughput`, `threat`, `flows`. One row per engine tick.

### `baselines`
`metric` (`flows` | `bytes` | `sources`), `bucket` (0–47), `mean`, `variance`,
`samples`, `updated_at`. Unique on (org, metric, bucket).

Buckets are (weekend?, hour-of-day) — 48 of them. A full hour-of-week baseline
would be more precise but needs a month of traffic before it says anything useful;
48 buckets still separate 3am from 3pm and Sunday from Tuesday, which is where
nearly all the daily variation lives, and they warm up in days instead.

Mean and variance are kept incrementally (EWMA/EWMV) rather than by retaining
samples, so the table stays a fixed size no matter how long the deployment runs.

### `anomalies`
`ts`, `last_seen_at`, `metric`, `direction` (`spike` | `drop`), `observed`,
`expected`, `deviation` (signed z-score), `severity`, `windows`,
`peak_deviation`, `status`, `acknowledged_by_id`.

Separate from `incidents` on purpose. An incident is "this source is attacking us"
and is keyed by source IP; an anomaly is "the shape of our traffic changed" and
has no single source to blame. Conflating them would mean an analyst filtering
incidents by IP silently loses every aggregate signal.

An attack lasting twenty minutes is one anomaly that stays open and extends, not
twenty rows.

### `flow_exporters`
`source_ip` (**globally unique**), `name`, `node_label`, `version`,
`sampling_rate`, `enabled`, `last_seen_at`, `packets_received`,
`flows_received`, `last_error`.

Globally unique, deliberately not unique-per-org: the collector resolves an
incoming packet to an org **by source IP alone**. If two orgs could both register
203.0.113.5 that lookup would be ambiguous and one tenant's traffic could be
attributed to the other. A global constraint turns that into a visible
registration conflict instead of a silent cross-tenant leak.

`version` is learned from the wire on first packet, not configured — operators
routinely do not know which version their device sends, and asking them to guess
produces wrong answers that are hard to debug.

`sampling_rate` is a configured override. Devices are supposed to advertise it
in-band and where they do, the collector uses that. Many do not, or advertise 0,
and a 1-in-1000 sample scored as if it were the full picture understates every
volume feature by three orders of magnitude — the model would see a flood as a
trickle.

`last_error` is almost always "awaiting template" on a v9 device that has not sent
its template refresh yet, which is normal for the first ~10 minutes and alarming
if it never clears. Surfacing it turns the commonest support ticket into a
self-serve answer.

### `unclaimed_exporters`
`source_ip`, `version`, `first_seen_at`, `last_seen_at`, `packets_received`.

Flow records from an address no org has registered. Kept because the alternative
is dropping them silently, and "I pointed my firewall at you and nothing happened"
is then unanswerable.

A separate table rather than a `FlowExporter` with a NULL `org_id`, because every
tenant-scoped query filters on `org_id` and a NULL there would be a row that
silently escapes that filter. In a security product that is exactly the bug you
cannot afford. Unclaimed data has no owner, so it lives somewhere with no owner
column to get wrong.

### `audit_log`
`user_id`, `user_label`, `action`, `detail`, `ts`.

### `UtcDateTime`

A custom `TypeDecorator` used by every timestamp column. SQLite has no timezone
type, so a value written as aware reads back naive even from
`DateTime(timezone=True)`. Anything that then calls `.timestamp()` or hands the
value to Pydantic gets it reinterpreted in the server's local zone — an audit
entry written seconds ago rendered as hours old, and worse, an invite expiry
compared against the wrong instant. Normalising on the way in and out fixes every
reader at once.

## 18. The detection stack

Three layers, answering three different questions.

### Layer 1 — the classifier (per flow)

"Is *this* flow malicious?" Every flow gets a forward pass and a verdict with a
confidence. Above the org's threshold (default 0.85) and non-benign, it is
flagged.

### Layer 2 — incident correlation (per source)

"Is this source attacking us?" Flagged flows are grouped by source IP into
`Incident` rows within a 10-minute window (`INCIDENT_WINDOW`). The incident tracks
`flow_count`, `peak_confidence`, `peak_bps` and a severity derived from them.

Severity, from `severity.py`:

```
normal                                        → low
dos_ddos, confidence ≥ 0.95 and bps > 5 Mb/s  → critical
dos_ddos, confidence ≥ 0.90                   → high
dos_ddos                                      → medium
scan,     confidence ≥ 0.90                   → medium
scan                                          → low
```

### Layer 3 — aggregate detection (per network)

"Did the *shape* of our traffic change?" and "is there a pattern no single flow
can show?"

**Baseline anomalies.** Three metrics — `flows`, `bytes`, `sources` — observed in
5-minute windows aligned to wall-clock multiples, compared against the EWMA
baseline for the current (weekend?, hour) bucket. A breach is `|z| > 4`. Samples
are winsorized to mean + 3σ before updating the baseline, so an attack does not
teach the baseline that attacks are normal. A bucket needs 30 observations before
it will fire. Sigma floors prevent a quiet bucket from making everything look
anomalous: 15% relative, plus absolute floors of 5 flows, 50,000 bytes, 3 sources.

**The slow-DoS rule.** The flagship example of something the model structurally
cannot learn. Groups flows by `(src_ip, dst_ip, dst_port)` and fires when:

| Constant | Value | Meaning |
| --- | --- | --- |
| `SLOW_DOS_MIN_FLOWS` | 30 | connections in the window |
| `SLOW_DOS_MIN_MEAN_DURATION_S` | 30.0 | held open this long on average |
| `SLOW_DOS_MAX_MEAN_BYTES` | 2048.0 | while sending almost nothing |
| `SLOW_DOS_MAX_PACKETS_PER_SEC` | 2.0 | at a trickle |
| `SLOW_DOS_HIGH_FLOWS` | 100 | → high severity |
| `SLOW_DOS_CRITICAL_FLOWS` | 400 | → critical |

Each of those flows is individually *correct* to classify as `normal` — it is one
idle connection. The attack exists only in the group. This is why the six features
being per-flow-in-isolation is a design constraint and not an oversight: the rule
had to be a rule.

A live verification during development produced a real incident reading: *74
connections held open against 10.20.4.38:8080, averaging 67s and 333 bytes each at
0.07 packets/sec.*

## 19. The mitigation ladder

`MITIGATION_TIERS = ("throttle", "repeat_offender", "ban")`. Rate-limit
recommendations by severity: low 1000, medium 500, high 100, critical 10 rps.

`escalation_score(label, confidence, bps, flow_count)` returns 0–1:

```
base    = {low: 0.25, medium: 0.5, high: 0.75, critical: 1.0}[severity]
scored  = base × (0.7 + 0.3 × confidence)
if flow_count < 5: scored ×= 0.6
```

Confidence pulls the score around *inside* its severity band rather than
overriding it, so a barely-confident critical still outranks a certain low.
`flow_count` acts as a sample-size damper rather than another additive term,
because a large flow count is not itself evidence of malice — it only makes the
other evidence worth trusting.

`REPEAT_OFFENDER_THRESHOLD = 3` auto-throttles inside the window. Three, not two:
two is a coincidence a busy network produces on its own, and a tier that fires on
coincidence is one operators learn to scroll past.

`MIN_FLOWS_FOR_FULL_RESPONSE = 5`. Below this the response is held at the gentlest
rung no matter how alarming the score, so a three-packet blip cannot present as a
critical-severity throttle.

Tiers never downgrade — `apply_to_incident` refuses to move an incident down the
ladder. `sweep_expired` runs periodically and clears tiers whose
`mitigation_expires_at` has passed.

**None of this is enforced.** See §4.

## 20. The three ingest paths

### A. NetFlow / IPFIX (UDP)

Enabled by `SENTRY_NETFLOW_ENABLED=true`. Listens on ports 2055 and 4739 by
default.

The parser handles **v5, v9 and IPFIX** with a per-exporter template cache
(capped at 1024 templates per exporter, 512 caches total, 4096 records and 256
fields per packet — all bounded because the protocol is unauthenticated and an
attacker can send whatever they like). It handles the 32-bit uptime wrap on
`flowStartSysUpTime`/`flowEndSysUpTime`, reads absolute timestamps in seconds,
milliseconds, microseconds and nanoseconds, and normalises sampling rates.

**The trust model is registration, not authentication.** NetFlow, IPFIX and sFlow
have no authentication of any kind — no key, no handshake, no signature. Anything
that can reach the UDP port can send records claiming to describe any traffic it
likes, and the only identifying signal is the packet's own source IP, which is
spoofable on a network that permits it.

So an operator states in advance "my firewall exports from 203.0.113.5" and the
collector only attributes flows to that org from that address. Data from an
unclaimed address lands in `unclaimed_exporters` and is **never scored**.

That is weaker than a signed agent and the product says so. What it buys is a
ten-minute setup on hardware the customer already owns, which is the difference
between a trial that starts today and one that waits on a change window.

Caps: 2000 packets per source per flush interval, 20,000 buffered flows, 200
unclaimed exporters tracked, 2-second flush, registry refresh every 30s.

### B. The collector agent

`agent/sentry_collector.py` — 370 lines, standalone, depends only on scapy and
requests. It does not import torch or a database driver, because it runs on
routers and laptops.

```bash
export SENTRY_API_KEY=sentry_ak_...
sudo -E python -m agent.sentry_collector --server https://sentry.example.com
```

`sudo` because packet capture needs root. `-E` is not optional — plain `sudo`
drops the environment, taking the key with it. `--key-file` reads from a file
instead, and refuses one that is group- or world-readable.

| Flag | Default | Why change it |
| --- | --- | --- |
| `--interface` / `-i` | scapy's default route | Capture on a mirror/SPAN port |
| `--node` | short hostname | The sensor's name in the dashboard |
| `--filter` | `ip or ip6` | Any BPF expression, e.g. `not port 22` |
| `--flush-interval` | `5.0` | Seconds between posts |
| `--key-file` | — | Mode-600 file instead of the environment |
| `--insecure` | off | Skip TLS verification. Self-signed labs only |

**It reads headers, never payloads.** Addresses, ports, sizes and timings go in;
only counters derived from them come out. A tool that watches a network should not
become a way to read everyone's traffic, and the narrow scope means a compromised
collector leaks metadata rather than content.

**It buffers, but not forever.** If the server is unreachable it retries with
backoff and holds up to 20,000 flows. Past that the oldest are dropped and the
loss is printed — during an attack the newest flows are the ones you need.

### C. Direct POST

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sentry_ak_...' \
  -d '{"flows":[{"src_ip":"172.16.0.5","dst_port":443,"protocol":"TCP",
        "node":"EDGE-01","duration":0.043,"packets":1284,"total_bytes":128400}]}'
```

Up to 500 flows per batch. Scored, persisted, promoted to incidents past the
threshold, and pushed to connected dashboards over the WebSocket. Supply either
`total_bytes` or `bytes_per_sec`; the other is derived.

### D. The simulator (development only)

`FlowGenerator` produces synthetic flows scored by the real model — the inference
is genuine, the traffic is not. `CICIDSReplay` cycles real CIC-IDS2017 CSVs where
the dataset is present.

The generator cycles phases with different attack probabilities, maintains six
destination targets so ordinary traffic spreads across destinations the way it
really does, and runs an **independent slow-DoS campaign** state machine: a
campaign picks one publicly-routable source, one target, one port and one node,
lives for 150–300 ticks, then cools down for 200–500.

Three design calls worth recording:

- The campaign is independent state, **not a fourth phase**. A slow DoS during a
  *quiet* phase is the better demo — flat throughput chart, incident appears
  anyway.
- Campaign flows carry `truth = "normal"`, because per-flow the model is
  genuinely correct. Labelling them `dos_ddos` would score the model wrong for
  giving the right answer.
- The attacker address is validated with the **same `is_global` predicate the
  detector uses**, not by hand-excluding octet ranges, so the two cannot drift.

Defaults **off** in production and warns loudly at boot if enabled.

## 21. Authentication and security

- **Passwords:** bcrypt, cost 12. Never stored or logged in plaintext.
- **Sessions:** HS256 JWTs in `HttpOnly`, `SameSite=Lax` cookies, `Secure` in
  production. 12-hour TTL.
- **Revocable server-side.** Each token embeds a `ver` claim matched against the
  user's `token_version`. Logging out bumps the counter, so the token is dead
  immediately rather than merely deleted from one browser — which is what makes
  signing out on a shared machine mean anything. Changing a password revokes every
  other session but keeps the current one.
- **Roles:** `admin` (team + settings + mitigate), `analyst` (mitigate +
  acknowledge), `viewer` (read-only). Ingest requires analyst or above.
- **Tenant isolation:** every query is scoped by `org_id`, covered by tests rather
  than by convention.
- **`Cache-Control: no-store`** on all `/api/*` responses. Without it browsers
  heuristically cache authenticated JSON and write one account's incident data
  into a shared on-disk cache.
- **Login throttling** per process. Signup is capped at 20 per window.
- **No inline scripts, no `unsafe-eval`.** Every JS module is an IIFE exposing a
  single global.
- **`.env` is gitignored.** If one was ever committed, rotate the key.

Open items: no CSRF token (defence-in-depth only — `SameSite=Lax` blocks the
classic vector); the webhook is validated but never fired (SSRF, see §4).

## 22. Real-time transport

A WebSocket at `/ws`, with `ConnectionManager` holding a per-org registry of
connections in process memory.

`WS_FLOW_BURST = 50` caps how many flow rows a single push carries, so a large
ingest batch cannot flood a browser tab.

Flows from `/api/ingest` are broadcast on the same socket as simulated ones. That
symmetry was a deliberate fix — before it, a customer's real traffic appeared only
after a poll while demo traffic appeared instantly.

The client falls back to polling at `poll_interval_ms` (default 2000) when the
socket is unavailable, and the topbar pill shows which mode it is in.

## 23. Retention and housekeeping

Per-org caps, swept every 300 seconds:

| Table | Keep |
| --- | --- |
| `flows` | 5,000 |
| `metric_points` | 20,000 (~7 hours at one point per 1.2s) |
| `anomalies` | 2,000 |
| `audit_log` | 10,000 |
| `incidents` | **uncapped** |

Incidents are uncapped deliberately. They are the record of what happened, they
are low-volume, and an incident that disappeared because the network got busy
afterwards would be the worst possible data loss in this product.

`expiry_pass()` clears mitigation tiers whose `mitigation_expires_at` has passed.

## 24. Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `SENTRY_ENV` | `development` | **Must be `production` in prod** |
| `SENTRY_SECRET_KEY` | generated in dev | App refuses to boot without it in prod |
| `SENTRY_DATABASE_URL` | `sqlite:///./sentry.db` | Use `postgresql+psycopg://` |
| `SENTRY_CORS_ORIGINS` | localhost:8777 | Real dashboard origin |
| `SENTRY_SIMULATOR_ENABLED` | on in dev, off in prod | Warns loudly if on in prod |
| `SENTRY_SIMULATOR_INTERVAL_MS` | 1200 | |
| `SENTRY_DEFAULT_THRESHOLD` | 0.85 | |
| `SENTRY_BASELINE_WINDOW_S` | 300 | |
| `SENTRY_RETAIN_FLOWS` | 5000 | |
| `SENTRY_RETENTION_INTERVAL_S` | 300 | |
| `SENTRY_NETFLOW_ENABLED` | false | |
| `SENTRY_NETFLOW_PORTS` | `2055,4739` | |
| `SENTRY_NETFLOW_BIND_HOST` | `0.0.0.0` | |
| `SENTRY_NETFLOW_FLUSH_INTERVAL_S` | 2.0 | |
| `SENTRY_NETFLOW_MAX_BUFFERED_FLOWS` | 20000 | |
| `SENTRY_ACCESS_TOKEN_TTL_MINUTES` | 720 | |
| `SENTRY_COOKIE_SAMESITE` | `lax` | |
| `PORT` | 8000 | Read from env — Render/Railway inject it |

## 25. Deployment

One image serves API, model and dashboard from one origin, so the session cookie
stays `SameSite=Lax` with no CORS exceptions to punch.

```bash
docker compose up --build          # app + Postgres
docker build -t sentry . && docker run -p 8000:8000 --env-file .env sentry
```

Render, Railway and Fly all build the Dockerfile as-is. Health check → `/api/health`.

**Things that will bite you:**

- `postgresql://` alone will not work. SQLAlchemy 2.0 maps it to psycopg2, which
  is not installed. Use `postgresql+psycopg://`. Managed platforms hand you the
  bare form, so this usually needs editing by hand.
- SQLite needs a persistent volume, or every redeploy starts from an empty
  database and all accounts are gone.
- **Run one worker per container.** The WebSocket registry, the login throttle and
  the simulator live in the process. With multiple workers a browser only receives
  events from whichever worker it connected to, and the login throttle could be
  sidestepped by landing on a different one. `--workers 1` is pinned deliberately.
- Set `SENTRY_SECRET_KEY` once and keep it. Changing it logs everyone out; leaking
  it lets anyone forge a session for any account.
- Charts and fonts load from CDNs (jsdelivr, Google Fonts). On an air-gapped or
  egress-filtered network the charts will not render — vendor Chart.js and the
  fonts locally if that is the target.

**Outstanding production checks:**

1. Verify `SENTRY_ENV=production` is set on Render. Without it the secret key
   regenerates each boot (everyone logged out on restart) *and* simulator traffic
   mixes into real data.
2. Confirm the Render Postgres password that was exposed has been rotated.

## 26. Testing

```bash
.venv/bin/python -m pytest backend/tests -q
```

**468 tests passing**, across 17 test files and ~6,400 lines, with no network and
no root required. (`WALKTHROUGH.md` says 340 and `README.md` says 337 — both
predate a lot of work. 468 is the current figure.) There is deliberately
**no `conftest.py`** — each module sets its environment variables before importing
the app, so test modules cannot contaminate each other's configuration.

Notable: tenant isolation is tested, not assumed. The two-UI split is tested so a
new page cannot arrive ungated. The slow-DoS test inserts real `Flow` rows and
calls the actual detector rather than re-implementing the rule in the test, which
is the difference between a test that verifies behaviour and one that verifies a
copy of the behaviour.

---

# PART III — THE WEBSITE, PAGE BY PAGE

Vanilla HTML, CSS and JavaScript. No build step, no framework, no bundler. Each
page loads its own IIFE module plus three shared ones.

**Every asset URL carries a cache-busting token** — currently `?v=20260837`, 119
occurrences across 17 HTML files. It must be bumped whenever any JS or CSS changes
or browsers serve stale assets. This has caused a real bug: a new table column
that had already shipped did not appear, because the browser was still running the
previous JavaScript.

## 27. The shell — present on every authenticated page

### The sidebar (`ui.js`, injected into `<aside class="sidebar">`)

Rendered from a `NAV` constant, filtered by org type, so the two UIs cannot drift
apart by someone forgetting to edit a second place.

**Company sidebar:**

- **Monitoring** (radar icon, open by default)
  - Live Overview → `index.html`
  - Alerts & Incidents → `alerts.html`
  - Traffic Analysis → `traffic.html`
  - Baseline & Anomalies → `baseline.html`
  - Network Nodes → `nodes.html`
  - Flow Sources → `exporters.html`
- **Analysis** (chart icon, open by default)
  - Model Performance → `model.html`
  - Reports → `reports.html`

**Consumer sidebar:** Home → `home-index.html`, Alerts → `home-alerts.html`,
My Devices → `home-devices.html`, Router Setup → `exporters.html`. No group
dropdown, because an accordion that opens onto two items is noise.

**Footer nav (both):** Profile, Team, Settings, Documentation (external link to
the GitHub README).

The logo is a link to your own dashboard — `index.html` or `home-index.html`
depending on org type — rather than a dead graphic.

### The topbar

Present on every page: an `<h1>`, a breadcrumb `<span class="crumb">` giving the
page's scope in lower case (`/ all nodes`, `/ grouped by source`, `/ who is
talking`, `/ what is normal here`), page-specific buttons on the right, and an
avatar showing the user's initials linking to `profile.html`.

### The opening sequence (`intro.js`)

A full-screen overlay that plays once and removes itself. Loaded **first** on
every page so it covers the initial paint rather than appearing over an
already-drawn dashboard.

It plays on **arrival, not navigation**. This is a multi-page app with no client
router, so every sidebar click is a full document load; running the sequence on
each one turns branding into a tic. There are exactly two arrivals: the front door
(login / signup / join) and the first dashboard after signing in. They get
separate keys so the sequence bookends the login — once on the way in, once when
the console appears. Everything past that is navigation and stays silent. Closing
the tab and returning is a new session and plays again.

The gate lives in the script rather than in a page list, because a rule spread
over sixteen hand-written files drifts. The overlay is `pointer-events: none` from
the first frame, so it never blocks interaction.

---

## 28. `index.html` — Live Overview

The flagship page. Breadcrumb `/ all nodes`. Module: `dashboard.js` (the largest
page module, ~31 KB).

### Topbar

| Control | Behaviour |
| --- | --- |
| **Stream pill** (`#stream-pill`) | Live connection state with a coloured dot: Connecting / Live / Polling. Tells you whether you are on the WebSocket or the fallback poll. |
| **Threats** (`#btn-threats`) | Toggles the class filter down to attack classes only. |
| **Refresh** (`#btn-refresh`) | Forces a full data refetch. |
| **Export** (`#btn-export`) | Downloads the current view. |
| **Avatar** | → `profile.html`. |

### The chart panel

**Asset badge** — a dropdown showing the current scope (`ALL NODES` by default)
with a chevron. Selects which node the whole page is filtered to.

**Headline** (`#headline-val`) — aggregate throughput in Mbps, large. Gains an
`alarm` class when the threat score reaches 50, which also flips the verdict
buttons in the console.

**Range segmented control** (`#range-seg`) — four buttons that set how many points
the chart draws:

| Button | Points |
| --- | --- |
| 5m | 30 |
| **15m** (default) | 90 |
| 30m | 180 |
| 1h | 360 |

**Three tool buttons:**

- `#tool-expand` — fullscreen the chart.
- `#tool-filter` — filter which predicted classes are drawn.
- `#tool-camera` — download the chart as a PNG.

**Chart meta strip** — five live figures under the title: **Scope** (node count),
**Peak** (highest throughput in the window, green), **Floor** (lowest, red),
**Flows stored**, **Threat score**. The threat score swaps between the up and down
colour classes at 50.

**The main chart** (`#mainChart`, Chart.js) — dual-axis line chart.
Green (`#2fe08a`) is throughput in Mbps; red (`#ff5064`) is threat score on a
0–100 scale. Two axes because they share a time base and nothing else, and
plotting them on one would make whichever is numerically smaller invisible.

**Node chips** (`#node-chips`) — one clickable chip per node under the chart, an
alternative to the dropdown for scoping.

### The detection console (right panel)

**Tabs:** Autonomous / Manual.

**Current network verdict** — two buttons, `THREAT` and `NORMAL`, one of which is
lit. Driven by the threat score crossing 50, not clicked by the user.

**Monitored scope** — a read-only text input showing the current scope, with an
`all` button to reset.

**Sensitivity (τ)** — read-only display of the current detection threshold.

**Mean confidence** — a large metric with a risk colour class.

**Threshold slider** (`#threshold-slider`) — range 50–99, default 85. Labelled at
both ends: *Permissive · fewer alerts* ←→ *Aggressive · more alerts*. Writes to
`POST /api/model/threshold`.

**Two checkboxes:**

- **Auto-mitigate** — when on, incidents past the threshold are labelled
  automatically. On by default. Remember this is a record, not an enforcement.
- **Desktop alerts** — browser notifications.

**ENGAGE MITIGATION** (`#btn-mitigate`) — the primary action button. Applies a
mitigation record to every flow the model scored above τ, which is exactly what
the footnote under it says: *"Applies to every flow the model scored above τ."*

**Console footer** — the model identifier and the current inference latency.

### The KPI strip (`#stat-strip`)

Five cards, each with a label, a value and a one-line explanation:

| Card | Value | Sub-line |
| --- | --- | --- |
| Flows / min | count | "scored by the model" |
| Mitigated | count | "flows marked for blocking" |
| Open incidents | count | "grouped by source IP" — red when > 0 |
| Mean confidence | 3 decimal places | "last 60 seconds" |
| Threat level | NOMINAL / etc. | "*n*/*m* nodes online" — green when NOMINAL |

### The analytics row — three mini charts

| Panel | Canvas | What it shows |
| --- | --- | --- |
| **Predicted classes · all stored flows** | `#classChart` | Doughnut of the three model classes across stored flows. |
| **Load by node** | `#nodeChart` | Bar chart, Mbps over 5 minutes, per node. |
| **Destination port activity** | `#portChart` | Bar chart of flow counts by destination port. |

### The live flow table

**Tabs:** Live Activity / Flagged / Mitigated.
**Right-hand controls:** `#btn-pause` (freeze the stream so a row can be read
before it scrolls away) and `#btn-csv` (export).

**Eleven columns:** Flow, Source IP, Node, Destination, Proto, Duration, Packets,
Throughput, Prediction, Confidence, Action.

The **Destination** column renders as `host:port` when a destination address is
known and bare `port` when it is not — folded into the existing port column rather
than added as a twelfth, matching the way an incident's own detail line phrases
it.

**Search is kept deliberately in step on both sides.** The client-side filter
matches against `src_ip`, `dst_ip`, `node`, `prediction`, `dst_port` and `id`, and
the SQL `LIKE` conditions in `list_flows` match the same set. If one matched a
destination address and the other did not, the same query would return different
rows depending on whether a flow arrived over the socket or came back from the
API.

CSV export columns include `dst_ip` immediately after `src_ip`.

---

## 29. `alerts.html` — Alerts & Incidents

Breadcrumb `/ grouped by source`. Module: `alerts.js`.

**Topbar:** Refresh, Export (primary).

**Notice banner** explaining what an incident is and how grouping works.

**KPI strip** — four cards: **Shown** (with the active status filter as its
sub-line), **Critical**, **Unacknowledged** (open), **Mitigated** ("marked for
blocking").

**Status tabs:** All / Open / Acknowledged / Resolved.

**Table — ten columns:** Severity, Source IP, Class, Node, Flows, Peak conf.,
Peak rate, Opened, Last seen, Status.

Where an incident has a `detail` line — every rule-based detection does, no
classifier detection does — it is shown under the row. NULL reads as "nothing
further to add" rather than as missing data.

### The ban modal (`#ban-modal`)

Opened from a row. **Everything it displays is already loaded with the incident —
nothing is fetched when it opens, so it cannot show a spinner or fail.**

- Source IP (monospace), a one-line summary, and a severity chip.
- **Duration** select: 1 hour / **24 hours** (default) / 7 days / Permanent — until
  someone lifts it / Custom…
- **Custom duration** field (minutes) appears only when Custom is chosen. Accepts
  decimals, so `0.5` is thirty seconds; range 0.1 to 525,600. The hint says
  *"Anything over a year is what Permanent is for."*
- **The honesty notice**, and the reason this is a modal rather than a one-click
  button: *"SENTRY records this ban — it does not apply it. Nothing here reaches
  your router or firewall, so the traffic keeps arriving until you add the block
  there yourself."*
- Buttons: Cancel / **Record ban**.

---

## 30. `traffic.html` — Traffic Analysis

Breadcrumb `/ who is talking`. Module: `traffic.js`.

**KPI strip — five cards:** Flows ("in the last *n*m"), Unique sources ("distinct
addresses"), Volume ("across all sources"), Attacking sources ("shown at the top
of the table" or "none in this window"), Busiest source (as a % of volume, naming
the address).

**Top talkers panel** with four sort buttons: **Threat** / **Volume** / **Flows**
/ **Ports**. Sorting is by a composite key array with tie-breaking, not a single
field, so two sources with the same flow count do not swap places on every
refresh.

**Eleven columns:** Source IP, Verdict, Flows, Attack flows, Packets, Volume,
Share, Ports, Seen on, Last seen, and an action column.

**Protocols panel** — Protocol, Flows, Volume, Attack flows.

**Destination ports panel** — Port, **Service** (the well-known name, so an
operator does not have to remember that 3389 is RDP), Flows, Sources, Attack
flows.

---

## 31. `baseline.html` — Baseline & Anomalies

Breadcrumb `/ what is normal here`. Module: `baseline.js`.

**Notice banner** explaining what a baseline is and why it is a different question
from "is this flow malicious".

**Warm-up notice** (`#warmup-notice`) — shown while buckets are still learning.
This is the page being honest about its own confidence rather than showing a
cold baseline as if it were a warm one.

**KPI strip — five cards:**

| Card | Value | Sub-line |
| --- | --- | --- |
| Window | 5m | "per observation" |
| Baseline warmth | % | "*n* of *m* slots ready" |
| Right now | current metric | "expected *x*" or "this slot is still learning" |
| Open anomalies | count | "listed below" / "none currently" |
| Largest deviation | *n*σ | the metric name, or "nothing outside the baseline" |

**Open anomalies table** with status filters (Open / Acknowledged / Resolved /
All). **Ten columns:** Signal, Severity, Observed, Expected, Deviation, Duration,
Started, Last seen, Status, and an acknowledge action.

**Learned profile panel** (`#profileChart`) with **Weekday / Weekend** toggle
buttons. Plots the 24 hourly baseline means for the selected day type — this is the
48-bucket model made visible, and it is the page where a user can see the system's
idea of "normal" and judge whether it matches their own.

---

## 32. `nodes.html` — Network Nodes

Breadcrumb `/ monitored links`. Module: `nodes.js`.

**Notice:** *"Nodes are the collection points flows are attributed to. Throughput
and attack counts cover the last five minutes. A node turns amber once more than
eight flagged flows arrive from it in that window."*

**Node grid** (`#node-grid`) — one tile per node with its label, description,
throughput and status colour. Clicking a tile filters the table below.

**Recent flows on selected node** — eight columns: Flow, Source IP, Destination,
Proto, Packets, Throughput, Prediction, Confidence. The pill on the right shows
the current selection.

### Rename modal

Name (max 60) and Description (max 200, optional, shown under the name on the
tile).

The hint explains the consequence rather than assuming the user knows it:
*renaming carries the history with it — every flow and incident already recorded
under the old name is updated.* The device is the same device; only what we call it
changed. Leaving those rows behind would strand the node's past traffic under a
name nothing answers to, and the renamed node would read as newly installed.

### Remove modal

Type-the-name-to-confirm. The hint is the honest one:

*Its flows and incidents are kept.* They are evidence of what happened on the
network, and taking a device off the inventory is not a claim its traffic never
occurred.

*A node which is still sending will register itself again within a tick or two* —
for a network monitor, something still talking still exists. To actually stop
collecting from it, remove the device on the Exporters page. That cross-reference
matters: without it, a user removes a node, watches it reappear, and concludes the
product is broken.

Buttons: Cancel / **Remove node** (danger styling).

---

## 33. `exporters.html` — Flow Sources

Breadcrumb `/ netflow / ipfix`. Titled **Router Setup** in the consumer nav.
Module: `exporters.js` (~27 KB).

**Topbar:** Refresh, Add (primary).

### Unclaimed senders on your network

Five columns: Source address, Protocol, First heard, Last heard, Packets.

This panel is the answer to the commonest support question. A user who configured
their firewall and sees nothing can look here and find out whether the packets are
arriving but unregistered — which is a two-click fix — or not arriving at all,
which is a firewall/routing problem on their side. Without this table, both
failures look identical.

### Registered devices

Eight columns: Device, Source address, Attributed to node, Protocol, Sampling,
State, Last packet, Flows.

**Protocol** is learned from the wire, not typed in. **Sampling** shows the
effective rate. **State** surfaces `last_error` — usually "awaiting template",
which is normal for ~10 minutes on a v9 device and alarming if it never clears.

### Set up a device

Copy-pasteable configuration instructions with a **Copy** button.

### Register / edit modal

Source address, display name, which node to attribute to, sampling-rate override.
Button: **Register device**.

### Remove modal

Confirm, then **Remove device** (danger).

---

## 34. `model.html` — Model Performance

Breadcrumb `/ detection network`. Module: `model.js`.

**The honesty notice** (`#honesty`) sits at the top in amber, and is not optional
chrome — a high score on synthetic data means something different from a high
score on a real capture, and the page says which one it is looking at before it
shows any number.

**KPI strip — four cards:** Test accuracy, Mean confidence, **Live agreement**
(the running match between generated `truth` and predicted label, simulated
traffic only), and **Status** (LOADED / DOWN).

### Per-class performance · held-out test split

Class, Precision, Recall, F1, Support — for `dos_ddos`, `normal`, `scan`.

### Accuracy by data domain

Domain, Accuracy, Benign, DoS/DDoS, Scan, Samples. **Two rows, never averaged into
one.** This is the table that stops the product claiming a single number that
describes neither domain.

### Live agreement · simulated traffic only

Labelled explicitly so nobody reads a simulated agreement rate as a production
accuracy.

### Architecture

`6 → 64 → 32 → 3`, ReLU, ~2,500 parameters, the `signed_log1p → StandardScaler →
MLP → softmax` pipeline.

### Input features

All six, named, with the note that none of them is an address.

### What the accuracy rests on

The ablation table: port-only 54.02%, shape-only 73.65%, full 94.92%, plus the
port-decorrelation figures (95.05% before treatment → 67.15% after).

### Known blind spots

The eight excluded attack families listed by name — Patator (FTP/SSH), Bot,
Infiltration, Heartbleed, Web Brute Force, XSS, SQL Injection — sitting directly
next to the accuracy figure rather than in a footnote.

### Confusion matrix · test split

A 3×3 grid on the held-out split.

---

## 35. `reports.html` — Reports

Breadcrumb `/ last 7 days`. Module: `reports.js`.

**Range segmented control:** 24h / **7d** (default) / 30d / 90d.
**Buttons:** CSV export (`#btn-csv`), Print (`#btn-print`, primary — produces the
printable/PDF version).

**Two charts:**

- **Flows by predicted class** (`#classChart`) — 220px.
- **Incidents** (`#incChart`) — 220px.

**Top flagged sources table:** #, Source IP, Flagged flows, Share of flagged.

Company-only (`export` and `scheduled_reports` are both false for consumer orgs).

---

## 36. `team.html` — Team

Breadcrumb `/ organisation`. Module: `team.js`. Admin-only for mutations; the
whole page is company-only.

**Topbar:** Add (primary).

### Waiting for approval

Five columns: Person, Email, **How they got here**, **Role they would get**,
Asked.

"How they got here" is the column that matters. A domain match is a *claim*; an
invite is a *decision*. The approval screen must not present the two as
equivalent, so the join method is shown, and a domain-matched address is marked
unverified.

### Members

Six columns: Member, Email, Role, Status, Joined, Last sign-in.

### Invite codes

Six columns: Code, Issued to, Role, State, Expires, Issued by. States are
`used` / `revoked` / `expired` / `open` in that precedence order — a used code is
spent whatever else is true of it, and revocation beats mere expiry.

Button: Issue an invite code.

### Audit trail

Four columns: When, Who, Action, Detail.

### Add team member modal
Name, email, role, title. Button: **Add member**.

### Issue invite modal
Invitee email (enforced at redemption, not merely recorded), role, expiry.
Button: **Create code**. The code is shown **exactly once** and is never
recoverable.

---

## 37. `settings.html` — Settings

Breadcrumb `/ organisation`. Module: `settings.js`. **Save** button in the topbar.

Six panels:

### Organisation
Name, and **Company email domain** — with the explanation that it lets employees
find their employer during signup, that it places them in a pending queue, and
that it is discovery rather than authentication.

### Detection
- **Detection threshold (τ)** — the confidence above which a non-benign verdict is
  flagged.
- **Auto-mitigate** — on by default.
- **Repeat-offender window** — minutes; default 60.

### Alerting
- **Minimum severity to alert on** — default `high`.
- **Webhook URL** — carrying a visible `not delivering yet` tag. Stored and
  scheme-validated; nothing posts to it. See §4.
- **Desktop notifications.**

### Collector keys
Titled "connect a device" for consumer orgs. **New key** button; the generated key
is shown once with a **Copy** button and never again. Company orgs may hold many
keys; consumer orgs one.

### Display
- **Refresh interval** — the polling fallback cadence, default 2000ms.
- **Rows in the flow table** — default 45.
- **API base URL.**

### Backend
**Test connection** button — pings the API and reports the result, so a
misconfigured base URL is diagnosable from the UI rather than from the browser
console.

---

## 38. `profile.html` — Profile

Breadcrumb `/ account`. Module: `profile.js`.

**Topbar:** a Settings pill link and a **Sign out** button. Signing out bumps
`token_version`, which kills the session server-side rather than merely deleting
the cookie.

**Session panel** — current session details.

**What your role allows** — a plain-language list of this user's actual
permissions. Worth having because "analyst" is a word, not a description, and the
person holding the role should be able to see what it means without reading the
docs.

**Your details** — name, title, etc. → **Save details**.

**Change password** — → **Update password**. Revokes every *other* session but
keeps the current one, so changing your password does not log you out of the tab
you changed it in.

**Your recent actions** — When, Action, Detail. The user's own slice of the audit
log.

---

## 39. The consumer pages

### `home-index.html` — Home
Breadcrumb `/ your network`.

**The hero** — a ring gauge (`#hero-ring`) with a one-sentence verdict
(`#hero-line`) and a one-sentence reason (`#hero-why`). Everything below it is the
evidence for that sentence. Initial state: *"Checking your network… One moment."*

This is the entire consumer design thesis in one component. A household does not
want a threat score, they want to know whether they are okay.

**What's happened recently** — a plain-language event list.
**Your devices** — the node list, phrased as devices.

### `home-devices.html` — My Devices
Breadcrumb `/ things on your network`. A notice explaining what a device is here,
and the device list.

### `home-alerts.html` — Alerts
Breadcrumb `/ what we've spotted`.

**The same hero component as the home page, deliberately** — someone who lands
here from a notification gets the same verdict in the same shape rather than
having to re-derive it.

**Needs your attention** list, with a **Show everything** toggle (`#btn-scope`)
that widens it from the things that need action to the full history.

---

## 40. The authentication pages

These have no sidebar and no topbar.

### `login.html`
Work email, Password, **Sign in** (`#submit`). Cookie-based — the response sets
`sentry_session` and the client never handles a token.

### `signup.html` — a three-way branching flow

**Step 1 — three choices:**

| Option | Leads to |
| --- | --- |
| **A company or team network** (default) | Two-step company flow |
| **My home network** | One-step household flow |
| **Join a company already using SENTRY** | `join.html` |

**Continue** (`#btn-choose`) commits the choice.

**Household path** (one screen): Household name (*"The Mercer House"*), Your name,
Email, Password → **Create household**.

**Company path** (two screens):
1. Your full name, Work email, Password → **Continue**.
2. Organisation name (*"Acme Networks"*), Your job title (*"Security Operations
   Lead"*), Company email domain (*optional*, `acme.com`) → **Create
   organisation**.

Every screen has a **Back** link. Splitting the company path in two is deliberate:
asking for an organisation name and a job title on the same screen as a password
makes a personal signup look like an IT procurement form.

The first account in an organisation becomes its admin.

### `join.html`
Breadcrumb-free. Fields: Your full name, Work email, **Invite code** (*optional*,
`sentry_inv_…`), Your job title (*optional*), Choose a password.

Button: **Request access** — not "Sign up", because that is what actually happens.
Without a code, the email domain is matched against registered orgs and the
request lands in an admin's approval queue. With a code, the code is checked
against `invitee_email` and refused if presented by any other address.

---

# PART IV — APPENDICES

## A. Endpoint inventory

### `/api/auth`
| Method | Path | Notes |
| --- | --- | --- |
| POST | `/signup` | Creates org + first admin |
| POST | `/join` | Invite code or email-domain match → pending |
| POST | `/login` | Sets the session cookie |
| POST | `/logout` | Bumps `token_version` |
| GET | `/me` | Current user |
| PATCH | `/me` | Update own details |
| POST | `/password` | Revokes other sessions |
| GET | `/features` | The org-type capability map |
| GET | `/bootstrap` | Everything the shell needs in one call |

### `/api` — core
| Method | Path |
| --- | --- |
| GET | `/status`, `/health`, `/summary` |
| GET | `/metrics/history`, `/metrics/current` |
| GET | `/flows` |
| POST | `/ingest` |
| GET | `/analytics/classes`, `/analytics/nodes`, `/analytics/ports`, `/analytics/talkers`, `/analytics/traffic` |
| GET | `/anomalies` · POST `/anomalies/{id}/acknowledge` |
| GET | `/baseline` |
| GET | `/nodes` · PATCH `/nodes/{id}` · DELETE `/nodes/{id}` |
| GET | `/incidents` · POST `/incidents/{id}/action` |
| POST | `/mitigate` |
| POST | `/model/threshold` · GET `/model/metrics` |
| GET | `/settings` · PATCH `/settings` |
| GET | `/reports/summary` |
| GET | `/stream/status` |

### `/api/team`
| Method | Path |
| --- | --- |
| GET/POST | `` (members) · PATCH/DELETE `/{user_id}` |
| GET/POST | `/invites` · DELETE `/invites/{id}` |
| GET | `/pending` · POST `/{user_id}/approve` · POST `/{user_id}/reject` |
| GET/POST | `/keys` · DELETE `/keys/{id}` |
| GET | `/audit` |

### `/api/exporters`
| Method | Path |
| --- | --- |
| GET/POST | `` · PATCH `/{id}` · DELETE `/{id}` |
| GET | `/unclaimed`, `/status` |

### WebSocket
`/ws` — per-org live push of flows, metrics and incidents.

## B. File map

```
backend/
  sentryv1.py             original model + training script (Sai) — DO NOT MODIFY
  artifacts/              model.pt, scaler.joblib, labels.joblib, metrics.json
  app/                    main, config, db, models, schemas, security, features,
                          severity, mitigation, baseline, engine
    ml/                   cicids, features, net, train, infer
    netflow/              parser, collector
    routers/              auth, team, api, exporters
  tests/                  17 files, ~6,400 lines
agent/
  sentry_collector.py     packet capture → flow aggregation → POST /api/ingest
  requirements.txt        scapy + requests only, deliberately not the backend's
assets/
  css/styles.css          theme tokens and all styling (~1,100 lines)
  css/intro.css           opening sequence
  js/                     20 modules, one per page + api/ui/config/intro shared
*.html                    17 pages
data/cicids2017/          CIC-IDS2017 CSVs (not committed, ~884 MB)
docker-compose.yml
```

## C. Glossary

| Term | Meaning here |
| --- | --- |
| **Flow** | One aggregated conversation between two endpoints. Not one TCP connection — this distinction is why the training-domain issue in §15 exists. |
| **Node** | A collection point flows are attributed to. A switch, a segment, a sensor. |
| **Exporter** | A device sending NetFlow/IPFIX records. Registered by source IP. |
| **Incident** | A correlated group of malicious flows from one source, within 10 minutes. |
| **Anomaly** | An aggregate observation outside the learned baseline. No single source to blame. |
| **Bucket** | One of 48 (weekend?, hour-of-day) slots the baseline is learned per. |
| **Tier** | A rung on the mitigation ladder: throttle / repeat_offender / ban. Recorded, never enforced. |
| **τ (tau)** | The detection threshold. Default 0.85. |
| **Warmth** | How much of the baseline has enough samples to fire. |
| **Truth** | What the simulator intended a flow to be. NULL for real flows. |

## D. Known gaps — the honest list

**Product**
1. No email delivery. Invites are copy-paste; there is no password reset.
2. No billing.
3. No cross-org roll-up for MSPs.
4. The webhook is stored and validated but never fires (SSRF, §4).
5. No public marketing site.

**Engineering**
6. No Alembic migrations. A hand-rolled additive column-adder in `db.py` handles
   additive changes only.
7. Blocking sync DB calls inside `async def engine_loop` and `baseline_loop`.
8. Single-worker state (WebSocket registry, login throttle, simulator).
9. No CSRF token — defence-in-depth only, `SameSite=Lax` covers the main vector.
10. Chart.js and Google Fonts load from CDNs; air-gapped deployments need them
    vendored.

**Detection**
11. Three classes. Eight attack families are structurally undetectable and named
    on the model page.
12. NetFlow's trust model is registration, not authentication.
13. `WALKTHROUGH.md` is stale — it predates the NetFlow stack, the exporters page,
    the slow-DoS detector, node rename/delete and the destination column, and its
    test count is out of date.

**Operations**
14. Verify `SENTRY_ENV=production` on the live deployment. Without it the secret
    key regenerates every boot and simulator traffic mixes into real data.
15. Confirm the exposed Render Postgres password has been rotated.
16. Two commits are unpushed: `862770b` (node UI) and `8048b81` (slow-DoS).

---

*Last updated against commit `8048b81`. When the codebase changes materially,
update this document, `README.md` and `WALKTHROUGH.md` together — three documents
that disagree are worse than one that is merely incomplete.*
