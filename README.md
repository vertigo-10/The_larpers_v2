# SENTRY — neural-network network threat detection

A multi-tenant security console: a PyTorch classifier scores network flows, the
backend persists and correlates them into incidents, and the dashboard shows it
live. Frontend, API and model are one deployable service.

## What the model actually is

Being precise about this, because the honest answer is narrower than the
dashboard makes it look.

| | |
| --- | --- |
| Architecture | MLP, `6 → 64 → 32 → 3`, ReLU, PyTorch 2.2.2 |
| Classes | `normal`, `dos_ddos`, `scan` |
| Features | duration, packets, total_bytes, packets_per_sec, bytes_per_packet, dst_port |
| Training data | **synthetic — not CIC-IDS2017, not captured traffic** |
| Held-out accuracy | 100% on 1,200 synthetic samples |

The model is the one in `backend/sentryv1.py`, persisted to servable artifacts
(`model.pt`, `scaler.joblib`, `labels.joblib`) by `python -m backend.app.ml.train`.
Inference at runtime is the real network — nothing is faked, and predictions come
from a forward pass through those weights.

**The 100% is not a real-world detection rate.** The training set is three
generated clusters that are cleanly separable by construction, so the number
measures "can an MLP separate three synthetic blobs" and nothing more. It says
nothing about performance on captured traffic. `metrics.json` carries the caveat
in a `dataset_note` field, the sidebar never prints the figure bare (it reads
"100% on synthetic data"), and the model page shows the full note under
*Provenance* — so the disclaimer travels with the number rather than living only
in this file.

An earlier version of this README claimed CIC-IDS2017 and 99.2%. That was never
true of this model. To make it true, retrain on real labelled captures and
re-run the trainer — the serving path needs no changes, it reads the class list
out of the artifacts.

## Run it locally

Requires Python 3.9+.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt

cp .env.example .env          # fine as-is for local development
python -m backend.app.ml.train   # writes backend/artifacts/
uvicorn backend.app.main:app --reload --port 8000
```

Open <http://localhost:8000> and create an account. The first account in an
organisation becomes its admin.

The traffic simulator is on in development, so the dashboard has something to
show immediately. It generates synthetic *flows* which are then scored by the
real model — the inference is genuine, the traffic is not. It defaults **off**
in production; see below.

### Tests

```bash
pip install -r backend/requirements-dev.txt
pytest backend/tests -q
```

## Deploying

The image serves the API and the dashboard from one origin, so the session
cookie stays `SameSite=Lax` with no CORS exceptions to punch.

### Docker Compose (app + Postgres)

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SENTRY_SECRET_KEY
docker compose up --build
```

### A single container

```bash
docker build -t sentry .
docker run -p 8000:8000 --env-file .env sentry
```

### Render / Railway / Fly

All three build the Dockerfile as-is. Set these in the platform's environment
settings — do not commit them:

| Variable | Value |
| --- | --- |
| `SENTRY_SECRET_KEY` | output of `secrets.token_urlsafe(48)` |
| `SENTRY_ENV` | `production` |
| `SENTRY_DATABASE_URL` | `postgresql+psycopg://…` (note the `+psycopg`) |
| `SENTRY_CORS_ORIGINS` | your real dashboard origin |

`PORT` is read from the environment, which is what Render and Railway inject.
Health checks should point at `/api/health`.

### Things that will bite you

- **`postgresql://` alone will not work.** SQLAlchemy 2.0 maps that to psycopg2,
  which is not installed. Use `postgresql+psycopg://`. Managed platforms hand
  you the bare form, so this usually needs editing by hand.
- **SQLite needs a persistent volume.** Without one, every redeploy starts from
  an empty database and all accounts are gone. Prefer Postgres for anything real.
- **Run one worker per container.** Three pieces of state live in the process
  and not the database: the WebSocket connection registry, the failed-login
  throttle, and the simulator. With multiple workers, a browser would only
  receive live events from whichever worker it connected to, and the login
  throttle could be sidestepped by landing on a different worker. Scale out with
  more containers behind a sticky-session load balancer, or move that state into
  Redis first. The Dockerfile pins `--workers 1` deliberately.
- **Set `SENTRY_SECRET_KEY` once and keep it.** It signs session cookies.
  Changing it logs everyone out; leaking it lets anyone forge a session for any
  account. In production the app refuses to boot without it rather than falling
  back to a generated key.
- **The simulator is off in production by default.** If you turn it on, the
  console will fabricate incidents an operator cannot distinguish from real
  ones. It stays *possible* because demo deployments are legitimate, but it
  warns loudly at boot.
- **"Mitigated" is a record, not an enforcement.** Marking a flow mitigated
  writes a decision to the database and updates the console. SENTRY does not
  push blocks to any router, firewall or upstream — there is no outbound
  integration. Auto-mitigate is on by default, so incidents past the threshold
  are labelled automatically; do not read that as traffic having been stopped.
- **The webhook setting does not fire yet.** It is stored and scheme-validated
  but nothing posts to it. Left unimplemented on purpose: the server fetching a
  user-supplied URL is an SSRF vector — a webhook pointing at
  `169.254.169.254` would read the host's cloud credentials — so it needs a
  private-range blocklist and DNS-rebinding protection before it ships. The
  settings page labels the field accordingly.
- **Charts and fonts load from CDNs** (jsdelivr, Google Fonts). On an air-gapped
  or egress-filtered network the charts will not render — vendor Chart.js and
  the fonts locally if that is the target environment.

## Feeding it real traffic

Until something posts to `/api/ingest`, the dashboard shows simulated flows and
nothing else. There are two ways to feed it.

### The collector agent

`agent/sentry_collector.py` captures live packets on a machine you want watched,
aggregates them into flows, and posts them. This is the piece that turns SENTRY
from a demo into a monitor.

```bash
# on the machine you want watched
pip install -r agent/requirements.txt

export SENTRY_API_KEY=sentry_ak_...        # Settings → Collector keys
sudo -E python -m agent.sentry_collector --server https://sentry.example.com
```

`sudo` is needed because packet capture requires root. The `-E` is not optional:
plain `sudo` drops your environment, taking `SENTRY_API_KEY` with it. If you
would rather not export a secret at all, put it in a file and pass `--key-file`
— the collector refuses to read one that is group- or world-readable.

Useful flags:

| Flag | Default | Why you would change it |
|---|---|---|
| `--interface` / `-i` | scapy's default route | Capture on a mirror/SPAN port instead of the uplink |
| `--node` | short hostname | The name this sensor gets in the dashboard |
| `--filter` | `ip or ip6` | Any BPF expression, e.g. `not port 22` to drop your own SSH |
| `--flush-interval` | `5.0` | Seconds between posts |
| `--key-file` | — | Read the key from a mode-600 file rather than the environment |
| `--insecure` | off | Skip TLS verification. Self-signed lab servers only |

Two limits worth knowing before you deploy it:

- **It reads headers, never payloads.** Addresses, ports, sizes and timings go in;
  only counters derived from them come out. A tool that watches a network should
  not become a way to read everyone's traffic, and the narrow scope means a
  compromised collector leaks metadata rather than content.
- **It buffers, but not forever.** If the server is unreachable it retries with
  backoff and holds up to 20,000 flows. Past that the oldest are dropped and the
  loss is printed — during an attack the newest flows are the ones you need.

To watch a whole network rather than one host, run it on a machine attached to a
switch mirror port. Flows where neither endpoint is local are kept and oriented
by convention, which is exactly the mirrored case.

### Posting flows yourself

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer sentry_ak_...' \
  -d '{"flows":[{
        "src_ip":"172.16.0.5","dst_port":443,"protocol":"TCP",
        "node":"EDGE-01","duration":0.043,"packets":1284,
        "total_bytes":128400
      }]}'
```

Batch up to 500 flows; they are scored, persisted, promoted to incidents past the
confidence threshold, and pushed to connected dashboards over the WebSocket.
`total_bytes` or `bytes_per_sec` — one of the two; the other is derived.

Authenticate with a collector key as above, or with a session cookie if you are
testing from a logged-in browser (`admin` or `analyst`). Keys are the right
choice for anything long-lived: they carry no person's access, they are scoped to
ingest alone, and revoking one does not disturb anybody's session.

## Architecture

```
backend/
  sentryv1.py           original model + training script (Sai)
  artifacts/            model.pt, scaler.joblib, labels.joblib, metrics.json
  app/
    main.py             app factory, security headers, WebSocket, static mounts
    config.py           env-driven settings, startup safety checks
    db.py               engine, session, additive migration shim
    models.py           User, Org, Flow, Incident, AuditLog, ApiKey, Settings
    schemas.py          pydantic request/response contracts
    security.py         bcrypt, JWT sessions, role guards, revocation, API keys
    engine.py           scoring loop, incident promotion, WebSocket fan-out
    ml/
      train.py          trains from sentryv1.py, writes artifacts
      infer.py          loads artifacts, batched inference
    routers/
      auth.py           signup, login, logout, profile, password
      team.py           member management, audit log, collector keys
      api.py            flows, incidents, analytics, settings, reports
  tests/                82 tests, no network or root required
agent/
  sentry_collector.py   packet capture → flow aggregation → POST /api/ingest
  requirements.txt      scapy + requests only, deliberately not the backend's
assets/
  css/styles.css        theme tokens and all styling
  js/                   one module per page, no build step
```

`agent/` is standalone on purpose. It runs on routers and laptops, which should
not have to install torch and a database driver to send counters over HTTP.

### Pages

| File | Purpose |
| --- | --- |
| `index.html` | Live console — throughput/threat charts, flow table, detection panel |
| `alerts.html` | Incident queue — triage, acknowledge, mitigate, resolve |
| `nodes.html` | Per-node traffic and health |
| `model.html` | Model card — architecture, per-class precision/recall, confusion matrix |
| `reports.html` | Period summaries and export |
| `team.html` | Members, roles, invitations, audit trail |
| `profile.html` | Own account, activity, password |
| `settings.html` | Threshold, retention, workspace |
| `login.html` / `signup.html` | Authentication |

## Security notes

- Passwords are bcrypt (cost 12). Sessions are HS256 JWTs in `HttpOnly`,
  `SameSite=Lax` cookies, `Secure` in production.
- **Sessions are revocable server-side.** Each token embeds a `ver` claim
  matched against a per-user counter. Logging out bumps the counter, so the
  token is dead immediately rather than merely deleted from one browser — which
  is what makes signing out on a shared machine mean anything. Changing a
  password revokes every other session but keeps the current one.
- Every query is scoped by `org_id`. Tenant isolation is covered by tests, not
  just by convention.
- Roles are `admin`, `analyst`, `viewer`. Mitigation and ingest require
  analyst or above; team management requires admin.
- `/api/*` responses carry `Cache-Control: no-store`. Without it browsers
  heuristically cache authenticated JSON and write one account's incident data
  into a shared on-disk cache.
- Failed logins are throttled per-process (see the single-worker note above).
- `.env` is gitignored. If you have ever committed one, rotate the key.

## Credits

The neural network and `backend/sentryv1.py` are **Sai Adheep Addala**'s work.
The serving layer, API, auth and dashboard are built around it.
