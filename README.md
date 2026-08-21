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

`POST /api/ingest` is the production path. Batch up to 500 flows; they are
scored, persisted, promoted to incidents past the confidence threshold, and
pushed to connected dashboards over the WebSocket.

```bash
curl -X POST http://localhost:8000/api/ingest \
  -H 'Content-Type: application/json' \
  -b 'sentry_session=<cookie>' \
  -d '{"flows":[{
        "src_ip":"172.16.0.5","dst_port":443,"protocol":"TCP",
        "node":"EDGE-01","duration":0.043,"packets":1284,
        "total_bytes":128400
      }]}'
```

`total_bytes` or `bytes_per_sec` — one of the two; the other is derived. Requires
the `admin` or `analyst` role.

## Architecture

```
backend/
  sentryv1.py           original model + training script (Sai)
  artifacts/            model.pt, scaler.joblib, labels.joblib, metrics.json
  app/
    main.py             app factory, security headers, WebSocket, static mounts
    config.py           env-driven settings, startup safety checks
    db.py               engine, session, additive migration shim
    models.py           User, Org, Flow, Incident, AuditLog, Settings
    schemas.py          pydantic request/response contracts
    security.py         bcrypt, JWT sessions, role guards, revocation
    engine.py           scoring loop, incident promotion, WebSocket fan-out
    ml/
      train.py          trains from sentryv1.py, writes artifacts
      infer.py          loads artifacts, batched inference
    routers/
      auth.py           signup, login, logout, profile, password
      team.py           member management, audit log
      api.py            flows, incidents, analytics, settings, reports
assets/
  css/styles.css        theme tokens and all styling
  js/                   one module per page, no build step
```

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
