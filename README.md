# AEGIS NN — DDoS Detection Dashboard

Front-end for a PyTorch neural network that classifies network flows as benign or
attack traffic, trained on **CIC-IDS2017**. Built as a single centralised console so one
company can watch every router, subnet and gateway from one screen.

It ships with a synthetic traffic generator, so the dashboard runs and animates
immediately — no backend required. Point it at your model when you're ready.

## Pages

| File | Purpose |
| --- | --- |
| `index.html` | Main console — live throughput/threat chart, detection panel, analytics, live flow table |
| `profile.html` | Operator profile — review activity, assigned network scope, recent actions |
| `settings.html` | Connect to the detection service, tune threshold, alerting, workspace |

## Run it

No build step, no dependencies to install. Any static server works:

```bash
python3 -m http.server 8777
# open http://localhost:8777
```

Opening `index.html` directly via `file://` also works, though a server is recommended.

## Put it on GitHub

```bash
git init
git add .
git commit -m "Add AEGIS DDoS detection dashboard UI"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```

To publish it: **Settings → Pages → Source: `main` / root**. The dashboard is fully
static, so it works on GitHub Pages as-is (running on demo data until you point it at a
reachable API).

## Connecting your neural network

Open **Settings** and set the *Detection API base URL*, then turn **Use demo data** off
and press **Test connection**. Values are saved in `localStorage`, so nothing needs
editing to switch environments. Defaults live in `assets/js/config.js`.

If the backend is unreachable the UI does **not** silently pretend to be live — the
status pill turns amber and reads *"Backend unreachable — demo data"*.

### Endpoints the UI calls

All are `GET` and return JSON unless noted.

| Endpoint | Returns |
| --- | --- |
| `/api/status` | `{ model, framework, dataset, accuracy, uptime_s }` |
| `/api/summary` | `{ flows_per_min, attacks_blocked, avg_confidence, inference_ms, nodes_online, nodes_total, threat_level, phase }` |
| `/api/metrics/current` | `{ ts, throughput, threat, phase }` |
| `/api/metrics/history?points=90` | `{ labels: [ts], throughput: [num], threat: [num] }` |
| `/api/flows?limit=25` | array of flow objects (below) |
| `/api/flows/next` | a single newest flow object |
| `/api/analytics/classes` | `{ labels: [str], values: [int] }` — predicted class counts |
| `/api/analytics/nodes` | `{ labels: [str], values: [int] }` — Mbps per router |
| `/api/analytics/ports` | `{ labels: [str], values: [int] }` — flows/min per port |
| `/api/nodes` | `[{ label, desc, mbps, status: "ok"\|"warn" }]` |
| `POST /api/mitigate` | body `{ flow_id, src_ip }` → `{ ok: true }` |
| `POST /api/model/threshold` | body `{ threshold: 0.85 }` → `{ ok: true }` |
| `WS /ws/live` | optional — pushes flow objects as they're classified |

### Flow object

`threat` is a 0–100 score; `confidence` is the raw softmax probability.

```json
{
  "id": "FLW-4821",
  "ts": 1754563200000,
  "src_ip": "172.16.0.5",
  "dst_port": 443,
  "protocol": "TCP",
  "node": "EDGE-01",
  "duration": 0.043,
  "packets": 1284,
  "bytes_per_sec": 918400,
  "prediction": "DDoS",
  "confidence": 0.9942,
  "mitigated": true
}
```

`prediction` should be one of the CIC-IDS2017 labels declared in `config.js`:
`BENIGN`, `DDoS`, `DoS Hulk`, `PortScan`, `Bot`, `FTP-Patator`. Adding a new class means
adding a colour in `CLASS_COLORS` and a tag class in `CLASS_TAG` (both in
`assets/js/dashboard.js`).

### Backend stub

`backend/app.py` is a runnable FastAPI service with every endpoint wired up and a single
`classify()` function to replace with your model. It has no dependency on this UI beyond
the JSON shapes above.

```bash
pip install fastapi uvicorn torch
python backend/app.py    # http://localhost:8000
```

CORS is open by default so the dashboard can call it from another port — lock that down
before deploying anywhere real.

## Feature mapping

The **28 CIC-IDS2017 features** your model consumes are extracted server-side. The UI only
displays the human-readable subset (duration, packet count, destination port, protocol,
throughput) plus the model's output. If you want more columns, extend the flow object and
add `<th>`/`<td>` entries in `index.html` and `flowRow()` in `assets/js/dashboard.js`.

## Layout

```
index.html / profile.html / settings.html
assets/
  css/styles.css        all styling and the dark theme tokens
  js/config.js          defaults + localStorage overrides
  js/mock.js            synthetic traffic generator (delete once live)
  js/api.js             fetch layer, falls back to mock on failure
  js/ui.js              icons, sidebar, toasts, formatters
  js/dashboard.js       charts + live table
  js/profile.js         profile page
  js/settings.js        settings page
backend/app.py          optional FastAPI stub to wrap your PyTorch model
```

Charts use [Chart.js 4](https://www.chartjs.org/) from a CDN — swap the `<script>` tag for
a vendored copy if the deployment has no outbound network access.
