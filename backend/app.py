"""FastAPI stub for the SENTRY dashboard.

Replace `classify()` with a call into your trained PyTorch model. Every other
endpoint already returns the shape the UI expects, so the dashboard will light up
as soon as this is running.

    pip install fastapi uvicorn
    python backend/app.py
"""

import random
import time
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="SENTRY DDoS Detection API")

# Tighten this to the dashboard's real origin before deploying.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

CLASSES = ["BENIGN", "DDoS", "DoS Hulk", "PortScan", "Bot", "FTP-Patator"]
NODES = [
    ("EDGE-01", "Core edge router"),
    ("EDGE-02", "Failover edge router"),
    ("DC-LB-01", "Datacenter load balancer"),
    ("VPN-GW", "Remote access gateway"),
    ("API-TIER", "Public API subnet"),
    ("DB-TIER", "Database subnet"),
    ("CDN-POP", "CDN point of presence"),
    ("IOT-SEG", "IoT segment"),
]

STARTED = time.time()
STATE: dict[str, Any] = {"threshold": 0.85, "blocked": 0, "flow_seq": 1000}


# ── model ─────────────────────────────────────────────────────────────────
#
# import torch
# MODEL = torch.jit.load("sentry_ddos_v1.pt")
# MODEL.eval()
#
# def classify(features: list[float]) -> tuple[str, float]:
#     with torch.no_grad():
#         logits = MODEL(torch.tensor([features], dtype=torch.float32))
#         probs = torch.softmax(logits, dim=1)[0]
#         idx = int(probs.argmax())
#     return CLASSES[idx], float(probs[idx])


def classify(features: list[float]) -> tuple[str, float]:
    """Placeholder. Swap for the commented PyTorch implementation above."""
    label = random.choices(CLASSES, weights=[88, 4, 3, 3, 1, 1])[0]
    confidence = random.uniform(0.88, 0.999) if label != "BENIGN" else random.uniform(0.74, 0.99)
    return label, round(confidence, 4)


def next_flow() -> dict[str, Any]:
    """Replace the synthetic feature vector with a real one from your capture pipeline."""
    features = [random.random() for _ in range(28)]
    label, confidence = classify(features)

    duration = round(random.uniform(0.001, 12.0), 3)
    packets = random.randint(1, 4000)
    total_bytes = random.uniform(300, 260_000)

    STATE["flow_seq"] += 1
    if label != "BENIGN":
        STATE["blocked"] += 1

    return {
        "id": f"FLW-{STATE['flow_seq']}",
        "ts": int(time.time() * 1000),
        "src_ip": ".".join(str(random.randint(1, 254)) for _ in range(4)),
        "dst_port": random.choice([80, 443, 22, 53, 3306, 8080, 21]),
        "protocol": random.choice(["TCP", "TCP", "TCP", "UDP"]),
        "node": random.choice(NODES)[0],
        "duration": duration,
        "packets": packets,
        "bytes_per_sec": int(total_bytes / max(duration, 0.001)),
        "prediction": label,
        "confidence": confidence,
        "mitigated": label != "BENIGN" and confidence >= STATE["threshold"],
    }


# ── endpoints ─────────────────────────────────────────────────────────────
@app.get("/api/status")
def status():
    return {
        "model": "sentry-ddos-v1",
        "framework": "PyTorch",
        "dataset": "CIC-IDS2017",
        "accuracy": 99.2,
        "uptime_s": int(time.time() - STARTED),
    }


@app.get("/api/summary")
def summary():
    return {
        "flows_per_min": random.randint(11_000, 14_500),
        "attacks_blocked": STATE["blocked"],
        "avg_confidence": round(random.uniform(0.94, 0.988), 3),
        "inference_ms": round(random.uniform(0.9, 2.6), 2),
        "nodes_online": len(NODES),
        "nodes_total": len(NODES),
        "threat_level": "NOMINAL",
        "phase": 0,
    }


@app.get("/api/metrics/current")
def metrics_current():
    return {
        "ts": int(time.time() * 1000),
        "throughput": round(random.uniform(500, 900), 1),
        "threat": round(random.uniform(1, 12), 1),
        "phase": 0,
    }


@app.get("/api/metrics/history")
def metrics_history(points: int = 90):
    now = int(time.time() * 1000)
    return {
        "labels": [now - (points - i) * 4000 for i in range(points)],
        "throughput": [round(random.uniform(500, 900), 1) for _ in range(points)],
        "threat": [round(random.uniform(1, 12), 1) for _ in range(points)],
    }


@app.get("/api/flows")
def flows(limit: int = 25):
    return [next_flow() for _ in range(limit)]


@app.get("/api/flows/next")
def flow_next():
    return next_flow()


@app.get("/api/analytics/classes")
def analytics_classes():
    return {"labels": CLASSES, "values": [random.randint(5, 9000) for _ in CLASSES]}


@app.get("/api/analytics/nodes")
def analytics_nodes():
    labels = [n[0] for n in NODES[:5]]
    return {"labels": labels, "values": [random.randint(150, 600) for _ in labels]}


@app.get("/api/analytics/ports")
def analytics_ports():
    labels = ["80", "443", "22", "53", "3306", "8080", "21"]
    return {"labels": labels, "values": [random.randint(50, 3300) for _ in labels]}


@app.get("/api/nodes")
def nodes():
    return [
        {"label": label, "desc": desc, "mbps": random.randint(150, 600), "status": "ok"}
        for label, desc in NODES
    ]


class MitigateRequest(BaseModel):
    flow_id: str | None = None
    src_ip: str | None = None


@app.post("/api/mitigate")
def mitigate(req: MitigateRequest):
    # Hook your firewall / BGP blackhole / rate-limiter in here.
    return {"ok": True, "flow_id": req.flow_id, "src_ip": req.src_ip, "action": "blocked"}


class ThresholdRequest(BaseModel):
    threshold: float


@app.post("/api/model/threshold")
def set_threshold(req: ThresholdRequest):
    STATE["threshold"] = req.threshold
    return {"ok": True, "threshold": req.threshold}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
