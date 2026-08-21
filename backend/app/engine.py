"""Detection engine: flow intake → real model inference → persistence → live push.

Two intake paths converge on `process_flows`:

  1. POST /api/ingest — real flows from a collector. This is the production path.
  2. The simulator     — synthetic flows, used for demos and when no collector
                         exists yet.

Crucially the simulator only invents *traffic characteristics*. It never invents
a verdict: every flow, simulated or real, is scored by the trained PyTorch model.
For simulated flows we also record what behaviour the generator intended, so the
Model page can display a genuine live agreement rate instead of a marketing
number.
"""

import asyncio
import math
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal
from .ml.infer import get_detector
from .models import Flow, Incident, IncidentStatus, MetricPoint, Node, Org, OrgSettings

# Correlate flows from one source into a single incident for this long.
INCIDENT_WINDOW = timedelta(minutes=10)

# The model's "benign" class. Everything else is treated as an attack.
BENIGN = "normal"

DEFAULT_NODES = [
    ("EDGE-01", "Core edge router"),
    ("EDGE-02", "Failover edge router"),
    ("DC-LB-01", "Datacenter load balancer"),
    ("VPN-GW", "Remote access gateway"),
    ("API-TIER", "Public API subnet"),
    ("DB-TIER", "Database subnet"),
    ("CDN-POP", "CDN point of presence"),
    ("IOT-SEG", "IoT segment"),
]


# ── live push ─────────────────────────────────────────────────────────────
class ConnectionManager:
    """Per-organisation websocket fan-out."""

    def __init__(self) -> None:
        self._conns: Dict[int, Set] = {}
        self._lock = asyncio.Lock()

    async def connect(self, org_id: int, ws) -> None:
        await ws.accept()
        async with self._lock:
            self._conns.setdefault(org_id, set()).add(ws)

    async def disconnect(self, org_id: int, ws) -> None:
        async with self._lock:
            self._conns.get(org_id, set()).discard(ws)

    async def broadcast(self, org_id: int, message: dict) -> None:
        async with self._lock:
            targets = list(self._conns.get(org_id, set()))
        dead = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001 - client vanished mid-send
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._conns.get(org_id, set()).discard(ws)

    def count(self, org_id: int) -> int:
        return len(self._conns.get(org_id, set()))


manager = ConnectionManager()


# ── synthetic traffic generator ───────────────────────────────────────────
class FlowGenerator:
    """Produces plausible flow characteristics with an attack-phase state machine.

    Phase 0 = quiet, 1 = elevated, 2 = active attack. The phase shifts the
    probability of generating attack-shaped traffic, which makes the dashboard
    tell a coherent story rather than flickering randomly.
    """

    def __init__(self, node_labels: List[str]) -> None:
        self.nodes = node_labels or ["EDGE-01"]
        self.phase = 0
        self.ticks = 0
        self.seq = random.randint(4000, 9000)

    def _advance(self) -> None:
        if self.ticks > 0:
            self.ticks -= 1
            if self.ticks == 0:
                self.phase = 0
        elif random.random() < 0.05:
            self.phase = 1 if random.random() < 0.6 else 2
            self.ticks = random.randint(8, 22)

    @staticmethod
    def _ip(internal: bool = False) -> str:
        if internal:
            return f"10.{random.randint(0,3)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return ".".join([
            str(random.randint(11, 223)), str(random.randint(0, 255)),
            str(random.randint(0, 255)), str(random.randint(1, 254)),
        ])

    def next_flow(self) -> Dict:
        """One flow. `truth` is the generator's intent, not a model output."""
        p_attack = {0: 0.06, 1: 0.42, 2: 0.72}[self.phase]
        roll = random.random()

        if roll < p_attack:
            truth = "dos_ddos" if random.random() < 0.72 else "scan"
        else:
            truth = "normal"

        if truth == "dos_ddos":
            duration = random.uniform(0.01, 2.0)
            packets = random.randint(3000, 50000)
            total_bytes = packets * random.uniform(40, 80)
            port = random.choice([80, 80, 443, 8080, 53])
            proto = "UDP" if random.random() < 0.3 else "TCP"
        elif truth == "scan":
            duration = random.uniform(0.001, 0.2)
            packets = random.randint(1, 5)
            total_bytes = packets * random.uniform(40, 80)
            port = random.randint(1, 65535)
            proto = "TCP"
        else:
            duration = random.uniform(0.5, 60.0)
            packets = random.randint(10, 500)
            total_bytes = packets * random.uniform(300, 1200)
            port = random.choice([443, 443, 443, 80, 22, 3306, 8443, 5432, 53])
            proto = "TCP" if random.random() < 0.86 else "UDP"

        self.seq += 1
        return {
            "flow_ref": f"FLW-{self.seq}",
            "src_ip": self._ip(internal=truth == "normal" and random.random() < 0.35),
            "dst_port": port,
            "protocol": proto,
            "node": random.choice(self.nodes),
            "duration": round(duration, 4),
            "packets": packets,
            "total_bytes": round(total_bytes, 1),
            "truth": truth,
        }

    def tick(self, n: int = 1) -> List[Dict]:
        self._advance()
        return [self.next_flow() for _ in range(n)]


# ── severity ──────────────────────────────────────────────────────────────
def severity_for(label: str, confidence: float, bps: float) -> str:
    if label == BENIGN:
        return "low"
    if label == "dos_ddos":
        if confidence >= 0.95 and bps > 5_000_000:
            return "critical"
        return "high" if confidence >= 0.9 else "medium"
    # scan
    return "medium" if confidence >= 0.9 else "low"


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# ── core processing ───────────────────────────────────────────────────────
def process_flows(
    db: Session,
    org_id: int,
    raw_flows: List[Dict],
    source: str,
    org_settings: Optional[OrgSettings] = None,
) -> List[Dict]:
    """Score, persist and correlate a batch of flows. Returns UI-shaped dicts."""
    if not raw_flows:
        return []

    detector = get_detector()
    if not detector.ready:
        raise RuntimeError(detector.error or "model unavailable")

    if org_settings is None:
        org_settings = db.get(OrgSettings, org_id)
    threshold = org_settings.threshold if org_settings else settings.default_threshold
    auto_mitigate = org_settings.auto_mitigate if org_settings else True

    results = detector.predict_batch(raw_flows)
    now = datetime.now(timezone.utc)
    out: List[Dict] = []

    for raw, (label, confidence, _probs) in zip(raw_flows, results):
        duration = max(float(raw.get("duration", 0.0)), 1e-3)
        total_bytes = float(raw.get("total_bytes") or 0.0)
        if not total_bytes and raw.get("bytes_per_sec"):
            total_bytes = float(raw["bytes_per_sec"]) * duration
        bps = total_bytes / duration

        is_attack = label != BENIGN
        mitigated = bool(is_attack and auto_mitigate and confidence >= threshold)
        ts = raw.get("ts") or now
        if isinstance(ts, (int, float)):
            ts = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)

        flow = Flow(
            org_id=org_id,
            flow_ref=raw.get("flow_ref") or f"FLW-{random.randint(100000, 999999)}",
            ts=ts,
            src_ip=raw.get("src_ip", "0.0.0.0"),
            dst_port=int(raw.get("dst_port", 0)),
            protocol=raw.get("protocol", "TCP"),
            node=raw.get("node", "unknown"),
            duration=duration,
            packets=int(raw.get("packets", 0)),
            total_bytes=total_bytes,
            bytes_per_sec=bps,
            prediction=label,
            confidence=confidence,
            mitigated=mitigated,
            source=source,
            truth=raw.get("truth"),
        )
        db.add(flow)

        if is_attack:
            _correlate_incident(db, org_id, flow, confidence, bps, now)

        out.append({
            "id": flow.flow_ref,
            "ts": int(ts.timestamp() * 1000),
            "src_ip": flow.src_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "node": flow.node,
            "duration": flow.duration,
            "packets": flow.packets,
            "bytes_per_sec": round(bps, 1),
            "prediction": label,
            "confidence": round(confidence, 4),
            "mitigated": mitigated,
            "source": source,
        })

    db.commit()
    return out


def _correlate_incident(
    db: Session, org_id: int, flow: Flow, confidence: float, bps: float, now: datetime
) -> None:
    """Attach the flow to an open incident from the same source, or open one."""
    cutoff = now - INCIDENT_WINDOW
    stmt = (
        select(Incident)
        .where(
            Incident.org_id == org_id,
            Incident.src_ip == flow.src_ip,
            Incident.label == flow.prediction,
            Incident.status != IncidentStatus.resolved.value,
            Incident.last_seen_at >= cutoff,
        )
        .order_by(Incident.last_seen_at.desc())
        .limit(1)
    )
    incident = db.execute(stmt).scalar_one_or_none()
    sev = severity_for(flow.prediction, confidence, bps)

    if incident is None:
        incident = Incident(
            org_id=org_id,
            src_ip=flow.src_ip,
            label=flow.prediction,
            node=flow.node,
            opened_at=now,
            last_seen_at=now,
            flow_count=1,
            peak_confidence=confidence,
            peak_bps=bps,
            severity=sev,
            status=IncidentStatus.open.value,
            mitigated=flow.mitigated,
        )
        db.add(incident)
        db.flush()
    else:
        incident.flow_count += 1
        incident.last_seen_at = now
        incident.peak_confidence = max(incident.peak_confidence, confidence)
        incident.peak_bps = max(incident.peak_bps, bps)
        if _SEVERITY_RANK[sev] > _SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = sev
        if flow.mitigated:
            incident.mitigated = True

    flow.incident_id = incident.id


# ── org bootstrap ─────────────────────────────────────────────────────────
def ensure_org_defaults(db: Session, org_id: int) -> None:
    if db.get(OrgSettings, org_id) is None:
        db.add(OrgSettings(org_id=org_id, threshold=settings.default_threshold))
    existing = db.execute(
        select(func.count(Node.id)).where(Node.org_id == org_id)
    ).scalar_one()
    if not existing:
        for label, desc in DEFAULT_NODES:
            db.add(Node(org_id=org_id, label=label, description=desc,
                        mbps=random.uniform(120, 520)))
    db.commit()


# ── background loop ───────────────────────────────────────────────────────
_generators: Dict[int, FlowGenerator] = {}
_stop = asyncio.Event()


def _generator_for(db: Session, org_id: int) -> FlowGenerator:
    if org_id not in _generators:
        labels = list(
            db.execute(select(Node.label).where(Node.org_id == org_id)).scalars()
        )
        _generators[org_id] = FlowGenerator(labels)
    return _generators[org_id]


def _trim(db: Session, org_id: int) -> None:
    """Keep the flow table bounded. Incidents are the durable record."""
    total = db.execute(
        select(func.count(Flow.id)).where(Flow.org_id == org_id)
    ).scalar_one()
    excess = total - settings.retain_flows
    if excess <= 0:
        return
    old_ids = db.execute(
        select(Flow.id).where(Flow.org_id == org_id)
        .order_by(Flow.ts.asc()).limit(excess)
    ).scalars().all()
    if old_ids:
        db.execute(delete(Flow).where(Flow.id.in_(old_ids)))
        db.commit()


async def engine_loop() -> None:
    """Generate → score → persist → broadcast, once per interval, per org."""
    interval = max(settings.simulator_interval_ms, 200) / 1000.0
    tick = 0

    while not _stop.is_set():
        try:
            if settings.simulator_enabled:
                db = SessionLocal()
                try:
                    org_ids = list(db.execute(select(Org.id)).scalars())
                    for org_id in org_ids:
                        gen = _generator_for(db, org_id)
                        batch = gen.tick(n=random.randint(1, 3))
                        scored = process_flows(db, org_id, batch, "simulated")

                        threat = _threat_score(scored)
                        throughput = sum(f["bytes_per_sec"] for f in scored) * 8 / 1e6
                        db.add(MetricPoint(
                            org_id=org_id,
                            throughput=round(throughput, 2),
                            threat=round(threat, 1),
                            flows=len(scored),
                        ))
                        db.commit()

                        for f in scored:
                            await manager.broadcast(org_id, {"type": "flow", "data": f})
                        await manager.broadcast(org_id, {
                            "type": "metric",
                            "data": {
                                "ts": int(time.time() * 1000),
                                "throughput": round(throughput, 2),
                                "threat": round(threat, 1),
                                "phase": gen.phase,
                            },
                        })

                        tick += 1
                        if tick % 200 == 0:
                            _trim(db, org_id)
                finally:
                    db.close()
        except Exception as exc:  # noqa: BLE001 - never let the loop die silently
            print(f"[sentry] engine tick failed: {exc}")

        try:
            await asyncio.wait_for(_stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


def _threat_score(scored: List[Dict]) -> float:
    """0–100 threat level for a batch, weighted by confidence."""
    if not scored:
        return 0.0
    attack = [f for f in scored if f["prediction"] != BENIGN]
    if not attack:
        return random.uniform(1.0, 8.0)
    ratio = len(attack) / len(scored)
    mean_conf = sum(f["confidence"] for f in attack) / len(attack)
    return min(100.0, 100.0 * ratio * mean_conf * (1.0 + 0.15 * math.log1p(len(attack))))


def stop_engine() -> None:
    _stop.set()
