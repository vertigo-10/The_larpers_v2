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
import csv
import math
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import mitigation
from .config import settings
from .db import SessionLocal
from .ml.infer import get_detector
from .models import (
    Anomaly, AuditLog, Flow, Incident, IncidentStatus, MetricPoint, Node, Org,
    OrgSettings, OrgType,
)

# Correlate flows from one source into a single incident for this long.
INCIDENT_WINDOW = timedelta(minutes=10)

# The model's "benign" class. Everything else is treated as an attack.
BENIGN = "normal"

DEFAULT_NODES_COMPANY = [
    ("EDGE-01", "Core edge router"),
    ("EDGE-02", "Failover edge router"),
    ("DC-LB-01", "Datacenter load balancer"),
    ("VPN-GW", "Remote access gateway"),
    ("API-TIER", "Public API subnet"),
    ("DB-TIER", "Database subnet"),
    ("CDN-POP", "CDN point of presence"),
    ("IOT-SEG", "IoT segment"),
]

# A household does not have datacenter tiers or a VPN gateway — seeding those
# would misrepresent what a consumer profile is actually watching. This is
# also the set a real deployment starts from: the collector agent posts flows
# tagged with whatever node name you give it, and any name that does not
# already exist here is added automatically (see `_ensure_node` below).
DEFAULT_NODES_CONSUMER = [
    ("HOME-ROUTER", "Your router — the edge of your home network"),
    ("IOT-DEVICES", "Smart home and IoT devices"),
    ("PERSONAL-DEVICES", "Laptops, phones and tablets"),
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
class CICIDSReplay:
    """Cycles through CIC-IDS2017 CSV rows as the simulator source.

    Replaces the random FlowGenerator when SENTRY_CICIDS_DATA_DIR points at a
    directory of CIC-IDS2017 CSVs. Every tick returns the next N rows from the
    dataset in order, looping back to the start when exhausted — so the demo
    runs indefinitely without needing a live network.

    The `phase` attribute mirrors FlowGenerator's contract so the engine_loop
    broadcast is unchanged: 0 = last row was BENIGN, 1 = elevated,
    2 = active attack. The frontend ignores it, but keeping the field means
    no changes upstream.

    Column mapping (CIC-IDS2017 → FlowIn):
        Flow Duration   ÷ 1e6      → duration   (microseconds → seconds)
        Total Fwd Packets          → packets
        Total Length of Fwd Packets→ total_bytes
        Destination Port           → dst_port
        Protocol  6→TCP 17→UDP    → protocol
        Label  BENIGN→normal else → truth  (dos_ddos / scan best-effort)
        src_ip synthesised from row index so incidents group realistically
    """

    # Labels we map from CICIDS2017's free-text Label column.
    _DOS_KEYWORDS = ("dos", "ddos", "hulk", "goldeneye", "slowloris", "heartbleed",
                     "bot", "infiltration")
    _SCAN_KEYWORDS = ("portscan", "ftp-patator", "ssh-patator", "brute")

    def __init__(self, node_labels: List[str], data_dir: str) -> None:
        self.nodes = node_labels or ["EDGE-01"]
        self.phase = 0
        self._rows: List[Dict] = []
        self._idx = 0
        self._load(Path(data_dir))

    def _load(self, data_dir: Path) -> None:
        csvs = sorted(data_dir.glob("*.csv"))
        if not csvs:
            print(f"[sentry] CICIDSReplay: no CSVs in {data_dir} — falling back to synthetic")
            return
        print(f"[sentry] CICIDSReplay: loading {len(csvs)} CSV(s) from {data_dir}")
        rows: List[Dict] = []
        for path in csvs:
            try:
                with open(path, newline="", encoding="utf-8-sig") as fh:
                    for row in csv.DictReader(fh):
                        rows.append({k.strip(): v.strip() for k, v in row.items()})
            except Exception as exc:
                print(f"[sentry] CICIDSReplay: skipping {path.name}: {exc}")
        random.shuffle(rows)          # mix files so attacks don't arrive in a block
        self._rows = rows
        print(f"[sentry] CICIDSReplay: {len(rows):,} rows loaded")

    @staticmethod
    def _map_label(raw: str) -> str:
        l = raw.lower()
        if l == "benign":
            return "normal"
        for kw in CICIDSReplay._DOS_KEYWORDS:
            if kw in l:
                return "dos_ddos"
        return "scan"

    @staticmethod
    def _map_protocol(raw: str) -> str:
        try:
            n = int(raw)
            return "TCP" if n == 6 else ("UDP" if n == 17 else "TCP")
        except (ValueError, TypeError):
            r = str(raw).upper()
            return r if r in ("TCP", "UDP", "ICMP") else "TCP"

    @staticmethod
    def _safe_float(val: str, default: float = 0.0) -> float:
        try:
            v = float(val)
            return default if (v != v or v == float("inf") or v == float("-inf")) else max(v, 0.0)
        except (ValueError, TypeError):
            return default

    def _row_to_flow(self, row: Dict, seq: int) -> Dict:
        """Convert one CIC-IDS2017 CSV row to the FlowGenerator output shape."""
        # Duration is stored in microseconds in CIC-IDS2017.
        dur_us = self._safe_float(row.get("Flow Duration", "0"))
        duration = max(dur_us / 1_000_000.0, 1e-4)

        packets = max(int(self._safe_float(row.get("Total Fwd Packets", "1"))), 1)
        total_bytes = self._safe_float(row.get("Total Length of Fwd Packets", "0"))
        dst_port = int(self._safe_float(row.get("Destination Port", "80"))) % 65536
        protocol = self._map_protocol(row.get("Protocol", "6"))

        label_raw = row.get("Label", "BENIGN")
        truth = self._map_label(label_raw)

        # Synthesise a stable src_ip from the row index so flows from the same
        # "attacker" in the dataset group into the same incident. Using the
        # real Source IP column from CICIDS2017 would be ideal but that column
        # is absent from the Kaggle version of the dataset.
        bucket = seq % 254
        src_ip = f"10.0.{bucket // 20}.{(bucket % 20) + 1}"
        if truth == "normal":
            # Benign traffic comes from varied internal addresses.
            src_ip = f"192.168.{random.randint(0, 3)}.{random.randint(1, 254)}"

        node = random.choice(self.nodes)

        return {
            "flow_ref": f"CIC-{seq}",
            "src_ip": src_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "node": node,
            "duration": round(duration, 4),
            "packets": packets,
            "total_bytes": round(total_bytes, 1),
            "truth": truth,
        }

    def tick(self, n: int = 1) -> List[Dict]:
        """Return next N rows, cycling back to start when exhausted."""
        if not self._rows:
            # No data loaded — generate one synthetic placeholder so the
            # dashboard doesn't go blank and the operator knows to check the
            # data directory.
            return [{
                "flow_ref": f"SYN-{random.randint(10000,99999)}",
                "src_ip": "0.0.0.0",
                "dst_port": 80,
                "protocol": "TCP",
                "node": self.nodes[0] if self.nodes else "EDGE-01",
                "duration": 1.0,
                "packets": 1,
                "total_bytes": 64.0,
                "truth": "normal",
            }]

        out = []
        for _ in range(n):
            row = self._rows[self._idx % len(self._rows)]
            flow = self._row_to_flow(row, self._idx)
            out.append(flow)
            self._idx += 1

        # Update phase for the broadcast (0=quiet 1=elevated 2=attack).
        truths = {f["truth"] for f in out}
        if "dos_ddos" in truths:
            self.phase = 2
        elif "scan" in truths:
            self.phase = 1
        else:
            self.phase = 0

        return out


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
# Defined in severity.py so mitigation.py can use it too — it is called from
# this module, so it cannot import from it. Re-exported here because api.py and
# the tests have always imported the name from `engine`.
from .severity import _SEVERITY_RANK, severity_for  # noqa: E402,F401


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
    window_minutes = (
        org_settings.repeat_offender_window_minutes if org_settings else 60
    )

    results = detector.predict_batch(raw_flows)
    now = datetime.now(timezone.utc)
    out: List[Dict] = []

    # Only real traffic can name a node the org has not seen before — the
    # simulator's flows always carry one of the pre-seeded demo labels, so
    # skipping it there avoids a redundant existence check on every tick.
    seen_nodes: Set[str] = set()

    for raw, (label, confidence, _probs) in zip(raw_flows, results):
        duration = max(float(raw.get("duration", 0.0)), 1e-3)
        total_bytes = float(raw.get("total_bytes") or 0.0)
        if not total_bytes and raw.get("bytes_per_sec"):
            total_bytes = float(raw["bytes_per_sec"]) * duration
        bps = total_bytes / duration

        is_attack = label != BENIGN
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
            # Set below, once the incident exists. The tier depends on how many
            # flows the incident has and how often this source has offended
            # lately, neither of which is knowable from the flow alone.
            mitigated=False,
            source=source,
            truth=raw.get("truth"),
        )
        db.add(flow)

        if source == "live" and flow.node not in seen_nodes:
            seen_nodes.add(flow.node)
            _ensure_node(db, org_id, flow.node)

        # Computed for every flow, not just attacks, so the payload shape is
        # uniform — a benign flow is simply "low". The browser filters
        # notifications against the org's min_severity using this field.
        sev = severity_for(label, confidence, bps)

        mitigated = False
        if is_attack:
            incident = _correlate_incident(db, org_id, flow, confidence, bps, now, sev)
            # Decided against the incident's running flow count, not this single
            # flow's, so the sample-size guardrail sees the whole picture: the
            # fifth flow of a flood should not be judged as if it were the only
            # evidence there is.
            decision = mitigation.decide(
                db, org_id, flow.src_ip, label, confidence, bps,
                incident.flow_count,
                is_attack=True,
                auto_mitigate=auto_mitigate,
                threshold=threshold,
                window_minutes=window_minutes,
                now=now,
            )
            mitigated = decision.mitigated
            flow.mitigated = mitigated
            if mitigation.apply_to_incident(incident, decision):
                # Logged only when the tier actually moved. Every flow of a
                # flood carries the same verdict, so writing on each one would
                # bury the escalation that matters under thousands of identical
                # lines in the one place an operator goes to reconstruct events.
                db.add(AuditLog(
                    org_id=org_id, user_id=None, user_label="SENTRY",
                    action=f"mitigation.{decision.tier}",
                    detail=(
                        f"Incident #{incident.id} ({label} from {flow.src_ip}) "
                        f"→ {decision.tier}"
                        + (f", {decision.rate_limit_rps} rps" if decision.rate_limit_rps else "")
                        + f". {decision.reason} Recorded only; not enforced."
                    ),
                ))

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
            "severity": sev,
            "mitigated": mitigated,
            "source": source,
        })

    db.commit()
    return out


def _correlate_incident(
    db: Session,
    org_id: int,
    flow: Flow,
    confidence: float,
    bps: float,
    now: datetime,
    sev: str,
) -> Incident:
    """Attach the flow to an open incident from the same source, or open one.

    `sev` is computed by the caller rather than here because the flow payload
    sent to the browser needs the same value; passing it in keeps the incident
    severity and the severity the UI sees from drifting apart.

    Returns the incident so the caller can pick a mitigation tier against its
    running flow count. It no longer decides `mitigated` itself: that now
    depends on the incident's own history, which is only knowable once the row
    exists.
    """
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
            mitigated=False,
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

    flow.incident_id = incident.id
    return incident


# ── org bootstrap ─────────────────────────────────────────────────────────
def ensure_org_defaults(db: Session, org_id: int, org_type: str = OrgType.company.value) -> None:
    if db.get(OrgSettings, org_id) is None:
        db.add(OrgSettings(org_id=org_id, threshold=settings.default_threshold))
    existing = db.execute(
        select(func.count(Node.id)).where(Node.org_id == org_id)
    ).scalar_one()
    if not existing:
        nodes = DEFAULT_NODES_CONSUMER if org_type == OrgType.consumer.value else DEFAULT_NODES_COMPANY
        for label, desc in nodes:
            db.add(Node(org_id=org_id, label=label, description=desc,
                        mbps=random.uniform(120, 520)))
    db.commit()


def _ensure_node(db: Session, org_id: int, label: str) -> None:
    """Register a node the first time a flow names it.

    A real collector is pointed at whatever it is watching and tags its flows
    with `--node <name>`, which will not match any of the demo nodes seeded at
    signup. Without this, that traffic is scored and stored correctly but the
    Nodes page — which only lists rows from the `nodes` table — never shows
    it, so a real deployment looks empty even while it is working. This is
    also why the empty-state copy on that page already promises "nodes appear
    as flows arrive that name them": that was the intended behavior, just not
    wired up.
    """
    if not label or label == "unknown":
        return
    exists = db.execute(
        select(Node.id).where(Node.org_id == org_id, Node.label == label)
    ).scalar_one_or_none()
    if exists is not None:
        return
    # Two collectors can both introduce the same brand-new label within the
    # same few hundred milliseconds, and the (org_id, label) unique
    # constraint would then reject the second insert at commit time and take
    # the whole ingest batch down with it. A savepoint scopes that failure to
    # just this one row: lose the race, and the label is already there.
    try:
        with db.begin_nested():
            db.add(Node(org_id=org_id, label=label,
                        description="Detected from live traffic", mbps=0.0))
    except IntegrityError:
        pass


# ── background loop ───────────────────────────────────────────────────────
# Key is org_id. Value is either CICIDSReplay or FlowGenerator, both expose
# the same .tick(n) → List[Dict] and .phase int interface.
_generators: Dict[int, object] = {}
_stop = asyncio.Event()


def _generator_for(db: Session, org_id: int) -> object:
    """Return the right generator for this org.

    Picks CICIDSReplay when SENTRY_CICIDS_DATA_DIR points at a directory that
    contains at least one *.csv file; falls back to the synthetic FlowGenerator
    otherwise. The fallback keeps development and CI working without needing the
    dataset downloaded.
    """
    if org_id not in _generators:
        labels = list(
            db.execute(select(Node.label).where(Node.org_id == org_id)).scalars()
        )
        data_dir = getattr(settings, "cicids_data_dir", None)
        if data_dir and Path(data_dir).is_dir() and list(Path(data_dir).glob("*.csv")):
            _generators[org_id] = CICIDSReplay(labels, data_dir)
        else:
            if data_dir:
                print(
                    f"[sentry] SENTRY_CICIDS_DATA_DIR={data_dir!r} set but no CSVs "
                    f"found — using synthetic generator. Drop CIC-IDS2017 CSVs there."
                )
            _generators[org_id] = FlowGenerator(labels)
    return _generators[org_id]


def _trim_table(db: Session, model, org_id: int, keep: int) -> int:
    """Drop the oldest rows of one table for one org beyond `keep`.

    Deletes by explicit id list rather than a correlated subquery because
    MySQL cannot delete from a table it is selecting from in the same
    statement, and the id list is bounded by `excess` anyway.
    """
    if keep <= 0:
        return 0
    total = db.execute(
        select(func.count(model.id)).where(model.org_id == org_id)
    ).scalar_one()
    excess = total - keep
    if excess <= 0:
        return 0
    old_ids = db.execute(
        select(model.id).where(model.org_id == org_id)
        .order_by(model.ts.asc()).limit(excess)
    ).scalars().all()
    if not old_ids:
        return 0
    db.execute(delete(model).where(model.id.in_(old_ids)))
    return len(old_ids)


def _trim(db: Session, org_id: int) -> None:
    """Keep the append-only tables bounded. Incidents are the durable record.

    This used to cover flows only, and only ran inside the simulator branch of
    the engine loop — so the one deployment that actually needed it, a real one
    with the simulator off and a live collector feeding it, never trimmed
    anything at all. Metric points, anomalies and audit entries were never
    trimmed in any mode. All four are append-only and written on a timer, so
    the failure mode was a disk that filled silently.
    """
    removed = 0
    removed += _trim_table(db, Flow, org_id, settings.retain_flows)
    removed += _trim_table(db, MetricPoint, org_id, settings.retain_metrics)
    removed += _trim_table(db, Anomaly, org_id, settings.retain_anomalies)
    removed += _trim_table(db, AuditLog, org_id, settings.retain_audit)
    if removed:
        db.commit()


def retention_pass() -> int:
    """Trim every org once. Returns the number of orgs processed."""
    db = SessionLocal()
    try:
        org_ids = list(db.execute(select(Org.id)).scalars())
        for org_id in org_ids:
            _trim(db, org_id)
        return len(org_ids)
    finally:
        db.close()


async def retention_loop() -> None:
    """Retention runs on its own clock, independent of the simulator.

    Deliberately not folded back into engine_loop: that loop only does work
    when the simulator is enabled, and retention is needed precisely when it
    is not.

    Ban expiry rides along here for exactly the same reason. It is tempting to
    put it in the engine tick, but a real deployment runs with the simulator
    off — so a "24h ban" would sit there forever on the one configuration that
    matters, and only expire correctly in demos.
    """
    interval = max(settings.retention_interval_s, 10)
    while not _stop.is_set():
        try:
            await asyncio.wait_for(_stop.wait(), timeout=interval)
            return  # stop requested
        except asyncio.TimeoutError:
            pass
        try:
            retention_pass()
        except Exception as exc:  # noqa: BLE001 - never let the loop die silently
            print(f"[sentry] retention pass failed: {exc}")
        # Separate try: a retention failure must not stop bans from lapsing,
        # and a sweep failure must not stop the trim. They share a clock, not
        # a fate.
        try:
            expiry_pass()
        except Exception as exc:  # noqa: BLE001 - never let the loop die silently
            print(f"[sentry] ban expiry sweep failed: {exc}")


def expiry_pass() -> int:
    """Retire every ban whose duration has elapsed. Returns how many."""
    db = SessionLocal()
    try:
        return mitigation.sweep_expired(db)
    finally:
        db.close()


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

                        point = record_metric_point(db, org_id, scored)
                        db.commit()

                        for f in scored:
                            await manager.broadcast(org_id, {"type": "flow", "data": f})
                        await manager.broadcast(org_id, {
                            "type": "metric",
                            "data": {
                                "ts": int(time.time() * 1000),
                                "throughput": point["throughput"],
                                "threat": point["threat"],
                                "phase": gen.phase,
                            },
                        })

                        tick += 1
                finally:
                    db.close()
        except Exception as exc:  # noqa: BLE001 - never let the loop die silently
            print(f"[sentry] engine tick failed: {exc}")

        try:
            await asyncio.wait_for(_stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


def threat_score(scored: List[Dict]) -> float:
    """0–100 threat level for a batch, weighted by confidence.

    A batch with no detections scores exactly zero. It used to return
    random.uniform(1.0, 8.0), which put a permanent flickering floor under the
    headline number on an idle network — the same failure as the mock-data
    fallback this project already removed: inventing signal where there is
    none. An operator needs "quiet" to look unmistakably different from "low
    but real", and a jittering 1-to-8 makes that impossible.
    """
    if not scored:
        return 0.0
    attack = [f for f in scored if f["prediction"] != BENIGN]
    if not attack:
        return 0.0
    ratio = len(attack) / len(scored)
    mean_conf = sum(f["confidence"] for f in attack) / len(attack)
    return min(100.0, 100.0 * ratio * mean_conf * (1.0 + 0.15 * math.log1p(len(attack))))


def record_metric_point(db: Session, org_id: int, scored: List[Dict]) -> Dict:
    """Persist one throughput/threat sample for a scored batch.

    Shared by the simulator loop and the live /api/ingest path. Previously only
    the simulator wrote MetricPoint rows, so a real deployment fed by a
    collector agent scored and stored flows correctly but left the throughput
    and threat charts permanently empty — the graphs worked in the demo and
    nowhere else. Same shape of bug as retention living inside the simulator
    branch.

    Does not commit; the caller owns the transaction.
    """
    if not scored:
        return {"throughput": 0.0, "threat": 0.0, "flows": 0}

    threat = threat_score(scored)
    throughput = sum(f["bytes_per_sec"] for f in scored) * 8 / 1e6  # Mb/s
    point = {
        "throughput": round(throughput, 2),
        "threat": round(threat, 1),
        "flows": len(scored),
    }
    db.add(MetricPoint(org_id=org_id, **point))
    return point


def stop_engine() -> None:
    _stop.set()
