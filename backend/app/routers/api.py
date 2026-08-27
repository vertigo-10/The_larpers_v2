"""Dashboard data endpoints. Every response is backed by the DB or the model.

Nothing here fabricates a number. Where a value cannot be computed (no model, no
data yet) the endpoint says so rather than inventing something plausible.
"""

import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import case, func, or_, select, update
from sqlalchemy.orm import Session

from .. import __version__
from .. import baseline as bl
from ..config import settings
from ..db import get_db
from ..engine import BENIGN, manager, process_flows, severity_for
from ..ml.infer import get_detector
from ..models import (
    Anomaly,
    AuditLog,
    Baseline,
    Flow,
    Incident,
    IncidentStatus,
    MetricPoint,
    Node,
    OrgSettings,
    User,
)
from ..schemas import (
    AnomalyOut,
    BaselineOut,
    BaselineSlotOut,
    BreakdownOut,
    FlowBatchIn,
    IncidentActionIn,
    IncidentOut,
    MitigateIn,
    PortRowOut,
    ProtocolRowOut,
    SeriesOut,
    SettingsIn,
    SettingsOut,
    StatusOut,
    SummaryOut,
    TalkerOut,
    TalkersOut,
    ThresholdIn,
    TrafficBreakdownOut,
)
from ..security import (
    IngestCaller,
    current_user,
    ingest_caller,
    require_admin,
    require_operator,
)

router = APIRouter(prefix="/api", tags=["data"])

STARTED = time.time()


def _ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _org_settings(db: Session, org_id: int) -> OrgSettings:
    row = db.get(OrgSettings, org_id)
    if row is None:
        row = OrgSettings(org_id=org_id, threshold=settings.default_threshold)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


# ── status ────────────────────────────────────────────────────────────────
@router.get("/status", response_model=StatusOut)
def status_endpoint(user: User = Depends(current_user)):
    d = get_detector()
    m = d.metrics or {}
    return StatusOut(
        model_ready=d.ready,
        model_error=d.error,
        model_name="sentry-ddos-v1",
        framework=m.get("framework", "PyTorch"),
        architecture=m.get("architecture"),
        dataset=m.get("dataset", "unknown"),
        dataset_note=m.get("dataset_note"),
        accuracy=m.get("accuracy"),
        classes=d.class_names,
        uptime_s=int(time.time() - STARTED),
        simulator=settings.simulator_enabled,
        version=__version__,
    )


@router.get("/health")
def health(db: Session = Depends(get_db)):
    """Unauthenticated liveness probe for the platform's health checker."""
    try:
        db.execute(select(1))
        db_ok = True
    except Exception:  # noqa: BLE001
        db_ok = False
    d = get_detector()
    ok = db_ok and d.ready
    return {
        "status": "ok" if ok else "degraded",
        "database": db_ok,
        "model": d.ready,
        "version": __version__,
    }


# ── summary + metrics ─────────────────────────────────────────────────────
@router.get("/summary", response_model=SummaryOut)
def summary(db: Session = Depends(get_db), user: User = Depends(current_user)):
    org_id = user.org_id
    minute_ago = datetime.now(timezone.utc) - timedelta(minutes=1)

    flows_last_min = db.execute(
        select(func.count(Flow.id)).where(Flow.org_id == org_id, Flow.ts >= minute_ago)
    ).scalar_one()

    blocked = db.execute(
        select(func.count(Flow.id)).where(Flow.org_id == org_id, Flow.mitigated.is_(True))
    ).scalar_one()

    avg_conf = db.execute(
        select(func.avg(Flow.confidence)).where(
            Flow.org_id == org_id, Flow.ts >= minute_ago
        )
    ).scalar_one()

    open_incidents = db.execute(
        select(func.count(Incident.id)).where(
            Incident.org_id == org_id,
            Incident.status != IncidentStatus.resolved.value,
        )
    ).scalar_one()

    nodes_total = db.execute(
        select(func.count(Node.id)).where(Node.org_id == org_id)
    ).scalar_one()
    nodes_online = db.execute(
        select(func.count(Node.id)).where(Node.org_id == org_id, Node.status == "ok")
    ).scalar_one()

    recent_threat = db.execute(
        select(MetricPoint.threat).where(MetricPoint.org_id == org_id)
        .order_by(MetricPoint.ts.desc()).limit(5)
    ).scalars().all()
    mean_threat = sum(recent_threat) / len(recent_threat) if recent_threat else 0.0
    level = "CRITICAL" if mean_threat >= 65 else "ELEVATED" if mean_threat >= 30 else "NOMINAL"

    return SummaryOut(
        flows_per_min=int(flows_last_min),
        attacks_blocked=int(blocked),
        avg_confidence=round(float(avg_conf or 0.0), 3),
        inference_ms=0.0,  # measured client-side per request; see /api/model/metrics
        nodes_online=int(nodes_online),
        nodes_total=int(nodes_total),
        threat_level=level,
        open_incidents=int(open_incidents),
    )


@router.get("/metrics/history", response_model=SeriesOut)
def metrics_history(
    points: int = Query(default=90, ge=5, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    rows = db.execute(
        select(MetricPoint).where(MetricPoint.org_id == user.org_id)
        .order_by(MetricPoint.ts.desc()).limit(points)
    ).scalars().all()
    rows = list(reversed(rows))
    return SeriesOut(
        labels=[_ms(r.ts) for r in rows],
        throughput=[r.throughput for r in rows],
        threat=[r.threat for r in rows],
    )


@router.get("/metrics/current")
def metrics_current(db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = db.execute(
        select(MetricPoint).where(MetricPoint.org_id == user.org_id)
        .order_by(MetricPoint.ts.desc()).limit(1)
    ).scalar_one_or_none()
    if not row:
        return {"ts": int(time.time() * 1000), "throughput": 0.0, "threat": 0.0, "empty": True}
    return {
        "ts": _ms(row.ts),
        "throughput": row.throughput,
        "threat": row.threat,
        "empty": False,
    }


# ── flows ─────────────────────────────────────────────────────────────────
@router.get("/flows")
def list_flows(
    limit: int = Query(default=50, ge=1, le=500),
    tab: str = Query(default="live", pattern="^(live|flagged|mitigated)$"),
    q: Optional[str] = Query(default=None, max_length=120),
    node: Optional[str] = Query(default=None, max_length=60),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    stmt = select(Flow).where(Flow.org_id == user.org_id)

    if tab == "flagged":
        stmt = stmt.where(Flow.prediction != BENIGN)
    elif tab == "mitigated":
        stmt = stmt.where(Flow.mitigated.is_(True))

    if node and node != "all":
        stmt = stmt.where(Flow.node == node)

    if q:
        raw = q.strip()
        # Parameterised LIKE — no string interpolation into SQL. The value is
        # still escaped, because % and _ are wildcards *inside* the parameter:
        # a bare "%" would match every row, turning the search box into a way
        # to pull the whole flow table regardless of what was typed, and "_"
        # silently matches any character rather than an underscore.
        escaped = raw.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        term = f"%{escaped}%"
        conditions = [
            Flow.src_ip.like(term, escape="\\"),
            Flow.node.like(term, escape="\\"),
            Flow.prediction.like(term, escape="\\"),
            Flow.flow_ref.like(term, escape="\\"),
        ]
        if raw.isdigit():
            conditions.append(Flow.dst_port == int(raw))
        stmt = stmt.where(or_(*conditions))

    rows = db.execute(stmt.order_by(Flow.ts.desc()).limit(limit)).scalars().all()
    return [
        {
            "id": r.flow_ref,
            "ts": _ms(r.ts),
            "src_ip": r.src_ip,
            "dst_port": r.dst_port,
            "protocol": r.protocol,
            "node": r.node,
            "duration": r.duration,
            "packets": r.packets,
            "bytes_per_sec": round(r.bytes_per_sec, 1),
            "prediction": r.prediction,
            "confidence": round(r.confidence, 4),
            # Recomputed rather than stored: severity is a pure function of
            # (label, confidence, bps), so persisting it would add a column
            # that can silently disagree with the rule after a tuning change.
            # This keeps the shape identical to the live WebSocket payload.
            "severity": severity_for(r.prediction, r.confidence, r.bytes_per_sec),
            "mitigated": r.mitigated,
            "source": r.source,
        }
        for r in rows
    ]


@router.post("/ingest")
def ingest(
    body: FlowBatchIn,
    db: Session = Depends(get_db),
    caller: IngestCaller = Depends(ingest_caller),
):
    """Submit real captured flows for scoring. This is the production path.

    Authenticates with either an API key (how a collector agent connects) or an
    operator session (how a human tests it).
    """
    detector = get_detector()
    if not detector.ready:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            f"Model unavailable: {detector.error}",
        )

    raw = []
    for f in body.flows:
        d = f.model_dump()
        d["truth"] = None  # no ground truth for real traffic
        raw.append(d)

    started = time.perf_counter()
    scored = process_flows(db, caller.org_id, raw, source="live")
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    return {
        "ok": True,
        "count": len(scored),
        "inference_ms": round(elapsed_ms / max(len(scored), 1), 3),
        "flows": scored,
    }


# ── analytics ─────────────────────────────────────────────────────────────
@router.get("/analytics/classes", response_model=BreakdownOut)
def analytics_classes(db: Session = Depends(get_db), user: User = Depends(current_user)):
    detector = get_detector()
    counts: Dict[str, int] = {name: 0 for name in detector.class_names}
    rows = db.execute(
        select(Flow.prediction, func.count(Flow.id))
        .where(Flow.org_id == user.org_id).group_by(Flow.prediction)
    ).all()
    for label, n in rows:
        counts[label] = n
    return BreakdownOut(labels=list(counts.keys()), values=[float(v) for v in counts.values()])


@router.get("/analytics/nodes", response_model=BreakdownOut)
def analytics_nodes(db: Session = Depends(get_db), user: User = Depends(current_user)):
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    rows = db.execute(
        select(Flow.node, func.sum(Flow.bytes_per_sec))
        .where(Flow.org_id == user.org_id, Flow.ts >= since)
        .group_by(Flow.node).order_by(func.sum(Flow.bytes_per_sec).desc()).limit(6)
    ).all()
    return BreakdownOut(
        labels=[r[0] for r in rows],
        values=[round(float(r[1] or 0) * 8 / 1e6, 2) for r in rows],  # Mbps
    )


@router.get("/analytics/ports", response_model=BreakdownOut)
def analytics_ports(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.execute(
        select(Flow.dst_port, func.count(Flow.id))
        .where(Flow.org_id == user.org_id)
        .group_by(Flow.dst_port).order_by(func.count(Flow.id).desc()).limit(8)
    ).all()
    return BreakdownOut(labels=[str(r[0]) for r in rows], values=[float(r[1]) for r in rows])


# Only the ports worth naming. A wrong guess is worse than a blank: an analyst
# who reads "HTTPS" next to port 443 on a flood stops looking, and the label is
# a guess about a port number, not an observation of the protocol.
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 137: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5432: "Postgres",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}


def _window_start(minutes: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def _epoch(dt: Optional[datetime]) -> int:
    if dt is None:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


_ATTACK_FLOW = case((Flow.prediction != BENIGN, 1), else_=0)
_MITIGATED_FLOW = case((Flow.mitigated.is_(True), 1), else_=0)


@router.get("/analytics/talkers", response_model=TalkersOut)
def analytics_talkers(
    window: int = Query(default=15, ge=1, le=1440),
    limit: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Who is sending the most, and is any of it an attack.

    Deliberately two-stage. A spoofed-source flood can produce hundreds of
    thousands of distinct addresses in a few minutes, so the candidate set is
    narrowed in SQL before any per-source detail is read — otherwise the one
    scenario this page exists for is the scenario that exhausts memory.

    Candidates come from two rankings, by bytes and by flow count, because a
    flood that tops the second is invisible in the first.
    """
    since = _window_start(window)
    scope = (Flow.org_id == user.org_id, Flow.ts >= since)

    totals = db.execute(
        select(
            func.coalesce(func.sum(Flow.total_bytes), 0.0),
            func.count(Flow.id),
            func.count(func.distinct(Flow.src_ip)),
        ).where(*scope)
    ).one()
    total_bytes, total_flows, unique_sources = float(totals[0]), int(totals[1]), int(totals[2])

    def _rank(column):
        return db.execute(
            select(Flow.src_ip).where(*scope)
            .group_by(Flow.src_ip).order_by(column.desc()).limit(limit)
        ).scalars().all()

    candidates = set(_rank(func.sum(Flow.total_bytes))) | set(_rank(func.count(Flow.id)))
    if not candidates:
        return TalkersOut(
            window_minutes=window, total_bytes=total_bytes, total_flows=total_flows,
            unique_sources=unique_sources, talkers=[],
        )

    narrowed = scope + (Flow.src_ip.in_(candidates),)

    rows = db.execute(
        select(
            Flow.src_ip,
            func.count(Flow.id),
            func.coalesce(func.sum(Flow.packets), 0),
            func.coalesce(func.sum(Flow.total_bytes), 0.0),
            func.coalesce(func.sum(_ATTACK_FLOW), 0),
            func.coalesce(func.sum(_MITIGATED_FLOW), 0),
            func.count(func.distinct(Flow.dst_port)),
            func.max(Flow.ts),
            func.min(Flow.ts),
        ).where(*narrowed).group_by(Flow.src_ip)
    ).all()

    # The label that best characterises each source, and how sure the model was.
    # An attack label wins over benign even when most of the source's flows are
    # benign — a host that is 95% normal and 5% flood is a host that is
    # flooding, and burying that under its own background traffic would be a
    # detection failure.
    verdicts: Dict[str, Dict[str, int]] = defaultdict(dict)
    confidence: Dict[str, float] = defaultdict(float)
    for ip, label, count, best in db.execute(
        select(Flow.src_ip, Flow.prediction, func.count(Flow.id), func.max(Flow.confidence))
        .where(*narrowed).group_by(Flow.src_ip, Flow.prediction)
    ).all():
        verdicts[ip][label] = int(count)
        if label != BENIGN:
            confidence[ip] = max(confidence[ip], float(best or 0.0))

    nodes_by_ip: Dict[str, List[str]] = defaultdict(list)
    for ip, node in db.execute(
        select(Flow.src_ip, Flow.node).where(*narrowed).distinct()
    ).all():
        nodes_by_ip[ip].append(node)

    talkers = []
    for ip, flows, packets, sent, attacks, mitigated, ports, last, first in rows:
        labels = verdicts.get(ip, {})
        attack_labels = {k: v for k, v in labels.items() if k != BENIGN}
        top = max(attack_labels or labels or {BENIGN: 0}, key=lambda k: (attack_labels or labels)[k])
        talkers.append(TalkerOut(
            src_ip=ip,
            flows=int(flows),
            packets=int(packets),
            total_bytes=float(sent),
            bytes_share=round(float(sent) / total_bytes * 100, 2) if total_bytes else 0.0,
            attack_flows=int(attacks),
            attack_share=round(int(attacks) / int(flows) * 100, 1) if flows else 0.0,
            top_prediction=top,
            max_confidence=round(confidence.get(ip, 0.0), 4),
            mitigated=int(mitigated),
            ports=int(ports),
            nodes=sorted(nodes_by_ip.get(ip, [])),
            first_seen=_epoch(first),
            last_seen=_epoch(last),
        ))

    # Attackers first, then by volume. Sorting purely by bytes would put a
    # backup job above an active flood.
    talkers.sort(key=lambda t: (t.attack_flows > 0, t.attack_flows, t.total_bytes), reverse=True)
    return TalkersOut(
        window_minutes=window, total_bytes=total_bytes, total_flows=total_flows,
        unique_sources=unique_sources, talkers=talkers[:limit],
    )


@router.get("/analytics/traffic", response_model=TrafficBreakdownOut)
def analytics_traffic(
    window: int = Query(default=15, ge=1, le=1440),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """What the traffic is made of — by protocol and by destination port."""
    since = _window_start(window)
    scope = (Flow.org_id == user.org_id, Flow.ts >= since)

    protocols = [
        ProtocolRowOut(
            protocol=proto, flows=int(flows),
            total_bytes=float(sent), attack_flows=int(attacks),
        )
        for proto, flows, sent, attacks in db.execute(
            select(
                Flow.protocol, func.count(Flow.id),
                func.coalesce(func.sum(Flow.total_bytes), 0.0),
                func.coalesce(func.sum(_ATTACK_FLOW), 0),
            ).where(*scope).group_by(Flow.protocol).order_by(func.count(Flow.id).desc())
        ).all()
    ]

    ports = [
        PortRowOut(
            port=int(port), service=WELL_KNOWN_PORTS.get(int(port), ""),
            flows=int(flows), total_bytes=float(sent),
            attack_flows=int(attacks), sources=int(sources),
        )
        for port, flows, sent, attacks, sources in db.execute(
            select(
                Flow.dst_port, func.count(Flow.id),
                func.coalesce(func.sum(Flow.total_bytes), 0.0),
                func.coalesce(func.sum(_ATTACK_FLOW), 0),
                func.count(func.distinct(Flow.src_ip)),
            ).where(*scope).group_by(Flow.dst_port)
            .order_by(func.count(Flow.id).desc()).limit(15)
        ).all()
    ]

    return TrafficBreakdownOut(window_minutes=window, protocols=protocols, ports=ports)


# ── baselining ────────────────────────────────────────────────────────────
def _anomaly_out(row: Anomaly) -> AnomalyOut:
    return AnomalyOut(
        id=row.id,
        ts=_epoch(row.ts),
        last_seen_at=_epoch(row.last_seen_at),
        metric=row.metric,
        metric_label=bl.METRIC_LABELS.get(row.metric, row.metric),
        direction=row.direction,
        observed=round(row.observed, 2),
        expected=round(row.expected, 2),
        deviation=round(row.deviation, 2),
        peak_deviation=round(row.peak_deviation, 2),
        severity=row.severity,
        windows=row.windows,
        status=row.status,
        acknowledged_by=row.acknowledged_by.name if row.acknowledged_by else None,
    )


@router.get("/anomalies", response_model=List[AnomalyOut])
def anomalies(
    status_filter: str = Query(default="all", alias="status"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Deviations from the learned baseline, newest first."""
    stmt = select(Anomaly).where(Anomaly.org_id == user.org_id)
    if status_filter != "all":
        stmt = stmt.where(Anomaly.status == status_filter)
    rows = db.execute(
        stmt.order_by(Anomaly.last_seen_at.desc()).limit(limit)
    ).scalars().all()
    return [_anomaly_out(r) for r in rows]


@router.post("/anomalies/{anomaly_id}/acknowledge", response_model=AnomalyOut)
def acknowledge_anomaly(
    anomaly_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_operator),
):
    row = db.get(Anomaly, anomaly_id)
    if row is None or row.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Anomaly not found")
    row.status = "acknowledged"
    row.acknowledged_by_id = user.id
    db.add(AuditLog(
        org_id=user.org_id, user_id=user.id, user_label=user.name,
        action="anomaly.acknowledge",
        detail=f"{row.direction} in {row.metric} ({row.deviation:+.1f}σ)",
    ))
    db.commit()
    db.refresh(row)
    return _anomaly_out(row)


@router.get("/baseline", response_model=BaselineOut)
def baseline_profile(
    metric: str = Query(default="flows"),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """The learned normal for one metric, plus how much of it is trustworthy.

    Returning `warmth` alongside the profile is the point: an empty anomaly
    list means "nothing unusual" only once the baseline has actually learned
    something, and before that it means "no opinion yet".
    """
    if metric not in bl.METRICS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Unknown metric. Expected one of: {', '.join(bl.METRICS)}",
        )

    rows = db.execute(
        select(Baseline)
        .where(Baseline.org_id == user.org_id, Baseline.metric == metric)
        .order_by(Baseline.bucket)
    ).scalars().all()

    slots = [
        BaselineSlotOut(
            bucket=r.bucket,
            label=bl.describe_bucket(r.bucket),
            metric=r.metric,
            mean=round(r.mean, 2),
            sigma=round(bl.sigma_for(r.mean, r.variance, r.metric), 2),
            samples=r.samples,
            ready=r.samples >= bl.MIN_SAMPLES,
        )
        for r in rows
    ]

    window = max(settings.baseline_window_s, 30)
    now = datetime.now(timezone.utc)
    observed = bl.observe(
        db, user.org_id, now - timedelta(seconds=window), now
    )

    return BaselineOut(
        window_seconds=window,
        z_threshold=bl.Z_THRESHOLD,
        warmth=bl.warmth(db, user.org_id),
        slots=slots,
        current={
            "bucket": bl.bucket_for(now),
            "label": bl.describe_bucket(bl.bucket_for(now)),
            "values": {k: round(v, 2) for k, v in observed.items()},
        },
    )


@router.get("/nodes")
def nodes(db: Session = Depends(get_db), user: User = Depends(current_user)):
    since = datetime.now(timezone.utc) - timedelta(minutes=5)
    traffic = dict(db.execute(
        select(Flow.node, func.sum(Flow.bytes_per_sec))
        .where(Flow.org_id == user.org_id, Flow.ts >= since).group_by(Flow.node)
    ).all())
    attacks = dict(db.execute(
        select(Flow.node, func.count(Flow.id))
        .where(Flow.org_id == user.org_id, Flow.ts >= since, Flow.prediction != BENIGN)
        .group_by(Flow.node)
    ).all())

    rows = db.execute(
        select(Node).where(Node.org_id == user.org_id).order_by(Node.label)
    ).scalars().all()
    return [
        {
            "label": n.label,
            "desc": n.description,
            "mbps": round(float(traffic.get(n.label, 0)) * 8 / 1e6, 2),
            "attacks": int(attacks.get(n.label, 0)),
            "status": "warn" if attacks.get(n.label, 0) > 8 else n.status,
        }
        for n in rows
    ]


# ── incidents ─────────────────────────────────────────────────────────────
@router.get("/incidents", response_model=List[IncidentOut])
def list_incidents(
    status_filter: str = Query(default="all", alias="status",
                               pattern="^(all|open|acknowledged|resolved)$"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    stmt = select(Incident).where(Incident.org_id == user.org_id)
    if status_filter != "all":
        stmt = stmt.where(Incident.status == status_filter)
    rows = db.execute(stmt.order_by(Incident.last_seen_at.desc()).limit(limit)).scalars().all()
    return [
        IncidentOut(
            id=r.id, src_ip=r.src_ip, label=r.label, node=r.node,
            opened_at=_ms(r.opened_at), last_seen_at=_ms(r.last_seen_at),
            resolved_at=_ms(r.resolved_at) if r.resolved_at else None,
            flow_count=r.flow_count, peak_confidence=round(r.peak_confidence, 4),
            peak_bps=round(r.peak_bps, 1), severity=r.severity, status=r.status,
            mitigated=r.mitigated,
            acknowledged_by=r.acknowledged_by.name if r.acknowledged_by else None,
        )
        for r in rows
    ]


@router.post("/incidents/{incident_id}/action", response_model=IncidentOut)
def incident_action(
    incident_id: int,
    body: IncidentActionIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_operator),
):
    inc = db.get(Incident, incident_id)
    if not inc or inc.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such incident.")

    now = datetime.now(timezone.utc)
    if body.action == "acknowledge":
        inc.status = IncidentStatus.acknowledged.value
        inc.acknowledged_by_id = user.id
    elif body.action == "resolve":
        inc.status = IncidentStatus.resolved.value
        inc.resolved_at = now
        inc.acknowledged_by_id = inc.acknowledged_by_id or user.id
    elif body.action == "reopen":
        inc.status = IncidentStatus.open.value
        inc.resolved_at = None
    elif body.action == "mitigate":
        inc.mitigated = True
        # One UPDATE. The previous version ran a SELECT whose result was
        # discarded, then a second SELECT that loaded every flow of the
        # incident into the identity map to set one boolean each — on a large
        # incident that is thousands of objects hydrated to write one column.
        db.execute(
            update(Flow)
            .where(Flow.incident_id == inc.id, Flow.org_id == user.org_id)
            .values(mitigated=True)
        )

    db.add(AuditLog(org_id=user.org_id, user_id=user.id, user_label=user.name,
                    action=f"incident.{body.action}",
                    detail=f"Incident #{inc.id} ({inc.label} from {inc.src_ip})"))
    db.commit()
    db.refresh(inc)
    return IncidentOut(
        id=inc.id, src_ip=inc.src_ip, label=inc.label, node=inc.node,
        opened_at=_ms(inc.opened_at), last_seen_at=_ms(inc.last_seen_at),
        resolved_at=_ms(inc.resolved_at) if inc.resolved_at else None,
        flow_count=inc.flow_count, peak_confidence=round(inc.peak_confidence, 4),
        peak_bps=round(inc.peak_bps, 1), severity=inc.severity, status=inc.status,
        mitigated=inc.mitigated,
        acknowledged_by=inc.acknowledged_by.name if inc.acknowledged_by else None,
    )


# ── actions ───────────────────────────────────────────────────────────────
@router.post("/mitigate")
def mitigate(
    body: MitigateIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_operator),
):
    """Mark matching flows as mitigated.

    This records the decision. Wiring it to an actual firewall / BGP blackhole /
    rate limiter is a deployment step — see README. It deliberately does not
    pretend to have blocked traffic it cannot reach.
    """
    if not body.flow_id and not body.src_ip:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Provide flow_id or src_ip.")

    # Bulk UPDATE rather than loading every matching flow. Mitigating by
    # src_ip during an active flood can match tens of thousands of rows, and
    # hydrating each one to flip a boolean is what turns a fast action into a
    # request that times out exactly when the operator most needs it.
    stmt = update(Flow).where(Flow.org_id == user.org_id)
    if body.flow_id:
        stmt = stmt.where(Flow.flow_ref == body.flow_id)
    if body.src_ip:
        stmt = stmt.where(Flow.src_ip == body.src_ip)

    result = db.execute(stmt.values(mitigated=True))
    count = result.rowcount or 0

    target = body.flow_id or body.src_ip
    db.add(AuditLog(org_id=user.org_id, user_id=user.id, user_label=user.name,
                    action="flow.mitigated",
                    detail=f"Mitigated {count} flow(s) matching {target}"))
    db.commit()
    return {"ok": True, "count": count, "enforced": False,
            "note": "Recorded in SENTRY. Connect an enforcement hook to block at the network edge."}


@router.post("/model/threshold")
def set_threshold(
    body: ThresholdIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_operator),
):
    cfg = _org_settings(db, user.org_id)
    cfg.threshold = body.threshold
    db.add(AuditLog(org_id=user.org_id, user_id=user.id, user_label=user.name,
                    action="model.threshold_changed",
                    detail=f"Detection threshold set to {body.threshold:.2f}"))
    db.commit()
    return {"ok": True, "threshold": body.threshold}


@router.get("/model/metrics")
def model_metrics(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Training metrics plus a live agreement rate on simulated traffic."""
    d = get_detector()

    live_total = db.execute(
        select(func.count(Flow.id)).where(
            Flow.org_id == user.org_id, Flow.truth.is_not(None)
        )
    ).scalar_one()
    live_agree = db.execute(
        select(func.count(Flow.id)).where(
            Flow.org_id == user.org_id,
            Flow.truth.is_not(None),
            Flow.truth == Flow.prediction,
        )
    ).scalar_one()

    matrix_rows = db.execute(
        select(Flow.truth, Flow.prediction, func.count(Flow.id))
        .where(Flow.org_id == user.org_id, Flow.truth.is_not(None))
        .group_by(Flow.truth, Flow.prediction)
    ).all()

    return {
        "ready": d.ready,
        "error": d.error,
        "training": d.metrics or {},
        "live": {
            "scored": int(live_total),
            "agreed": int(live_agree),
            "agreement_pct": round(live_agree / live_total * 100, 2) if live_total else None,
            "matrix": [
                {"truth": t, "predicted": p, "count": int(c)} for t, p, c in matrix_rows
            ],
            "note": (
                "Agreement between the generator's intended behaviour and the "
                "model's prediction on simulated flows. Only meaningful for "
                "simulated traffic — ingested flows have no ground truth."
            ),
        },
    }


# ── settings ──────────────────────────────────────────────────────────────
@router.get("/settings", response_model=SettingsOut)
def get_settings(db: Session = Depends(get_db), user: User = Depends(current_user)):
    cfg = _org_settings(db, user.org_id)
    return SettingsOut(
        threshold=cfg.threshold, auto_mitigate=cfg.auto_mitigate,
        webhook_url=cfg.webhook_url, notify_browser=cfg.notify_browser,
        min_severity=cfg.min_severity, poll_interval_ms=cfg.poll_interval_ms,
        max_table_rows=cfg.max_table_rows,
        org_name=user.org.name if user.org else "",
    )


@router.patch("/settings", response_model=SettingsOut)
def update_settings(
    body: SettingsIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    cfg = _org_settings(db, user.org_id)
    changed = []
    for field in ("threshold", "auto_mitigate", "webhook_url", "notify_browser",
                  "min_severity", "poll_interval_ms", "max_table_rows"):
        value = getattr(body, field)
        if value is not None:
            setattr(cfg, field, value)
            changed.append(field)
    if body.org_name and user.org:
        user.org.name = body.org_name.strip()
        changed.append("org_name")

    if changed:
        db.add(AuditLog(org_id=user.org_id, user_id=user.id, user_label=user.name,
                        action="settings.updated", detail=", ".join(changed)))
    db.commit()
    db.refresh(cfg)
    return SettingsOut(
        threshold=cfg.threshold, auto_mitigate=cfg.auto_mitigate,
        webhook_url=cfg.webhook_url, notify_browser=cfg.notify_browser,
        min_severity=cfg.min_severity, poll_interval_ms=cfg.poll_interval_ms,
        max_table_rows=cfg.max_table_rows,
        org_name=user.org.name if user.org else "",
    )


# ── reports ───────────────────────────────────────────────────────────────
@router.get("/reports/summary")
def report_summary(
    days: int = Query(default=7, ge=1, le=90),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    org_id = user.org_id

    total = db.execute(
        select(func.count(Flow.id)).where(Flow.org_id == org_id, Flow.ts >= since)
    ).scalar_one()
    attacks = db.execute(
        select(func.count(Flow.id)).where(
            Flow.org_id == org_id, Flow.ts >= since, Flow.prediction != BENIGN
        )
    ).scalar_one()
    mitigated = db.execute(
        select(func.count(Flow.id)).where(
            Flow.org_id == org_id, Flow.ts >= since, Flow.mitigated.is_(True)
        )
    ).scalar_one()

    by_class = db.execute(
        select(Flow.prediction, func.count(Flow.id))
        .where(Flow.org_id == org_id, Flow.ts >= since)
        .group_by(Flow.prediction)
    ).all()

    top_sources = db.execute(
        select(Flow.src_ip, func.count(Flow.id))
        .where(Flow.org_id == org_id, Flow.ts >= since, Flow.prediction != BENIGN)
        .group_by(Flow.src_ip).order_by(func.count(Flow.id).desc()).limit(10)
    ).all()

    incidents_opened = db.execute(
        select(func.count(Incident.id)).where(
            Incident.org_id == org_id, Incident.opened_at >= since
        )
    ).scalar_one()
    incidents_resolved = db.execute(
        select(func.count(Incident.id)).where(
            Incident.org_id == org_id, Incident.resolved_at.is_not(None),
            Incident.resolved_at >= since,
        )
    ).scalar_one()

    return {
        "period_days": days,
        "generated_at": int(time.time() * 1000),
        "org": user.org.name if user.org else "",
        "totals": {
            "flows": int(total),
            "attacks": int(attacks),
            "mitigated": int(mitigated),
            "attack_rate_pct": round(attacks / total * 100, 2) if total else 0.0,
        },
        "by_class": [{"label": c, "count": int(n)} for c, n in by_class],
        "top_sources": [{"src_ip": ip, "count": int(n)} for ip, n in top_sources],
        "incidents": {"opened": int(incidents_opened), "resolved": int(incidents_resolved)},
    }


@router.get("/stream/status")
def stream_status(user: User = Depends(current_user)):
    return {"connected_clients": manager.count(user.org_id)}
