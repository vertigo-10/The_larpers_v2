"""Traffic baselining and aggregate anomaly detection.

The neural network scores one flow at a time, on that flow's own shape. That
makes it blind to a whole category of trouble: traffic that is individually
unremarkable but collectively wrong. Ten thousand well-formed HTTP requests
from ten thousand addresses is a botnet, and every one of those flows looks
benign on its own. A link that goes silent at 2am is either a dead collector or
a severed uplink, and there are no flows at all to classify.

So this module asks the other question — *is this normal for this network* —
and it asks it about aggregates rather than individual flows.

Three things it has to get right to be worth having:

1. **Not learn the attack.** A self-updating baseline that folds in whatever it
   sees will, given a sustained attack, quietly decide the attack is normal and
   stop reporting it. Observations are therefore winsorized to mean + 3σ before
   they update the baseline, so an attack nudges it instead of dragging it.
   A genuine permanent shift still gets learned, just over days rather than
   minutes, which is the correct trade for a security tool.

2. **Not fire while it is still learning.** Every bucket carries a sample count
   and stays silent until it has seen enough. The API reports how warm each
   bucket is so the UI can say "still learning" instead of "all clear".

3. **Not fire on a quiet network.** On a link doing three flows per window, σ
   is nearly zero and any flicker is a fifty-sigma event. σ is floored both
   relatively (a fraction of the mean) and absolutely (a per-metric minimum),
   which is what stops the page filling with nonsense on a home connection.
"""

import asyncio
import ipaddress
import math
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal
from .models import Anomaly, Baseline, Flow, Incident, IncidentStatus, Org
# From severity.py rather than engine.py: engine imports the model runtime, and
# the background loop below has no business dragging torch into memory to ask
# what "critical" outranks.
from .severity import _SEVERITY_RANK

METRICS = ("flows", "bytes", "sources")

# A bucket is (weekend?, hour-of-day). See Baseline's docstring for why this
# rather than a full 168-slot hour-of-week.
BUCKETS = 48

# Below this many observations a bucket has no opinion and stays quiet.
MIN_SAMPLES = 30

# |z| beyond this is an anomaly.
Z_THRESHOLD = 4.0

# EWMA weight floor. 1/n while a bucket is young so it converges quickly, then
# settling here — roughly a fifty-observation memory, so the baseline tracks
# real seasonal drift without being yanked around by a single busy afternoon.
MIN_ALPHA = 0.02

# σ is never taken as less than this fraction of the mean. With Z_THRESHOLD at
# 4 this means a spike must be at least ~1.6x normal before it counts, no
# matter how metronomic the traffic has been.
RELATIVE_SIGMA_FLOOR = 0.15

# ...nor less than this in absolute terms, which is what covers the near-idle
# case where a fraction of the mean is still almost zero.
ABSOLUTE_SIGMA_FLOOR = {"flows": 5.0, "bytes": 50_000.0, "sources": 3.0}

# A drop is only meaningful if there was something there to begin with. Without
# this, a lab segment that normally carries a trickle reports an outage every
# time it goes properly idle.
DROP_FLOOR = {"flows": 50.0, "bytes": 250_000.0, "sources": 10.0}

# An open anomaly not re-observed for this many windows is considered over.
STALE_WINDOWS = 3

METRIC_LABELS = {
    "flows": "flow rate",
    "bytes": "traffic volume",
    "sources": "unique sources",
}


def bucket_for(when: datetime) -> int:
    """0-47: hour of day, offset by 24 on weekends."""
    weekend = 1 if when.weekday() >= 5 else 0
    return weekend * 24 + when.hour


def describe_bucket(bucket: int) -> str:
    day = "weekend" if bucket >= 24 else "weekday"
    hour = bucket % 24
    return f"{day} {hour:02d}:00-{(hour + 1) % 24:02d}:00"


def sigma_for(mean: float, variance: float, metric: str) -> float:
    """Standard deviation with both floors applied."""
    return max(
        math.sqrt(max(variance, 0.0)),
        RELATIVE_SIGMA_FLOOR * abs(mean),
        ABSOLUTE_SIGMA_FLOOR.get(metric, 1.0),
    )


def severity_for(z: float) -> str:
    az = abs(z)
    if az >= 8.0:
        return "critical"
    if az >= 6.0:
        return "high"
    return "medium"


def observe(db: Session, org_id: int, start: datetime, end: datetime) -> Dict[str, float]:
    """Aggregate one window of flows into the three baselined metrics."""
    row = db.execute(
        select(
            func.count(Flow.id),
            func.coalesce(func.sum(Flow.total_bytes), 0.0),
            func.count(func.distinct(Flow.src_ip)),
        ).where(Flow.org_id == org_id, Flow.ts >= start, Flow.ts < end)
    ).one()
    return {"flows": float(row[0]), "bytes": float(row[1]), "sources": float(row[2])}


def _load_slots(db: Session, org_id: int, bucket: int) -> Dict[str, Baseline]:
    rows = db.execute(
        select(Baseline).where(
            Baseline.org_id == org_id, Baseline.bucket == bucket
        )
    ).scalars().all()
    slots = {r.metric: r for r in rows}
    for metric in METRICS:
        if metric not in slots:
            # Column defaults are applied by the INSERT, not by the
            # constructor, so a slot built here and read back before the flush
            # would have `samples = None` and blow up the first comparison.
            slot = Baseline(org_id=org_id, metric=metric, bucket=bucket,
                            mean=0.0, variance=0.0, samples=0)
            db.add(slot)
            slots[metric] = slot
    return slots


def _update(slot: Baseline, value: float, now: datetime) -> None:
    """Fold one observation in, winsorized so an attack cannot retrain us."""
    if slot.samples == 0:
        slot.mean = value
        slot.variance = 0.0
    else:
        sigma = sigma_for(slot.mean, slot.variance, slot.metric)
        capped = min(max(value, slot.mean - 3.0 * sigma), slot.mean + 3.0 * sigma)
        capped = max(capped, 0.0)

        alpha = max(1.0 / (slot.samples + 1), MIN_ALPHA)
        delta = capped - slot.mean
        slot.mean += alpha * delta
        slot.variance = (1.0 - alpha) * (slot.variance + alpha * delta * delta)

    slot.samples += 1
    slot.updated_at = now


def score(slot: Baseline, value: float) -> Optional[Tuple[float, str]]:
    """Signed z-score and direction, or None if this slot should stay quiet."""
    if slot.samples < MIN_SAMPLES:
        return None

    sigma = sigma_for(slot.mean, slot.variance, slot.metric)
    z = (value - slot.mean) / sigma
    if abs(z) < Z_THRESHOLD:
        return None

    if z > 0:
        return z, "spike"

    # A near-idle baseline "dropping" to zero is not news.
    if slot.mean < DROP_FLOOR.get(slot.metric, 0.0):
        return None
    return z, "drop"


def _record(
    db: Session,
    org_id: int,
    slot: Baseline,
    value: float,
    z: float,
    direction: str,
    now: datetime,
    window: timedelta,
) -> None:
    """Open a new anomaly, or extend the one already live for this signal.

    Acknowledged rows are extended too, not skipped: acknowledging means "I know
    about this", so a still-ongoing condition must not keep reopening as fresh
    anomalies the moment someone marks it seen.
    """
    cutoff = now - window * STALE_WINDOWS
    existing = db.execute(
        select(Anomaly)
        .where(
            Anomaly.org_id == org_id,
            Anomaly.metric == slot.metric,
            Anomaly.direction == direction,
            Anomaly.status.in_(("open", "acknowledged")),
            Anomaly.last_seen_at >= cutoff,
        )
        .order_by(Anomaly.last_seen_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if existing is not None:
        existing.last_seen_at = now
        existing.windows += 1
        existing.observed = value
        existing.expected = slot.mean
        existing.deviation = z
        if abs(z) > abs(existing.peak_deviation):
            existing.peak_deviation = z
            existing.severity = severity_for(z)
        return

    db.add(Anomaly(
        org_id=org_id,
        ts=now,
        last_seen_at=now,
        metric=slot.metric,
        direction=direction,
        observed=value,
        expected=slot.mean,
        deviation=z,
        peak_deviation=z,
        severity=severity_for(z),
        windows=1,
        status="open",
    ))


def _close_stale(db: Session, org_id: int, now: datetime, window: timedelta) -> None:
    cutoff = now - window * STALE_WINDOWS
    stale = db.execute(
        select(Anomaly).where(
            Anomaly.org_id == org_id,
            Anomaly.status.in_(("open", "acknowledged")),
            Anomaly.last_seen_at < cutoff,
        )
    ).scalars().all()
    for row in stale:
        row.status = "resolved"


# ── slow denial of service ────────────────────────────────────────────────
# A different kind of detector from everything above, and it is worth being
# explicit about how.
#
# The z-score machinery asks "is this volume normal for this hour". Slow DoS is
# invisible to that question by construction: Slowloris, RUDY and slow-read all
# work by holding a server's connection table open with traffic so thin that
# volume goes *down*, not up. The attack succeeds precisely by not being a
# spike. Twenty thousand bytes over five minutes will never breach a threshold
# built to catch floods.
#
# It is equally invisible to the classifier, and that is not a training gap
# that more data would close. The model's six features — duration, packets,
# total_bytes, packets_per_sec, bytes_per_packet, dst_port — all describe a
# single flow in isolation. One held-open connection sending a header every
# forty seconds *is* a normal flow. It is indistinguishable from an idle SSH
# session, and the model calling it benign is the correct answer to the
# question the model was asked. The attack does not exist at the level of one
# flow; it exists in the fact that there are four hundred of them, all from one
# place, all aimed at one service, all doing nothing. No amount of retraining
# puts that in a feature space that cannot express "at the same time as".
#
# So this is a rule, not an estimator. It has no warm-up and it learns nothing,
# because there is nothing here to learn: the shape it looks for has no
# legitimate explanation that the guards below do not already exclude.
SLOW_DOS_LABEL = "slow_dos"

# All four thresholds are a conjunction and none of them means anything alone.
# Many flows to one port is a busy web server. Long duration is a download.
# Tiny transfers are health checks. A near-zero packet rate is an idle
# keepalive. Every one of those is somewhere on this network right now. What has
# no benign reading is all four at once — a client that opened dozens of
# connections and then deliberately did nothing with any of them.
SLOW_DOS_MIN_FLOWS = 30            # concurrent held-open connections
SLOW_DOS_MIN_MEAN_DURATION_S = 30.0
SLOW_DOS_MAX_MEAN_BYTES = 2048.0   # a request header and little else
SLOW_DOS_MAX_PACKETS_PER_SEC = 2.0

# Severity tracks flow count because flow count is the resource being consumed.
# Apache's default MaxRequestWorkers is 256 and nginx's default worker
# connection limit is 512, so a few hundred held-open sockets is not "worse than
# medium" in the abstract — it is the point at which a stock server stops
# answering anyone else.
SLOW_DOS_HIGH_FLOWS = 100
SLOW_DOS_CRITICAL_FLOWS = 400


def slow_dos_severity(flows: int) -> str:
    if flows >= SLOW_DOS_CRITICAL_FLOWS:
        return "critical"
    if flows >= SLOW_DOS_HIGH_FLOWS:
        return "high"
    return "medium"


def _is_external(ip: str) -> bool:
    """Is this address one that could not be our own infrastructure?

    The guard that makes the rule usable rather than a permanent false alarm.

    An application server holding fifty pooled connections open to a database
    matches every shape test above exactly — dozens of flows, one destination
    port, minute-long durations, almost no bytes, a packet every few seconds.
    So does a message broker, an IMAP client sitting in IDLE, a websocket fleet
    and a monitoring agent. Those are not edge cases; they are what a normal
    datacentre is mostly made of, and a detector that reported them would be
    switched off within a day.

    What separates them from an attack is not shape, it is origin: they run
    between hosts the operator owns. So the rule only considers sources that are
    globally routable — traffic that arrived from the internet.

    The cost is stated plainly because it is real: **a slow DoS from a
    compromised machine inside the network will not be caught here.** That case
    needs to know which internal pairs normally talk, which is a per-peer
    baseline this does not keep. Catching the external attacker and saying so is
    worth more than catching both and being ignored.

    `is_global` also excludes carrier-grade NAT (100.64.0.0/10) and the
    documentation ranges, which is right rather than incidental: traffic
    genuinely arriving from the internet carries the carrier's public address,
    so a 100.64 source seen at an edge is the org's own side of an ISP handoff,
    not a stranger.
    """
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        # Not parseable, so not attributable. An exporter sending garbage in the
        # source field must not have it treated as a hostile internet address.
        return False


def slow_dos_groups(
    db: Session, org_id: int, start: datetime, end: datetime
) -> List[Dict]:
    """Every (source, target, port) triple in this window that fits the shape.

    Grouped on the destination as well as the source because the destination is
    what makes it an attack. Thirty idle connections from one address spread
    across thirty different servers is a crawler having a slow day. The same
    thirty pointed at one of them is that server running out of workers.
    Grouping on the source alone cannot tell those apart, which is why `dst_ip`
    is carried through the pipeline at all.

    Every flow counts regardless of what the classifier said about it, and that
    is deliberate. The obvious alternative — only re-examine flows the model
    waved through, since anything it flagged already has an incident — was
    tried and is wrong. Put held-open connections of 280 bytes over 4 packets
    through the deployed model and the label flips at around three minutes:

        hold  60s -> normal    0.851      hold 240s -> dos_ddos  0.510
        hold 120s -> normal    0.809      hold 300s -> dos_ddos  0.663
        hold 180s -> normal    0.668      hold 600s -> dos_ddos  0.930

    That is not a fault in the model; duration is one of its six features and a
    ten-minute flow moving nothing genuinely is odd. But it means one attack
    arrives under two labels. Exporters emit on an active timeout, commonly 60s,
    so a single slowloris produces a stream of 60s records that read as normal
    plus whatever longer record closes each connection, which may not. Filtering
    to benign flows would discard an arbitrary fraction of every group and could
    thin it below the threshold — the detector would fall silent on precisely
    the traffic it exists for, and it would do so without saying anything.

    The cost is that a source in that band can end up with two incidents: a
    weak `dos_ddos` from the model and a `slow_dos` from here. That is the
    better failure. The `dos_ddos` row says "flood" about traffic moving a few
    bytes a second, next to a row that says how many connections are held open
    and against what.
    """
    rows = db.execute(
        select(
            Flow.src_ip,
            Flow.dst_ip,
            Flow.dst_port,
            func.count(Flow.id),
            func.sum(Flow.duration),
            func.sum(Flow.total_bytes),
            func.sum(Flow.packets),
            # Deterministic rather than arbitrary. A group is one source to one
            # destination, so in practice every flow in it carries the same node;
            # min() just guarantees the incident does not relabel itself between
            # windows if two exporters both observed the traffic.
            func.min(Flow.node),
        )
        .where(
            Flow.org_id == org_id,
            Flow.ts >= start,
            Flow.ts < end,
            # Blank means the exporter never told us the destination. Those
            # flows cannot be grouped by target, and lumping them together under
            # a shared empty string would invent one enormous fictional victim.
            Flow.dst_ip != "",
        )
        .group_by(Flow.src_ip, Flow.dst_ip, Flow.dst_port)
        # Applied in SQL so the rows that come back are already a handful. The
        # remaining conditions are cheap once the count has cut the set down,
        # and they read far better in Python than as a stack of HAVING clauses.
        .having(func.count(Flow.id) >= SLOW_DOS_MIN_FLOWS)
    ).all()

    groups: List[Dict] = []
    for src_ip, dst_ip, dst_port, count, dur_sum, byte_sum, pkt_sum, node in rows:
        count = int(count or 0)
        dur_sum = float(dur_sum or 0.0)
        byte_sum = float(byte_sum or 0.0)
        pkt_sum = float(pkt_sum or 0.0)
        if count <= 0 or dur_sum <= 0.0:
            continue

        mean_duration = dur_sum / count
        mean_bytes = byte_sum / count
        # The group's aggregate rate, not the mean of per-flow rates. A single
        # sub-second flow that slipped into the group would have a huge
        # instantaneous rate and drag a mean-of-rates above the threshold, which
        # would let one stray packet mask four hundred idle sockets.
        packets_per_sec = pkt_sum / dur_sum

        if mean_duration < SLOW_DOS_MIN_MEAN_DURATION_S:
            continue
        if mean_bytes > SLOW_DOS_MAX_MEAN_BYTES:
            continue
        if packets_per_sec > SLOW_DOS_MAX_PACKETS_PER_SEC:
            continue
        if not _is_external(src_ip):
            continue

        groups.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port or 0),
            "node": node or "unknown",
            "flows": count,
            "mean_duration": mean_duration,
            "mean_bytes": mean_bytes,
            "packets_per_sec": packets_per_sec,
            "total_bytes": byte_sum,
            "severity": slow_dos_severity(count),
        })
    return groups


def describe_slow_dos(groups: List[Dict]) -> str:
    """The sentence stored on the incident, for one source's groups.

    Deliberately the observation and not the conclusion. "Slow DoS" is already
    the label; what an operator cannot get anywhere else is the numbers that
    made the rule fire, so they can decide in ten seconds whether this is an
    attack or the one long-poll integration nobody documented.
    """
    if not groups:
        return ""
    flows = sum(g["flows"] for g in groups)
    # Weighted by flow count, so a group of four hundred sockets is not averaged
    # on equal footing with a group of thirty.
    duration = sum(g["mean_duration"] * g["flows"] for g in groups) / flows
    mean_bytes = sum(g["mean_bytes"] * g["flows"] for g in groups) / flows
    rate = sum(g["packets_per_sec"] * g["flows"] for g in groups) / flows

    first = f"{groups[0]['dst_ip']}:{groups[0]['dst_port']}"
    if len(groups) == 1:
        target = first
    else:
        target = f"{len(groups)} services ({first} and {len(groups) - 1} more)"

    return (
        f"{flows} connections held open against {target}, averaging "
        f"{duration:.0f}s and {mean_bytes:.0f} bytes each at "
        f"{rate:.2f} packets/sec."
    )[:200]


def _record_slow_dos(
    db: Session, org_id: int, src_ip: str, groups: List[Dict],
    now: datetime, window: timedelta,
) -> Incident:
    """Open an incident for one source, or extend the one already running.

    Keyed on source and label, exactly like the classifier's incidents in
    engine.py. One address starving three services is one attacker running one
    campaign, and the fix is the same edge rule for all three — splitting it
    into three rows would triple the queue without adding a decision.

    Never auto-resolves, which again matches every other incident in the system:
    an operator closes them. That matters more here than elsewhere, because an
    attacker who goes quiet for one window has not stopped, and a row that
    closed itself would take the investigation with it.
    """
    cutoff = now - window * STALE_WINDOWS
    detail = describe_slow_dos(groups)
    flows = sum(g["flows"] for g in groups)
    severity = slow_dos_severity(flows)
    # Averaged over the window rather than reported raw, so it is the same unit
    # as every other peak_bps in the table. It will be a derisory number, and
    # that is the finding: this much traffic could not knock anything over, yet
    # the connection table is full.
    bps = sum(g["total_bytes"] for g in groups) / max(window.total_seconds(), 1.0)

    existing = db.execute(
        select(Incident)
        .where(
            Incident.org_id == org_id,
            Incident.src_ip == src_ip,
            Incident.label == SLOW_DOS_LABEL,
            Incident.status != IncidentStatus.resolved.value,
            Incident.last_seen_at >= cutoff,
        )
        .order_by(Incident.last_seen_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if existing is not None:
        existing.last_seen_at = now
        # Replaced, not accumulated, and this is the one place slow DoS has to
        # differ from the classifier's incidents. There, `flow_count` counts
        # flows seen and climbing is the point. Here it means "connections being
        # held open right now" — the number that decides whether the server has
        # any workers left. Summing it across windows would turn a steady
        # forty-socket attack into a four-figure total that reads as escalating
        # when nothing has changed.
        existing.flow_count = flows
        existing.peak_bps = max(existing.peak_bps, bps)
        existing.detail = detail
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK.get(existing.severity, 0):
            existing.severity = severity
        return existing

    incident = Incident(
        org_id=org_id,
        src_ip=src_ip,
        label=SLOW_DOS_LABEL,
        node=groups[0]["node"],
        opened_at=now,
        last_seen_at=now,
        flow_count=flows,
        # Left at zero, and the UI renders it as "—" rather than "0%". This is
        # the model's confidence field and no model was consulted; writing a
        # number here would be inventing a probability to fill a column.
        peak_confidence=0.0,
        peak_bps=bps,
        severity=severity,
        status=IncidentStatus.open.value,
        mitigated=False,
        detail=detail,
    )
    db.add(incident)
    db.flush()
    return incident


def detect_slow_dos(
    db: Session, org_id: int, start: datetime, end: datetime, window: timedelta
) -> List[Dict]:
    """Run the rule over one closed window. Returns the groups that fired."""
    found = slow_dos_groups(db, org_id, start, end)
    if not found:
        return []

    by_source: Dict[str, List[Dict]] = {}
    for group in found:
        by_source.setdefault(group["src_ip"], []).append(group)

    for src_ip, groups in by_source.items():
        # Biggest target first, so the sentence names the service in the most
        # trouble rather than whichever address happened to sort first.
        groups.sort(key=lambda g: g["flows"], reverse=True)
        _record_slow_dos(db, org_id, src_ip, groups, now=end, window=window)
    return found


def evaluate_window(
    db: Session, org_id: int, end: datetime, window: timedelta
) -> List[Dict]:
    """Score one closed window against the baseline, then learn from it.

    Scoring happens before the update, so a window is always judged against
    what was known before it arrived rather than against a baseline it has
    already influenced.
    """
    start = end - window
    values = observe(db, org_id, start, end)
    slots = _load_slots(db, org_id, bucket_for(start))

    fired: List[Dict] = []
    for metric in METRICS:
        slot = slots[metric]
        verdict = score(slot, values[metric])
        if verdict is not None:
            z, direction = verdict
            _record(db, org_id, slot, values[metric], z, direction, end, window)
            fired.append({
                "metric": metric,
                "direction": direction,
                "observed": values[metric],
                "expected": slot.mean,
                "deviation": z,
            })
        _update(slot, values[metric], end)

    # Runs on the same window boundaries but is not part of the loop above and
    # does not touch the baseline. It is a rule over the raw flows, so there is
    # no slot to warm and nothing for it to learn — see the section above for
    # why an estimator could not see this attack at all.
    #
    # Deliberately after the baseline has been scored and updated: a slow DoS
    # pushes volume *down*, and if the rule raised an exception the baseline
    # would still have learned this window rather than skipping it and leaving a
    # hole in the hour-of-week history.
    detect_slow_dos(db, org_id, start, end, window)

    _close_stale(db, org_id, end, window)
    db.commit()
    return fired


def _window_length() -> timedelta:
    return timedelta(seconds=max(settings.baseline_window_s, 30))


def _last_window_end(db: Session, org_id: int) -> Optional[datetime]:
    ts = db.execute(
        select(func.max(Baseline.updated_at)).where(Baseline.org_id == org_id)
    ).scalar_one()
    if ts is not None and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def run_due_windows(db: Session, org_id: int, now: datetime) -> List[Dict]:
    """Evaluate every window that has closed since the last one we processed.

    Aligned to wall-clock multiples of the window length so that restarting the
    server does not shift the window boundaries, and derived from the stored
    `updated_at` rather than in-process state so a restart does not double-count
    a window either.
    """
    window = _window_length()
    seconds = int(window.total_seconds())
    epoch = int(now.timestamp())
    end = datetime.fromtimestamp(epoch - (epoch % seconds), tz=timezone.utc)

    last = _last_window_end(db, org_id)
    if last is None:
        # Nothing learned yet: seed from the window that just closed.
        return evaluate_window(db, org_id, end, window)

    fired: List[Dict] = []
    # Bounded so a server that was off for a week does not replay 2000 windows
    # of empty history on the first tick.
    cursor = max(last + window, end - window * 12)
    while cursor <= end:
        fired.extend(evaluate_window(db, org_id, cursor, window))
        cursor += window
    return fired


def warmth(db: Session, org_id: int) -> Dict:
    """How much of the baseline is usable yet, for honest UI copy."""
    rows = db.execute(
        select(Baseline.metric, Baseline.samples).where(Baseline.org_id == org_id)
    ).all()
    total = BUCKETS * len(METRICS)
    ready = sum(1 for _, samples in rows if samples >= MIN_SAMPLES)
    return {
        "slots_total": total,
        "slots_ready": ready,
        "percent": round(100.0 * ready / total, 1) if total else 0.0,
        "min_samples": MIN_SAMPLES,
    }


# ── background loop ───────────────────────────────────────────────────────
_stop = asyncio.Event()


async def baseline_loop() -> None:
    """Independent of the simulator loop: real deployments run with it off."""
    interval = max(settings.baseline_window_s, 30)

    while not _stop.is_set():
        try:
            db = SessionLocal()
            try:
                now = datetime.now(timezone.utc)
                for org_id in list(db.execute(select(Org.id)).scalars()):
                    run_due_windows(db, org_id, now)
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001 - never let the loop die silently
            print(f"[sentry] baseline tick failed: {exc}")

        try:
            await asyncio.wait_for(_stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


def stop_baseline() -> None:
    _stop.set()
