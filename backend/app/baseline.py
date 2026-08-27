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
import math
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal
from .models import Anomaly, Baseline, Flow, Org

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
