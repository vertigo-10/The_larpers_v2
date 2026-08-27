"""Traffic baselining and aggregate anomaly detection.

The statistics are exercised directly rather than through the API, because the
properties that matter here are properties of the estimator — that it stays
quiet while cold, that a sustained attack cannot retrain it, that a near-idle
link does not produce nonsense — and none of those are visible from a single
HTTP response. The API tests below cover scoping and permissions only.
"""

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_TMP_DB = os.path.join(tempfile.mkdtemp(), "baseline.db")
os.environ["SENTRY_DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SENTRY_SIMULATOR_ENABLED"] = "false"
os.environ["SENTRY_SIGNUP_MAX_PER_WINDOW"] = "100000"  # the suite creates many orgs from one client
os.environ["SENTRY_SECRET_KEY"] = "test-key-not-used-in-production-abcdefghijklmnop"
os.environ["SENTRY_MODEL_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "artifacts"
)

from fastapi.testclient import TestClient  # noqa: E402

from backend.app import baseline as bl  # noqa: E402
from backend.app.db import SessionLocal, init_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Anomaly, Baseline, Flow  # noqa: E402

GOOD_PW = "correct-horse-battery-staple"

# A Tuesday, so every window lands in a weekday bucket.
NOW = datetime(2026, 3, 3, 14, 0, tzinfo=timezone.utc)
WINDOW = timedelta(minutes=5)


# ── helpers ───────────────────────────────────────────────────────────────
def _slot(metric="flows"):
    return Baseline(org_id=1, metric=metric, bucket=14, mean=0.0,
                    variance=0.0, samples=0)


def _train(slot, value, windows, jitter=0.0):
    """Feed a bucket `windows` observations so it warms up."""
    for i in range(windows):
        wobble = jitter * (1 if i % 2 else -1)
        bl._update(slot, value + wobble, NOW)


# ── the estimator ─────────────────────────────────────────────────────────
def test_a_cold_bucket_has_no_opinion():
    slot = _slot()
    _train(slot, 100.0, bl.MIN_SAMPLES - 1)
    assert slot.samples < bl.MIN_SAMPLES
    # An absurd value, and it still says nothing, because it has no grounds to.
    assert bl.score(slot, 500_000.0) is None


def test_a_warm_bucket_starts_scoring():
    slot = _slot()
    _train(slot, 100.0, bl.MIN_SAMPLES)
    assert bl.score(slot, 500_000.0) is not None


def test_normal_variation_is_not_an_anomaly():
    slot = _slot()
    _train(slot, 100.0, 60, jitter=8.0)
    for value in (92.0, 100.0, 108.0, 115.0, 85.0):
        assert bl.score(slot, value) is None, f"{value} should be unremarkable"


def test_a_spike_is_flagged_as_a_spike():
    slot = _slot()
    _train(slot, 100.0, 60)
    verdict = bl.score(slot, 900.0)
    assert verdict is not None
    z, direction = verdict
    assert direction == "spike"
    assert z > bl.Z_THRESHOLD


def test_a_sustained_attack_does_not_become_the_new_normal():
    """The failure this whole design exists to avoid.

    A baseline that folds in whatever it sees will, given two hours of attack
    traffic, decide the attack is normal and fall silent — right when it is
    most needed. The winsorized update is what prevents that, and the second
    half of this test computes what an unwinsorized update would have done so
    the difference is visible rather than asserted.
    """
    slot = _slot()
    _train(slot, 100.0, 60)
    quiet_mean = slot.mean

    attack = 1000.0
    windows = 24  # two hours of five-minute windows
    fired = 0
    for _ in range(windows):
        if bl.score(slot, attack) is not None:
            fired += 1
        bl._update(slot, attack, NOW)

    assert fired == windows, "the baseline learned the attack and stopped reporting it"
    assert slot.mean < 2.0 * quiet_mean

    # Same observations, same smoothing weight, but folded in raw: the mean
    # runs most of the way to the attack level and the alarm would stop.
    naive = quiet_mean
    for _ in range(windows):
        naive += bl.MIN_ALPHA * (attack - naive)
    assert naive > 4.0 * quiet_mean


def test_a_permanent_shift_is_eventually_learned():
    """Winsorizing must slow adaptation, not prevent it.

    A company that doubles its traffic should not generate anomalies forever.
    It should take days rather than minutes, which is the right trade for a
    security tool but is still a finite number of windows.
    """
    slot = _slot()
    _train(slot, 100.0, 60)

    new_normal = 1000.0
    windows = 0
    while bl.score(slot, new_normal) is not None and windows < 2000:
        bl._update(slot, new_normal, NOW)
        windows += 1

    assert windows < 2000, "the shift was never learned"

    # A bucket only collects observations during its own hour, so with
    # five-minute windows it sees about twelve a day. Converting makes the
    # bound mean something: the shift has to hold for days before it is
    # accepted, which is exactly long enough to outlast an attack.
    days = windows / 12.0
    assert days > 2.0, "adapted too fast to survive a sustained attack"
    assert days < 30.0, "would nag about genuine traffic growth for a month"


def test_a_quiet_link_does_not_fire_on_noise():
    """Three flows becoming eight is not an incident.

    Without the absolute sigma floor a metronomic low-traffic link has a
    near-zero standard deviation, and every ordinary flicker scores as a
    fifty-sigma event.
    """
    slot = _slot()
    _train(slot, 3.0, 60)
    for value in (0.0, 1.0, 8.0, 12.0):
        assert bl.score(slot, value) is None, f"{value} flows should be unremarkable"
    # It is not simply deaf, though — a real flood on the same link still lands.
    assert bl.score(slot, 400.0) is not None


def test_a_drop_is_flagged_as_a_drop():
    slot = _slot("sources")
    _train(slot, 60.0, 60)
    verdict = bl.score(slot, 2.0)
    assert verdict is not None
    z, direction = verdict
    assert direction == "drop"
    assert z < -bl.Z_THRESHOLD


def test_an_almost_idle_baseline_does_not_report_a_drop():
    """A trickle going quiet is not an outage."""
    slot = _slot("bytes")
    _train(slot, 200_000.0, 60)
    assert slot.mean < bl.DROP_FLOOR["bytes"]
    assert bl.score(slot, 0.0) is None
    # The same silence on a link that normally carries real traffic does count.
    loud = _slot("bytes")
    _train(loud, 40_000_000.0, 60)
    assert bl.score(loud, 0.0) is not None


def test_variance_stays_non_negative_under_wild_input():
    slot = _slot()
    for value in (0.0, 1e9, 0.0, 5.0, 1e9, 0.0):
        bl._update(slot, value, NOW)
        assert slot.variance >= 0.0
        assert slot.mean >= 0.0


def test_buckets_separate_night_from_day_and_weekend_from_weekday():
    tuesday_2pm = datetime(2026, 3, 3, 14, 30, tzinfo=timezone.utc)
    tuesday_3am = datetime(2026, 3, 3, 3, 30, tzinfo=timezone.utc)
    saturday_2pm = datetime(2026, 3, 7, 14, 30, tzinfo=timezone.utc)
    wednesday_2pm = datetime(2026, 3, 4, 14, 30, tzinfo=timezone.utc)

    assert bl.bucket_for(tuesday_2pm) != bl.bucket_for(tuesday_3am)
    assert bl.bucket_for(tuesday_2pm) != bl.bucket_for(saturday_2pm)
    # Two ordinary weekdays at the same hour share a bucket, which is what
    # makes the profile warm up in days rather than a month.
    assert bl.bucket_for(tuesday_2pm) == bl.bucket_for(wednesday_2pm)
    assert 0 <= bl.bucket_for(saturday_2pm) < bl.BUCKETS


# ── persistence and correlation ───────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def _signup(client, email, org, org_type="company"):
    client.cookies.clear()
    r = client.post("/api/auth/signup", json={
        "email": email, "password": GOOD_PW, "name": "Admin", "org_name": org,
        "org_type": org_type,
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()
    return {"cookies": cookies, "org_id": r.json()["org_id"]}


@pytest.fixture(scope="module")
def alpha(client):
    return _signup(client, "bl-a@alpha.example.com", "Alpha Baseline")


@pytest.fixture(scope="module")
def beta(client):
    return _signup(client, "bl-b@beta.example.com", "Beta Baseline")


def _flows(org_id, count, ts, *, src_prefix="10.1.0", total_bytes=20_000.0):
    db = SessionLocal()
    try:
        for i in range(count):
            db.add(Flow(
                org_id=org_id, flow_ref=f"bl-{ts.timestamp()}-{i}", ts=ts,
                src_ip=f"{src_prefix}.{i % 250 + 1}", dst_port=443, protocol="TCP",
                node="EDGE-01", duration=1.0, packets=20, total_bytes=total_bytes,
                bytes_per_sec=total_bytes, prediction="normal", confidence=0.9,
            ))
        db.commit()
    finally:
        db.close()


def _warm(db, org_id, metric, mean, bucket):
    """Install an already-warm bucket, so tests need not simulate days."""
    slot = Baseline(org_id=org_id, metric=metric, bucket=bucket,
                    mean=mean, variance=0.0, samples=bl.MIN_SAMPLES + 20)
    db.add(slot)
    db.commit()
    return slot


def test_a_breach_is_persisted_as_an_anomaly(client, alpha):
    org = alpha["org_id"]
    end = NOW
    db = SessionLocal()
    try:
        for metric, mean in (("flows", 100.0), ("bytes", 2_000_000.0), ("sources", 80.0)):
            _warm(db, org, metric, mean, bl.bucket_for(end - WINDOW))
        _flows(org, 400, end - timedelta(minutes=1))
        fired = bl.evaluate_window(db, org, end, WINDOW)
        metrics = {f["metric"] for f in fired}
        assert "flows" in metrics
        assert all(f["direction"] == "spike" for f in fired)

        rows = db.query(Anomaly).filter(Anomaly.org_id == org).all()
        assert rows and all(r.status == "open" for r in rows)
        assert all(r.expected > 0 for r in rows)
    finally:
        db.close()


def test_consecutive_breaches_extend_one_anomaly(client, beta):
    """Twenty minutes of attack is one anomaly, not four."""
    org = beta["org_id"]
    db = SessionLocal()
    try:
        # All four windows start inside the 14:00 hour so they share a bucket;
        # one that crossed the hour boundary would land in a cold bucket and
        # silently stop firing, which is correct behaviour but not what this
        # test is about.
        _warm(db, org, "flows", 100.0, bl.bucket_for(NOW))
        for step in range(4):
            end = NOW + WINDOW * (step + 1)
            _flows(org, 500, end - timedelta(minutes=1), src_prefix=f"10.2.{step}")
            bl.evaluate_window(db, org, end, WINDOW)

        rows = db.query(Anomaly).filter(
            Anomaly.org_id == org, Anomaly.metric == "flows",
            Anomaly.direction == "spike",
        ).all()
        assert len(rows) == 1, "each window opened its own anomaly"
        assert rows[0].windows == 4
        assert rows[0].last_seen_at > rows[0].ts
    finally:
        db.close()


def test_an_anomaly_resolves_once_the_condition_passes(client, beta):
    org = beta["org_id"]
    db = SessionLocal()
    try:
        open_rows = db.query(Anomaly).filter(
            Anomaly.org_id == org, Anomaly.status == "open").all()
        assert open_rows, "expected the previous test to leave one open"

        # Jump past the staleness horizon measured from the last observation,
        # not from an arbitrary fixed point.
        newest = max(r.last_seen_at for r in open_rows)
        if newest.tzinfo is None:
            newest = newest.replace(tzinfo=timezone.utc)
        later = newest + WINDOW * (bl.STALE_WINDOWS + 1)
        bl._close_stale(db, org, later, WINDOW)
        db.commit()

        for row in open_rows:
            db.refresh(row)
            assert row.status == "resolved"
    finally:
        db.close()


def test_one_orgs_traffic_does_not_move_another_orgs_baseline(client, alpha, beta):
    a, b = alpha["org_id"], beta["org_id"]
    # An hour no earlier test has touched, so both orgs start this bucket cold
    # and the only thing that can move either mean is its own traffic.
    end = NOW + timedelta(hours=5)
    _flows(a, 300, end - timedelta(minutes=1), src_prefix="10.7.0")

    db = SessionLocal()
    try:
        bl.evaluate_window(db, a, end, WINDOW)
        bl.evaluate_window(db, b, end, WINDOW)
        bucket = bl.bucket_for(end - WINDOW)
        got = {
            org: db.query(Baseline).filter(
                Baseline.org_id == org, Baseline.metric == "flows",
                Baseline.bucket == bucket,
            ).one().mean
            for org in (a, b)
        }
        assert got[a] > 0
        assert got[b] == 0.0
    finally:
        db.close()


def test_replaying_the_same_window_is_bounded(client, alpha):
    """A server that was off for a month must not replay a month of windows."""
    org = alpha["org_id"]
    db = SessionLocal()
    try:
        before = db.query(Baseline).filter(Baseline.org_id == org).count()
        stale = datetime.now(timezone.utc) - timedelta(days=30)
        db.query(Baseline).filter(Baseline.org_id == org).update(
            {Baseline.updated_at: stale})
        db.commit()

        bl.run_due_windows(db, org, datetime.now(timezone.utc))
        # Twelve windows is the cap; each touches at most three metrics across
        # a handful of buckets, so the table cannot have exploded.
        after = db.query(Baseline).filter(Baseline.org_id == org).count()
        assert after - before <= 12 * len(bl.METRICS)
    finally:
        db.close()


# ── API ───────────────────────────────────────────────────────────────────
def test_baseline_endpoint_reports_how_warm_it_is(client, alpha):
    r = client.get("/api/baseline?metric=flows", cookies=alpha["cookies"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["window_seconds"] > 0
    assert body["z_threshold"] == bl.Z_THRESHOLD
    assert body["warmth"]["slots_total"] == bl.BUCKETS * len(bl.METRICS)
    assert 0.0 <= body["warmth"]["percent"] <= 100.0
    assert body["current"]["label"]
    assert set(body["current"]["values"]) == set(bl.METRICS)


def test_baseline_endpoint_rejects_an_unknown_metric(client, alpha):
    r = client.get("/api/baseline?metric=packets", cookies=alpha["cookies"])
    assert r.status_code == 422
    assert "flows" in r.json()["detail"]


def test_anomalies_are_scoped_to_the_callers_org(client, alpha, beta):
    a = client.get("/api/anomalies", cookies=alpha["cookies"]).json()
    b = client.get("/api/anomalies", cookies=beta["cookies"]).json()
    assert {row["id"] for row in a}.isdisjoint({row["id"] for row in b})


def test_an_anomaly_can_be_acknowledged(client, alpha):
    rows = client.get("/api/anomalies", cookies=alpha["cookies"]).json()
    assert rows, "expected the persistence tests to have left anomalies"
    target = rows[0]["id"]
    r = client.post(f"/api/anomalies/{target}/acknowledge", cookies=alpha["cookies"])
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "acknowledged"
    assert r.json()["acknowledged_by"] == "Admin"


def test_acknowledging_another_orgs_anomaly_is_a_404(client, alpha, beta):
    rows = client.get("/api/anomalies", cookies=alpha["cookies"]).json()
    assert rows
    r = client.post(f"/api/anomalies/{rows[0]['id']}/acknowledge",
                    cookies=beta["cookies"])
    assert r.status_code == 404


def test_anomalies_require_authentication(client):
    client.cookies.clear()
    assert client.get("/api/anomalies").status_code == 401
    assert client.get("/api/baseline").status_code == 401
