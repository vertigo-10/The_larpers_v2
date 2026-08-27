"""Top talkers and traffic breakdown.

Flows are written straight to the database rather than posted through
`/api/ingest`, because these tests are about ranking and aggregation, not about
the model. Going through ingest would mean the model decided the labels, and a
test that cannot state which flows are attacks cannot check that attacks are
ranked above bulk transfers.
"""

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_TMP_DB = os.path.join(tempfile.mkdtemp(), "analytics.db")
os.environ["SENTRY_DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SENTRY_SIMULATOR_ENABLED"] = "false"
os.environ["SENTRY_SIGNUP_MAX_PER_WINDOW"] = "100000"  # the suite creates many orgs from one client
os.environ["SENTRY_SECRET_KEY"] = "test-key-not-used-in-production-abcdefghijklmnop"
os.environ["SENTRY_MODEL_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "artifacts"
)

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.db import SessionLocal, init_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Flow  # noqa: E402

GOOD_PW = "correct-horse-battery-staple"
BENIGN = "normal"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def _signup(client, email, org):
    client.cookies.clear()
    r = client.post("/api/auth/signup", json={
        "email": email, "password": GOOD_PW, "name": "Admin", "org_name": org,
        "org_type": "company",
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()
    return {"cookies": cookies, "org_id": r.json()["org_id"]}


@pytest.fixture(scope="module")
def alpha(client):
    return _signup(client, "an-a@alpha.example.com", "Alpha Analytics")


@pytest.fixture(scope="module")
def beta(client):
    return _signup(client, "an-b@beta.example.com", "Beta Analytics")


def _write(org_id, src_ip, count=1, *, total_bytes=1000.0, packets=10,
           prediction=BENIGN, dst_port=443, protocol="TCP", node="EDGE-01",
           confidence=0.9, mitigated=False, age_minutes=1):
    ts = datetime.now(timezone.utc) - timedelta(minutes=age_minutes)
    db = SessionLocal()
    try:
        for i in range(count):
            db.add(Flow(
                org_id=org_id, flow_ref=f"{src_ip}-{dst_port}-{age_minutes}-{i}",
                ts=ts, src_ip=src_ip, dst_port=dst_port, protocol=protocol,
                node=node, duration=1.0, packets=packets, total_bytes=total_bytes,
                bytes_per_sec=total_bytes, prediction=prediction,
                confidence=confidence, mitigated=mitigated, source="live",
            ))
        db.commit()
    finally:
        db.close()


def _talkers(client, org, **params):
    r = client.get("/api/analytics/talkers", cookies=org["cookies"], params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _find(payload, ip):
    return next((t for t in payload["talkers"] if t["src_ip"] == ip), None)


# ── ranking ───────────────────────────────────────────────────────────────
def test_a_flood_of_tiny_flows_is_not_hidden_by_a_bulk_transfer(client, alpha):
    """The failure this endpoint exists to avoid.

    A SYN flood moves almost no data — its method is a great many tiny
    conversations. Ranking sources by bytes alone would put a backup job on top
    and leave the flood off the page entirely.
    """
    org = alpha["org_id"]
    # Enough heavy senders to fill the byte ranking on their own, so the flood
    # can only reach the page through the second, flow-count ranking. Without
    # that ranking this test fails, which is the point of it.
    for i in range(15):
        _write(org, f"10.9.0.{i + 1}", count=1,
               total_bytes=500_000_000.0 - i, packets=400_000)
    _write(org, "203.0.113.50", count=300, total_bytes=64.0, packets=1,
           prediction="ddos", dst_port=80)

    payload = _talkers(client, alpha, window=60, limit=10)

    flood = _find(payload, "203.0.113.50")
    assert flood is not None, "a byte-only ranking would have dropped the flood"
    assert flood["flows"] == 300
    # Its whole volume is a rounding error next to any one of the transfers.
    assert flood["bytes_share"] < 0.01
    # And it still has to come first, because it is the only thing attacking.
    assert payload["talkers"][0]["src_ip"] == "203.0.113.50"


def test_a_source_that_is_mostly_benign_is_still_labelled_by_its_attack(client, alpha):
    """A host that is 95% normal and 5% flood is a host that is flooding."""
    org = alpha["org_id"]
    _write(org, "198.51.100.5", count=95, prediction=BENIGN)
    _write(org, "198.51.100.5", count=5, prediction="ddos", confidence=0.97)

    talker = _find(_talkers(client, alpha, window=60, limit=50), "198.51.100.5")
    assert talker["top_prediction"] == "ddos"
    assert talker["attack_flows"] == 5
    assert talker["attack_share"] == 5.0
    assert talker["max_confidence"] == pytest.approx(0.97, abs=1e-3)


def test_a_purely_benign_source_is_reported_as_benign(client, alpha):
    _write(alpha["org_id"], "10.9.0.77", count=4, prediction=BENIGN)

    talker = _find(_talkers(client, alpha, window=60, limit=50), "10.9.0.77")
    assert talker["top_prediction"] == BENIGN
    assert talker["attack_flows"] == 0
    assert talker["attack_share"] == 0.0


def test_attack_sources_sort_above_quiet_ones(client, alpha):
    payload = _talkers(client, alpha, window=60, limit=50)
    attacking = [i for i, t in enumerate(payload["talkers"]) if t["attack_flows"] > 0]
    quiet = [i for i, t in enumerate(payload["talkers"]) if t["attack_flows"] == 0]

    assert attacking and quiet, "need both kinds present for this to mean anything"
    assert max(attacking) < min(quiet)


# ── per-source detail ─────────────────────────────────────────────────────
def test_counters_are_summed_across_a_sources_flows(client, alpha):
    _write(alpha["org_id"], "10.9.0.20", count=3, total_bytes=1500.0, packets=12)

    talker = _find(_talkers(client, alpha, window=60, limit=50), "10.9.0.20")
    assert talker["flows"] == 3
    assert talker["packets"] == 36
    assert talker["total_bytes"] == 4500.0


def test_distinct_ports_are_counted_not_summed(client, alpha):
    """A port scan is one source touching many ports, so this number is the
    signal. Summing per-group counts would double-count and inflate it."""
    org = alpha["org_id"]
    for port in (22, 23, 80, 443, 3389):
        _write(org, "203.0.113.60", count=2, dst_port=port, prediction="portscan")

    talker = _find(_talkers(client, alpha, window=60, limit=50), "203.0.113.60")
    assert talker["ports"] == 5
    assert talker["flows"] == 10


def test_nodes_a_source_reached_are_listed_once_each(client, alpha):
    org = alpha["org_id"]
    _write(org, "10.9.0.30", count=2, node="EDGE-01")
    _write(org, "10.9.0.30", count=2, node="CORE-02")

    talker = _find(_talkers(client, alpha, window=60, limit=50), "10.9.0.30")
    assert talker["nodes"] == ["CORE-02", "EDGE-01"]


def test_mitigated_flows_are_counted(client, alpha):
    _write(alpha["org_id"], "203.0.113.70", count=3, prediction="ddos", mitigated=True)
    _write(alpha["org_id"], "203.0.113.70", count=1, prediction="ddos", mitigated=False)

    talker = _find(_talkers(client, alpha, window=60, limit=50), "203.0.113.70")
    assert talker["mitigated"] == 3


def test_bytes_share_is_a_percentage_of_the_window(client, alpha):
    payload = _talkers(client, alpha, window=60, limit=200)
    assert payload["total_bytes"] > 0
    for talker in payload["talkers"]:
        assert 0.0 <= talker["bytes_share"] <= 100.0


def test_first_and_last_seen_bracket_the_activity(client, alpha):
    org = alpha["org_id"]
    _write(org, "10.9.0.40", count=1, age_minutes=30)
    _write(org, "10.9.0.40", count=1, age_minutes=2)

    talker = _find(_talkers(client, alpha, window=60, limit=50), "10.9.0.40")
    assert talker["first_seen"] < talker["last_seen"]
    assert talker["last_seen"] - talker["first_seen"] == pytest.approx(28 * 60, abs=90)


# ── the window ────────────────────────────────────────────────────────────
def test_flows_outside_the_window_are_excluded(client, alpha):
    _write(alpha["org_id"], "10.9.0.50", count=5, age_minutes=120)

    assert _find(_talkers(client, alpha, window=15, limit=50), "10.9.0.50") is None
    assert _find(_talkers(client, alpha, window=240, limit=50), "10.9.0.50") is not None


def test_an_empty_window_returns_a_clean_empty_answer(client, alpha):
    """No data must render as no data, not as a 500 or a zero-division."""
    payload = _talkers(client, alpha, window=1)
    assert payload["talkers"] == [] or all(t["flows"] > 0 for t in payload["talkers"])
    assert payload["total_bytes"] >= 0


def test_an_absurd_window_is_refused_rather_than_scanned(client, alpha):
    r = client.get("/api/analytics/talkers", cookies=alpha["cookies"],
                   params={"window": 999_999})
    assert r.status_code == 422


def test_limit_is_capped(client, alpha):
    r = client.get("/api/analytics/talkers", cookies=alpha["cookies"],
                   params={"limit": 100_000})
    assert r.status_code == 422


def test_the_limit_is_honoured(client, alpha):
    payload = _talkers(client, alpha, window=60, limit=3)
    assert len(payload["talkers"]) <= 3


# ── tenancy ───────────────────────────────────────────────────────────────
def test_one_tenant_never_sees_anothers_talkers(client, alpha, beta):
    _write(beta["org_id"], "203.0.113.200", count=50, prediction="ddos")

    assert _find(_talkers(client, alpha, window=60, limit=200), "203.0.113.200") is None
    assert _find(_talkers(client, beta, window=60, limit=200), "203.0.113.200") is not None


def test_talkers_requires_a_session(client):
    client.cookies.clear()
    assert client.get("/api/analytics/talkers").status_code == 401


# ── traffic breakdown ─────────────────────────────────────────────────────
def _traffic(client, org, **params):
    r = client.get("/api/analytics/traffic", cookies=org["cookies"], params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_protocols_are_broken_out_with_their_attack_counts(client, alpha):
    org = alpha["org_id"]
    _write(org, "10.9.1.1", count=4, protocol="UDP", prediction="ddos")
    _write(org, "10.9.1.2", count=2, protocol="UDP", prediction=BENIGN)

    udp = next(p for p in _traffic(client, alpha, window=60)["protocols"]
               if p["protocol"] == "UDP")
    assert udp["flows"] >= 6
    assert udp["attack_flows"] >= 4


def test_well_known_ports_are_named(client, alpha):
    _write(alpha["org_id"], "10.9.1.3", count=3, dst_port=22)

    ssh = next(p for p in _traffic(client, alpha, window=60)["ports"] if p["port"] == 22)
    assert ssh["service"] == "SSH"


def test_an_unknown_port_is_left_blank_rather_than_guessed(client, alpha):
    """A wrong label is worse than none — an analyst who reads a familiar
    service name next to a flood stops looking."""
    _write(alpha["org_id"], "10.9.1.4", count=3, dst_port=47821)

    row = next(p for p in _traffic(client, alpha, window=60)["ports"] if p["port"] == 47821)
    assert row["service"] == ""


def test_a_port_reports_how_many_distinct_sources_hit_it(client, alpha):
    org = alpha["org_id"]
    for i in range(4):
        _write(org, f"203.0.113.{150 + i}", count=2, dst_port=9999, prediction="ddos")

    row = next(p for p in _traffic(client, alpha, window=60)["ports"] if p["port"] == 9999)
    assert row["sources"] == 4
    assert row["flows"] == 8


def test_traffic_breakdown_is_tenant_scoped(client, alpha, beta):
    _write(beta["org_id"], "10.9.2.1", count=6, dst_port=6001, protocol="SCTP")

    alpha_ports = {p["port"] for p in _traffic(client, alpha, window=60)["ports"]}
    assert 6001 not in alpha_ports
    beta_ports = {p["port"] for p in _traffic(client, beta, window=60)["ports"]}
    assert 6001 in beta_ports


def test_traffic_requires_a_session(client):
    client.cookies.clear()
    assert client.get("/api/analytics/traffic").status_code == 401
