"""API key authentication for collector agents.

A key is a credential that skips login entirely and lives on a machine nobody
watches — a router in a cupboard, a laptop in a bag. The tests that matter are
the ones about blast radius when it leaks: what a key cannot reach, whether
revocation actually works, and whether it can cross into another tenant.
"""

import os
import tempfile

import pytest

_TMP_DB = os.path.join(tempfile.mkdtemp(), "keys.db")
os.environ["SENTRY_DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SENTRY_SIMULATOR_ENABLED"] = "false"
os.environ["SENTRY_SIGNUP_MAX_PER_WINDOW"] = "100000"  # the suite creates many orgs from one client
os.environ["SENTRY_SECRET_KEY"] = "test-key-not-used-in-production-abcdefghijklmnop"
os.environ["SENTRY_MODEL_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "artifacts"
)

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.db import init_db  # noqa: E402
from backend.app.main import app  # noqa: E402

GOOD_PW = "correct-horse-battery-staple"

FLOW = {
    "src_ip": "172.16.0.5", "dst_port": 443, "protocol": "TCP",
    "node": "EDGE-01", "duration": 0.043, "packets": 1284,
    "total_bytes": 128400,
}


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
    return cookies


@pytest.fixture(scope="module")
def alpha(client):
    return _signup(client, "keys-a@alpha.example.com", "Alpha Corp")


@pytest.fixture(scope="module")
def beta(client):
    return _signup(client, "keys-b@beta.example.com", "Beta Ltd")


def _mint(client, cookies, label="collector"):
    r = client.post("/api/team/keys", cookies=cookies, json={"label": label})
    assert r.status_code == 201, r.text
    return r.json()


def _auth(key):
    return {"Authorization": f"Bearer {key}"}


# ── issuing ───────────────────────────────────────────────────────────────
def test_key_is_returned_once_and_never_again(client, alpha):
    """The secret exists outside the agent exactly once.

    Only a digest is stored, so a lost key must be reissued rather than
    recovered — and a database leak yields nothing usable.
    """
    created = _mint(client, alpha, "once")
    assert created["key"].startswith("sentry_ak_")

    listed = client.get("/api/team/keys", cookies=alpha).json()
    row = next(k for k in listed if k["id"] == created["id"])
    assert "key" not in row
    # The prefix is enough to recognise which key this is, and grants nothing.
    assert row["prefix"] in created["key"]
    assert len(row["prefix"]) < len(created["key"])


def test_only_admins_can_mint_keys(client, alpha):
    """Minting a key is equivalent to granting access, so it is admin-only."""
    r = client.post("/api/team", cookies=alpha, json={
        "email": "analyst-keys@alpha.example.com", "name": "Analyst",
        "role": "analyst", "password": GOOD_PW,
    })
    assert r.status_code == 201, r.text

    client.cookies.clear()
    login = client.post("/api/auth/login", json={
        "email": "analyst-keys@alpha.example.com", "password": GOOD_PW,
    })
    assert login.status_code == 200
    analyst = dict(client.cookies)
    client.cookies.clear()

    assert client.post("/api/team/keys", cookies=analyst,
                       json={"label": "nope"}).status_code == 403
    assert client.get("/api/team/keys", cookies=analyst).status_code == 403


# ── using ─────────────────────────────────────────────────────────────────
def test_key_can_ingest_flows(client, alpha):
    created = _mint(client, alpha, "ingest-ok")
    r = client.post("/api/ingest", headers=_auth(created["key"]),
                    json={"flows": [FLOW]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == 1
    # Scored by the real model, not stored raw.
    assert body["flows"][0]["prediction"]
    assert 0.0 <= body["flows"][0]["confidence"] <= 1.0


def test_key_records_last_used(client, alpha):
    """Needed to spot a leaked key being exercised, and to retire dead ones."""
    created = _mint(client, alpha, "tracked")
    before = next(k for k in client.get("/api/team/keys", cookies=alpha).json()
                  if k["id"] == created["id"])
    assert before["last_used_at"] is None

    client.post("/api/ingest", headers=_auth(created["key"]), json={"flows": [FLOW]})

    after = next(k for k in client.get("/api/team/keys", cookies=alpha).json()
                 if k["id"] == created["id"])
    assert after["last_used_at"] is not None


def test_key_cannot_read_anything_else(client, alpha):
    """The blast radius of a leaked collector key.

    A key sits on an unattended machine, so it must not be a general-purpose
    credential. Ingest is the only door it opens; everything else still demands
    a session cookie.
    """
    created = _mint(client, alpha, "scoped")
    headers = _auth(created["key"])
    for path in ("/api/incidents", "/api/flows", "/api/summary",
                 "/api/team", "/api/settings", "/api/team/keys"):
        r = client.get(path, headers=headers)
        assert r.status_code == 401, f"{path} accepted a collector key ({r.status_code})"


def test_key_cannot_mint_more_keys(client, alpha):
    """Otherwise one leaked key bootstraps into permanent access."""
    created = _mint(client, alpha, "no-escalation")
    r = client.post("/api/team/keys", headers=_auth(created["key"]),
                    json={"label": "escalated"})
    assert r.status_code == 401


# ── rejecting ─────────────────────────────────────────────────────────────
def test_revoked_key_stops_working_immediately(client, alpha):
    created = _mint(client, alpha, "doomed")
    assert client.post("/api/ingest", headers=_auth(created["key"]),
                       json={"flows": [FLOW]}).status_code == 200

    assert client.delete(f"/api/team/keys/{created['id']}",
                         cookies=alpha).status_code == 200

    r = client.post("/api/ingest", headers=_auth(created["key"]),
                    json={"flows": [FLOW]})
    assert r.status_code == 401, "revoked key still ingesting"


def test_revoked_key_is_kept_for_the_audit_trail(client, alpha):
    """Deleting the row would orphan every past log entry naming this key."""
    created = _mint(client, alpha, "kept")
    client.delete(f"/api/team/keys/{created['id']}", cookies=alpha)

    listed = client.get("/api/team/keys", cookies=alpha).json()
    row = next(k for k in listed if k["id"] == created["id"])
    assert row["revoked_at"] is not None
    assert row["is_active"] is False


@pytest.mark.parametrize("bad", [
    "sentry_ak_totally-made-up-value-that-was-never-issued",
    "not-even-the-right-prefix",
    "",
])
def test_garbage_keys_are_refused(client, bad):
    r = client.post("/api/ingest", headers=_auth(bad), json={"flows": [FLOW]})
    assert r.status_code == 401


def test_ingest_without_any_credential_is_refused(client):
    assert client.post("/api/ingest", json={"flows": [FLOW]}).status_code == 401


# ── tenancy ───────────────────────────────────────────────────────────────
def test_one_orgs_key_cannot_revoke_anothers(client, alpha, beta):
    """Sequential ids make this trivially reachable if the org check is missing."""
    victim = _mint(client, alpha, "alpha-key")
    r = client.delete(f"/api/team/keys/{victim['id']}", cookies=beta)
    assert r.status_code == 404, "cross-tenant revocation succeeded"

    still_live = next(k for k in client.get("/api/team/keys", cookies=alpha).json()
                      if k["id"] == victim["id"])
    assert still_live["is_active"] is True


def test_keys_are_not_visible_across_orgs(client, alpha, beta):
    mine = _mint(client, alpha, "alpha-private")
    theirs = client.get("/api/team/keys", cookies=beta).json()
    assert all(k["id"] != mine["id"] for k in theirs)


def test_ingested_flows_land_in_the_keys_own_org(client, alpha, beta):
    """The whole point of scoping a key to an org.

    If a key wrote into the wrong tenant it would be both a data leak and a
    false alarm in someone else's console.
    """
    created = _mint(client, beta, "beta-collector")
    marker = "203.0.113.77"
    r = client.post("/api/ingest", headers=_auth(created["key"]),
                    json={"flows": [dict(FLOW, src_ip=marker)]})
    assert r.status_code == 200, r.text

    in_beta = client.get("/api/flows?limit=200", cookies=beta).json()
    assert any(f["src_ip"] == marker for f in in_beta)

    in_alpha = client.get("/api/flows?limit=200", cookies=alpha).json()
    assert all(f["src_ip"] != marker for f in in_alpha)


def test_a_real_collector_flow_survives_the_whole_pipeline(client, alpha):
    """Packet → flow table → ingest → model → dashboard, end to end.

    Every other test checks one link. This one checks that the collector and the
    server, which are separate programs that never import each other, actually
    agree — a flow built by the real aggregation code is posted with a real key
    and comes back out scored.
    """
    from .test_collector import LOCAL, collector, ipv4

    table = collector.FlowTable(LOCAL)
    for _ in range(900):
        table.observe(ipv4("198.51.100.42", "10.0.0.5", size=1400, dport=80))
    (flow,) = table.expire(force=True)
    flow["node"] = "COLLECTOR-01"

    created = _mint(client, alpha, "e2e-collector")
    r = client.post("/api/ingest", headers=_auth(created["key"]),
                    json={"flows": [flow]})
    assert r.status_code == 200, r.text

    listed = client.get("/api/flows?limit=200", cookies=alpha).json()
    scored = next(f for f in listed if f["src_ip"] == "198.51.100.42")
    assert scored["node"] == "COLLECTOR-01"
    assert scored["packets"] == 900
    # The model has to have said something about it — an unscored flow reaching
    # the dashboard would be a silent hole in the detection path.
    assert scored["prediction"]
    assert 0.0 <= scored["confidence"] <= 1.0
