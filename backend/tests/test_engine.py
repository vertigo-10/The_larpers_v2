"""Simulator generator lifecycle.

Exercised directly rather than through the API because the property that
matters — that a generator is rebuilt when the topology changes and *only*
then — is invisible from any HTTP response.
"""

import os
import tempfile

_TMP_DB = os.path.join(tempfile.mkdtemp(), "engine.db")
os.environ["SENTRY_DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SENTRY_SIMULATOR_ENABLED"] = "false"
os.environ["SENTRY_SIGNUP_MAX_PER_WINDOW"] = "100000"
os.environ["SENTRY_SECRET_KEY"] = "test-key-not-used-in-production-abcdefghijklmnop"
os.environ["SENTRY_MODEL_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "artifacts"
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.app.db import SessionLocal, init_db  # noqa: E402
from backend.app.engine import _generator_for, _generators  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Node  # noqa: E402

GOOD_PW = "correct-horse-battery-staple"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def org_id(client):
    """A fresh org, so no test inherits another's node topology."""
    email = f"gen{os.urandom(4).hex()}@alpha.example.com"
    r = client.post("/api/auth/signup", json={
        "email": email, "password": GOOD_PW, "name": "Gen Admin",
        "org_name": f"Gen {email}", "org_type": "company",
    })
    assert r.status_code == 201, r.text
    client.cookies.clear()
    oid = r.json()["org_id"]
    _generators.pop(oid, None)
    return oid


def test_a_new_node_reaches_the_generator(org_id):
    """A node registered after startup must show up in simulated traffic.

    Nodes are auto-registered from live traffic, so this happens without any
    node-management call to hang an invalidation off. The cache used to be
    populated once and never refreshed, which meant a generator built at boot
    kept emitting for the seeded topology forever — a real collector could
    report a device and the simulator would never mention it again.
    """
    db = SessionLocal()
    try:
        first = _generator_for(db, org_id)
        assert "MACBOOK-JUDE" not in first.nodes

        db.add(Node(org_id=org_id, label="MACBOOK-JUDE",
                    description="Detected from live traffic"))
        db.commit()

        second = _generator_for(db, org_id)
        assert "MACBOOK-JUDE" in second.nodes
    finally:
        db.close()


def test_an_unchanged_topology_reuses_the_same_generator(org_id):
    """Rebuilding resets the attack-phase state machine, so it must be rare.

    The label set is re-read every tick to notice changes. If that comparison
    were wrong — comparing an unordered query as a list, say — the generator
    would be rebuilt on every tick, `phase` would reset to quiet before it
    could ever advance, and the dashboard would flatline while looking healthy.
    """
    db = SessionLocal()
    try:
        first = _generator_for(db, org_id)
        for _ in range(5):
            assert _generator_for(db, org_id) is first
    finally:
        db.close()


def test_a_renamed_node_does_not_linger_in_the_generator(org_id):
    """Renaming must remove the old label, not just add the new one."""
    db = SessionLocal()
    try:
        row = db.query(Node).filter(
            Node.org_id == org_id, Node.label == "EDGE-01"
        ).one()
        _generator_for(db, org_id)

        row.label = "EDGE-RENAMED"
        db.commit()

        gen = _generator_for(db, org_id)
        assert "EDGE-RENAMED" in gen.nodes
        assert "EDGE-01" not in gen.nodes, (
            "the generator kept emitting a label that no longer exists — those "
            "flows would auto-register the deleted node right back"
        )
    finally:
        db.close()


def test_generators_are_isolated_per_org(client, org_id):
    """One org's topology must never leak into another's simulated traffic."""
    other = client.post("/api/auth/signup", json={
        "email": f"gen2{os.urandom(4).hex()}@beta.example.com",
        "password": GOOD_PW, "name": "Gen Admin 2",
        "org_name": "Gen Beta", "org_type": "consumer",
    })
    assert other.status_code == 201, other.text
    client.cookies.clear()
    other_id = other.json()["org_id"]

    db = SessionLocal()
    try:
        a = _generator_for(db, org_id)
        b = _generator_for(db, other_id)
        assert a is not b
        assert set(a.nodes).isdisjoint(b.nodes)
    finally:
        db.close()
