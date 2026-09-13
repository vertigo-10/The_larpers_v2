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

import ipaddress  # noqa: E402
import random  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.app import baseline as bl  # noqa: E402
from backend.app.db import SessionLocal, init_db  # noqa: E402
from backend.app.engine import (  # noqa: E402
    FlowGenerator, _generator_for, _generators,
)
from backend.app.main import app  # noqa: E402
from backend.app.models import Flow, Node  # noqa: E402

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


# ── simulated slow DoS ────────────────────────────────────────────────────
# The detector added alongside these tests groups flows by (source, target,
# port). If the simulator never produces such a group the rule is dead code in
# every demo and every dev environment, and nothing else in the suite would
# notice: the API tests post their own flows, and the detector's own tests
# construct rows by hand. These cover the seam between the two.

# One 300s baseline window at the default 1200ms tick.
_WINDOW_TICKS = 250


def _run_window(gen, ticks=_WINDOW_TICKS):
    """Flows a generator emits over one baseline window."""
    out = []
    for _ in range(ticks):
        out.extend(gen.tick(n=random.randint(1, 3)))
    return out


def test_every_simulated_flow_carries_a_destination():
    """Blank dst_ip is dropped by every detector that groups on the target.

    `slow_dos_groups` filters `Flow.dst_ip != ""` rather than lumping unknown
    destinations under a shared empty string, so a generator that omitted the
    field would not fail loudly — it would just make the rule permanently
    silent on simulated traffic.
    """
    random.seed(4242)
    gen = FlowGenerator(["EDGE-01", "EDGE-02"])
    flows = _run_window(gen, ticks=60)
    assert flows
    missing = [f for f in flows if not f.get("dst_ip")]
    assert not missing, f"{len(missing)} simulated flows had no destination"


def test_a_simulated_slow_dos_trips_the_real_detector(client, org_id):
    """End to end: generator output through the actual grouping query.

    Deliberately calls `slow_dos_groups` rather than re-checking the thresholds
    in Python. Restating the rule in the test would pass just as happily if the
    rule and the generator drifted apart in the same direction, which is the
    failure this exists to catch.
    """
    random.seed(7)
    gen = FlowGenerator(["EDGE-01"])
    flows = _run_window(gen)

    start = datetime(2026, 3, 3, 14, 0, tzinfo=timezone.utc)
    end = start + timedelta(minutes=5)

    db = SessionLocal()
    try:
        for i, f in enumerate(flows):
            db.add(Flow(
                org_id=org_id,
                # Spread across the window; the query is a half-open range.
                ts=start + timedelta(seconds=(i % 290)),
                flow_ref=f["flow_ref"], src_ip=f["src_ip"], dst_ip=f["dst_ip"],
                dst_port=f["dst_port"], protocol=f["protocol"], node=f["node"],
                duration=f["duration"], packets=f["packets"],
                total_bytes=f["total_bytes"],
                bytes_per_sec=f["total_bytes"] / max(f["duration"], 1e-4),
                prediction="normal", confidence=0.9,
                source="simulated", truth=f["truth"],
            ))
        db.commit()

        groups = bl.slow_dos_groups(db, org_id, start, end)
        assert groups, (
            "a full baseline window of simulated traffic produced no slow-DoS "
            "group, so the detector cannot fire in any demo or dev environment"
        )

        g = groups[0]
        assert g["flows"] >= bl.SLOW_DOS_MIN_FLOWS
        assert g["mean_duration"] >= bl.SLOW_DOS_MIN_MEAN_DURATION_S
        assert g["mean_bytes"] <= bl.SLOW_DOS_MAX_MEAN_BYTES
        assert g["packets_per_sec"] <= bl.SLOW_DOS_MAX_PACKETS_PER_SEC

        # The sentence an operator actually reads.
        assert bl.describe_slow_dos(groups)
    finally:
        db.close()


def test_the_slow_dos_source_is_always_publicly_routable():
    """`_ip()` can land in private and documentation space; the rule rejects it.

    `slow_dos_groups` discards any group failing `is_global`, so an attacker
    address drawn from 172.16/12, 192.168/16, 100.64/10 or 203.0.113/24 would
    generate a full campaign and then vanish at the final filter — an
    intermittently missing demo with nothing logged to explain it.
    """
    random.seed(11)
    gen = FlowGenerator(["EDGE-01"])

    # Only about 0.6% of raw `_ip()` draws land in a reserved block, so a
    # handful of samples would let the wiring regress to `_ip()` and still pass
    # most runs. The count is set high enough that swapping the helper out is
    # caught essentially every time rather than one run in three.
    seen = 0
    for _ in range(3000):
        gen.slow_dos = None
        gen.slow_dos_cooldown = 0
        gen._advance_slow_dos()
        assert gen.slow_dos is not None
        addr = gen.slow_dos["src_ip"]
        assert ipaddress.ip_address(addr).is_global, (
            f"campaign source {addr} is not routable, so the detector "
            f"would silently discard the whole campaign"
        )
        # The predicate the rule itself applies, not just a restatement of it.
        assert bl._is_external(addr)
        seen += 1
    assert seen == 3000


def test_a_campaign_keeps_one_target_for_its_whole_life():
    """Re-rolling the triple each tick would scatter it into singleton groups.

    The detector counts flows per (source, target, port). A campaign that
    changed any of the three would never reach the threshold however many
    flows it emitted, and would look like ordinary traffic forever.
    """
    random.seed(99)
    gen = FlowGenerator(["EDGE-01", "EDGE-02"])
    while gen.slow_dos is None:
        gen._advance_slow_dos()

    triple = (gen.slow_dos["src_ip"], gen.slow_dos["dst_ip"],
              gen.slow_dos["dst_port"])
    emitted = []
    for _ in range(120):
        if gen.slow_dos is None:
            break
        emitted.append(gen._slow_dos_flow())
        gen._advance_slow_dos()

    assert len(emitted) > 30
    for f in emitted:
        assert (f["src_ip"], f["dst_ip"], f["dst_port"]) == triple
        # Truth feeds the live agreement rate and the confusion matrix. Judged
        # alone each of these flows really is unremarkable, and the model is
        # right to say so — the attack is only visible in the count.
        assert f["truth"] == "normal"


def test_a_quiet_phase_does_not_suppress_the_campaign():
    """The campaign is independent of the phase machine, and must stay so.

    `p_attack` indexes a three-entry dict by phase, so a slow DoS modelled as
    "phase 3" would raise KeyError on the next flow. It is also the better
    demo: held-open connections during a quiet phase leave the throughput
    chart flat while the incident still appears.
    """
    random.seed(5)
    gen = FlowGenerator(["EDGE-01"])
    while gen.slow_dos is None:
        gen._advance_slow_dos()

    gen.phase = 0
    gen.ticks = 0
    flows = [gen.next_flow() for _ in range(400)]
    campaign = [f for f in flows
                if f["src_ip"] == gen.slow_dos["src_ip"]]
    assert len(campaign) > 100, (
        "a quiet phase starved the campaign, so the flat-chart demo would "
        "show no incident"
    )
    assert gen.phase == 0, "the campaign must not move the phase machine"
