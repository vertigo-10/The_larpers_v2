"""Exporter registration, discovery scoping, and one real UDP round trip.

Two things are being proven here.

The first is the tenancy boundary. NetFlow attributes traffic to an org purely
by the source IP of a UDP packet, so the registration endpoints are the entire
access-control surface for flow ingest. If an org could register an address
another org already holds, or could see unclaimed addresses it has no
relationship with, the product would leak one customer's network metadata to
another.

The second is that the whole path actually joins up: a datagram on a socket
becomes a row in `flows` with a prediction on it. Every layer is unit tested
above, but they are wired together by convention — a renamed dict key would
pass every other test in the suite and produce silence in production.
"""

import asyncio
import os
import socket
import tempfile

import pytest

_TMP_DB = os.path.join(tempfile.mkdtemp(), "netflow_api.db")
os.environ["SENTRY_DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SENTRY_SIMULATOR_ENABLED"] = "false"
os.environ["SENTRY_SIGNUP_MAX_PER_WINDOW"] = "100000"
os.environ["SENTRY_SECRET_KEY"] = "test-key-not-used-in-production-abcdefghijklmnop"
os.environ["SENTRY_MODEL_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "artifacts"
)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select  # noqa: E402

from backend.app.config import settings  # noqa: E402
from backend.app.db import SessionLocal, init_db  # noqa: E402
from backend.app.main import app  # noqa: E402
from backend.app.models import Flow, FlowExporter, UnclaimedExporter  # noqa: E402
from backend.app.netflow.collector import FlowCollector  # noqa: E402

from .test_netflow_parser import build_v5, ip_to_int  # noqa: E402

GOOD_PW = "correct-horse-battery-staple"


def _free_udp_port() -> int:
    """Ask the kernel for an unused port, then release it.

    Port 0 would be the natural way to say "any free port", but the config
    layer rejects it — 0 in SENTRY_NETFLOW_PORTS is a misconfiguration in
    production, and weakening that validator to make a test easier would be
    the wrong trade.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


def _signup(client, email, org_name):
    r = client.post("/api/auth/signup", json={
        "email": email, "password": GOOD_PW, "name": "Admin",
        "org_name": org_name, "org_type": "company",
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()
    return cookies


@pytest.fixture(scope="module")
def alpha(client):
    return _signup(client, "netflow-alpha@example.com", "NetFlow Alpha")


@pytest.fixture(scope="module")
def beta(client):
    return _signup(client, "netflow-beta@example.com", "NetFlow Beta")


# ── registration ──────────────────────────────────────────────────────────
def test_register_and_list_an_exporter(client, alpha):
    r = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "203.0.113.10", "name": "Edge firewall",
        "node_label": "EDGE-FW", "sampling_rate": 1000,
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["source_ip"] == "203.0.113.10"
    assert body["sampling_rate"] == 1000
    # Nothing has arrived yet, and the UI needs to say that rather than imply
    # a fault.
    assert body["state"] == "waiting"
    assert body["version"] == ""

    listed = client.get("/api/exporters", cookies=alpha).json()
    assert "203.0.113.10" in [e["source_ip"] for e in listed]


def test_a_hostname_is_rejected(client, alpha):
    """The collector matches a packet's literal source address.

    Accepting a name would mean a DNS lookup on the receive path — too slow for
    the event loop, and it would let whoever controls that record decide which
    org a stranger's traffic is attributed to.
    """
    r = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "firewall.example.com", "name": "By name",
    })
    assert r.status_code == 422


def test_sampling_rate_must_be_at_least_one(client, alpha):
    r = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "203.0.113.44", "sampling_rate": 0,
    })
    assert r.status_code == 422


def test_a_second_org_cannot_register_an_address_already_claimed(client, alpha, beta):
    """The core tenancy guarantee: one address resolves to exactly one org.

    Without this, org B registers org A's firewall IP and the collector has two
    candidate owners for every packet from it — and whichever it picks, someone
    is reading traffic that is not theirs.
    """
    client.post("/api/exporters", cookies=alpha, json={"source_ip": "203.0.113.20"})
    r = client.post("/api/exporters", cookies=beta, json={"source_ip": "203.0.113.20"})

    assert r.status_code == 409
    # And the refusal must not confirm who holds it.
    assert "Alpha" not in r.text


def test_an_org_cannot_see_another_orgs_exporters(client, alpha, beta):
    client.post("/api/exporters", cookies=alpha, json={"source_ip": "203.0.113.30"})
    listed = client.get("/api/exporters", cookies=beta).json()
    assert "203.0.113.30" not in [e["source_ip"] for e in listed]


def test_an_org_cannot_modify_another_orgs_exporter(client, alpha, beta):
    created = client.post(
        "/api/exporters", cookies=alpha, json={"source_ip": "203.0.113.31"}
    ).json()

    r = client.patch(f"/api/exporters/{created['id']}", cookies=beta,
                     json={"name": "stolen"})
    # 404, not 403 — a 403 would confirm the row exists.
    assert r.status_code == 404

    r = client.delete(f"/api/exporters/{created['id']}", cookies=beta)
    assert r.status_code == 404


def test_update_and_delete(client, alpha):
    created = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "203.0.113.40", "name": "Before",
    }).json()

    r = client.patch(f"/api/exporters/{created['id']}", cookies=alpha, json={
        "name": "After", "enabled": False,
    })
    assert r.status_code == 200
    assert r.json()["name"] == "After"
    assert r.json()["state"] == "disabled"

    assert client.delete(
        f"/api/exporters/{created['id']}", cookies=alpha
    ).status_code == 204
    listed = client.get("/api/exporters", cookies=alpha).json()
    assert "203.0.113.40" not in [e["source_ip"] for e in listed]


# ── registry invalidation ─────────────────────────────────────────────────
# The collector answers "is this sender ours?" from an in-memory registry that
# it reloads on a thirty-second timer, because that question is asked once per
# datagram and cannot be a query. So every write on this router has to poke it.
#
# The symptom when this is missing is nastier than a delay. An operator claims
# a device, the dashboard shows it stuck at "waiting", and the
# unregistered-drop counter keeps climbing — which is precisely what a wrong
# source address looks like. They go and change a configuration that was
# already correct. These tests exist because that failure is invisible from
# every other test in this file: the HTTP responses are all completely normal.
class _SpyCollector:
    """Just the surface the router touches."""

    def __init__(self):
        self.invalidations = 0

    def invalidate_registry(self):
        self.invalidations += 1


@pytest.fixture
def spy_collector(monkeypatch):
    spy = _SpyCollector()
    monkeypatch.setattr(
        "backend.app.routers.exporters.get_collector", lambda: spy
    )
    return spy


def test_registering_a_device_reaches_the_collector(client, alpha, spy_collector):
    r = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "203.0.113.70", "name": "Fresh",
    })
    assert r.status_code == 201, r.text
    assert spy_collector.invalidations == 1, (
        "the collector was never told about the new registration, so its "
        "packets stay dropped as unregistered until the refresh timer fires"
    )


def test_disabling_a_device_reaches_the_collector(client, alpha, spy_collector):
    created = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "203.0.113.71",
    }).json()
    spy_collector.invalidations = 0

    client.patch(f"/api/exporters/{created['id']}", cookies=alpha,
                 json={"enabled": False})
    assert spy_collector.invalidations == 1, (
        "a device the operator has been shown as disabled would keep being "
        "ingested until the registry happened to reload"
    )


def test_deleting_a_device_reaches_the_collector(client, alpha, spy_collector):
    created = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "203.0.113.72",
    }).json()
    spy_collector.invalidations = 0

    client.delete(f"/api/exporters/{created['id']}", cookies=alpha)
    assert spy_collector.invalidations == 1


def test_a_patch_that_changes_nothing_does_not_disturb_the_collector(
    client, alpha, spy_collector
):
    """Reloading the registry drops nothing, but it is a database round trip
    on a shared cache. A no-op PATCH should not buy one."""
    created = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "203.0.113.73", "name": "Steady",
    }).json()
    spy_collector.invalidations = 0

    r = client.patch(f"/api/exporters/{created['id']}", cookies=alpha, json={})
    assert r.status_code == 200
    assert spy_collector.invalidations == 0


def test_registration_works_with_no_collector_running(client, alpha, monkeypatch):
    """NetFlow ingest is optional, and these routes must not require it.

    A deployment with the collector switched off still manages exporters —
    ahead of turning it on, most obviously — so the invalidation hook has to
    tolerate there being nothing to invalidate.
    """
    monkeypatch.setattr(
        "backend.app.routers.exporters.get_collector", lambda: None
    )
    r = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "203.0.113.74",
    })
    assert r.status_code == 201, r.text


def test_invalidating_survives_a_freshly_booted_clock():
    """`invalidate_registry` must mark the cache stale on any machine.

    time.monotonic() has an undefined epoch. Setting the load time to 0.0 would
    read as stale only once the host had been up longer than the refresh
    window, so on a box that just booted — a container, say, which is the
    normal case — a claim would silently not take effect.
    """
    collector = FlowCollector()
    collector._registry_loaded_at = 1.0     # a clock that started moments ago
    collector.invalidate_registry()

    assert collector._registry_loaded_at < 1.0 - 30.0, (
        "the registry is not marked stale relative to a small monotonic clock"
    )


def test_registration_is_written_to_the_audit_trail(client, alpha):
    """Registering an exporter is a tenancy decision, so it is on the record."""
    client.post("/api/exporters", cookies=alpha, json={"source_ip": "203.0.113.50"})
    entries = client.get("/api/team/audit", cookies=alpha).json()

    created = [e for e in entries if e["action"] == "exporter.created"]
    assert created
    assert any("203.0.113.50" in e["detail"] for e in created)


def test_registration_requires_admin(client, alpha):
    """Deciding whose traffic we ingest is not an analyst-level change."""
    r = client.post("/api/exporters", json={"source_ip": "203.0.113.60"})
    assert r.status_code == 401


# ── discovery scoping ─────────────────────────────────────────────────────
def _seed_unclaimed(source_ip):
    db = SessionLocal()
    try:
        existing = db.scalar(
            select(UnclaimedExporter).where(
                UnclaimedExporter.source_ip == source_ip)
        )
        if existing is None:
            db.add(UnclaimedExporter(source_ip=source_ip, version="v5",
                                     packets_received=3))
            db.commit()
    finally:
        db.close()


def test_unclaimed_sources_you_have_no_relationship_with_are_invisible(client, alpha):
    """An unfiltered discovery list is a cross-tenant leak.

    It would expose other customers' edge addresses, and let anyone claim one.
    """
    _seed_unclaimed("198.51.100.200")
    visible = client.get("/api/exporters/unclaimed", cookies=alpha).json()
    assert "198.51.100.200" not in [u["source_ip"] for u in visible]


def test_an_unclaimed_source_next_to_your_own_device_is_visible(client, alpha):
    """A second firewall in the rack beside one you already registered."""
    client.post("/api/exporters", cookies=alpha, json={"source_ip": "203.0.113.70"})
    _seed_unclaimed("203.0.113.71")

    visible = client.get("/api/exporters/unclaimed", cookies=alpha).json()
    assert "203.0.113.71" in [u["source_ip"] for u in visible]


def test_adjacency_does_not_span_a_whole_isp(client, alpha):
    """/24, not /16. Wider and it would match unrelated customers."""
    client.post("/api/exporters", cookies=alpha, json={"source_ip": "203.0.113.80"})
    _seed_unclaimed("203.0.199.80")

    visible = client.get("/api/exporters/unclaimed", cookies=alpha).json()
    assert "203.0.199.80" not in [u["source_ip"] for u in visible]


class _FromAddress:
    """ASGI shim that makes requests appear to come from a given address.

    This version of TestClient hardcodes the client as "testclient", and the
    address the admin is browsing from is precisely what the discovery filter
    keys on — stubbing the extraction helper instead would test everything
    except the thing in question.
    """

    def __init__(self, app, ip):
        self._app = app
        self._ip = ip

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope)
            scope["client"] = (self._ip, 40000)
        await self._app(scope, receive, send)


def test_you_can_see_a_source_exporting_from_the_address_you_browse_from(alpha):
    """The common case: the firewall NATs out of the same IP as the admin.

    That is the ownership proof — you can only see it if you are on that
    network.
    """
    _seed_unclaimed("192.0.2.123")
    # Not used as a context manager on purpose: that would run the app's
    # lifespan a second time alongside the module-scoped client.
    c = TestClient(_FromAddress(app, "192.0.2.123"))
    visible = c.get("/api/exporters/unclaimed", cookies=alpha).json()
    assert "192.0.2.123" in [u["source_ip"] for u in visible]


def test_the_same_source_stays_hidden_from_an_admin_elsewhere(client, alpha):
    """The mirror of the test above — the filter is doing real work."""
    _seed_unclaimed("192.0.2.124")
    visible = client.get("/api/exporters/unclaimed", cookies=alpha).json()
    assert "192.0.2.124" not in [u["source_ip"] for u in visible]


def test_claiming_an_unclaimed_source_removes_it_from_the_list(client, alpha):
    _seed_unclaimed("203.0.113.90")
    client.post("/api/exporters", cookies=alpha, json={"source_ip": "203.0.113.90"})

    db = SessionLocal()
    try:
        assert db.scalar(select(UnclaimedExporter).where(
            UnclaimedExporter.source_ip == "203.0.113.90")) is None
    finally:
        db.close()


# ── status ────────────────────────────────────────────────────────────────
def test_status_reports_the_collector_as_off_when_it_is(client, alpha):
    body = client.get("/api/exporters/status", cookies=alpha).json()
    assert body["enabled"] is False
    assert body["listening"] is False
    assert body["ports"] == []
    assert body["exporters"] >= 1


# ── end to end over a real socket ─────────────────────────────────────────
def test_a_udp_datagram_becomes_a_scored_flow(client, alpha, monkeypatch):
    """The one test that proves the layers are actually joined up.

    Binds a real socket on an ephemeral port, sends a real NetFlow v5 packet
    over the loopback, and looks for the resulting row in `flows`. Everything
    in between — registry lookup, decode, feature extraction, inference,
    persistence — runs for real.
    """
    r = client.post("/api/exporters", cookies=alpha, json={
        "source_ip": "127.0.0.1", "name": "Loopback", "node_label": "E2E-NODE",
    })
    assert r.status_code == 201

    db = SessionLocal()
    try:
        exporter = db.scalar(
            select(FlowExporter).where(FlowExporter.source_ip == "127.0.0.1")
        )
        org_id = exporter.org_id
        before = len(db.scalars(
            select(Flow.id).where(Flow.org_id == org_id)).all())
    finally:
        db.close()

    monkeypatch.setattr(settings, "netflow_ports", str(_free_udp_port()))
    monkeypatch.setattr(settings, "netflow_bind_host", "127.0.0.1")
    monkeypatch.setattr(settings, "netflow_flush_interval_s", 0.05)

    packet = build_v5([{
        "src": ip_to_int("198.51.100.77"), "dst": ip_to_int("10.0.0.5"),
        "packets": 900, "octets": 54000, "first": 1_000, "last": 3_000,
        "src_port": 53124, "dst_port": 445, "proto": 6,
    }])

    async def scenario():
        collector = FlowCollector()
        await collector.start()
        assert collector.listening, "collector did not bind"

        port = collector._transports[0].get_extra_info("socket").getsockname()[1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(packet, ("127.0.0.1", port))
            # UDP delivery is not synchronous with send even on loopback; yield
            # until the event loop has actually run the receive callback.
            for _ in range(200):
                await asyncio.sleep(0.01)
                if collector.stats["packets"]:
                    break
        finally:
            sock.close()

        await collector.stop()   # stop() drains, so no flow is lost
        return collector

    loop = asyncio.new_event_loop()
    try:
        collector = loop.run_until_complete(scenario())
    finally:
        loop.close()

    assert collector.stats["packets"] == 1, "the datagram never arrived"
    assert collector.stats["dropped_unregistered"] == 0, "source was not resolved"
    assert collector.stats["flows"] == 1

    db = SessionLocal()
    try:
        rows = db.scalars(
            select(Flow).where(Flow.org_id == org_id, Flow.source == "live")
            .order_by(Flow.id.desc())
        ).all()
        assert len(rows) == before + 1 or rows, "no flow row was written"

        flow = rows[0]
        assert flow.src_ip == "198.51.100.77"
        assert flow.dst_port == 445
        assert flow.protocol == "TCP"
        assert flow.node == "E2E-NODE"
        assert flow.packets == 900
        assert flow.total_bytes == 54000
        assert flow.duration == pytest.approx(2.0)
        # The model ran. Which label it chose is not this test's business —
        # that it produced one, with a real confidence, is.
        assert flow.prediction
        assert 0.0 < flow.confidence <= 1.0

        # And the exporter's own counters were written back.
        exporter = db.scalar(
            select(FlowExporter).where(FlowExporter.source_ip == "127.0.0.1")
        )
        assert exporter.packets_received == 1
        assert exporter.flows_received == 1
        assert exporter.version == "v5"
        assert exporter.last_seen_at is not None
    finally:
        db.close()


def test_a_datagram_from_an_unregistered_address_is_recorded_not_scored(
    client, alpha, monkeypatch
):
    """The other half of the guarantee: unknown senders never reach the model."""
    monkeypatch.setattr(settings, "netflow_ports", str(_free_udp_port()))
    monkeypatch.setattr(settings, "netflow_bind_host", "127.0.0.1")
    monkeypatch.setattr(settings, "netflow_flush_interval_s", 0.05)

    packet = build_v5([{
        "src": ip_to_int("198.51.100.99"), "dst": ip_to_int("10.0.0.9"),
        "packets": 10, "octets": 1000, "first": 0, "last": 1000,
        "src_port": 1234, "dst_port": 80, "proto": 6,
    }])

    async def scenario():
        collector = FlowCollector()
        # An empty registry, so loopback is not a registered source here.
        await collector.start()
        collector._registry = {}

        port = collector._transports[0].get_extra_info("socket").getsockname()[1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(packet, ("127.0.0.1", port))
            for _ in range(200):
                await asyncio.sleep(0.01)
                if collector.stats["packets"]:
                    break
        finally:
            sock.close()
        await collector.stop()
        return collector

    loop = asyncio.new_event_loop()
    try:
        collector = loop.run_until_complete(scenario())
    finally:
        loop.close()

    assert collector.stats["dropped_unregistered"] == 1
    assert collector.stats["flows"] == 0

    db = SessionLocal()
    try:
        assert db.scalar(select(UnclaimedExporter).where(
            UnclaimedExporter.source_ip == "127.0.0.1")) is not None
        # Nothing from that packet was scored.
        assert db.scalar(
            select(Flow).where(Flow.src_ip == "198.51.100.99")
        ) is None
    finally:
        db.close()
