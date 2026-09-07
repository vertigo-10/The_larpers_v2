"""The collector's receive path, with no sockets and no database.

`handle_datagram` runs on the event loop for every packet that arrives on an
unauthenticated UDP port, which makes it the highest-risk function in the
ingest path: it is the one an attacker can call, at whatever rate they like,
with whatever bytes they choose. So it is tested in isolation, by driving it
directly with a hand-built registry, rather than only through the end-to-end
path where a failure is harder to attribute.

What matters here is not that good packets decode — the parser suite already
proves that. It is that bad ones cost us a bounded amount of memory and CPU,
and that one tenant's traffic can never land in another's buffer.
"""

import pytest

from backend.app.config import settings
from backend.app.netflow.collector import (
    FlowCollector,
    _ExporterState,
    flow_record_to_dict,
)
from backend.app.netflow.parser import FlowRecord, TemplateCache

from .test_netflow_parser import (
    V9_FIELDS,
    _data_set,
    _template_set,
    _v9_payload,
    build_ipfix,
    build_v5,
    build_v9,
    ip_to_int,
)


def _flow(**kw):
    base = {
        "src": ip_to_int("203.0.113.9"), "dst": ip_to_int("10.0.0.1"),
        "packets": 10, "octets": 1000, "first": 0, "last": 1000,
        "src_port": 40000, "dst_port": 443, "proto": 6,
    }
    base.update(kw)
    return base


def v9_template():
    return build_v9([_template_set(256, V9_FIELDS, set_id=0)])


def v9_data(src="203.0.113.9"):
    return build_v9([_data_set(256, _v9_payload(
        src, "192.0.2.1", 40000, 443, 6, 120, 9600, 5_000, 8_000))])


def make_collector(exporters=None, on_scored=None):
    """A collector with a registry injected, so nothing touches the database."""
    c = FlowCollector(on_scored=on_scored)
    c._registry = {}
    for source_ip, org_id, node, rate, ex_id in exporters or []:
        c._registry[source_ip] = _ExporterState(
            exporter_id=ex_id, org_id=org_id, node_label=node,
            sampling_rate=rate, templates=TemplateCache(),
        )
    c._registry_loaded_at = 1e12  # far future: never auto-refresh mid-test
    return c


ONE_EXPORTER = [("203.0.113.5", 7, "EDGE-FW", 1, 1)]


# ── the happy path ────────────────────────────────────────────────────────
def test_registered_source_buffers_flows_against_its_org():
    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(build_v5([_flow()]), "203.0.113.5")

    assert list(c._buffers.keys()) == [7]
    assert len(c._buffers[7]) == 1
    assert c._buffers[7][0]["node"] == "EDGE-FW"
    assert c._buffers[7][0]["src_ip"] == "203.0.113.9"
    assert c.stats["flows"] == 1


def test_exporter_counters_accumulate_between_flushes():
    c = make_collector(ONE_EXPORTER)
    for _ in range(3):
        c.handle_datagram(build_v5([_flow(), _flow()]), "203.0.113.5")

    state = c._registry["203.0.113.5"]
    assert state.packets == 3
    assert state.flows == 6
    assert state.version == "v5"
    assert state.last_seen_at is not None


def test_version_is_learned_from_the_wire_not_configured():
    c = make_collector([("198.51.100.1", 1, "n", 1, 1), ("198.51.100.2", 1, "n", 1, 2)])
    c.handle_datagram(build_v5([_flow()]), "198.51.100.1")
    c.handle_datagram(build_ipfix([]), "198.51.100.2")

    assert c._registry["198.51.100.1"].version == "v5"
    assert c._registry["198.51.100.2"].version == "ipfix"


def test_per_exporter_sampling_rate_scales_the_counters():
    c = make_collector([("203.0.113.5", 7, "EDGE-FW", 1000, 1)])
    c.handle_datagram(build_v5([_flow(packets=3, octets=300)]), "203.0.113.5")

    flow = c._buffers[7][0]
    assert flow["packets"] == 3000
    assert flow["total_bytes"] == 300_000


# ── tenant isolation ──────────────────────────────────────────────────────
def test_two_exporters_never_share_a_buffer():
    """The whole multi-tenant guarantee reduces to this one mapping."""
    c = make_collector([
        ("203.0.113.5", 7, "ALPHA-EDGE", 1, 1),
        ("203.0.113.6", 99, "BETA-EDGE", 1, 2),
    ])
    c.handle_datagram(build_v5([_flow(src=ip_to_int("1.1.1.1"))]), "203.0.113.5")
    c.handle_datagram(build_v5([_flow(src=ip_to_int("2.2.2.2"))]), "203.0.113.6")

    assert [f["src_ip"] for f in c._buffers[7]] == ["1.1.1.1"]
    assert [f["src_ip"] for f in c._buffers[99]] == ["2.2.2.2"]
    assert c._buffers[7][0]["node"] == "ALPHA-EDGE"
    assert c._buffers[99][0]["node"] == "BETA-EDGE"


def test_template_state_is_not_shared_between_exporters():
    """Two devices behind separate NATs routinely both use template ID 256.

    If one cache were shared, the second exporter's template would silently
    overwrite the first and its flows would decode into the wrong fields —
    wrong ports, wrong byte counts, wrong verdicts, no error anywhere.
    """
    c = make_collector([
        ("203.0.113.5", 7, "ALPHA", 1, 1),
        ("203.0.113.6", 99, "BETA", 1, 2),
    ])
    # Only the first exporter is taught a template.
    c.handle_datagram(v9_template(), "203.0.113.5")

    assert len(c._registry["203.0.113.5"].templates) == 1
    assert len(c._registry["203.0.113.6"].templates) == 0


# ── unregistered sources ──────────────────────────────────────────────────
def test_unregistered_source_is_recorded_but_never_scored():
    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(build_v5([_flow()]), "192.0.2.77")

    assert c._buffers == {}
    assert c.stats["dropped_unregistered"] == 1
    assert "192.0.2.77" in c._unclaimed
    assert c._unclaimed["192.0.2.77"].version == "v5"


def test_unclaimed_set_is_bounded(monkeypatch):
    monkeypatch.setattr(settings, "netflow_max_unclaimed", 5)
    c = make_collector(ONE_EXPORTER)
    for i in range(50):
        c.handle_datagram(build_v5([_flow()]), f"192.0.2.{i}")

    assert len(c._unclaimed) == 5


def test_a_flood_of_new_sources_cannot_evict_a_known_one(monkeypatch):
    """Eviction would be the lever a spoofer pulls to hide a real device."""
    monkeypatch.setattr(settings, "netflow_max_unclaimed", 3)
    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(build_v5([_flow()]), "192.0.2.1")
    for i in range(100, 150):
        c.handle_datagram(build_v5([_flow()]), f"192.0.2.{i}")

    assert "192.0.2.1" in c._unclaimed


# ── bounds under hostile load ─────────────────────────────────────────────
def test_per_source_rate_limit_stops_parsing(monkeypatch):
    monkeypatch.setattr(settings, "netflow_max_packets_per_source", 10)
    c = make_collector(ONE_EXPORTER)
    for _ in range(100):
        c.handle_datagram(build_v5([_flow()]), "203.0.113.5")

    assert len(c._buffers[7]) == 10
    assert c.stats["dropped_rate_limited"] == 90


def test_rate_limit_budget_resets_each_flush_window(monkeypatch):
    monkeypatch.setattr(settings, "netflow_max_packets_per_source", 2)
    c = make_collector(ONE_EXPORTER)
    for _ in range(5):
        c.handle_datagram(build_v5([_flow()]), "203.0.113.5")
    assert len(c._buffers[7]) == 2

    c._packets_this_window.clear()  # what _flush() does
    for _ in range(5):
        c.handle_datagram(build_v5([_flow()]), "203.0.113.5")
    assert len(c._buffers[7]) == 4


def test_one_noisy_exporter_does_not_spend_anothers_budget(monkeypatch):
    monkeypatch.setattr(settings, "netflow_max_packets_per_source", 3)
    c = make_collector([
        ("203.0.113.5", 7, "ALPHA", 1, 1),
        ("203.0.113.6", 99, "BETA", 1, 2),
    ])
    for _ in range(50):
        c.handle_datagram(build_v5([_flow()]), "203.0.113.5")
    c.handle_datagram(build_v5([_flow()]), "203.0.113.6")

    assert len(c._buffers[99]) == 1


def test_buffer_cap_drops_the_overflow_and_counts_it(monkeypatch):
    monkeypatch.setattr(settings, "netflow_max_buffered_flows", 25)
    monkeypatch.setattr(settings, "netflow_max_packets_per_source", 100_000)
    c = make_collector(ONE_EXPORTER)
    for _ in range(10):
        c.handle_datagram(build_v5([_flow()] * 10), "203.0.113.5")

    assert len(c._buffers[7]) == 25
    assert c.stats["dropped_buffer_full"] == 75


def test_a_full_buffer_does_not_starve_another_org(monkeypatch):
    """The cap is per org, so a loud tenant cannot silence a quiet one."""
    monkeypatch.setattr(settings, "netflow_max_buffered_flows", 5)
    c = make_collector([
        ("203.0.113.5", 7, "ALPHA", 1, 1),
        ("203.0.113.6", 99, "BETA", 1, 2),
    ])
    c.handle_datagram(build_v5([_flow()] * 50), "203.0.113.5")
    c.handle_datagram(build_v5([_flow()]), "203.0.113.6")

    assert len(c._buffers[7]) == 5
    assert len(c._buffers[99]) == 1


# ── hostile and malformed input ───────────────────────────────────────────
@pytest.mark.parametrize("payload", [
    b"",
    b"\x00",
    b"\xff" * 4,
    b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    b"\x00\x05" + b"\x00" * 6,          # v5 header truncated
    b"\x00\x09" + b"\xff" * 400,        # v9 with garbage sets
    b"\x00\x0a\xff\xff" + b"\x00" * 12,  # ipfix claiming 65535 bytes
    bytes(range(256)) * 8,
])
def test_hostile_payloads_never_raise(payload):
    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(payload, "203.0.113.5")  # must not raise
    assert c.stats["packets"] == 1


def test_a_malformed_packet_leaves_an_explanation_on_the_exporter():
    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(b"\x00\x05\xff\xff", "203.0.113.5")

    assert c.stats["malformed"] == 1
    assert c._registry["203.0.113.5"].last_error


def test_awaiting_template_is_reported_as_normal_not_as_an_error():
    """A fresh v9 session is deaf until the first template. Say so kindly."""
    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(v9_data(), "203.0.113.5")

    msg = c._registry["203.0.113.5"].last_error
    assert c.stats["awaiting_template"] == 1
    assert "template" in msg.lower()
    assert "normal" in msg.lower()


def test_the_error_clears_once_the_template_arrives():
    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(v9_data(), "203.0.113.5")
    assert c._registry["203.0.113.5"].last_error

    c.handle_datagram(v9_template(), "203.0.113.5")
    assert c._registry["203.0.113.5"].last_error == ""


def test_an_exception_in_decoding_is_contained(monkeypatch):
    """The receive callback is a boundary: a bug must cost one packet, not the loop."""
    import backend.app.netflow.collector as mod

    def boom(*_a, **_kw):
        raise ValueError("simulated decoder bug")

    monkeypatch.setattr(mod, "parse_packet", boom)
    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(build_v5([_flow()]), "203.0.113.5")  # must not raise
    assert c._buffers == {}


# ── the contract with the scoring pipeline ────────────────────────────────
def test_flow_dict_carries_every_field_the_model_reads():
    """The parser and the feature extractor are joined only by this dict.

    `flow_to_features` reads six keys off it. If a rename on either side broke
    the join, the symptom would be a model silently scoring zeros rather than
    an error, so the shape is asserted explicitly.
    """
    from backend.app.ml.features import flow_to_features

    rec = FlowRecord(
        src_ip="203.0.113.9", dst_ip="10.0.0.1", src_port=40000,
        dst_port=443, protocol=6, packets=120, octets=48000, duration_s=2.0,
    )
    d = flow_record_to_dict(rec, "EDGE-FW")

    assert d["src_ip"] == "203.0.113.9"
    assert d["dst_port"] == 443
    assert d["protocol"] == "TCP"
    assert d["node"] == "EDGE-FW"
    assert d["duration"] == 2.0
    assert d["packets"] == 120
    assert d["total_bytes"] == 48000.0
    assert d["bytes_per_sec"] == 24000.0
    assert d["truth"] is None

    feats = flow_to_features(d)
    assert len(feats) == 6
    assert all(isinstance(f, float) for f in feats)


def test_a_zero_duration_flow_cannot_divide_by_zero():
    """Exporters emit these constantly — any flow of a single packet."""
    rec = FlowRecord(packets=1, octets=64, duration_s=0.0)
    d = flow_record_to_dict(rec, "n")

    assert d["duration"] > 0
    assert d["bytes_per_sec"] == pytest.approx(64.0 / d["duration"])


# ── registry refresh ──────────────────────────────────────────────────────
def test_a_registry_refresh_keeps_learned_templates(monkeypatch):
    """v9 exporters resend templates every few minutes.

    The registry reloads every thirty seconds. If that discarded the template
    cache, most data sets would be undecodable for most of their life and the
    device would look permanently broken.
    """
    import asyncio

    c = make_collector(ONE_EXPORTER)
    c.handle_datagram(v9_template(), "203.0.113.5")
    assert len(c._registry["203.0.113.5"].templates) == 1

    monkeypatch.setattr(
        FlowCollector, "_load_registry_rows",
        staticmethod(lambda: [(1, 7, "203.0.113.5", "EDGE-FW", 1)]),
    )
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        c._refresh_registry()
    )

    assert len(c._registry["203.0.113.5"].templates) == 1
    # And data arriving after the refresh still decodes against it.
    c.handle_datagram(v9_data(), "203.0.113.5")
    assert len(c._buffers[7]) == 1


def test_a_disabled_exporter_disappears_from_the_registry(monkeypatch):
    import asyncio

    c = make_collector(ONE_EXPORTER)
    monkeypatch.setattr(
        FlowCollector, "_load_registry_rows", staticmethod(lambda: [])
    )
    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        c._refresh_registry()
    )

    c.handle_datagram(build_v5([_flow()]), "203.0.113.5")
    assert c._buffers == {}
    assert c.stats["dropped_unregistered"] == 1
