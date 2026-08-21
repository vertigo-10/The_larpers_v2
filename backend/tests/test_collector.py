"""Collector agent behaviour, without scapy or a network.

The collector's dependencies are stubbed into `sys.modules` before it is
imported. That is not just convenience: scapy needs root to do anything real,
so a test that required it would be a test nobody runs. Everything worth
checking here — how packets are folded into flows, which direction a flow is
recorded in, when one expires — is pure logic sitting above the capture call.

The load-bearing test is `test_emitted_flow_matches_the_server_schema`. The
collector and the server are separate programs that agree on a wire format by
convention only; if someone renames a field on either side, that test is what
notices.
"""

import importlib
import os
import stat
import sys
import types

import pytest


# ── stub the capture and HTTP dependencies ────────────────────────────────
def _install_stubs():
    if "scapy.all" in sys.modules:
        return

    class IP: pass
    class IPv6: pass
    class TCP: pass
    class UDP: pass

    scapy = types.ModuleType("scapy")
    scapy_all = types.ModuleType("scapy.all")
    scapy_all.IP, scapy_all.IPv6 = IP, IPv6
    scapy_all.TCP, scapy_all.UDP = TCP, UDP
    scapy_all.conf = types.SimpleNamespace(iface="stub0")
    scapy_all.get_if_addr = lambda _iface: "10.0.0.5"
    scapy_all.sniff = lambda **_kw: None
    scapy.all = scapy_all
    sys.modules["scapy"] = scapy
    sys.modules["scapy.all"] = scapy_all

    if "requests" not in sys.modules:
        requests = types.ModuleType("requests")

        class RequestException(Exception): pass

        class Session:
            def __init__(self):
                self.headers = {}
            def post(self, *_a, **_kw):
                raise RequestException("no network in tests")

        requests.RequestException = RequestException
        requests.Session = Session
        sys.modules["requests"] = requests


_install_stubs()

collector = importlib.import_module("agent.sentry_collector")
from scapy.all import IP, IPv6, TCP, UDP  # noqa: E402  (the stubs, installed above)

LOCAL = {"10.0.0.5", "127.0.0.1"}


class FakePacket:
    """Just enough of scapy's Packet to satisfy `_parse`.

    Layers are keyed by class, the way scapy addresses them, so they cannot be
    passed as keyword arguments.
    """

    def __init__(self, layers=None, size=100):
        self._layers = layers or {}
        self._size = size

    def __contains__(self, cls):
        return cls in self._layers

    def __getitem__(self, cls):
        return self._layers[cls]

    def __len__(self):
        return self._size


def ipv4(src, dst, size=100, proto=TCP, sport=54321, dport=443):
    layers = {IP: types.SimpleNamespace(src=src, dst=dst)}
    if proto is not None:
        layers[proto] = types.SimpleNamespace(sport=sport, dport=dport)
    return FakePacket(layers, size=size)


# ── flow orientation ──────────────────────────────────────────────────────
# Incidents are grouped by source address. Recording our own address as the
# source would collapse every attacker in the world into a single row, so the
# direction logic is the part most worth pinning down.
def test_inbound_flow_is_recorded_against_the_remote_sender():
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "10.0.0.5", dport=443))

    (flow,) = table.expire(force=True)
    assert flow["src_ip"] == "203.0.113.9"
    assert flow["dst_port"] == 443


def test_outbound_flow_is_recorded_against_the_remote_destination():
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("10.0.0.5", "198.51.100.7", dport=8080))

    (flow,) = table.expire(force=True)
    assert flow["src_ip"] == "198.51.100.7"


def test_loopback_traffic_is_dropped():
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("127.0.0.1", "10.0.0.5"))

    assert table.expire(force=True) == []
    assert table.ignored_packets == 1


def test_mirrored_traffic_between_two_strangers_is_kept():
    """On a monitor port neither endpoint is ours, and dropping it would make
    the collector useless in exactly the deployment that sees the most."""
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "203.0.113.20", dport=53))

    (flow,) = table.expire(force=True)
    assert flow["src_ip"] == "203.0.113.9"


def test_packets_without_an_ip_layer_are_ignored():
    table = collector.FlowTable(LOCAL)
    table.observe(FakePacket(size=42))  # ARP and friends

    assert table.expire(force=True) == []
    assert table.seen_packets == 0
    assert table.ignored_packets == 1


def test_ipv6_is_captured():
    table = collector.FlowTable({"fe80::1"})
    packet = FakePacket(
        {IPv6: types.SimpleNamespace(src="2001:db8::99", dst="fe80::1"),
         TCP: types.SimpleNamespace(sport=40000, dport=22)},
        size=140,
    )
    table.observe(packet)

    (flow,) = table.expire(force=True)
    assert flow["src_ip"] == "2001:db8::99"
    assert flow["dst_port"] == 22


def test_protocol_falls_back_to_other_without_tcp_or_udp():
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "10.0.0.5", proto=None))  # ICMP-like

    (flow,) = table.expire(force=True)
    assert flow["protocol"] == "OTHER"
    assert flow["dst_port"] == 0


def test_udp_and_tcp_to_the_same_port_are_separate_flows():
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "10.0.0.5", proto=TCP, dport=53))
    table.observe(ipv4("203.0.113.9", "10.0.0.5", proto=UDP, dport=53))

    assert len(table.expire(force=True)) == 2


# ── aggregation ───────────────────────────────────────────────────────────
def test_packets_of_one_conversation_accumulate_into_a_single_flow():
    table = collector.FlowTable(LOCAL)
    for _ in range(5):
        table.observe(ipv4("203.0.113.9", "10.0.0.5", size=200, dport=443))

    (flow,) = table.expire(force=True)
    assert flow["packets"] == 5
    assert flow["total_bytes"] == 1000
    assert table.seen_packets == 5


def test_a_busy_conversation_is_one_open_flow_not_many():
    table = collector.FlowTable(LOCAL)
    for port in (443, 443, 443):
        table.observe(ipv4("203.0.113.9", "10.0.0.5", dport=port))

    assert table.open_count() == 1


# ── expiry ────────────────────────────────────────────────────────────────
def test_an_active_conversation_is_not_expired():
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "10.0.0.5"))

    assert table.expire() == []
    assert table.open_count() == 1


def test_a_quiet_conversation_expires_on_the_idle_timeout():
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "10.0.0.5"))

    (key,) = list(table._flows)
    table._flows[key]["last"] -= collector.IDLE_TIMEOUT_S + 1

    assert len(table.expire()) == 1
    assert table.open_count() == 0


def test_a_long_running_transfer_reports_progress_on_the_active_timeout():
    """A download that runs for an hour must not surface as one flow at the end
    of it — by then the attack it might have been is long over."""
    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "10.0.0.5"))

    (key,) = list(table._flows)
    table._flows[key]["first"] -= collector.ACTIVE_TIMEOUT_S + 1

    (flow,) = table.expire()
    assert flow["duration"] >= 0


def test_force_drains_everything_so_shutdown_loses_nothing():
    table = collector.FlowTable(LOCAL)
    for i in range(4):
        table.observe(ipv4(f"203.0.113.{i}", "10.0.0.5"))

    assert len(table.expire(force=True)) == 4
    assert table.open_count() == 0


# ── the wire contract ─────────────────────────────────────────────────────
def test_emitted_flow_matches_the_server_schema():
    """What the collector sends must be what the server accepts.

    These are two separate programs agreeing on a format by convention. This is
    the test that fails if either side renames a field.
    """
    from backend.app.schemas import FlowIn

    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "10.0.0.5", size=250, dport=80))
    (flow,) = table.expire(force=True)
    flow["node"] = "laptop"

    parsed = FlowIn(**flow)
    assert parsed.src_ip == "203.0.113.9"
    assert parsed.dst_port == 80
    assert parsed.total_bytes == 250


def test_emitted_flow_survives_feature_extraction():
    """Passing schema validation is not enough — the flow has to reach the
    model without a division by zero on a single-packet, zero-duration flow,
    which is the most common shape a scan produces."""
    from backend.app.ml.features import flow_to_features

    table = collector.FlowTable(LOCAL)
    table.observe(ipv4("203.0.113.9", "10.0.0.5", size=64, dport=22))
    (flow,) = table.expire(force=True)

    features = flow_to_features(flow)
    assert len(features) == 6
    assert all(isinstance(f, float) for f in features)


# ── the send buffer ───────────────────────────────────────────────────────
def _sender():
    return collector.Sender("http://localhost:8000", "sentry_ak_x", "node-a")


def test_queue_stamps_the_node_name():
    sender = _sender()
    sender.queue([{"src_ip": "203.0.113.9"}])

    assert sender._pending[0]["node"] == "node-a"


def test_the_buffer_is_bounded_and_drops_the_oldest():
    """A server outage must cost bounded memory, and during an attack the newest
    flows are the ones an analyst needs."""
    sender = _sender()
    sender.queue([{"src_ip": f"10.0.0.{i}", "seq": i} for i in range(collector.MAX_PENDING + 100)])

    assert len(sender._pending) == collector.MAX_PENDING
    assert sender.dropped == 100
    assert sender._pending[0]["seq"] == 100  # oldest went, newest stayed
    assert sender._pending[-1]["seq"] == collector.MAX_PENDING + 99


def test_a_network_failure_keeps_the_flows_for_a_retry(monkeypatch):
    sender = _sender()
    sender.queue([{"src_ip": "203.0.113.9"}])
    monkeypatch.setattr(collector.time, "sleep", lambda _s: None)

    sender.flush()  # the stubbed Session always raises

    assert sender.pending_count() == 1
    assert sender.sent == 0
    assert sender._backoff > 1.0  # and it will wait longer next time


def test_the_api_key_never_appears_in_a_flow_record():
    sender = collector.Sender("http://localhost:8000", "sentry_ak_secret", "node-a")
    sender.queue([{"src_ip": "203.0.113.9"}])

    assert "sentry_ak_secret" not in repr(sender._pending)


# ── key handling ──────────────────────────────────────────────────────────
def test_a_world_readable_key_file_is_refused(tmp_path):
    """A key file anyone on the box can read is not a secret. Refusing is the
    only useful response — reading it anyway teaches the operator nothing."""
    path = tmp_path / "key"
    path.write_text("sentry_ak_abcdef")
    path.chmod(0o644)

    with pytest.raises(SystemExit) as exc:
        collector.read_api_key(str(path))
    assert "chmod 600" in str(exc.value)


def test_a_correctly_permissioned_key_file_is_read(tmp_path):
    path = tmp_path / "key"
    path.write_text("sentry_ak_abcdef\n")
    path.chmod(0o600)

    assert collector.read_api_key(str(path)) == "sentry_ak_abcdef"


def test_a_missing_key_file_says_so(tmp_path):
    with pytest.raises(SystemExit) as exc:
        collector.read_api_key(str(tmp_path / "nope"))
    assert "not found" in str(exc.value)


def test_the_key_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("SENTRY_API_KEY", "sentry_ak_fromenv")
    assert collector.read_api_key(None) == "sentry_ak_fromenv"


def test_a_missing_key_explains_the_sudo_trap(monkeypatch):
    """`sudo python …` drops the environment, so the key vanishes exactly when
    you add the root the capture needs. The error has to name -E."""
    monkeypatch.delenv("SENTRY_API_KEY", raising=False)

    with pytest.raises(SystemExit) as exc:
        collector.read_api_key(None)
    assert "sudo -E" in str(exc.value)


def test_something_that_is_not_a_collector_key_is_rejected_early(monkeypatch):
    monkeypatch.setenv("SENTRY_API_KEY", "hunter2")

    with pytest.raises(SystemExit) as exc:
        collector.read_api_key(None)
    assert "sentry_ak_" in str(exc.value)
