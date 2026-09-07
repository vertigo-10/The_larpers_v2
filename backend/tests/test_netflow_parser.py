"""NetFlow v5 / v9 / IPFIX decoding, against packets built byte by byte.

There is no way to test this against "real" traffic in CI, so the packets here
are constructed from the wire specs directly (RFC 3954 for v9, RFC 7011 for
IPFIX, the Cisco v5 layout for v5). That makes the builders themselves part of
the test: if a builder is wrong the assertions fail loudly rather than passing
against a shared misunderstanding.

The hostile-input cases matter as much as the happy path. This parser eats
unauthenticated UDP from the open internet, so "returns junk" is acceptable and
"raises" is not — an exception here would kill the collector for every tenant.
"""

import struct

import pytest

from backend.app.netflow.parser import (
    IE_DST_IPV4,
    IE_DST_PORT,
    IE_FIRST_SWITCHED,
    IE_FLOW_END_MS,
    IE_FLOW_START_MS,
    IE_LAST_SWITCHED,
    IE_OCTETS,
    IE_PACKETS,
    IE_PROTOCOL,
    IE_SRC_IPV4,
    IE_SRC_PORT,
    TemplateCache,
    parse_packet,
    protocol_name,
)


# ── packet builders ───────────────────────────────────────────────────────
def build_v5(records, sys_uptime=100_000, sampling_field=0):
    """records: list of dicts with src, dst, packets, octets, first, last, ports."""
    header = struct.pack(
        "!HHIIIIBBH",
        5, len(records), sys_uptime, 1_700_000_000, 0, 0, 0, 0, sampling_field,
    )
    body = b""
    for r in records:
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            r["src"], r["dst"], 0, 1, 2,
            r["packets"], r["octets"], r["first"], r["last"],
            r["src_port"], r["dst_port"],
            0, 0, r.get("proto", 6), 0, 0, 0, 0, 0, 0,
        )
    return header + body


def _template_set(template_id, fields, set_id):
    body = struct.pack("!HH", template_id, len(fields))
    for ie, length in fields:
        body += struct.pack("!HH", ie, length)
    return struct.pack("!HH", set_id, len(body) + 4) + body


def _data_set(template_id, payload):
    return struct.pack("!HH", template_id, len(payload) + 4) + payload


def build_v9(sets, sys_uptime=100_000, source_id=1, count=None):
    body = b"".join(sets)
    header = struct.pack(
        "!HHIIII", 9, count if count is not None else len(sets),
        sys_uptime, 1_700_000_000, 0, source_id,
    )
    return header + body


def build_ipfix(sets, domain_id=7, length=None):
    body = b"".join(sets)
    total = length if length is not None else len(body) + 16
    return struct.pack("!HHIII", 10, total, 1_700_000_000, 0, domain_id) + body


def ip_to_int(dotted):
    a, b, c, d = (int(x) for x in dotted.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


# ── NetFlow v5 ────────────────────────────────────────────────────────────
def test_v5_decodes_a_single_flow():
    pkt = build_v5([{
        "src": ip_to_int("192.0.2.10"), "dst": ip_to_int("198.51.100.5"),
        "packets": 42, "octets": 3600, "first": 10_000, "last": 12_500,
        "src_port": 51514, "dst_port": 443, "proto": 6,
    }])
    result = parse_packet(pkt, TemplateCache())

    assert result.ok
    assert result.version == 5
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.src_ip == "192.0.2.10"
    assert rec.dst_ip == "198.51.100.5"
    assert rec.src_port == 51514
    assert rec.dst_port == 443
    assert rec.protocol == 6
    assert rec.protocol_name() == "TCP"
    assert rec.packets == 42
    assert rec.octets == 3600
    assert rec.duration_s == pytest.approx(2.5)


def test_v5_decodes_many_flows_in_one_datagram():
    recs = [{
        "src": ip_to_int(f"10.0.0.{i}"), "dst": ip_to_int("10.0.1.1"),
        "packets": i + 1, "octets": (i + 1) * 100, "first": 0, "last": 1000,
        "src_port": 1024 + i, "dst_port": 80, "proto": 6,
    } for i in range(30)]
    result = parse_packet(build_v5(recs), TemplateCache())

    assert result.ok
    assert len(result.records) == 30
    assert result.records[29].src_ip == "10.0.0.29"


def test_v5_handles_sysuptime_counter_wrap():
    """A flow straddling the 32-bit ms wrap must not decode as ~49 days."""
    pkt = build_v5([{
        "src": ip_to_int("192.0.2.1"), "dst": ip_to_int("192.0.2.2"),
        "packets": 5, "octets": 500,
        "first": (1 << 32) - 500, "last": 500,   # wrapped: true duration 1.0s
        "src_port": 1234, "dst_port": 80, "proto": 6,
    }])
    result = parse_packet(pkt, TemplateCache())
    assert result.records[0].duration_s == pytest.approx(1.0)


def test_v5_applies_configured_sampling_rate():
    pkt = build_v5([{
        "src": ip_to_int("192.0.2.1"), "dst": ip_to_int("192.0.2.2"),
        "packets": 10, "octets": 1000, "first": 0, "last": 1000,
        "src_port": 1234, "dst_port": 80, "proto": 6,
    }])
    result = parse_packet(pkt, TemplateCache(), sampling_rate=1000)
    assert result.records[0].packets == 10_000
    assert result.records[0].octets == 1_000_000


def test_v5_reads_sampling_rate_from_the_wire_when_not_configured():
    # mode 1 (deterministic) in the top two bits, interval 100 in the low 14.
    field = (1 << 14) | 100
    pkt = build_v5([{
        "src": ip_to_int("192.0.2.1"), "dst": ip_to_int("192.0.2.2"),
        "packets": 2, "octets": 200, "first": 0, "last": 1000,
        "src_port": 1234, "dst_port": 80, "proto": 6,
    }], sampling_field=field)
    result = parse_packet(pkt, TemplateCache())
    assert result.records[0].packets == 200


def test_v5_lying_record_count_does_not_read_past_the_buffer():
    """Header claims 50 records, packet contains one."""
    pkt = build_v5([{
        "src": ip_to_int("192.0.2.1"), "dst": ip_to_int("192.0.2.2"),
        "packets": 1, "octets": 100, "first": 0, "last": 100,
        "src_port": 1, "dst_port": 2, "proto": 6,
    }])
    forged = struct.pack("!HH", 5, 50) + pkt[4:]
    result = parse_packet(forged, TemplateCache())
    assert len(result.records) == 1          # decoded what was actually there
    assert "exceeds packet length" in result.reason


# ── NetFlow v9 ────────────────────────────────────────────────────────────
V9_FIELDS = [
    (IE_SRC_IPV4, 4), (IE_DST_IPV4, 4),
    (IE_SRC_PORT, 2), (IE_DST_PORT, 2),
    (IE_PROTOCOL, 1),
    (IE_PACKETS, 4), (IE_OCTETS, 4),
    (IE_FIRST_SWITCHED, 4), (IE_LAST_SWITCHED, 4),
]


def _v9_payload(src, dst, sport, dport, proto, pkts, octets, first, last):
    return (
        struct.pack("!I", ip_to_int(src))
        + struct.pack("!I", ip_to_int(dst))
        + struct.pack("!HH", sport, dport)
        + struct.pack("!B", proto)
        + struct.pack("!II", pkts, octets)
        + struct.pack("!II", first, last)
    )


def test_v9_template_then_data_in_one_packet():
    tpl = _template_set(256, V9_FIELDS, set_id=0)
    data = _data_set(256, _v9_payload(
        "203.0.113.9", "192.0.2.1", 40000, 22, 6, 120, 9600, 5_000, 8_000))
    result = parse_packet(build_v9([tpl, data]), TemplateCache())

    assert result.ok
    assert result.version == 9
    assert result.templates_learned == 1
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.src_ip == "203.0.113.9"
    assert rec.dst_port == 22
    assert rec.packets == 120
    assert rec.octets == 9600
    assert rec.duration_s == pytest.approx(3.0)


def test_v9_data_before_template_is_counted_not_lost_silently():
    """UDP reorders. A data set with no template yet is normal at startup."""
    cache = TemplateCache()
    data = _data_set(256, _v9_payload(
        "203.0.113.9", "192.0.2.1", 40000, 22, 6, 1, 100, 0, 1000))

    first = parse_packet(build_v9([data]), cache)
    assert first.records == []
    assert first.awaiting_template == 1
    assert first.ok                       # not an error, just early

    # Once the template arrives, later data decodes.
    parse_packet(build_v9([_template_set(256, V9_FIELDS, set_id=0)]), cache)
    second = parse_packet(build_v9([data]), cache)
    assert len(second.records) == 1


def test_v9_template_cache_persists_across_datagrams():
    cache = TemplateCache()
    parse_packet(build_v9([_template_set(256, V9_FIELDS, set_id=0)]), cache)
    assert len(cache) == 1

    for _ in range(3):
        result = parse_packet(build_v9([_data_set(256, _v9_payload(
            "10.0.0.1", "10.0.0.2", 1, 80, 6, 5, 500, 0, 2000))]), cache)
        assert len(result.records) == 1


def test_v9_separates_templates_by_observation_domain():
    """Two exporters behind one NAT may both use template ID 256."""
    cache = TemplateCache()
    parse_packet(build_v9([_template_set(256, V9_FIELDS, set_id=0)],
                          source_id=1), cache)

    # Same template id, different source_id — must not resolve.
    result = parse_packet(build_v9([_data_set(256, _v9_payload(
        "10.0.0.1", "10.0.0.2", 1, 80, 6, 5, 500, 0, 1000))],
        source_id=2), cache)
    assert result.records == []
    assert result.awaiting_template == 1


def test_v9_multiple_records_in_one_data_set():
    tpl = _template_set(256, V9_FIELDS, set_id=0)
    payload = b"".join(
        _v9_payload(f"10.0.0.{i}", "10.0.1.1", 1000 + i, 443, 6,
                    i + 1, (i + 1) * 60, 0, 1000)
        for i in range(5)
    )
    result = parse_packet(build_v9([tpl, _data_set(256, payload)]),
                          TemplateCache())
    assert len(result.records) == 5
    assert result.records[4].src_ip == "10.0.0.4"


def test_v9_options_template_is_skipped_without_breaking_parsing():
    options = _template_set(999, [(IE_PACKETS, 4)], set_id=1)
    tpl = _template_set(256, V9_FIELDS, set_id=0)
    data = _data_set(256, _v9_payload(
        "10.0.0.1", "10.0.0.2", 1, 80, 6, 7, 700, 0, 1000))
    result = parse_packet(build_v9([options, tpl, data]), TemplateCache())
    assert len(result.records) == 1


# ── IPFIX ─────────────────────────────────────────────────────────────────
IPFIX_FIELDS = [
    (IE_SRC_IPV4, 4), (IE_DST_IPV4, 4),
    (IE_SRC_PORT, 2), (IE_DST_PORT, 2),
    (IE_PROTOCOL, 1),
    (IE_PACKETS, 8), (IE_OCTETS, 8),
    (IE_FLOW_START_MS, 8), (IE_FLOW_END_MS, 8),
]


def _ipfix_payload(src, dst, sport, dport, proto, pkts, octets, start_ms, end_ms):
    return (
        struct.pack("!I", ip_to_int(src))
        + struct.pack("!I", ip_to_int(dst))
        + struct.pack("!HH", sport, dport)
        + struct.pack("!B", proto)
        + struct.pack("!Q", pkts)
        + struct.pack("!Q", octets)
        + struct.pack("!Q", start_ms)
        + struct.pack("!Q", end_ms)
    )


def test_ipfix_template_then_data():
    tpl = _template_set(300, IPFIX_FIELDS, set_id=2)
    data = _data_set(300, _ipfix_payload(
        "198.51.100.7", "203.0.113.1", 33000, 53, 17,
        4, 512, 1_700_000_000_000, 1_700_000_001_500))
    result = parse_packet(build_ipfix([tpl, data]), TemplateCache())

    assert result.ok
    assert result.version == 10
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.src_ip == "198.51.100.7"
    assert rec.dst_port == 53
    assert rec.protocol_name() == "UDP"
    assert rec.packets == 4
    assert rec.octets == 512
    assert rec.duration_s == pytest.approx(1.5)


def test_ipfix_64bit_counters_survive_large_values():
    """A 10 GB flow overflows 32 bits; IPFIX uses 64-bit counters for this."""
    big = 12_000_000_000
    tpl = _template_set(300, IPFIX_FIELDS, set_id=2)
    data = _data_set(300, _ipfix_payload(
        "10.0.0.1", "10.0.0.2", 1, 443, 6, 8_000_000, big,
        1_700_000_000_000, 1_700_000_060_000))
    result = parse_packet(build_ipfix([tpl, data]), TemplateCache())
    assert result.records[0].octets == big
    assert result.records[0].duration_s == pytest.approx(60.0)


def test_ipfix_enterprise_fields_are_skipped_without_misaligning():
    """A vendor field we don't understand must still consume its bytes."""
    fields = [
        (IE_SRC_IPV4, 4),
        (0x8000 | 1234, 4),          # enterprise bit set
        (IE_DST_IPV4, 4),
        (IE_DST_PORT, 2),
        (IE_PACKETS, 8),
    ]
    body = struct.pack("!HH", 301, len(fields))
    for ie, length in fields:
        body += struct.pack("!HH", ie, length)
        if ie & 0x8000:
            body += struct.pack("!I", 9999)     # enterprise number
    tpl = struct.pack("!HH", 2, len(body) + 4) + body

    payload = (
        struct.pack("!I", ip_to_int("10.1.1.1"))
        + b"\xde\xad\xbe\xef"                    # the vendor field
        + struct.pack("!I", ip_to_int("10.2.2.2"))
        + struct.pack("!H", 8080)
        + struct.pack("!Q", 99)
    )
    result = parse_packet(build_ipfix([tpl, _data_set(301, payload)]),
                          TemplateCache())
    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.src_ip == "10.1.1.1"
    assert rec.dst_ip == "10.2.2.2"          # would be garbage if misaligned
    assert rec.dst_port == 8080
    assert rec.packets == 99


def test_ipfix_message_length_shorter_than_datagram_is_respected():
    """Trailing bytes past the declared length must be ignored."""
    tpl = _template_set(300, IPFIX_FIELDS, set_id=2)
    data = _data_set(300, _ipfix_payload(
        "10.0.0.1", "10.0.0.2", 1, 80, 6, 1, 100,
        1_700_000_000_000, 1_700_000_001_000))
    good = build_ipfix([tpl, data])
    result = parse_packet(good + b"\xff" * 200, TemplateCache())
    assert result.ok
    assert len(result.records) == 1


# ── hostile and malformed input ───────────────────────────────────────────
@pytest.mark.parametrize("payload", [
    b"",
    b"\x00",
    b"\x00\x09",
    b"\x00\x05",
    b"\x00\x0a" + b"\x00" * 4,
    b"\xff\xff" + b"\xff" * 100,
    b"\x00\x09" + b"\xff" * 400,
    b"\x00\x0a" + b"\xff" * 400,
    b"\x00\x05" + b"\xff" * 400,
    bytes(range(256)),
    b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
])
def test_malformed_packets_never_raise(payload):
    result = parse_packet(payload, TemplateCache())
    assert isinstance(result.records, list)


def test_zero_length_set_does_not_loop_forever():
    """A set claiming length 0 would otherwise spin the parser at one offset."""
    evil = struct.pack("!HHIIII", 9, 1, 0, 0, 0, 1) + struct.pack("!HH", 256, 0)
    result = parse_packet(evil, TemplateCache())
    assert result.records == []


def test_template_with_absurd_field_count_is_rejected():
    body = struct.pack("!HH", 256, 60000)     # claims 60k fields
    tpl = struct.pack("!HH", 0, len(body) + 4) + body
    result = parse_packet(build_v9([tpl]), TemplateCache())
    assert result.templates_learned == 0


def test_template_cache_is_bounded():
    """A broken exporter cycling template IDs must not exhaust memory."""
    cache = TemplateCache()
    for tid in range(256, 256 + 2000):
        parse_packet(build_v9([_template_set(tid, V9_FIELDS, set_id=0)]), cache)
    assert len(cache) <= 1024


def test_unsupported_version_is_reported_not_raised():
    result = parse_packet(struct.pack("!H", 7) + b"\x00" * 40, TemplateCache())
    assert result.malformed
    assert "unsupported version 7" in result.reason


def test_protocol_name_falls_back_to_the_number():
    assert protocol_name(6) == "TCP"
    assert protocol_name(17) == "UDP"
    assert protocol_name(253) == "253"
