"""Decode NetFlow v5, NetFlow v9 and IPFIX datagrams.

Three wire formats, one output shape. The formats differ more than their shared
name suggests:

  v5    Fixed 48-byte records. No templates, no options, IPv4 only. Ancient,
        trivial to parse, still emitted by a lot of hardware.
  v9    Cisco's template-based format. The exporter periodically sends a
        *template* describing the field layout, then sends data records that
        reference it by ID. You cannot decode a data record without having
        already seen its template.
  IPFIX The IETF standardisation of v9 (it is "version 10" on the wire).
        Similar shape, different set IDs, plus enterprise-specific fields and
        variable-length encoding.

SECURITY NOTE. Everything this module parses arrived over UDP from an
unauthenticated source. It is the most exposed code in the product. Every read
is bounds-checked, every length is validated against the remaining buffer, and
a malformed packet raises no exception to the caller — it returns whatever was
successfully decoded plus a reason. A parser that throws on hostile input is a
denial-of-service vector against our own collector.
"""

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── IPFIX Information Element IDs ─────────────────────────────────────────
# NetFlow v9 field types and IPFIX IEs share numbering for everything we care
# about, so one table serves both.
IE_OCTETS = 1            # octetDeltaCount
IE_PACKETS = 2           # packetDeltaCount
IE_PROTOCOL = 4          # protocolIdentifier
IE_SRC_PORT = 7          # sourceTransportPort
IE_SRC_IPV4 = 8          # sourceIPv4Address
IE_DST_PORT = 11         # destinationTransportPort
IE_DST_IPV4 = 12         # destinationIPv4Address
IE_LAST_SWITCHED = 21    # flowEndSysUpTime      (ms since exporter boot)
IE_FIRST_SWITCHED = 22   # flowStartSysUpTime    (ms since exporter boot)
IE_SRC_IPV6 = 27         # sourceIPv6Address
IE_DST_IPV6 = 28         # destinationIPv6Address
IE_SAMPLING_INTERVAL = 34
IE_OCTETS_TOTAL = 85     # octetTotalCount
IE_PACKETS_TOTAL = 86    # packetTotalCount
IE_FLOW_START_SEC = 150
IE_FLOW_END_SEC = 151
IE_FLOW_START_MS = 152
IE_FLOW_END_MS = 153
IE_FLOW_START_US = 154
IE_FLOW_END_US = 155
IE_FLOW_START_NS = 156
IE_FLOW_END_NS = 157
IE_FLOW_DURATION_MS = 161
IE_FLOW_DURATION_US = 162
IE_SAMPLER_RANDOM_INTERVAL = 305

# Set / FlowSet IDs
V9_TEMPLATE_SET = 0
V9_OPTIONS_SET = 1
IPFIX_TEMPLATE_SET = 2
IPFIX_OPTIONS_SET = 3
MIN_DATA_SET_ID = 256

# A 32-bit millisecond sysUpTime counter wraps roughly every 49.7 days.
_UPTIME_WRAP_MS = 1 << 32

_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
    132: "SCTP",
}

# Refuse to allocate unbounded memory from a hostile header count field. No
# real exporter sends anywhere near this many records in one datagram.
_MAX_RECORDS_PER_PACKET = 4096
_MAX_FIELDS_PER_TEMPLATE = 256
_MAX_TEMPLATES_PER_EXPORTER = 1024


def protocol_name(number: int) -> str:
    return _PROTO_NAMES.get(number, str(number))


@dataclass
class FlowRecord:
    """One decoded flow, normalised across all three wire formats."""

    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    packets: int = 0
    octets: int = 0
    duration_s: float = 0.0

    def protocol_name(self) -> str:
        return protocol_name(self.protocol)


@dataclass
class ParseResult:
    """What came out of one datagram, and what went wrong."""

    records: List[FlowRecord] = field(default_factory=list)
    version: int = 0
    templates_learned: int = 0
    # Data sets we had to drop because their template had not arrived yet.
    # Expected and harmless at startup — exporters resend templates on a timer
    # (typically every 20-600s), so a fresh collector is briefly deaf. Surfaced
    # rather than swallowed so the UI can say "waiting for templates" instead
    # of showing an unexplained silence.
    awaiting_template: int = 0
    malformed: bool = False
    reason: str = ""

    @property
    def ok(self) -> bool:
        return not self.malformed


@dataclass
class _Template:
    template_id: int
    # (information_element_id, length_in_bytes) in wire order.
    fields: List[Tuple[int, int]]
    # Sum of field lengths, or None when any field is variable-length.
    fixed_length: Optional[int]
    is_options: bool = False


class TemplateCache:
    """Per-exporter store of the templates needed to decode its data records.

    Scoped by (observation domain, template id). Two exporters behind the same
    NAT would collide if this were global, and an exporter is entitled to reuse
    template ID 256 for a completely different layout in a different domain.
    """

    def __init__(self) -> None:
        self._templates: Dict[Tuple[int, int], _Template] = {}

    def put(self, domain: int, template: _Template) -> None:
        # A rogue or broken exporter announcing endless template IDs would
        # otherwise grow this dict without limit.
        if (len(self._templates) >= _MAX_TEMPLATES_PER_EXPORTER
                and (domain, template.template_id) not in self._templates):
            return
        self._templates[(domain, template.template_id)] = template

    def get(self, domain: int, template_id: int) -> Optional[_Template]:
        return self._templates.get((domain, template_id))

    def __len__(self) -> int:
        return len(self._templates)


# ── helpers ───────────────────────────────────────────────────────────────
def _int(buf: bytes) -> int:
    """Decode a big-endian unsigned integer of any length."""
    return int.from_bytes(buf, "big", signed=False)


def _ipv4(buf: bytes) -> str:
    if len(buf) != 4:
        return "0.0.0.0"
    return str(ipaddress.IPv4Address(buf))


def _ipv6(buf: bytes) -> str:
    if len(buf) != 16:
        return "::"
    return str(ipaddress.IPv6Address(buf))


def _uptime_delta_ms(first: int, last: int) -> int:
    """last - first, accounting for the 32-bit sysUpTime counter wrapping.

    Without this, any flow that straddles a wrap decodes as a ~49-day duration,
    which lands in the model as a wildly out-of-distribution feature vector.
    """
    delta = last - first
    if delta < 0:
        delta += _UPTIME_WRAP_MS
    return delta


def parse_packet(
    data: bytes,
    cache: TemplateCache,
    sampling_rate: int = 1,
) -> ParseResult:
    """Decode one UDP datagram. Never raises.

    `sampling_rate` scales packet and byte counters back up when the exporter
    is sampling (1:N). Configured per exporter rather than read from the wire:
    the samplingInterval field is optional, frequently absent, and often wrong,
    while getting it wrong silently scales all volume features by 1000x.
    """
    if len(data) < 2:
        return ParseResult(malformed=True, reason="packet too short")

    version = _int(data[0:2])
    try:
        if version == 5:
            return _parse_v5(data, sampling_rate)
        if version == 9:
            return _parse_v9(data, cache, sampling_rate)
        if version == 10:
            return _parse_ipfix(data, cache, sampling_rate)
    except (struct.error, ValueError, IndexError, OverflowError) as exc:
        # Deliberately broad over the decode-error family. This is untrusted
        # input; a crash here would take the collector down for every tenant.
        return ParseResult(
            version=version, malformed=True, reason=f"decode error: {exc}"
        )

    return ParseResult(
        version=version, malformed=True, reason=f"unsupported version {version}"
    )


# ── NetFlow v5 ────────────────────────────────────────────────────────────
_V5_HEADER = struct.Struct("!HHIIIIBBH")   # 24 bytes
_V5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")  # 48 bytes


def _parse_v5(data: bytes, sampling_rate: int) -> ParseResult:
    out = ParseResult(version=5)
    if len(data) < _V5_HEADER.size:
        out.malformed = True
        out.reason = "v5 header truncated"
        return out

    (_version, count, _sys_uptime, _unix_secs, _unix_nsecs,
     _seq, _engine_type, _engine_id, sampling_field) = _V5_HEADER.unpack_from(data, 0)

    # The low 14 bits are the interval; the top 2 are the sampling mode. Mode 0
    # means no sampling, in which case the interval field is meaningless.
    mode = (sampling_field >> 14) & 0x3
    wire_rate = sampling_field & 0x3FFF
    rate = sampling_rate
    if rate <= 1 and mode != 0 and wire_rate > 1:
        rate = wire_rate

    count = min(count, _MAX_RECORDS_PER_PACKET)
    offset = _V5_HEADER.size

    for _ in range(count):
        if offset + _V5_RECORD.size > len(data):
            out.reason = "v5 record count exceeds packet length"
            break
        (src, dst, _nexthop, _in_if, _out_if, packets, octets,
         first, last, src_port, dst_port, _pad1, _flags, proto,
         _tos, _src_as, _dst_as, _src_mask, _dst_mask,
         _pad2) = _V5_RECORD.unpack_from(data, offset)
        offset += _V5_RECORD.size

        out.records.append(FlowRecord(
            src_ip=str(ipaddress.IPv4Address(src)),
            dst_ip=str(ipaddress.IPv4Address(dst)),
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            packets=packets * max(rate, 1),
            octets=octets * max(rate, 1),
            duration_s=_uptime_delta_ms(first, last) / 1000.0,
        ))

    return out


# ── shared template-format decoding (v9 and IPFIX) ────────────────────────
def _read_template_set(
    data: bytes, start: int, end: int, ipfix: bool
) -> List[_Template]:
    """Decode a template set into template definitions."""
    templates: List[_Template] = []
    offset = start
    while offset + 4 <= end:
        template_id, field_count = struct.unpack_from("!HH", data, offset)
        offset += 4
        if field_count == 0 or field_count > _MAX_FIELDS_PER_TEMPLATE:
            break

        fields: List[Tuple[int, int]] = []
        fixed_length: Optional[int] = 0
        for _ in range(field_count):
            if offset + 4 > end:
                return templates          # truncated; keep what we decoded
            ie_id, length = struct.unpack_from("!HH", data, offset)
            offset += 4
            if ipfix and (ie_id & 0x8000):
                # Enterprise-specific element: 4 more bytes of enterprise
                # number follow. We do not interpret vendor elements, but we
                # must consume the bytes or every later field misaligns.
                if offset + 4 > end:
                    return templates
                offset += 4
                ie_id = 0                 # treat as an ignorable padding field
            fields.append((ie_id, length))
            if length == 0xFFFF:
                fixed_length = None       # variable-length, IPFIX only
            elif fixed_length is not None:
                fixed_length += length

        templates.append(_Template(
            template_id=template_id, fields=fields, fixed_length=fixed_length
        ))
    return templates


def _decode_data_record(
    data: bytes, offset: int, end: int, template: _Template, ipfix: bool
) -> Tuple[Optional[Dict[int, bytes]], int]:
    """Pull one record's fields out as {ie_id: raw_bytes}.

    Returns (values, new_offset). values is None when the record does not fit
    in the remaining buffer.
    """
    values: Dict[int, bytes] = {}
    for ie_id, length in template.fields:
        if length == 0xFFFF and ipfix:
            # Variable length: one length byte, or 0xFF then two more.
            if offset + 1 > end:
                return None, offset
            length = data[offset]
            offset += 1
            if length == 255:
                if offset + 2 > end:
                    return None, offset
                length = struct.unpack_from("!H", data, offset)[0]
                offset += 2
        if offset + length > end:
            return None, offset
        if ie_id:
            values[ie_id] = data[offset:offset + length]
        offset += length
    return values, offset


def _record_from_values(
    values: Dict[int, bytes],
    header_uptime_ms: int,
    sampling_rate: int,
) -> Optional[FlowRecord]:
    """Map decoded IEs onto our normalised flow shape."""
    rec = FlowRecord()

    if IE_SRC_IPV4 in values:
        rec.src_ip = _ipv4(values[IE_SRC_IPV4])
    elif IE_SRC_IPV6 in values:
        rec.src_ip = _ipv6(values[IE_SRC_IPV6])

    if IE_DST_IPV4 in values:
        rec.dst_ip = _ipv4(values[IE_DST_IPV4])
    elif IE_DST_IPV6 in values:
        rec.dst_ip = _ipv6(values[IE_DST_IPV6])

    if IE_SRC_PORT in values:
        rec.src_port = _int(values[IE_SRC_PORT])
    if IE_DST_PORT in values:
        rec.dst_port = _int(values[IE_DST_PORT])
    if IE_PROTOCOL in values:
        rec.protocol = _int(values[IE_PROTOCOL])

    # Delta counters are the common case; total counters appear on exporters
    # configured for non-expiring flow records.
    if IE_PACKETS in values:
        rec.packets = _int(values[IE_PACKETS])
    elif IE_PACKETS_TOTAL in values:
        rec.packets = _int(values[IE_PACKETS_TOTAL])

    if IE_OCTETS in values:
        rec.octets = _int(values[IE_OCTETS])
    elif IE_OCTETS_TOTAL in values:
        rec.octets = _int(values[IE_OCTETS_TOTAL])

    rate = max(sampling_rate, 1)
    rec.packets *= rate
    rec.octets *= rate

    rec.duration_s = _duration_from_values(values, header_uptime_ms)

    # A record with no addressing at all is either a pure options record or a
    # template we mis-decoded. Either way it is not a flow.
    if rec.src_ip == "0.0.0.0" and rec.dst_ip == "0.0.0.0" and rec.packets == 0:
        return None
    return rec


def _duration_from_values(values: Dict[int, bytes], header_uptime_ms: int) -> float:
    """Work out flow duration from whichever timestamp pair the exporter sent.

    Six encodings are in circulation. Checked cheapest-first; sysUpTime last
    because it is the only one needing the header for context.
    """
    if IE_FLOW_DURATION_MS in values:
        return _int(values[IE_FLOW_DURATION_MS]) / 1000.0
    if IE_FLOW_DURATION_US in values:
        return _int(values[IE_FLOW_DURATION_US]) / 1_000_000.0

    for start_ie, end_ie, divisor in (
        (IE_FLOW_START_MS, IE_FLOW_END_MS, 1000.0),
        (IE_FLOW_START_US, IE_FLOW_END_US, 1_000_000.0),
        (IE_FLOW_START_NS, IE_FLOW_END_NS, 1_000_000_000.0),
        (IE_FLOW_START_SEC, IE_FLOW_END_SEC, 1.0),
    ):
        if start_ie in values and end_ie in values:
            delta = _int(values[end_ie]) - _int(values[start_ie])
            return max(delta, 0) / divisor

    if IE_FIRST_SWITCHED in values and IE_LAST_SWITCHED in values:
        first = _int(values[IE_FIRST_SWITCHED])
        last = _int(values[IE_LAST_SWITCHED])
        return _uptime_delta_ms(first, last) / 1000.0

    return 0.0


# ── NetFlow v9 ────────────────────────────────────────────────────────────
_V9_HEADER = struct.Struct("!HHIIII")   # 20 bytes


def _parse_v9(data: bytes, cache: TemplateCache, sampling_rate: int) -> ParseResult:
    out = ParseResult(version=9)
    if len(data) < _V9_HEADER.size:
        out.malformed = True
        out.reason = "v9 header truncated"
        return out

    _version, _count, sys_uptime, _unix_secs, _seq, source_id = \
        _V9_HEADER.unpack_from(data, 0)

    offset = _V9_HEADER.size
    total = len(data)

    while offset + 4 <= total:
        flowset_id, length = struct.unpack_from("!HH", data, offset)
        if length < 4:
            out.reason = "v9 flowset length below minimum"
            break
        set_end = min(offset + length, total)
        body = offset + 4
        offset += length

        if flowset_id == V9_TEMPLATE_SET:
            for tpl in _read_template_set(data, body, set_end, ipfix=False):
                cache.put(source_id, tpl)
                out.templates_learned += 1

        elif flowset_id == V9_OPTIONS_SET:
            # Options templates describe metadata records (sampling config,
            # interface names), not flows. Skipped deliberately.
            continue

        elif flowset_id >= MIN_DATA_SET_ID:
            template = cache.get(source_id, flowset_id)
            if template is None:
                out.awaiting_template += 1
                continue
            _consume_data_set(
                data, body, set_end, template, out,
                header_uptime_ms=sys_uptime, sampling_rate=sampling_rate,
                ipfix=False,
            )

    return out


# ── IPFIX ─────────────────────────────────────────────────────────────────
_IPFIX_HEADER = struct.Struct("!HHIII")   # 16 bytes


def _parse_ipfix(data: bytes, cache: TemplateCache, sampling_rate: int) -> ParseResult:
    out = ParseResult(version=10)
    if len(data) < _IPFIX_HEADER.size:
        out.malformed = True
        out.reason = "ipfix header truncated"
        return out

    _version, msg_length, _export_time, _seq, domain_id = \
        _IPFIX_HEADER.unpack_from(data, 0)

    # The header carries the authoritative message length. Trust the smaller of
    # it and what actually arrived, so a lying length field cannot walk us off
    # the end of the buffer or make us re-read a previous datagram's bytes.
    total = min(msg_length, len(data)) if msg_length >= _IPFIX_HEADER.size else len(data)
    offset = _IPFIX_HEADER.size

    while offset + 4 <= total:
        set_id, length = struct.unpack_from("!HH", data, offset)
        if length < 4:
            out.reason = "ipfix set length below minimum"
            break
        set_end = min(offset + length, total)
        body = offset + 4
        offset += length

        if set_id == IPFIX_TEMPLATE_SET:
            for tpl in _read_template_set(data, body, set_end, ipfix=True):
                cache.put(domain_id, tpl)
                out.templates_learned += 1

        elif set_id == IPFIX_OPTIONS_SET:
            continue

        elif set_id >= MIN_DATA_SET_ID:
            template = cache.get(domain_id, set_id)
            if template is None:
                out.awaiting_template += 1
                continue
            _consume_data_set(
                data, body, set_end, template, out,
                header_uptime_ms=0, sampling_rate=sampling_rate, ipfix=True,
            )

    return out


def _consume_data_set(
    data: bytes,
    body: int,
    set_end: int,
    template: _Template,
    out: ParseResult,
    header_uptime_ms: int,
    sampling_rate: int,
    ipfix: bool,
) -> None:
    """Decode every record in one data set, appending to `out.records`."""
    offset = body
    # Trailing padding shorter than one record is legal and expected.
    min_record = template.fixed_length if template.fixed_length else 1
    while offset + min_record <= set_end:
        if len(out.records) >= _MAX_RECORDS_PER_PACKET:
            return
        values, new_offset = _decode_data_record(
            data, offset, set_end, template, ipfix
        )
        if values is None or new_offset == offset:
            return                        # truncated or zero-width; stop
        offset = new_offset
        rec = _record_from_values(values, header_uptime_ms, sampling_rate)
        if rec is not None:
            out.records.append(rec)
