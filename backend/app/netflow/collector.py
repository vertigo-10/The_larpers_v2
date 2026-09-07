"""UDP collector for NetFlow / IPFIX flow records.

This is the piece that makes SENTRY installable in ten minutes. A customer
does not deploy an agent, does not span a port, does not touch a server: they
point the flow export their switch or firewall already supports at this port
and traffic starts being scored.

Three constraints shape everything below.

**The socket is unauthenticated and reachable.** NetFlow carries no key and no
signature. Anything that can route a packet here can send one. So every buffer
is bounded, every source is rate limited before it costs us a parse, and an
address nobody registered is recorded but never scored.

**The receive callback runs on the event loop.** `datagram_received` shares a
thread with every WebSocket push and HTTP response in the process. A database
round trip there would stall the whole app for the duration, and under load the
kernel's receive buffer overflows and datagrams are lost with no error anywhere
— UDP has no retransmit. So the callback only ever does in-memory work:
resolve, parse, append. Persistence happens on a separate task, and the actual
scoring happens off the loop entirely via a worker thread.

**Flow records are already stale.** An exporter aggregates a flow and ships it
seconds to minutes after the packets moved. Flushing per-packet would buy no
freshness at all while costing a transaction each time, so records are batched.
"""

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from ..config import settings
from ..db import SessionLocal
from ..models import FlowExporter, UnclaimedExporter, utcnow
from .parser import FlowRecord, ParseResult, TemplateCache, parse_packet

log = logging.getLogger("sentry.netflow")

# How often the in-memory exporter registry is rebuilt from the database. The
# registry is read on every single datagram, so it cannot be a query; it is a
# cache, and this is how stale it is allowed to get. Thirty seconds means an
# operator who registers a device sees flows within half a minute, which reads
# as "it worked" rather than as a failure.
_REGISTRY_REFRESH_S = 30.0

# Ceiling on distinct source IPs holding template state. v9 and IPFIX require
# us to remember each exporter's templates to decode its data, so this is
# per-source memory that a spoofed source could otherwise multiply at will.
_MAX_TEMPLATE_CACHES = 512


@dataclass
class _ExporterState:
    """Everything the receive path needs about one registered device.

    Deliberately a plain snapshot rather than an ORM object. A detached
    SQLAlchemy instance touched from the event loop can emit a lazy load — a
    blocking query in the one place that must never block.
    """

    exporter_id: int
    org_id: int
    node_label: str
    sampling_rate: int
    templates: TemplateCache = field(default_factory=TemplateCache)

    # Accumulated since the last flush, written back in one UPDATE.
    packets: int = 0
    flows: int = 0
    version: str = ""
    last_error: str = ""
    last_seen_at: Optional[datetime] = None


@dataclass
class _UnclaimedState:
    packets: int = 0
    version: str = ""
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None


def _version_label(version: int) -> str:
    if version == 5:
        return "v5"
    if version == 9:
        return "v9"
    if version == 10:
        return "ipfix"
    return str(version) if version else ""


def flow_record_to_dict(
    rec: FlowRecord, node_label: str, ts: Optional[datetime] = None
) -> Dict:
    """Convert a decoded record into the shape the scoring pipeline expects.

    The model's six features are duration, packets, total_bytes, packets_per_sec,
    bytes_per_packet and dst_port. A flow record carries all of them directly,
    which is the quiet advantage of this ingest path over packet capture: the
    exporter already did the aggregation the feature extractor would otherwise
    have to reconstruct from individual packets.
    """
    duration = max(float(rec.duration_s), 1e-3)
    total_bytes = float(rec.octets)
    return {
        "src_ip": rec.src_ip,
        # Not a model feature. Carried through for the aggregate detectors,
        # which need to know whether a group of flows is converging on one host.
        "dst_ip": rec.dst_ip,
        "dst_port": int(rec.dst_port),
        "protocol": rec.protocol_name(),
        "node": node_label,
        "duration": duration,
        "packets": int(rec.packets),
        "total_bytes": total_bytes,
        "bytes_per_sec": total_bytes / duration,
        "ts": ts or datetime.now(timezone.utc),
        # Real traffic has no ground truth. Recording a guess here would poison
        # the Model page's agreement rate, which exists to compare predictions
        # against labels that are actually known.
        "truth": None,
    }


class FlowCollector:
    """Owns the UDP sockets, the registry cache and the flush loop."""

    def __init__(
        self,
        on_scored: Optional[
            Callable[[int, List[Dict], Dict], Awaitable[None]]
        ] = None,
    ) -> None:
        # Awaited after each org's batch is scored, with (org_id, flows,
        # metric_point). Used to push to WebSocket subscribers. Injected rather
        # than imported so the collector can be tested without the app's
        # connection manager, and so this module does not depend on the
        # transport it happens to feed.
        self._on_scored = on_scored

        self._registry: Dict[str, _ExporterState] = {}
        self._registry_loaded_at = 0.0

        # org_id -> pending flow dicts
        self._buffers: Dict[int, List[Dict]] = defaultdict(list)
        self._unclaimed: Dict[str, _UnclaimedState] = {}

        # Reset every flush window. Bounds the CPU a single source can consume.
        self._packets_this_window: Dict[str, int] = defaultdict(int)

        self._transports: List[asyncio.DatagramTransport] = []
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False

        # Counters for the health endpoint. Cheap to keep, and the difference
        # between "no flows" and "20,000 flows dropped" is the whole diagnosis.
        self.stats = {
            "packets": 0,
            "flows": 0,
            "dropped_buffer_full": 0,
            "dropped_rate_limited": 0,
            "dropped_unregistered": 0,
            "malformed": 0,
            "awaiting_template": 0,
        }

    # ── lifecycle ─────────────────────────────────────────────────────────
    async def start(self) -> None:
        """Bind every configured port. Ports that fail to bind are skipped.

        A bind failure is usually either "already in use" (a second worker) or
        "permission denied" (a port under 1024, though the defaults are not).
        Neither should take down the API — a collector that cannot listen is a
        degraded feature, not a broken app — so each is logged and the rest
        still come up.
        """
        if self._running:
            return

        loop = asyncio.get_running_loop()
        await self._refresh_registry()

        for port in settings.netflow_port_list:
            try:
                transport, _protocol = await loop.create_datagram_endpoint(
                    lambda: _FlowProtocol(self),
                    local_addr=(settings.netflow_bind_host, port),
                )
                self._transports.append(transport)
                log.info("netflow collector listening on udp/%d", port)
            except OSError as exc:
                log.error("netflow: could not bind udp/%d: %s", port, exc)

        if not self._transports:
            log.error("netflow: no ports bound, collector inactive")
            return

        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None

        for transport in self._transports:
            transport.close()
        self._transports = []

        # One last drain so records already decoded are not thrown away on a
        # graceful shutdown. They cost nothing to keep and a redeploy would
        # otherwise silently lose a window of a customer's traffic.
        await self._flush()

    @property
    def listening(self) -> bool:
        return self._running and bool(self._transports)

    # ── receive path (event loop, must not block) ──────────────────────────
    def handle_datagram(self, data: bytes, source_ip: str) -> None:
        """Decode one datagram and buffer its flows. Never raises.

        Called directly from the protocol's receive callback, so an exception
        here would propagate into asyncio's exception handler and, worse, mean
        one malformed packet stops the rest of the batch being processed.
        """
        try:
            self._handle_datagram_inner(data, source_ip)
        except Exception:  # pragma: no cover - defensive
            # Broad on purpose. This is the boundary between hostile input and
            # our process; a bug in decoding must degrade to a dropped packet,
            # never to a dead collector.
            log.exception("netflow: unhandled error processing packet from %s", source_ip)

    def _handle_datagram_inner(self, data: bytes, source_ip: str) -> None:
        self.stats["packets"] += 1

        # Rate limit before parsing, not after. The point is to cap the CPU an
        # unauthenticated sender can make us spend, and parsing is the expensive
        # part — checking afterwards would already have paid the cost.
        count = self._packets_this_window[source_ip] + 1
        self._packets_this_window[source_ip] = count
        if count > settings.netflow_max_packets_per_source:
            self.stats["dropped_rate_limited"] += 1
            return

        state = self._registry.get(source_ip)
        if state is None:
            self._note_unclaimed(source_ip, data)
            return

        result = parse_packet(data, state.templates, sampling_rate=state.sampling_rate)

        state.packets += 1
        state.last_seen_at = datetime.now(timezone.utc)
        if result.version:
            state.version = _version_label(result.version)

        self._record_parse_health(state, result)

        if not result.records:
            return

        buf = self._buffers[state.org_id]
        room = settings.netflow_max_buffered_flows - len(buf)
        if room <= 0:
            self.stats["dropped_buffer_full"] += len(result.records)
            return

        records = result.records
        if len(records) > room:
            self.stats["dropped_buffer_full"] += len(records) - room
            records = records[:room]

        now = datetime.now(timezone.utc)
        for rec in records:
            buf.append(flow_record_to_dict(rec, state.node_label, ts=now))

        state.flows += len(records)
        self.stats["flows"] += len(records)

    def _record_parse_health(self, state: _ExporterState, result: ParseResult) -> None:
        """Translate a parse outcome into something an operator can act on."""
        if result.malformed:
            self.stats["malformed"] += 1
            state.last_error = result.reason or "malformed packet"
        elif result.awaiting_template:
            self.stats["awaiting_template"] += result.awaiting_template
            # Not an error in the first minutes of a v9 session — the exporter
            # sends templates on its own timer and data before the first one
            # arrives is undecodable by design. Worded so it does not read as a
            # fault when it is merely early.
            state.last_error = (
                "waiting for the exporter to send its template "
                "(normal for the first few minutes)"
            )
        elif result.records or result.templates_learned:
            state.last_error = ""

    def _note_unclaimed(self, source_ip: str, data: bytes) -> None:
        """Remember an unregistered sender without letting it cost us anything.

        No parsing happens here beyond the version byte. Decoding a packet from
        an address nobody vouched for would mean an unauthenticated stranger
        can direct our CPU, and there is nothing to gain: the flows have no org
        to belong to and will never be scored.
        """
        self.stats["dropped_unregistered"] += 1

        entry = self._unclaimed.get(source_ip)
        if entry is None:
            if len(self._unclaimed) >= settings.netflow_max_unclaimed:
                # Full. Dropped rather than evicting an existing entry, because
                # eviction is exactly the lever a spoofing sender would pull to
                # push a real misconfigured device out of the operator's view.
                return
            entry = _UnclaimedState(first_seen_at=datetime.now(timezone.utc))
            self._unclaimed[source_ip] = entry

        entry.packets += 1
        entry.last_seen_at = datetime.now(timezone.utc)
        if not entry.version and len(data) >= 2:
            entry.version = _version_label(int.from_bytes(data[:2], "big"))

    # ── flush path (background task, may block in a worker thread) ─────────
    async def _flush_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(settings.netflow_flush_interval_s)
                await self._flush()

                if time.monotonic() - self._registry_loaded_at > _REGISTRY_REFRESH_S:
                    await self._refresh_registry()
            except asyncio.CancelledError:
                raise
            except Exception:
                # The loop must outlive any single failure. A transient database
                # error on one flush should cost that window's flows, not the
                # collector — losing the loop would mean the socket keeps
                # filling buffers nothing ever drains.
                log.exception("netflow: flush cycle failed")

    async def _flush(self) -> None:
        # Reset the rate-limit window here rather than on a timer of its own so
        # the budget is exactly "per flush interval" with no second clock to
        # keep in step.
        self._packets_this_window.clear()

        batches = {org_id: buf for org_id, buf in self._buffers.items() if buf}
        self._buffers.clear()

        stats_snapshot = [
            (s.exporter_id, s.packets, s.flows, s.version, s.last_error, s.last_seen_at)
            for s in self._registry.values()
            if s.packets
        ]
        for state in self._registry.values():
            state.packets = 0
            state.flows = 0

        unclaimed_snapshot = dict(self._unclaimed)
        self._unclaimed.clear()

        if not batches and not stats_snapshot and not unclaimed_snapshot:
            return

        # to_thread because everything below is synchronous SQLAlchemy and,
        # for the scoring call, PyTorch. Both would hold the event loop for the
        # whole batch — tens of milliseconds during which no WebSocket frame is
        # sent and no HTTP request is answered.
        scored = await asyncio.to_thread(
            self._flush_blocking, batches, stats_snapshot, unclaimed_snapshot
        )

        if self._on_scored:
            for org_id, flows, point in scored:
                try:
                    await self._on_scored(org_id, flows, point)
                except Exception:
                    # A slow or broken subscriber must not stop the next flush.
                    # The flows are already persisted at this point; the live
                    # push is a convenience on top of durable state.
                    log.exception("netflow: broadcast callback failed")

    def _flush_blocking(
        self,
        batches: Dict[int, List[Dict]],
        stats_snapshot: List[Tuple],
        unclaimed_snapshot: Dict[str, _UnclaimedState],
    ) -> List[Tuple[int, List[Dict], Dict]]:
        """Score and persist. Runs in a worker thread, never on the loop."""
        # Imported here, not at module scope: engine imports a good deal of the
        # app, and a top-level import would make this module's import graph
        # heavy enough to matter at startup and circular in places.
        from ..engine import process_flows, record_metric_point

        out: List[Tuple[int, List[Dict], Dict]] = []
        db = SessionLocal()
        try:
            for org_id, raw in batches.items():
                try:
                    flows = process_flows(db, org_id, raw, source="live")
                    point = record_metric_point(db, org_id, flows)
                    db.commit()
                    out.append((org_id, flows, point))
                except SQLAlchemyError:
                    db.rollback()
                    log.exception("netflow: failed to persist %d flows for org %d",
                                  len(raw), org_id)
                except RuntimeError as exc:
                    # process_flows raises this when the model is not loaded.
                    # Expected on a broken deploy; logged once per batch rather
                    # than per flow so it does not bury the rest of the log.
                    db.rollback()
                    log.error("netflow: cannot score flows for org %d: %s", org_id, exc)

            self._persist_exporter_stats(db, stats_snapshot)
            self._persist_unclaimed(db, unclaimed_snapshot)
        finally:
            db.close()
        return out

    @staticmethod
    def _persist_exporter_stats(db, stats_snapshot: List[Tuple]) -> None:
        if not stats_snapshot:
            return
        try:
            for exporter_id, packets, flows, version, last_error, last_seen in stats_snapshot:
                row = db.get(FlowExporter, exporter_id)
                if row is None:
                    continue  # deleted between snapshot and flush
                row.packets_received = (row.packets_received or 0) + packets
                row.flows_received = (row.flows_received or 0) + flows
                if last_seen:
                    row.last_seen_at = last_seen
                if version:
                    row.version = version
                row.last_error = last_error[:200]
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            # Counters are telemetry. Losing a window of them is a cosmetic
            # problem, and it must not be allowed to take the flows down with it.
            log.exception("netflow: failed to update exporter counters")

    @staticmethod
    def _persist_unclaimed(db, snapshot: Dict[str, _UnclaimedState]) -> None:
        if not snapshot:
            return
        try:
            for source_ip, entry in snapshot.items():
                row = db.scalar(
                    select(UnclaimedExporter).where(
                        UnclaimedExporter.source_ip == source_ip
                    )
                )
                if row is None:
                    row = UnclaimedExporter(
                        source_ip=source_ip,
                        version=entry.version,
                        first_seen_at=entry.first_seen_at or utcnow(),
                        # Set explicitly rather than relying on the column
                        # default: a `default=` is applied by the INSERT, so on
                        # a row that has not been flushed yet the attribute is
                        # still None and the increment below would raise.
                        packets_received=0,
                    )
                    db.add(row)
                row.packets_received = (row.packets_received or 0) + entry.packets
                row.last_seen_at = entry.last_seen_at or utcnow()
                if entry.version and not row.version:
                    row.version = entry.version
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            log.exception("netflow: failed to record unclaimed sources")

    # ── registry ──────────────────────────────────────────────────────────
    async def _refresh_registry(self) -> None:
        try:
            rows = await asyncio.to_thread(self._load_registry_rows)
        except SQLAlchemyError:
            # Keep serving the previous snapshot. A database blip should not
            # make us stop recognising exporters we already know about — that
            # would turn a brief outage into a gap in a customer's traffic.
            log.exception("netflow: registry refresh failed, keeping previous view")
            return

        fresh: Dict[str, _ExporterState] = {}
        for exporter_id, org_id, source_ip, node_label, sampling_rate in rows:
            existing = self._registry.get(source_ip)
            # Template state is carried across refreshes deliberately. v9
            # exporters resend templates only every few minutes; discarding the
            # cache every thirty seconds would make most data sets undecodable
            # and the device would look permanently broken.
            state = _ExporterState(
                exporter_id=exporter_id,
                org_id=org_id,
                node_label=node_label or source_ip,
                sampling_rate=max(1, int(sampling_rate or 1)),
                templates=existing.templates if existing else TemplateCache(),
            )
            if existing and existing.exporter_id == exporter_id:
                state.packets = existing.packets
                state.flows = existing.flows
                state.version = existing.version
                state.last_error = existing.last_error
                state.last_seen_at = existing.last_seen_at
            fresh[source_ip] = state

        if len(fresh) > _MAX_TEMPLATE_CACHES:
            log.warning(
                "netflow: %d registered exporters exceeds the %d template-cache "
                "ceiling; the excess will not decode v9/IPFIX",
                len(fresh), _MAX_TEMPLATE_CACHES,
            )

        self._registry = fresh
        self._registry_loaded_at = time.monotonic()

    def invalidate_registry(self) -> None:
        """Reload the exporter registry on the next flush rather than on time.

        Called by the API whenever a registration changes. Without it, a device
        claimed in the dashboard keeps being dropped as unregistered for up to
        `_REGISTRY_REFRESH_S` — during which the operator watches it sit at
        "waiting" while the unregistered-drop counter climbs, which is exactly
        what a wrong source address looks like. They then go and "fix" a
        working configuration.

        A flag rather than an awaited reload: the routes that call this are
        synchronous and the reload queries the database, so doing it inline
        would put a query on the request path to save at most one flush
        interval. `-inf` rather than 0.0 because `time.monotonic()` has an
        undefined epoch — on a machine that just booted it can be small enough
        that a zero would not compare as stale.
        """
        self._registry_loaded_at = float("-inf")

    @staticmethod
    def _load_registry_rows() -> List[Tuple]:
        db = SessionLocal()
        try:
            return list(
                db.execute(
                    select(
                        FlowExporter.id,
                        FlowExporter.org_id,
                        FlowExporter.source_ip,
                        FlowExporter.node_label,
                        FlowExporter.sampling_rate,
                    ).where(FlowExporter.enabled.is_(True))
                ).all()
            )
        finally:
            db.close()


class _FlowProtocol(asyncio.DatagramProtocol):
    """Thin adapter. All the logic lives on the collector."""

    def __init__(self, collector: FlowCollector) -> None:
        self._collector = collector

    def datagram_received(self, data: bytes, addr) -> None:
        self._collector.handle_datagram(data, addr[0])

    def error_received(self, exc: Exception) -> None:
        # On UDP this is usually an ICMP port-unreachable for a datagram *we*
        # sent, which we never do. Logged at debug because it is noise, not a
        # fault, and it can arrive at a high rate.
        log.debug("netflow: socket error: %s", exc)


# Module-level handle so lifespan can start it and the API can read its stats.
_collector: Optional[FlowCollector] = None


def get_collector() -> Optional[FlowCollector]:
    return _collector


def set_collector(collector: Optional[FlowCollector]) -> None:
    global _collector
    _collector = collector
