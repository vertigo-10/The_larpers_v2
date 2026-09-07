"""Managing the network devices that send us flow records.

The whole trust model of NetFlow ingest lives in this file, so it is worth
stating plainly: **the protocol has no authentication.** There is no key, no
signature, no handshake. A datagram arrives, and the only thing distinguishing
a customer's firewall from a stranger's laptop is the source IP in the packet
header — a field that is spoofable on any network that does not filter egress.

Given that, an org claims a source address in advance and the collector will
only ever attribute flows from that address to that org. Which raises the
question this module has to answer carefully: how does an org discover the
address of its own exporter?

The obvious design — show every org every unregistered sender and let them
click "that one's mine" — is a cross-tenant data breach with extra steps. Any
customer could claim any other customer's firewall address and start receiving
their traffic metadata: who they talk to, on what ports, in what volume. The
list itself leaks too, since knowing an address appears on it reveals another
customer's edge IP.

So discovery is gated on evidence of network adjacency. An unclaimed source is
visible to an org only if the admin asking is *browsing from that same address*
(the overwhelmingly common case: the firewall exports from the same WAN IP the
office NATs out of), or if it is adjacent to a device that org already
registered. Everything else stays invisible. It is a weaker proof than a shared
secret and it is not pretending otherwise; what it does is make claiming
someone else's exporter require already being on their network, at which point
they have larger problems.
"""

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import AuditLog, FlowExporter, UnclaimedExporter, User
from ..netflow.collector import get_collector
from ..schemas import (
    CollectorStatusOut,
    ExporterIn,
    ExporterOut,
    ExporterPatch,
    UnclaimedExporterOut,
)
from ..security import current_user, require_admin

log = logging.getLogger("sentry.netflow")

router = APIRouter(prefix="/api/exporters", tags=["exporters"])

# An exporter that has sent nothing for this long is reported as silent. Chosen
# against how these devices behave rather than arbitrarily: exporters emit on
# an active-flow timeout that is commonly 60s and rarely above 300s, so ten
# minutes of nothing means the export has genuinely stopped, not that the
# network happened to be quiet.
_SILENT_AFTER = timedelta(minutes=10)


def _state(row: FlowExporter, now: datetime) -> str:
    if not row.enabled:
        return "disabled"
    if row.last_seen_at is None:
        return "waiting"
    last = row.last_seen_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return "silent" if now - last > _SILENT_AFTER else "live"


def _out(row: FlowExporter, now: Optional[datetime] = None) -> ExporterOut:
    now = now or datetime.now(timezone.utc)
    return ExporterOut(
        id=row.id,
        source_ip=row.source_ip,
        name=row.name,
        node_label=row.node_label or row.source_ip,
        version=row.version,
        sampling_rate=row.sampling_rate,
        enabled=row.enabled,
        last_seen_at=row.last_seen_at,
        packets_received=row.packets_received,
        flows_received=row.flows_received,
        last_error=row.last_error,
        state=_state(row, now),
    )


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _wake_collector() -> None:
    """Tell the collector its exporter registry is stale.

    Every write on this router changes which datagrams are attributable to
    whom, so each one has to reach the collector rather than waiting on its
    refresh timer. Tolerant of there being no collector at all: NetFlow ingest
    is optional, and these routes still work (and are still tested) with it
    switched off.
    """
    collector = get_collector()
    if collector is not None:
        collector.invalidate_registry()


def _adjacent(candidate: str, known: str) -> bool:
    """Are two addresses on the same edge network?

    /24 for IPv4 and /48 for IPv6 — the smallest blocks routinely allocated as
    a single site. Wider would start spanning unrelated customers of the same
    ISP, which is exactly the adjacency this must not accept.
    """
    try:
        a = ipaddress.ip_address(candidate)
        b = ipaddress.ip_address(known)
    except ValueError:
        return False
    if a.version != b.version:
        return False
    prefix = 24 if a.version == 4 else 48
    net = ipaddress.ip_network(f"{b}/{prefix}", strict=False)
    return a in net


# ── CRUD ──────────────────────────────────────────────────────────────────
@router.get("", response_model=List[ExporterOut])
def list_exporters(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    rows = db.scalars(
        select(FlowExporter)
        .where(FlowExporter.org_id == user.org_id)
        .order_by(FlowExporter.created_at.desc())
    ).all()
    now = datetime.now(timezone.utc)
    return [_out(r, now) for r in rows]


@router.post("", response_model=ExporterOut, status_code=status.HTTP_201_CREATED)
def create_exporter(
    body: ExporterIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Register a device. Admin-only: this decides whose traffic we ingest."""
    existing = db.scalar(
        select(FlowExporter).where(FlowExporter.source_ip == body.source_ip)
    )
    if existing is not None:
        # The message deliberately does not say who holds it. Confirming that
        # some *other* organisation registered an address would turn this
        # endpoint into an oracle for mapping other customers' edge IPs.
        if existing.org_id != user.org_id:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "That address is already registered. If it belongs to you, "
                "contact support to have it moved.",
            )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{body.source_ip} is already registered to this organisation.",
        )

    row = FlowExporter(
        org_id=user.org_id,
        source_ip=body.source_ip,
        name=body.name.strip() or body.source_ip,
        node_label=(body.node_label.strip() or body.name.strip() or body.source_ip)[:60],
        sampling_rate=body.sampling_rate,
        enabled=body.enabled,
        created_by_id=user.id,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        # The uniqueness check above is racy — two admins can pass it at once.
        # The constraint is what actually enforces one-org-per-address, and it
        # has to be, because that mapping is what keeps tenants apart.
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "That address is already registered."
        )

    # Registering an exporter is a tenancy decision: it says "flows from this
    # address are ours". That belongs in the audit trail next to the other
    # things only an admin can do.
    db.add(AuditLog(
        org_id=user.org_id, user_id=user.id, user_label=user.name,
        action="exporter.created",
        detail=f"{row.source_ip} ({row.name}), sampling 1:{row.sampling_rate}",
    ))
    # Now claimed, so it is no longer an open question.
    db.execute(
        delete(UnclaimedExporter).where(
            UnclaimedExporter.source_ip == body.source_ip
        )
    )
    db.commit()
    db.refresh(row)
    # The collector reads a cached registry on every datagram. Left to its own
    # timer, a device claimed here keeps being dropped as unregistered for the
    # next half-minute, which on the dashboard is indistinguishable from having
    # typed the wrong address.
    _wake_collector()
    return _out(row)


@router.patch("/{exporter_id}", response_model=ExporterOut)
def update_exporter(
    exporter_id: int,
    body: ExporterPatch,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    row = db.get(FlowExporter, exporter_id)
    # 404 rather than 403 when it belongs to someone else. A 403 would confirm
    # the row exists, which is one bit more than a stranger should learn.
    if row is None or row.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Exporter not found.")

    changed = []
    if body.name is not None:
        row.name = body.name.strip()
        changed.append("name")
    if body.node_label is not None:
        row.node_label = body.node_label.strip()
        changed.append("node_label")
    if body.sampling_rate is not None:
        row.sampling_rate = body.sampling_rate
        changed.append(f"sampling_rate=1:{body.sampling_rate}")
    if body.enabled is not None and body.enabled != row.enabled:
        row.enabled = body.enabled
        changed.append("enabled" if body.enabled else "disabled")

    if changed:
        db.add(AuditLog(
            org_id=user.org_id, user_id=user.id, user_label=user.name,
            action="exporter.updated",
            detail=f"{row.source_ip}: {', '.join(changed)}",
        ))
    db.commit()
    db.refresh(row)
    # Sampling rate and node label are both read per datagram, and `enabled`
    # decides whether the device is in the registry at all — so a disable that
    # took thirty seconds to bite would keep ingesting traffic an operator has
    # already been told is being ignored.
    if changed:
        _wake_collector()
    return _out(row)


@router.delete("/{exporter_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_exporter(
    exporter_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    row = db.get(FlowExporter, exporter_id)
    if row is None or row.org_id != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Exporter not found.")

    source_ip, name = row.source_ip, row.name
    db.delete(row)
    db.add(AuditLog(
        org_id=user.org_id, user_id=user.id, user_label=user.name,
        action="exporter.deleted", detail=f"{source_ip} ({name})",
    ))
    db.commit()
    _wake_collector()
    # Flows already ingested are deliberately left alone. They are evidence of
    # what happened on the network, and deleting a device registration is not a
    # claim that the traffic it reported never occurred.
    return None


# ── discovery ─────────────────────────────────────────────────────────────
@router.get("/unclaimed", response_model=List[UnclaimedExporterOut])
def list_unclaimed(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Unregistered senders this org can prove some adjacency to.

    See the module docstring for why this is filtered rather than global. In
    short: an unfiltered list would let any customer enumerate and then claim
    any other customer's edge address.
    """
    caller_ip = _client_ip(request)
    mine = db.scalars(
        select(FlowExporter.source_ip).where(FlowExporter.org_id == user.org_id)
    ).all()

    rows = db.scalars(
        select(UnclaimedExporter).order_by(UnclaimedExporter.last_seen_at.desc())
    ).all()

    visible = []
    for row in rows:
        if caller_ip and row.source_ip == caller_ip:
            visible.append(row)          # exporting from the address you are on
        elif any(_adjacent(row.source_ip, ip) for ip in mine):
            visible.append(row)          # next to a device you already own
    return [
        UnclaimedExporterOut(
            source_ip=r.source_ip, version=r.version,
            first_seen_at=r.first_seen_at, last_seen_at=r.last_seen_at,
            packets_received=r.packets_received,
        )
        for r in visible
    ]


@router.get("/status", response_model=CollectorStatusOut)
def collector_status(
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Is the collector actually up, and is anything reaching it?

    The counters matter more than they look. "No flows" and "40,000 flows
    dropped because a buffer was full" present identically on the dashboard,
    and they need completely different responses.
    """
    collector = get_collector()
    total = db.scalar(
        select(func.count(FlowExporter.id)).where(FlowExporter.org_id == user.org_id)
    ) or 0

    return CollectorStatusOut(
        enabled=settings.netflow_enabled,
        listening=bool(collector and collector.listening),
        ports=settings.netflow_port_list if settings.netflow_enabled else [],
        exporters=total,
        # Process-wide, not per-org. These describe the health of the socket
        # itself, which is shared, and none of them can be attributed to a
        # tenant — a dropped packet from an unregistered source has no org.
        stats=dict(collector.stats) if collector else {},
    )
