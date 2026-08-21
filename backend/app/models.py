"""ORM models.

Multi-tenant by organisation: every row that carries data belongs to an Org, and
every query is scoped by the caller's org_id. A user can never read another
organisation's flows.
"""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    admin = "admin"      # manage team + settings + mitigate
    analyst = "analyst"  # mitigate + acknowledge incidents
    viewer = "viewer"    # read-only


class IncidentStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class Org(Base):
    __tablename__ = "orgs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    users: Mapped[list["User"]] = relationship(back_populates="org", cascade="all, delete-orphan")
    settings: Mapped[Optional["OrgSettings"]] = relationship(
        back_populates="org", uselist=False, cascade="all, delete-orphan"
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="uq_users_email"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    email: Mapped[str] = mapped_column(String(255), nullable=False)
    # bcrypt digest. Plaintext passwords are never stored or logged anywhere.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default=Role.analyst.value)
    title: Mapped[str] = mapped_column(String(120), default="Security Analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Server-side session revocation. Every token embeds the version it was
    # minted against; bumping this invalidates all of them at once. That is
    # what makes "sign out" and "change password" actually end a session — a
    # JWT is otherwise valid until it expires, so deleting the cookie alone
    # leaves a replayable token behind.
    #
    # A counter rather than a timestamp on purpose: `iat` is only
    # second-resolution, so any time-based cutoff either leaves a sub-second
    # window open or has to future-date the replacement token, which PyJWT
    # then rejects as immature. An integer has neither problem.
    token_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    org: Mapped["Org"] = relationship(back_populates="users")

    @property
    def initials(self) -> str:
        parts = [p for p in self.name.split() if p]
        return ("".join(p[0] for p in parts[:2]) or "OP").upper()


class OrgSettings(Base):
    __tablename__ = "org_settings"

    org_id: Mapped[int] = mapped_column(
        ForeignKey("orgs.id", ondelete="CASCADE"), primary_key=True
    )
    threshold: Mapped[float] = mapped_column(Float, default=0.85)
    auto_mitigate: Mapped[bool] = mapped_column(Boolean, default=True)
    webhook_url: Mapped[str] = mapped_column(String(500), default="")
    notify_browser: Mapped[bool] = mapped_column(Boolean, default=False)
    min_severity: Mapped[str] = mapped_column(String(20), default="high")
    poll_interval_ms: Mapped[int] = mapped_column(Integer, default=2000)
    max_table_rows: Mapped[int] = mapped_column(Integer, default=45)

    org: Mapped["Org"] = relationship(back_populates="settings")


class ApiKey(Base):
    """A non-human credential, used by collectors posting to /api/ingest.

    An agent on a router or laptop cannot hold a person's password, and should
    not: it would inherit that person's full access and survive their departure.
    A key is scoped to one org, carries a fixed role, and can be revoked on its
    own without disturbing anyone's session.
    """

    __tablename__ = "api_keys"
    __table_args__ = (Index("ix_api_keys_org_active", "org_id", "revoked_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    label: Mapped[str] = mapped_column(String(120), default="collector")

    # The first few characters, stored in the clear so a key can be identified
    # in a list and in the audit log without holding anything that grants access.
    prefix: Mapped[str] = mapped_column(String(16), index=True)

    # SHA-256 of the secret, not bcrypt. bcrypt's cost exists to slow down
    # guessing of low-entropy human passwords; these are 32 random bytes, so
    # brute force is not the threat and a per-request bcrypt verify would just
    # add latency to every ingested batch. What matters is that a database leak
    # does not hand over usable keys, which a plain digest already achieves.
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # Deliberately not a full Role: a collector needs to submit flows and
    # nothing else. If a key leaks it must not be able to read incidents, change
    # settings, or manage the team.
    scope: Mapped[str] = mapped_column(String(20), default="ingest")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Soft revocation: the row survives so the audit trail still resolves which
    # key performed past actions.
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


class Node(Base):
    """A monitored network segment or device."""

    __tablename__ = "nodes"
    __table_args__ = (UniqueConstraint("org_id", "label", name="uq_node_org_label"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(60), nullable=False)
    description: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(20), default="ok")
    mbps: Mapped[float] = mapped_column(Float, default=0.0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Flow(Base):
    """One scored network flow. This is the raw detection record."""

    __tablename__ = "flows"
    __table_args__ = (
        Index("ix_flows_org_ts", "org_id", "ts"),
        Index("ix_flows_org_pred", "org_id", "prediction"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    flow_ref: Mapped[str] = mapped_column(String(40), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    src_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10))
    node: Mapped[str] = mapped_column(String(60), index=True)

    duration: Mapped[float] = mapped_column(Float)
    packets: Mapped[int] = mapped_column(Integer)
    total_bytes: Mapped[float] = mapped_column(Float)
    bytes_per_sec: Mapped[float] = mapped_column(Float)

    prediction: Mapped[str] = mapped_column(String(30), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    mitigated: Mapped[bool] = mapped_column(Boolean, default=False)

    # "live"  = scored from a real flow posted to /api/ingest
    # "simulated" = synthetic flow, still scored by the real model
    source: Mapped[str] = mapped_column(String(20), default="simulated")

    # For simulated flows only: the behaviour the generator actually intended.
    # The model never sees this — it is recorded so the Model page can show a
    # live agreement rate between generated truth and predicted label. Null for
    # ingested flows, where no ground truth exists.
    truth: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)

    incident_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True
    )


class Incident(Base):
    """A correlated group of malicious flows from one source.

    Flows are ephemeral and high-volume; incidents are what an analyst actually
    works. They persist so an attack can be investigated after the fact.
    """

    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_org_status", "org_id", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    label: Mapped[str] = mapped_column(String(30))
    node: Mapped[str] = mapped_column(String(60))

    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    flow_count: Mapped[int] = mapped_column(Integer, default=1)
    peak_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    peak_bps: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    status: Mapped[str] = mapped_column(String(20), default=IncidentStatus.open.value)
    mitigated: Mapped[bool] = mapped_column(Boolean, default=False)

    acknowledged_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    acknowledged_by: Mapped[Optional["User"]] = relationship()


class MetricPoint(Base):
    """Rolled-up throughput / threat score, one row per engine tick."""

    __tablename__ = "metric_points"
    __table_args__ = (Index("ix_metrics_org_ts", "org_id", "ts"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    throughput: Mapped[float] = mapped_column(Float)
    threat: Mapped[float] = mapped_column(Float)
    flows: Mapped[int] = mapped_column(Integer, default=0)


class AuditLog(Base):
    """Who did what. Security tools need an answer to that question."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    user_label: Mapped[str] = mapped_column(String(120), default="system")
    action: Mapped[str] = mapped_column(String(60))
    detail: Mapped[str] = mapped_column(Text, default="")
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
