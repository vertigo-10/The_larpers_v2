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
from sqlalchemy.types import TypeDecorator

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UtcDateTime(TypeDecorator):
    """A datetime that is still UTC-aware after a round trip through SQLite.

    SQLite has no timezone type, so a value written as aware reads back naive
    even from DateTime(timezone=True). Anything that then calls .timestamp() or
    hands the value to Pydantic gets it reinterpreted in the server's local
    zone — an audit entry written seconds ago rendered as hours old, and, worse,
    an invite expiry compared against the wrong instant.

    Normalising on the way in and out fixes every reader at once, rather than
    asking each call site to remember the guard.
    """

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(DateTime(timezone=True))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        # A naive value here is a bug upstream, but storing it as if it were
        # local would bake the mistake in. UTC is the only assumption that
        # matches everything else this app writes.
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class Role(str, enum.Enum):
    admin = "admin"      # manage team + settings + mitigate
    analyst = "analyst"  # mitigate + acknowledge incidents
    viewer = "viewer"    # read-only


class IncidentStatus(str, enum.Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class UserStatus(str, enum.Enum):
    """Whether an account has been let in yet.

    Deliberately separate from `is_active`. That flag means "an admin turned
    this person off"; this one means "this person has asked to join and nobody
    has decided yet". Collapsing them would make a brand-new joiner
    indistinguishable from a suspended employee in the team list, which is
    exactly the distinction an admin needs in order to act.
    """

    active = "active"
    pending = "pending"


class OrgType(str, enum.Enum):
    """What kind of network this org is protecting.

    This is not cosmetic: it picks the default node topology seeded at signup
    (a company gets edge/DC/API-tier segments, a household gets a router and a
    couple of device groups) and it steers a handful of nav labels and page
    copy so the product reads like it was built for whichever one you are,
    instead of a scaled-down enterprise tool wearing a coat of paint.
    """

    company = "company"
    consumer = "consumer"


class Org(Base):
    __tablename__ = "orgs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # Existing orgs (created before this column existed) default to "company"
    # via the additive migration below, matching the enterprise-style demo
    # topology they were already seeded with — not "consumer", which would
    # silently relabel a workspace nobody asked to relabel.
    org_type: Mapped[str] = mapped_column(String(20), default=OrgType.consumer.value)

    # Lets an employee find their employer during signup without an invite.
    # Stored lowercase and bare ("acme.com", no "@"). Empty means the org
    # cannot be joined this way and an invite code is the only route in.
    #
    # Note this is a *discovery* mechanism, not an authentication one: nothing
    # in this application verifies that a person controls the address they
    # signed up with, so a domain match alone must never grant access. It
    # places the joiner in a pending state for an admin to approve, and that
    # admin is shown that the address is unverified.
    email_domain: Mapped[str] = mapped_column(String(255), default="", index=True)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

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

    # See UserStatus: "pending" is awaiting admin approval, not suspended.
    status: Mapped[str] = mapped_column(
        String(20), default=UserStatus.active.value, index=True
    )
    # How this person got into the org, kept so an admin approving a request
    # can see whether anyone actually invited them. A domain match is a claim,
    # an invite is a decision, and the approval screen should not present the
    # two as equivalent.
    join_method: Mapped[str] = mapped_column(String(20), default="founder")

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(UtcDateTime, nullable=True)

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
    # How far back to look when deciding whether a source is a repeat offender.
    # Per-org because "three times in an hour" means something very different on
    # a home router than on an edge segment where scans are background noise.
    repeat_offender_window_minutes: Mapped[int] = mapped_column(Integer, default=60)

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

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    created_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        UtcDateTime, nullable=True
    )
    # Soft revocation: the row survives so the audit trail still resolves which
    # key performed past actions.
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        UtcDateTime, nullable=True
    )

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


class Invite(Base):
    """A single-use code that lets one named person join an existing org.

    Modelled on ApiKey rather than on a password: the secret is 32 random
    bytes, so it is hashed with SHA-256 (not bcrypt) for the reasons given on
    ApiKey.key_hash, returned to the admin exactly once, and never recoverable.

    The distinct `sentry_inv_` prefix matters. Collector keys live unattended
    on capture devices; invite codes create user accounts. If the two shared a
    prefix, a key scraped off a Raspberry Pi would be indistinguishable from a
    credential that mints logins, and a copy-paste error could hand one out in
    place of the other.

    Single-use and expiring by design: an invite is a decision an admin made
    about one person at one moment, and it should not outlive that. A code
    that still works six months later is a standing password to a security
    dashboard sitting in somebody's inbox.
    """

    __tablename__ = "invites"
    __table_args__ = (Index("ix_invites_org_open", "org_id", "used_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    prefix: Mapped[str] = mapped_column(String(20), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    # Who it is for, and enforced at redemption rather than merely recorded:
    # /api/auth/join refuses a code presented by any other address. An invite
    # is a decision about one named person, so a code forwarded to a colleague
    # — or lifted out of a mailbox — must not work for whoever ends up holding
    # it. The cost is that a typo here kills the invite and it has to be
    # reissued, which is the safe direction to fail.
    invitee_email: Mapped[str] = mapped_column(String(255), default="")

    # The role the joiner receives on approval, chosen by the admin when the
    # invite is issued.
    role: Mapped[str] = mapped_column(String(20), default=Role.viewer.value)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    created_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)

    used_at: Mapped[Optional[datetime]] = mapped_column(
        UtcDateTime, nullable=True
    )
    used_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Soft revocation, matching ApiKey: the row survives so the audit trail
    # still resolves who issued an invite that was later withdrawn.
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        UtcDateTime, nullable=True
    )

    def state(self, now: Optional[datetime] = None) -> str:
        """One word for the list view. Order matters: a used code is spent
        whatever else is true of it, and revocation beats mere expiry."""
        now = now or datetime.now(timezone.utc)
        if self.used_at is not None:
            return "used"
        if self.revoked_at is not None:
            return "revoked"
        # SQLite has no timezone type, so a value written as aware reads back
        # naive. Comparing the two raises, and this comparison is the one
        # deciding whether a credential still works — so the value is pinned
        # to UTC rather than left to whatever the server's local zone is.
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= now:
            return "expired"
        return "open"


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
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


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
    ts: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)

    src_ip: Mapped[str] = mapped_column(String(45))
    # Which target the flow was aimed at. Not a model feature — the classifier
    # never sees an address, deliberately, because learning that "traffic to
    # 10.0.0.7 is bad" is memorising a host rather than recognising an attack.
    #
    # It is stored because the aggregate detectors need to know what a group of
    # flows is converging *on*. Slow-DoS is the clearest case: thirty idle
    # connections spread across thirty servers is a quiet afternoon, and the
    # same thirty aimed at one of them is an outage in progress. Without this
    # column those two are the same row set.
    #
    # Empty string, not NULL, means "we were never told" — the ingest API makes
    # it optional and flows recorded before this column existed genuinely have
    # no answer. Detectors must skip those rather than group them all together
    # under a shared blank, which would invent a target that does not exist.
    dst_ip: Mapped[str] = mapped_column(String(45), default="")
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

    opened_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(UtcDateTime, nullable=True)

    flow_count: Mapped[int] = mapped_column(Integer, default=1)
    peak_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    peak_bps: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(20), default="medium")

    # One sentence saying what was actually observed, written by whichever
    # detector opened the row.
    #
    # It exists because not every incident comes from the classifier. A model
    # detection is self-describing — the label is the finding, and
    # `peak_confidence` says how sure it was. A rule-based aggregate detection
    # is not: "slow_dos from 203.0.113.9" leaves out the only facts an operator
    # needs, which are how many connections, against what, and how idle they
    # were. Those live here rather than in three new columns because they
    # differ per detector and none of them is ever filtered or sorted on.
    #
    # NULL on every incident the classifier opened, and on every incident that
    # predates this column. The UI shows the line only when there is one, so a
    # null reads as "nothing further to add" rather than as missing data.
    detail: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default=IncidentStatus.open.value)
    mitigated: Mapped[bool] = mapped_column(Boolean, default=False)

    # The escalation tier layered over `mitigated`. That boolean only ever said
    # whether a decision was taken; these say which one and for how long.
    # Nullable rather than defaulted to a tier name, because every incident
    # opened before this existed genuinely has no tier and guessing one for it
    # would put words in the record's mouth.
    #
    # None of these three are enforced by SENTRY. It watches traffic and has no
    # path to the router, so a tier is a decision it recorded and stands behind,
    # not an action it performed — the UI must keep saying so.
    mitigation_tier: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    rate_limit_rps: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # NULL means two different things depending on the tier: no ban at all, or a
    # permanent one. Read it together with `mitigation_tier`, never alone.
    mitigation_expires_at: Mapped[Optional[datetime]] = mapped_column(
        UtcDateTime, nullable=True
    )

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
    ts: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    throughput: Mapped[float] = mapped_column(Float)
    threat: Mapped[float] = mapped_column(Float)
    flows: Mapped[int] = mapped_column(Integer, default=0)


class Baseline(Base):
    """What this network normally looks like, per metric, per time-of-week bucket.

    The model classifies each flow on its own shape, so it cannot see an attack
    that is only visible in aggregate — traffic quietly tripling, a thousand new
    source addresses appearing, a link going silent. That is what a baseline is
    for, and it is a genuinely different question from "is this flow malicious".

    Buckets are (weekend?, hour-of-day), so 48 of them. A full hour-of-week
    baseline would be more precise but needs a month of traffic before it says
    anything useful; 48 buckets still separate 3am from 3pm and Sunday from
    Tuesday, which is where nearly all of the daily variation lives, and they
    warm up in a few days instead.

    Mean and variance are kept incrementally (EWMA/EWMV) rather than by
    retaining samples, so the table stays a fixed size no matter how long the
    deployment runs.
    """

    __tablename__ = "baselines"
    __table_args__ = (
        UniqueConstraint("org_id", "metric", "bucket", name="uq_baseline_slot"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    metric: Mapped[str] = mapped_column(String(20))   # flows | bytes | sources
    bucket: Mapped[int] = mapped_column(Integer)      # 0-47

    mean: Mapped[float] = mapped_column(Float, default=0.0)
    variance: Mapped[float] = mapped_column(Float, default=0.0)
    samples: Mapped[int] = mapped_column(Integer, default=0)

    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class Anomaly(Base):
    """An observation that did not match the baseline.

    Separate from Incident on purpose. An incident is "this source is attacking
    us" and is keyed by source IP; an anomaly is "the shape of our traffic
    changed" and has no single source to blame. Conflating them would mean an
    analyst filtering incidents by IP silently loses every aggregate signal.
    """

    __tablename__ = "anomalies"
    __table_args__ = (Index("ix_anomalies_org_ts", "org_id", "ts"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    ts: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    metric: Mapped[str] = mapped_column(String(20))
    direction: Mapped[str] = mapped_column(String(10))  # spike | drop

    observed: Mapped[float] = mapped_column(Float)
    expected: Mapped[float] = mapped_column(Float)
    deviation: Mapped[float] = mapped_column(Float)  # signed z-score
    severity: Mapped[str] = mapped_column(String(20), default="medium")

    # An attack lasting twenty minutes should be one anomaly that stays open,
    # not twenty rows. Consecutive breaches extend the open row instead.
    windows: Mapped[int] = mapped_column(Integer, default=1)
    peak_deviation: Mapped[float] = mapped_column(Float, default=0.0)

    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    acknowledged_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    acknowledged_by: Mapped[Optional["User"]] = relationship()


class FlowExporter(Base):
    """A switch, router or firewall registered to send flow records to us.

    NetFlow, IPFIX and sFlow have no authentication of any kind. There is no
    key, no handshake, no signature — anything that can reach the collector's
    UDP port can send records claiming to describe any traffic it likes. The
    only identifying signal in the datagram is the source IP of the packet
    itself, and even that is spoofable on a network that permits it.

    So the trust model is registration, not authentication: an operator states
    in advance "my firewall exports from 203.0.113.5", and the collector will
    only attribute flows to that org from that address. Data from an address
    nobody has claimed lands in UnclaimedExporter and is not scored.

    That is weaker than a signed agent and it should be described that way to
    customers. What it buys is a ten-minute setup on hardware they already own,
    which is the difference between a trial that starts today and one that
    waits on a change window.
    """

    __tablename__ = "flow_exporters"
    __table_args__ = (
        # Globally unique, deliberately not unique-per-org. The collector
        # resolves an incoming packet to an org *by source IP alone*; if two
        # orgs could register 203.0.113.5, that lookup would be ambiguous and
        # one tenant's traffic could be attributed to the other. A global
        # constraint turns that into a visible registration conflict instead of
        # a silent cross-tenant leak.
        UniqueConstraint("source_ip", name="uq_flow_exporter_source_ip"),
        Index("ix_flow_exporters_org_enabled", "org_id", "enabled"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("orgs.id", ondelete="CASCADE"), index=True)

    # 45 chars so an IPv6 literal fits, matching Flow.src_ip.
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    name: Mapped[str] = mapped_column(String(120), default="")

    # Which Node these flows are attributed to on the dashboard. Kept as a
    # label rather than a FK because nodes are created lazily by the engine and
    # an exporter may be registered before its node exists.
    node_label: Mapped[str] = mapped_column(String(60), default="")

    # Learned from the wire on first packet ("v5" | "v9" | "ipfix"), not
    # configured. Operators routinely do not know which their device sends, and
    # asking them to guess produces wrong answers that are hard to debug.
    version: Mapped[str] = mapped_column(String(10), default="")

    # 1 means unsampled. Above 1, counters are multiplied up on ingest.
    #
    # This is the configured override. Devices are supposed to advertise their
    # sampling rate in-band, and where they do the collector uses that. Many
    # do not, or advertise 0, and a 1-in-1000 sample scored as if it were the
    # full picture understates every volume feature by three orders of
    # magnitude — the model would see a flood as a trickle.
    sampling_rate: Mapped[int] = mapped_column(Integer, default=1)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    created_by_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    last_seen_at: Mapped[Optional[datetime]] = mapped_column(UtcDateTime, nullable=True)
    packets_received: Mapped[int] = mapped_column(Integer, default=0)
    flows_received: Mapped[int] = mapped_column(Integer, default=0)

    # The most recent reason a packet from this exporter produced no usable
    # flows. Almost always "awaiting template" on a v9 device that has not sent
    # its template refresh yet, which is normal for the first ~10 minutes and
    # alarming if it never clears. Surfacing it turns the commonest support
    # ticket ("I configured it and see nothing") into a self-serve answer.
    last_error: Mapped[str] = mapped_column(String(200), default="")


class UnclaimedExporter(Base):
    """Flow records arriving from an address no org has registered.

    Kept because the alternative is dropping them silently, and "I pointed my
    firewall at you and nothing happened" is then unanswerable. This table lets
    the answer be "we are receiving your packets, the address just is not
    registered yet".

    It is a separate table rather than a FlowExporter with a null org_id on
    purpose. Every tenant-scoped query in this app filters on org_id; a null
    there would be a row that silently escapes that filter, and in a security
    product that is exactly the bug you cannot afford. Unclaimed data has no
    owner, so it lives somewhere that has no owner column to get wrong.
    """

    __tablename__ = "unclaimed_exporters"
    __table_args__ = (
        UniqueConstraint("source_ip", name="uq_unclaimed_exporter_source_ip"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    version: Mapped[str] = mapped_column(String(10), default="")

    first_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    packets_received: Mapped[int] = mapped_column(Integer, default=0)


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
    ts: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
