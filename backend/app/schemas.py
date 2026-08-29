"""Request/response models.

Note the asymmetry: inbound schemas validate hard, outbound schemas never carry
password_hash. `UserOut` is the only user shape any endpoint returns.
"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# Not exhaustive and not meant to be — it catches the providers an admin might
# plausibly type by mistake. The real guarantee is that a domain match only
# produces a pending request, never access.
_PUBLIC_EMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "gmx.com", "mail.com", "zoho.com",
    "yandex.com", "fastmail.com", "tutanota.com", "hey.com",
})


def normalise_email_domain(v: str) -> str:
    """Shared by signup and settings, which are two doors onto one decision.

    Two copies of this would drift, and the direction it drifts is the one
    that matters: whichever door forgot the public-provider rule becomes the
    way to point an org at gmail.com.
    """
    v = v.strip().lower().lstrip("@")
    if not v:
        return ""  # explicit opt-out: turns domain joining back off
    if "/" in v or " " in v or "@" in v or "." not in v:
        raise ValueError("Enter a bare domain, like acme.com")
    # A public mailbox provider here would turn "anyone at our company" into
    # "anyone at all" — every Gmail address on earth could file a join request
    # against this org. Approval would still be required, but the request queue
    # is itself a target, and an admin clicking through a hundred lookalikes
    # will eventually approve the wrong one.
    if v in _PUBLIC_EMAIL_DOMAINS:
        raise ValueError(
            f"'{v}' is a public email provider, so anyone could request to "
            "join. Use a domain your organisation controls."
        )
    return v


# ── auth ──────────────────────────────────────────────────────────────────
class SignupIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    org_name: str = Field(min_length=1, max_length=120)
    # Picks the default node topology and a handful of nav/page labels. Required
    # rather than defaulted so a signing-up user makes the choice once, on
    # purpose, instead of it being silently assumed.
    org_type: str = Field(pattern="^(company|consumer)$")
    # Collected by the company signup, which asks what you do; the household
    # form does not, because "job title" is a strange question to ask someone
    # about their own flat. Blank falls back to a per-org-type default.
    title: str = Field(default="", max_length=120)
    # Set here rather than left to a follow-up settings call, so a rejected
    # domain fails the whole signup instead of leaving a live account whose
    # owner believes they configured something they did not.
    email_domain: str = Field(default="", max_length=255)

    @field_validator("name", "org_name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("cannot be blank")
        return v

    @field_validator("email_domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        return normalise_email_domain(v)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class JoinIn(BaseModel):
    """Request to join an org that already exists, rather than creating one.

    `code` is optional because there are two routes in: an invite an admin
    issued for you specifically, or a match on the org's email domain. The
    server decides which applies — the client cannot pick, and a domain match
    never confers more than an invite would.
    """

    email: EmailStr
    password: str = Field(min_length=12, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    title: str = Field(default="", max_length=120)
    code: Optional[str] = Field(default=None, max_length=200)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("cannot be blank")
        return v


class JoinOut(BaseModel):
    """The result of a join request. Carries no session.

    A pending account gets no cookie and no token: approval is what grants
    access, so handing out a session here and filtering it later would make
    the wrong thing the default.
    """

    ok: bool
    status: str
    org_name: str
    join_method: str
    message: str


class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str
    title: str
    initials: str
    is_active: bool
    org_id: int
    org_name: str
    org_type: str
    created_at: datetime
    last_login_at: Optional[datetime] = None
    # "pending" means they asked to join and no admin has decided yet. Distinct
    # from is_active, which means an admin turned an existing account off.
    status: str = "active"
    # founder | invite | domain — how this person got in. The approval screen
    # shows it, because a domain match is an unverified claim about an email
    # address and an invite is a decision somebody actually made.
    join_method: str = "founder"


class InviteIn(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=120)
    role: str = Field(pattern="^(admin|analyst|viewer)$")
    password: str = Field(min_length=12, max_length=200)


class UpdateUserIn(BaseModel):
    name: Optional[str] = Field(default=None, max_length=120)
    title: Optional[str] = Field(default=None, max_length=120)
    role: Optional[str] = Field(default=None, pattern="^(admin|analyst|viewer)$")
    is_active: Optional[bool] = None


class UpdateMeIn(BaseModel):
    """Self-service profile edit.

    Deliberately narrower than UpdateUserIn: `role` and `is_active` are absent,
    so this endpoint cannot be used to escalate your own privileges. Changing
    those stays with an admin.
    """

    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    title: Optional[str] = Field(default=None, max_length=120)


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=200)


# ── flows ─────────────────────────────────────────────────────────────────
class FlowIn(BaseModel):
    """A flow submitted by a real collector to POST /api/ingest."""

    src_ip: str = Field(max_length=45)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = Field(default="TCP", max_length=10)
    node: str = Field(default="unknown", max_length=60)
    duration: float = Field(ge=0)
    packets: int = Field(ge=0)
    total_bytes: Optional[float] = Field(default=None, ge=0)
    bytes_per_sec: Optional[float] = Field(default=None, ge=0)
    ts: Optional[datetime] = None


class FlowBatchIn(BaseModel):
    flows: List[FlowIn] = Field(max_length=500)


class FlowOut(BaseModel):
    id: str
    ts: int
    src_ip: str
    dst_port: int
    protocol: str
    node: str
    duration: float
    packets: int
    bytes_per_sec: float
    prediction: str
    confidence: float
    mitigated: bool
    source: str


# ── incidents ─────────────────────────────────────────────────────────────
class IncidentOut(BaseModel):
    id: int
    src_ip: str
    label: str
    node: str
    opened_at: int
    last_seen_at: int
    resolved_at: Optional[int] = None
    flow_count: int
    peak_confidence: float
    peak_bps: float
    severity: str
    status: str
    mitigated: bool
    # Which escalation step was recorded, if any. `mitigation_expires_at` is
    # null both when there is no ban and when the ban is permanent, so the two
    # fields have to be read together — see MITIGATION_TIERS.
    mitigation_tier: Optional[str] = None
    rate_limit_rps: Optional[int] = None
    mitigation_expires_at: Optional[int] = None
    # Constant false today. Sent anyway so the UI reads enforcement state back
    # rather than inferring it from the tier: the day an enforcement hook does
    # land, a page that assumed "tier set means applied" would already have been
    # lying for months, and nothing would flag the change.
    enforced: bool = False
    acknowledged_by: Optional[str] = None


# The escalation ladder. Ordered, and the order is load-bearing: the engine only
# ever moves an incident up it, so an operator's ban cannot be quietly downgraded
# to a throttle by the next flow that happens to arrive.
MITIGATION_TIERS = ("throttle", "repeat_offender", "ban")

# A ban longer than this is what "permanent" is for. The real reason for a cap is
# narrower: `now + timedelta(minutes=v)` raises OverflowError on absurd input,
# which surfaces as a 500 rather than a message anyone can act on.
MAX_BAN_MINUTES = 525_600  # one year


class IncidentActionIn(BaseModel):
    action: str = Field(pattern="^(acknowledge|resolve|mitigate|reopen|ban)$")
    # Float, not int, so a ban can be tested without waiting a minute for it to
    # expire. None on a ban means permanent.
    duration_minutes: Optional[float] = Field(
        default=None, gt=0, le=MAX_BAN_MINUTES
    )


# ── settings ──────────────────────────────────────────────────────────────
class SettingsOut(BaseModel):
    threshold: float
    auto_mitigate: bool
    webhook_url: str
    notify_browser: bool
    min_severity: str
    poll_interval_ms: int
    max_table_rows: int
    repeat_offender_window_minutes: int = 60
    org_name: str
    # Empty means nobody can request to join by email domain, and an invite is
    # the only route in.
    email_domain: str = ""


class SettingsIn(BaseModel):
    threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    auto_mitigate: Optional[bool] = None
    webhook_url: Optional[str] = Field(default=None, max_length=500)
    notify_browser: Optional[bool] = None
    min_severity: Optional[str] = Field(default=None, pattern="^(low|medium|high|critical)$")
    poll_interval_ms: Optional[int] = Field(default=None, ge=250, le=60000)
    max_table_rows: Optional[int] = Field(default=None, ge=5, le=500)
    # Floor of 1: a zero-length window would mean no two events are ever "in the
    # same window", so nothing could ever reach repeat-offender and the tier
    # would silently stop existing. Ceiling of a week keeps the lookback inside
    # the range the incident table is actually indexed for.
    repeat_offender_window_minutes: Optional[int] = Field(
        default=None, ge=1, le=10_080
    )
    org_name: Optional[str] = Field(default=None, max_length=120)
    email_domain: Optional[str] = Field(default=None, max_length=255)

    @field_validator("email_domain")
    @classmethod
    def _real_domain(cls, v: Optional[str]) -> Optional[str]:
        # None means "not in this PATCH" and must stay distinct from "", which
        # is how an admin switches domain joining back off.
        if v is None:
            return v
        return normalise_email_domain(v)

    @field_validator("webhook_url")
    @classmethod
    def _safe_webhook(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        v = v.strip()
        # Outbound alerts must not be coerced into hitting internal services or
        # arbitrary schemes; require an explicit https/http URL.
        if not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("Webhook URL must start with http:// or https://")
        return v


# ── API keys ──────────────────────────────────────────────────────────────
class ApiKeyCreateIn(BaseModel):
    label: str = Field(default="collector", min_length=1, max_length=120)


class ApiKeyOut(BaseModel):
    """A key as listed. Deliberately carries no usable secret."""

    id: int
    label: str
    prefix: str
    scope: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    is_active: bool


class ApiKeyCreatedOut(ApiKeyOut):
    """Returned only from the create call.

    `key` is the one and only time the secret exists outside the agent that
    will use it — the database holds a digest, so it genuinely cannot be shown
    again later.
    """

    key: str


# ── invites ───────────────────────────────────────────────────────────────
class InviteCreateIn(BaseModel):
    """Issue one invite for one person.

    `expires_in_hours` is capped at a fortnight rather than left open. An
    invite is a decision an admin made about one person at one moment; a code
    that still works months later is a standing password to a security
    dashboard sitting in somebody's inbox.
    """

    email: EmailStr
    role: str = Field(pattern="^(admin|analyst|viewer)$")
    expires_in_hours: int = Field(default=72, ge=1, le=336)


class InviteOut(BaseModel):
    """An invite as listed. Like ApiKeyOut, deliberately carries no secret."""

    id: int
    prefix: str
    invitee_email: str
    role: str
    state: str  # open | used | expired | revoked
    created_at: datetime
    created_by: str
    expires_at: datetime
    used_at: Optional[datetime] = None
    used_by: Optional[str] = None


class InviteCreatedOut(InviteOut):
    """Returned only from the create call — the one time the code is visible."""

    code: str


# ── misc ──────────────────────────────────────────────────────────────────
class MitigateIn(BaseModel):
    flow_id: Optional[str] = None
    src_ip: Optional[str] = None


class ThresholdIn(BaseModel):
    threshold: float = Field(ge=0.0, le=1.0)


class StatusOut(BaseModel):
    model_ready: bool
    model_error: Optional[str] = None
    model_name: str
    framework: str
    architecture: Optional[str] = None
    dataset: str
    # `dataset` is the machine key the training run wrote ("cicids2017+synthetic");
    # `dataset_label` is the same thing spelled for a human. Both travel together
    # because tests assert on the key and the UI prints the label.
    dataset_label: Optional[str] = None
    dataset_note: Optional[str] = None
    accuracy: Optional[float] = None
    classes: List[str]
    uptime_s: int
    simulator: bool
    version: str


class AuditOut(BaseModel):
    id: int
    user_label: str
    action: str
    detail: str
    ts: int


class SeriesOut(BaseModel):
    labels: List[int]
    throughput: List[float]
    threat: List[float]


class BreakdownOut(BaseModel):
    labels: List[str]
    values: List[float]


class TalkerOut(BaseModel):
    """One source address, summarised over the requested window.

    Carries bytes, packets and flow count together rather than a single "volume"
    number, because the three rank differently and the difference is diagnostic.
    A bulk download tops the byte ranking; a SYN flood is nearly invisible there
    and tops the flow count instead, since its whole method is a great many tiny
    conversations. Ranking by bytes alone would hide the attack this tool exists
    to find.
    """

    src_ip: str
    flows: int
    packets: int
    total_bytes: float
    bytes_share: float          # percent of all traffic in the window
    attack_flows: int
    attack_share: float         # percent of this talker's own flows
    top_prediction: str
    max_confidence: float
    mitigated: int
    ports: int                  # distinct destination ports touched
    nodes: List[str]
    first_seen: int             # epoch seconds
    last_seen: int


class TalkersOut(BaseModel):
    window_minutes: int
    total_bytes: float
    total_flows: int
    unique_sources: int
    talkers: List[TalkerOut]


class ProtocolRowOut(BaseModel):
    protocol: str
    flows: int
    total_bytes: float
    attack_flows: int


class PortRowOut(BaseModel):
    port: int
    service: str
    flows: int
    total_bytes: float
    attack_flows: int
    sources: int


class TrafficBreakdownOut(BaseModel):
    window_minutes: int
    protocols: List[ProtocolRowOut]
    ports: List[PortRowOut]


class AnomalyOut(BaseModel):
    """An aggregate deviation from the learned baseline.

    `expected` is what the baseline predicted for this time of week, not a
    configured threshold — the difference matters, because it is why a busy
    Monday morning does not read as an attack.
    """

    id: int
    ts: int
    last_seen_at: int
    metric: str
    metric_label: str
    direction: str          # spike | drop
    observed: float
    expected: float
    deviation: float        # signed z-score
    peak_deviation: float
    severity: str
    windows: int
    status: str
    acknowledged_by: Optional[str] = None


class BaselineSlotOut(BaseModel):
    bucket: int
    label: str
    metric: str
    mean: float
    sigma: float
    samples: int
    ready: bool


class BaselineOut(BaseModel):
    """The learned profile plus how much of it is trustworthy yet.

    `warmth` exists so the dashboard can say "still learning" rather than
    showing an empty anomaly list as though the network were verified clean.
    """

    window_seconds: int
    z_threshold: float
    warmth: Dict
    slots: List[BaselineSlotOut]
    current: Dict


class SummaryOut(BaseModel):
    flows_per_min: int
    attacks_blocked: int
    avg_confidence: float
    inference_ms: float
    nodes_online: int
    nodes_total: int
    threat_level: str
    open_incidents: int


class ModelMetricsOut(BaseModel):
    ready: bool
    metrics: Dict
