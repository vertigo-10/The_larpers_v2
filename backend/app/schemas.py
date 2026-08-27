"""Request/response models.

Note the asymmetry: inbound schemas validate hard, outbound schemas never carry
password_hash. `UserOut` is the only user shape any endpoint returns.
"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


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

    @field_validator("name", "org_name")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("cannot be blank")
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str


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
    acknowledged_by: Optional[str] = None


class IncidentActionIn(BaseModel):
    action: str = Field(pattern="^(acknowledge|resolve|mitigate|reopen)$")


# ── settings ──────────────────────────────────────────────────────────────
class SettingsOut(BaseModel):
    threshold: float
    auto_mitigate: bool
    webhook_url: str
    notify_browser: bool
    min_severity: str
    poll_interval_ms: int
    max_table_rows: int
    org_name: str


class SettingsIn(BaseModel):
    threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    auto_mitigate: Optional[bool] = None
    webhook_url: Optional[str] = Field(default=None, max_length=500)
    notify_browser: Optional[bool] = None
    min_severity: Optional[str] = Field(default=None, pattern="^(low|medium|high|critical)$")
    poll_interval_ms: Optional[int] = Field(default=None, ge=250, le=60000)
    max_table_rows: Optional[int] = Field(default=None, ge=5, le=500)
    org_name: Optional[str] = Field(default=None, max_length=120)

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
