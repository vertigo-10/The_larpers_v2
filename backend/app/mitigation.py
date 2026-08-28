"""Escalation: deciding *how hard* to respond, once detection has decided *whether*.

Detection is untouched by this module. `engine.severity_for` still says how bad a
flow looks and the threshold still says whether it counts as an attack at all.
What was missing is that every attack got the same response — a single
`mitigated` boolean — so a one-off scan from a mistyped IP and the fourth flood
from the same host in twenty minutes were recorded identically, and an operator
scanning the alerts page had no way to see which sources had earned attention.

The ladder, lowest first:

  throttle         Auto. A rate limit proportional to how loud the source is.
  repeat_offender  Auto. The same source tripped throttle enough times inside
                   the org's window that it stopped looking like an accident.
  ban              Never automatic. An operator chooses it, with a duration.

Two things this module deliberately does not do:

  It does not enforce anything. SENTRY watches traffic and has no path to the
  router, so a tier is a decision recorded and stood behind, not an action
  performed. `enforced` is false on every response and the UI says "recorded,
  not yet enforced" in as many words. Wiring a real firewall in belongs behind
  one hook, and the day it exists the UI should read enforcement back rather
  than assume it — see IncidentOut.enforced.

  It does not promote itself to `ban`. An automatic ban with a duration is the
  one action here that could take a household off the internet on a false
  positive at 3am with nobody awake to undo it. The engine can raise an alarm;
  a person decides to pull the cord.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AuditLog, Incident
from .schemas import MITIGATION_TIERS
from .severity import severity_for

# Severity is a four-step ladder and the rate limit tracks it. The numbers are
# request-per-second ceilings, tightening as confidence and volume rise, and are
# recommendations for whoever applies them — nothing here reads them back.
_RATE_LIMIT_BY_SEVERITY = {
    "low": 1000,
    "medium": 500,
    "high": 100,
    "critical": 10,
}

# How many auto-throttles inside the window make a source a repeat offender.
# Three, not two: two is a coincidence a busy network produces on its own, and a
# tier that fires on coincidence is one operators learn to scroll past.
REPEAT_OFFENDER_THRESHOLD = 3

# An incident built from a handful of flows is a weak sample — the model may be
# confident about each one and still be describing noise. Below this, the
# response is held at the gentlest rung no matter how alarming the score, so a
# three-packet blip cannot present as a critical-severity throttle.
MIN_FLOWS_FOR_FULL_RESPONSE = 5


@dataclass(frozen=True)
class MitigationDecision:
    """What to record for one attack flow. Never applied, only written down."""

    mitigated: bool
    tier: Optional[str]
    rate_limit_rps: Optional[int]
    is_repeat_offender: bool
    reason: str

    @property
    def rank(self) -> int:
        """Position on the ladder, -1 for no tier. Used to refuse downgrades."""
        return MITIGATION_TIERS.index(self.tier) if self.tier else -1


def escalation_score(label: str, confidence: float, bps: float, flow_count: int) -> float:
    """0..1, combining what the model saw with how much of it there was.

    Not `engine.threat_score`, which grades a whole batch 0–100 for the
    dashboard gauge. This one grades a single source's case for a harder
    response. Named apart because the two are easy to reach for by mistake and
    their ranges do not even match.

    Severity alone is too coarse to rank two critical incidents against each
    other, and confidence alone ignores volume: a 0.99-confidence scan of three
    packets is not the equal of a 0.91-confidence flood. `flow_count` acts as a
    sample-size damper rather than another additive term, because a large flow
    count is not itself evidence of malice — it only makes the other evidence
    worth trusting.
    """
    severity = severity_for(label, confidence, bps)
    base = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}[severity]
    # Confidence pulls the score around inside its severity band instead of
    # overriding it, so a barely-confident critical still outranks a certain low.
    scored = base * (0.7 + 0.3 * min(max(confidence, 0.0), 1.0))
    if flow_count < MIN_FLOWS_FOR_FULL_RESPONSE:
        scored *= 0.6
    return round(min(scored, 1.0), 4)


def _count_recent_throttles(
    db: Session, org_id: int, src_ip: str, window_minutes: int, now: datetime
) -> int:
    """How many times this source was auto-throttled inside the window.

    Counts incidents rather than flows. A flood is thousands of flows and one
    incident, and counting flows would make a single sustained attack look like
    a thousand separate offences — every flood would cross the threshold on its
    own, which is the same as having no threshold.
    """
    cutoff = now - timedelta(minutes=max(window_minutes, 1))
    return int(
        db.execute(
            select(func.count(Incident.id)).where(
                Incident.org_id == org_id,
                Incident.src_ip == src_ip,
                Incident.mitigation_tier.in_(("throttle", "repeat_offender")),
                Incident.last_seen_at >= cutoff,
            )
        ).scalar_one()
        or 0
    )


def decide(
    db: Session,
    org_id: int,
    src_ip: str,
    label: str,
    confidence: float,
    bps: float,
    flow_count: int,
    *,
    is_attack: bool,
    auto_mitigate: bool,
    threshold: float,
    window_minutes: int,
    now: datetime,
) -> MitigationDecision:
    """Pick a tier for one scored flow.

    The `is_attack and auto_mitigate and confidence >= threshold` test is the
    one this replaced, and it is preserved exactly: the same flows are mitigated
    as before. Everything added here describes flows that were already being
    acted on, so turning escalation on cannot start responding to traffic that
    the previous version left alone.
    """
    if not (is_attack and auto_mitigate and confidence >= threshold):
        return MitigationDecision(
            mitigated=False, tier=None, rate_limit_rps=None,
            is_repeat_offender=False,
            reason="Below the org's auto-response threshold.",
        )

    severity = severity_for(label, confidence, bps)
    if flow_count < MIN_FLOWS_FOR_FULL_RESPONSE:
        # Held at the gentlest rung, not exempted. The decision is still
        # recorded; it is the strength of the response that waits for evidence.
        severity = "low"

    rps = _RATE_LIMIT_BY_SEVERITY[severity]
    priors = _count_recent_throttles(db, org_id, src_ip, window_minutes, now)

    # `priors` counts throttles already on record, so this flow is the
    # (priors + 1)th. Comparing the stored count alone would need one extra
    # offence before the tier fired.
    if priors + 1 >= REPEAT_OFFENDER_THRESHOLD:
        return MitigationDecision(
            mitigated=True,
            tier="repeat_offender",
            rate_limit_rps=rps,
            is_repeat_offender=True,
            reason=(
                f"{priors + 1} auto-throttles from {src_ip} in the last "
                f"{window_minutes} min."
            ),
        )

    return MitigationDecision(
        mitigated=True,
        tier="throttle",
        rate_limit_rps=rps,
        is_repeat_offender=False,
        reason=f"{severity.title()}-severity {label} from {src_ip}.",
    )


def apply_to_incident(incident: Incident, decision: MitigationDecision) -> bool:
    """Write a decision onto an incident, refusing to walk back down the ladder.

    Incidents outlive the flows that opened them, so a quiet flow arriving after
    a loud one would otherwise relax a critical throttle, and — worse — overwrite
    an operator's ban with an automatic tier. Returns whether anything changed,
    so the caller can avoid writing an audit entry for a no-op.
    """
    if not decision.mitigated:
        return False

    current = MITIGATION_TIERS.index(incident.mitigation_tier) \
        if incident.mitigation_tier in MITIGATION_TIERS else -1
    if decision.rank <= current:
        return False

    incident.mitigated = True
    incident.mitigation_tier = decision.tier
    incident.rate_limit_rps = decision.rate_limit_rps
    return True


def is_expired(incident: Incident, now: datetime) -> bool:
    """Whether a timed ban has run out.

    A null expiry on a ban is permanent, not expired — the two are the same
    value in the column and only the tier separates them.
    """
    if incident.mitigation_tier != "ban":
        return False
    if incident.mitigation_expires_at is None:
        return False
    return incident.mitigation_expires_at <= now


def sweep_expired(db: Session, now: Optional[datetime] = None) -> int:
    """Retire bans whose clock has run out. Returns how many were retired.

    Without this a "24h ban" is permanent in everything but the label, which is
    the worst version of the feature: the operator is told it lapses on its own,
    so nobody goes back to lift it.

    Dropped to `repeat_offender` rather than cleared, because a source that
    earned a ban did so by offending repeatedly and that history did not stop
    being true when the timer ran out. Clearing the tier outright would let it
    walk back up from `throttle` as though it were new.

    Not scoped to one org: expiry is wall-clock and applies everywhere at once.
    """
    now = now or datetime.now(timezone.utc)
    rows = list(
        db.execute(
            select(Incident).where(
                Incident.mitigation_tier == "ban",
                Incident.mitigation_expires_at.is_not(None),
                Incident.mitigation_expires_at <= now,
            )
        ).scalars()
    )
    for inc in rows:
        inc.mitigation_tier = "repeat_offender"
        inc.mitigation_expires_at = None
        db.add(AuditLog(
            org_id=inc.org_id, user_id=None, user_label="SENTRY",
            action="mitigation.ban_expired",
            detail=(
                f"Ban on incident #{inc.id} ({inc.label} from {inc.src_ip}) "
                "expired. Remove the block at your router or firewall."
            ),
        ))
    if rows:
        db.commit()
    return len(rows)
