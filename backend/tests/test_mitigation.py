"""The escalation ladder: throttle → repeat offender → ban.

Two things these tests are really protecting.

The first is that SENTRY does not enforce anything. It watches traffic and has
no path to the router, so every tier is a decision recorded, not an action
performed. That is easy to state and easy to erode — one helpful-sounding label
change ("Banned") and the product is lying about something a user would act on.
`test_no_response_claims_to_have_been_enforced` fails if any of it starts
claiming otherwise.

The second is that escalation only ever goes up. Incidents outlive the flows
that opened them, so without an explicit guard the next quiet flow to arrive
would relax a critical throttle — or overwrite an operator's ban with an
automatic tier, silently undoing a deliberate human decision.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

_TMP_DB = os.path.join(tempfile.mkdtemp(), "mitigation.db")
os.environ.setdefault("SENTRY_DATABASE_URL", f"sqlite:///{_TMP_DB}")
os.environ.setdefault("SENTRY_SIMULATOR_ENABLED", "false")
os.environ.setdefault("SENTRY_SECRET_KEY", "test-key-not-used-in-production-abcdefghijk")
os.environ.setdefault(
    "SENTRY_MODEL_DIR", os.path.join(os.path.dirname(__file__), "..", "artifacts")
)

from backend.app import mitigation  # noqa: E402
from backend.app.db import SessionLocal, init_db  # noqa: E402
from backend.app.models import Incident, IncidentStatus, Org, OrgType  # noqa: E402
from backend.app.schemas import MAX_BAN_MINUTES, MITIGATION_TIERS  # noqa: E402

NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def db():
    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="module")
def org_id(db):
    org = Org(name="Escalation Test Co", org_type=OrgType.company.value)
    db.add(org)
    db.commit()
    return org.id


def _incident(db, org_id, src_ip, *, tier=None, seen=NOW, expires=None):
    inc = Incident(
        org_id=org_id, src_ip=src_ip, label="dos_ddos", node="EDGE-01",
        opened_at=seen, last_seen_at=seen, flow_count=50,
        peak_confidence=0.97, peak_bps=9_000_000, severity="critical",
        status=IncidentStatus.open.value, mitigated=tier is not None,
        mitigation_tier=tier, mitigation_expires_at=expires,
    )
    db.add(inc)
    db.commit()
    return inc


def _decide(db, org_id, src_ip, **kw):
    params = dict(
        label="dos_ddos", confidence=0.97, bps=9_000_000, flow_count=50,
        is_attack=True, auto_mitigate=True, threshold=0.85,
        window_minutes=60, now=NOW,
    )
    params.update(kw)
    return mitigation.decide(db, org_id, src_ip, **params)


# ── the honesty guarantee ─────────────────────────────────────────────────
def test_no_response_claims_to_have_been_enforced(db, org_id):
    """
    The whole feature rests on this. SENTRY cannot reach the router, so a tier
    is a recommendation someone still has to apply. A decision that reported
    itself as enforced would put a user in the worst position available: certain
    the traffic stopped, and wrong.
    """
    decision = _decide(db, org_id, "203.0.113.10")
    assert not hasattr(decision, "enforced") or decision.enforced is False
    # The reason is operator-facing copy. It may describe what was decided; it
    # must not describe traffic as stopped.
    assert not any(
        word in decision.reason.lower()
        for word in ("blocked", "stopped", "dropped", "enforced")
    ), f"reason claims enforcement: {decision.reason!r}"


# ── the ladder ────────────────────────────────────────────────────────────
def test_a_first_offence_is_throttled_not_escalated(db, org_id):
    decision = _decide(db, org_id, "203.0.113.20")
    assert decision.tier == "throttle"
    assert decision.is_repeat_offender is False
    assert decision.mitigated is True


def test_third_offence_in_the_window_is_a_repeat_offender(db, org_id):
    ip = "203.0.113.30"
    _incident(db, org_id, ip, tier="throttle")
    _incident(db, org_id, ip, tier="throttle")
    # Two on record plus the one being decided now is the third.
    decision = _decide(db, org_id, ip)
    assert decision.tier == "repeat_offender"
    assert decision.is_repeat_offender is True


def test_offences_outside_the_window_do_not_count(db, org_id):
    """
    The window is the whole point of the tier. Without the cutoff, a source that
    misbehaved three times last year is a repeat offender forever, and the badge
    stops meaning "active problem" — which is the only thing it is useful for.
    """
    ip = "203.0.113.40"
    old = NOW - timedelta(hours=5)
    for _ in range(4):
        _incident(db, org_id, ip, tier="throttle", seen=old)
    decision = _decide(db, org_id, ip, window_minutes=60)
    assert decision.tier == "throttle", "stale offences leaked into the window"


def test_the_window_is_the_orgs_own_setting(db, org_id):
    """A household and an edge segment do not agree on what 'often' means."""
    ip = "203.0.113.50"
    seen = NOW - timedelta(hours=3)
    for _ in range(3):
        _incident(db, org_id, ip, tier="throttle", seen=seen)
    assert _decide(db, org_id, ip, window_minutes=60).tier == "throttle"
    assert _decide(db, org_id, ip, window_minutes=600).tier == "repeat_offender"


def test_the_engine_never_reaches_ban_on_its_own(db, org_id):
    """
    An automatic ban is the one action here that can take a household off the
    internet on a false positive at 3am, with nobody awake to undo it. However
    bad the traffic looks, the ladder must top out below it.
    """
    ip = "203.0.113.60"
    for _ in range(25):
        _incident(db, org_id, ip, tier="repeat_offender")
    decision = _decide(db, org_id, ip, confidence=1.0, bps=9e9, flow_count=100_000)
    assert decision.tier != "ban"
    assert MITIGATION_TIERS.index(decision.tier) < MITIGATION_TIERS.index("ban")


# ── the threshold is unchanged ────────────────────────────────────────────
def test_traffic_below_the_threshold_is_still_left_alone(db, org_id):
    """
    Escalation re-decides how hard to respond, never whether to. If it widened
    the net, turning it on would start acting on traffic the previous version
    deliberately ignored.
    """
    decision = _decide(db, org_id, "203.0.113.70", confidence=0.5, threshold=0.85)
    assert decision.mitigated is False
    assert decision.tier is None


def test_auto_mitigate_off_means_no_tier_at_all(db, org_id):
    decision = _decide(db, org_id, "203.0.113.80", auto_mitigate=False)
    assert decision.mitigated is False
    assert decision.tier is None


def test_benign_traffic_is_never_tiered(db, org_id):
    decision = _decide(db, org_id, "203.0.113.90", is_attack=False, label="normal")
    assert decision.mitigated is False


# ── sample-size guardrail ─────────────────────────────────────────────────
def test_a_tiny_incident_is_held_at_the_gentlest_response(db, org_id):
    """
    A model can be confident about three packets and still be describing noise.
    The decision is still recorded — it is the severity of the response that
    waits for enough evidence to justify it.
    """
    loud = _decide(db, org_id, "203.0.113.100", flow_count=500)
    tiny = _decide(db, org_id, "203.0.113.101", flow_count=2)
    assert tiny.mitigated is True, "the guardrail should soften, not exempt"
    assert tiny.rate_limit_rps > loud.rate_limit_rps, (
        "a 2-flow blip was rate-limited as hard as a 500-flow flood"
    )


def test_the_score_discounts_a_weak_sample(db, org_id):
    strong = mitigation.escalation_score("dos_ddos", 0.97, 9_000_000, 500)
    weak = mitigation.escalation_score("dos_ddos", 0.97, 9_000_000, 2)
    assert weak < strong
    assert 0.0 <= weak <= 1.0 and 0.0 <= strong <= 1.0


# ── no downgrades ─────────────────────────────────────────────────────────
def test_a_quiet_flow_cannot_relax_a_harsher_tier(db, org_id):
    """
    Incidents outlive the flows that opened them. The last flow to arrive must
    not get to overwrite the verdict earned by everything before it.
    """
    inc = _incident(db, org_id, "203.0.113.110", tier="repeat_offender")
    softer = mitigation.MitigationDecision(
        mitigated=True, tier="throttle", rate_limit_rps=1000,
        is_repeat_offender=False, reason="later, quieter flow",
    )
    assert mitigation.apply_to_incident(inc, softer) is False
    assert inc.mitigation_tier == "repeat_offender"


def test_an_automatic_tier_cannot_overwrite_an_operators_ban(db, org_id):
    """The sharpest version: a person decided, and the engine must not undecide."""
    inc = _incident(db, org_id, "203.0.113.120", tier="ban",
                    expires=NOW + timedelta(hours=24))
    auto = mitigation.MitigationDecision(
        mitigated=True, tier="repeat_offender", rate_limit_rps=100,
        is_repeat_offender=True, reason="engine",
    )
    assert mitigation.apply_to_incident(inc, auto) is False
    assert inc.mitigation_tier == "ban"
    assert inc.mitigation_expires_at is not None, "the ban lost its clock"


def test_escalating_upward_is_allowed(db, org_id):
    inc = _incident(db, org_id, "203.0.113.130", tier="throttle")
    harsher = mitigation.MitigationDecision(
        mitigated=True, tier="repeat_offender", rate_limit_rps=100,
        is_repeat_offender=True, reason="engine",
    )
    assert mitigation.apply_to_incident(inc, harsher) is True
    assert inc.mitigation_tier == "repeat_offender"


# ── expiry ────────────────────────────────────────────────────────────────
def test_an_elapsed_ban_is_retired(db, org_id):
    """
    Without the sweep a "24h ban" is permanent in all but name — and because the
    operator was told it lapses on its own, nobody goes back to lift it.
    """
    inc = _incident(db, org_id, "203.0.113.140", tier="ban",
                    expires=NOW - timedelta(minutes=1))
    assert mitigation.is_expired(inc, NOW) is True
    swept = mitigation.sweep_expired(db, now=NOW)
    assert swept >= 1
    db.refresh(inc)
    assert inc.mitigation_tier == "repeat_offender", (
        "an expired ban should fall back to the history that earned it, "
        "not clear to nothing and let the source start again as a stranger"
    )
    assert inc.mitigation_expires_at is None


def test_a_permanent_ban_never_expires(db, org_id):
    """
    Null expiry means two different things depending on tier: no ban, or a
    permanent one. Reading the column alone would sweep away every permanent ban
    on the first tick.
    """
    inc = _incident(db, org_id, "203.0.113.150", tier="ban", expires=None)
    assert mitigation.is_expired(inc, NOW + timedelta(days=3650)) is False
    mitigation.sweep_expired(db, now=NOW + timedelta(days=3650))
    db.refresh(inc)
    assert inc.mitigation_tier == "ban"


def test_a_ban_still_running_is_left_alone(db, org_id):
    inc = _incident(db, org_id, "203.0.113.160", tier="ban",
                    expires=NOW + timedelta(hours=24))
    mitigation.sweep_expired(db, now=NOW)
    db.refresh(inc)
    assert inc.mitigation_tier == "ban"


def test_the_sweep_ignores_incidents_that_were_never_banned(db, org_id):
    inc = _incident(db, org_id, "203.0.113.170", tier="throttle")
    mitigation.sweep_expired(db, now=NOW + timedelta(days=1))
    db.refresh(inc)
    assert inc.mitigation_tier == "throttle"


# ── bounds ────────────────────────────────────────────────────────────────
def test_the_ban_cap_is_short_of_what_overflows_a_date():
    """
    The cap exists because `now + timedelta(minutes=v)` raises OverflowError on
    absurd input, which reaches the user as a 500 rather than anything they can
    act on. Anything past a year is what Permanent is for.
    """
    assert datetime.now(timezone.utc) + timedelta(minutes=MAX_BAN_MINUTES)
    with pytest.raises(OverflowError):
        datetime.now(timezone.utc) + timedelta(minutes=1e15)


def test_the_ladder_is_ordered_weakest_first():
    """apply_to_incident compares by index, so the order is load-bearing."""
    assert MITIGATION_TIERS == ("throttle", "repeat_offender", "ban")
