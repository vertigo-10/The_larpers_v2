"""What each org type actually gets.

One table, consulted by both the API and the dashboard, so the two can never
drift into disagreeing about whether a feature exists.

The split is not "consumer is the crippled tier". It is that a household and a
company are protecting different things and the same screen serves neither well.
A household running one collector on one router does not have a compliance
obligation, a rota of analysts, or a data-retention policy — surfacing those
makes the product harder to use without making anyone safer. A company has all
three and a home-simplified view actively hides what it needs.

IMPORTANT: this module decides what is *offered*. It is not the enforcement
point on its own — every gated route re-checks with `require_feature`, because
a hidden button has never been a permission. The frontend reads the same table
to decide what to render, so the UI and the API agree by construction rather
than by two people remembering to make the same edit twice.
"""

from typing import Dict, List

from fastapi import Depends, HTTPException, status

from .models import OrgType, Role, User
from .security import current_user

# ── the table ─────────────────────────────────────────────────────────────
# Every key is a capability the UI can ask about by name.
_FEATURES: Dict[str, Dict[str, bool]] = {
    OrgType.company.value: {
        # Several people with different levels of trust need different access,
        # and someone has to be able to answer "who turned that off".
        "roles": True,
        "audit_log": True,
        # Employees join by invite code or company email domain, and wait for
        # an admin to approve them.
        "invites": True,
        # Multiple collectors across sites, each with its own revocable key.
        "api_keys": True,
        "multiple_api_keys": True,
        # Somebody owns the detection tuning and is accountable for it.
        "model_tuning": True,
        "retention_policy": True,
        # Feeds a SIEM or an auditor.
        "export": True,
        "scheduled_reports": True,
        "node_metadata": True,
    },
    OrgType.consumer.value: {
        # A household is not an org chart. Everyone who is in it, is in it.
        "roles": False,
        "audit_log": False,
        # No self-service joining: a household has no domain to match on, and
        # a queue of strangers requesting access to your home network is a
        # liability rather than a feature. Someone already inside adds you.
        "invites": False,
        # Kept: this is how the collector authenticates, so removing it would
        # mean a household could not connect anything at all. Presented as
        # "connect a device" rather than as credential management.
        "api_keys": True,
        "multiple_api_keys": False,
        "model_tuning": False,
        "retention_policy": False,
        "export": False,
        "scheduled_reports": False,
        "node_metadata": False,
    },
}

# Which roles can be assigned, per org type. A household gets one axis of
# choice — can this person change things, or only look at them — instead of a
# three-tier scheme that only means something with a security team behind it.
_ASSIGNABLE_ROLES: Dict[str, List[str]] = {
    OrgType.company.value: [Role.admin.value, Role.analyst.value, Role.viewer.value],
    OrgType.consumer.value: [Role.admin.value, Role.viewer.value],
}


def features_for(org_type: str) -> Dict[str, bool]:
    """The capability map for an org type, falling back to the company set."""
    return dict(_FEATURES.get(org_type, _FEATURES[OrgType.company.value]))


def assignable_roles(org_type: str) -> List[str]:
    return list(
        _ASSIGNABLE_ROLES.get(org_type, _ASSIGNABLE_ROLES[OrgType.company.value])
    )


def has_feature(org_type: str, name: str) -> bool:
    return features_for(org_type).get(name, False)


def require_feature(name: str):
    """Dependency that 403s when the caller's org type does not include `name`.

    Returns 403 rather than 404 deliberately: the route exists, the caller is
    authenticated, and the reason for refusal is not a secret. Pretending the
    endpoint is absent would make a misconfigured client much harder to debug
    for no security gain, since org type is not sensitive.
    """

    def _dep(user: User = Depends(current_user)) -> User:
        org_type = user.org.org_type if user.org else OrgType.company.value
        if not has_feature(org_type, name):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"'{name}' is not available for this account type.",
            )
        return user

    return _dep
