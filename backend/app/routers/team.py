"""Team management. Admin-only, and scoped to the caller's organisation."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..features import assignable_roles, has_feature, require_feature
from ..models import ApiKey, AuditLog, OrgType, Role, User, utcnow
from ..schemas import (
    ApiKeyCreatedOut,
    ApiKeyCreateIn,
    ApiKeyOut,
    AuditOut,
    InviteIn,
    UpdateUserIn,
    UserOut,
)
from ..security import (
    current_user,
    generate_api_key,
    hash_password,
    password_problem,
    require_admin,
)

router = APIRouter(prefix="/api/team", tags=["team"])


def _out(u: User) -> UserOut:
    return UserOut(
        id=u.id, email=u.email, name=u.name, role=u.role, title=u.title,
        initials=u.initials, is_active=u.is_active, org_id=u.org_id,
        org_name=u.org.name if u.org else "",
        org_type=u.org.org_type if u.org else OrgType.company.value,
        created_at=u.created_at, last_login_at=u.last_login_at,
    )


@router.get("", response_model=List[UserOut])
def list_team(db: Session = Depends(get_db), user: User = Depends(current_user)):
    rows = db.execute(
        select(User).where(User.org_id == user.org_id).order_by(User.created_at)
    ).scalars().all()
    return [_out(u) for u in rows]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def add_member(
    body: InviteIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Create a teammate with an initial password.

    A production deployment should email a one-time invite link instead of an
    admin choosing the password — that way no one but the user ever knows it.
    This direct form exists so the app is usable without an email provider
    configured; the new member should change it immediately.
    """
    problem = password_problem(body.password)
    if problem:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, problem)

    # A household gets admin/viewer, not the three-tier analyst scheme, which
    # only means something with a security rota behind it. Enforced here and
    # not only in the role dropdown, because the dropdown is a suggestion.
    org_type = admin.org.org_type if admin.org else OrgType.company.value
    allowed = assignable_roles(org_type)
    if body.role not in allowed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Role '{body.role}' is not available for this account type. "
            f"Choose one of: {', '.join(allowed)}.",
        )

    email = body.email.lower().strip()
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That email is already in use.")

    member = User(
        org_id=admin.org_id,
        email=email,
        password_hash=hash_password(body.password),
        name=body.name.strip(),
        role=body.role,
        title="Security Analyst",
    )
    db.add(member)
    db.flush()
    db.add(AuditLog(org_id=admin.org_id, user_id=admin.id, user_label=admin.name,
                    action="team.member_added",
                    detail=f"Added {member.email} as {member.role}"))
    db.commit()
    db.refresh(member)
    return _out(member)


@router.patch("/{user_id}", response_model=UserOut)
def update_member(
    user_id: int,
    body: UpdateUserIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    member = db.get(User, user_id)
    if not member or member.org_id != admin.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such team member.")

    org_type = admin.org.org_type if admin.org else OrgType.company.value
    allowed = assignable_roles(org_type)
    if body.role is not None and body.role not in allowed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Role '{body.role}' is not available for this account type. "
            f"Choose one of: {', '.join(allowed)}.",
        )

    # Guard against an org locking itself out of admin access entirely.
    if member.id == admin.id and body.role and body.role != Role.admin.value:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "You cannot remove your own admin role. Ask another admin to do it.",
        )
    if member.id == admin.id and body.is_active is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot deactivate yourself.")

    changes = []
    for field in ("name", "title", "role", "is_active"):
        value = getattr(body, field)
        if value is not None:
            setattr(member, field, value)
            changes.append(f"{field}={value}")

    if changes:
        db.add(AuditLog(org_id=admin.org_id, user_id=admin.id, user_label=admin.name,
                        action="team.member_updated",
                        detail=f"{member.email}: {', '.join(changes)}"))
    db.commit()
    db.refresh(member)
    return _out(member)


@router.delete("/{user_id}")
def remove_member(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    member = db.get(User, user_id)
    if not member or member.org_id != admin.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such team member.")
    if member.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot remove yourself.")

    remaining_admins = db.execute(
        select(User).where(
            User.org_id == admin.org_id,
            User.role == Role.admin.value,
            User.is_active.is_(True),
            User.id != member.id,
        )
    ).scalars().all()
    if member.role == Role.admin.value and not remaining_admins:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "That is the last admin. Promote someone else first.",
        )

    email = member.email
    db.delete(member)
    db.add(AuditLog(org_id=admin.org_id, user_id=admin.id, user_label=admin.name,
                    action="team.member_removed", detail=f"Removed {email}"))
    db.commit()
    return {"ok": True}


# ── API keys ──────────────────────────────────────────────────────────────
# Admin-only. A key is a credential that bypasses login entirely, so handing out
# the ability to mint one is equivalent to handing out access.
def _key_out(k: ApiKey) -> ApiKeyOut:
    return ApiKeyOut(
        id=k.id, label=k.label, prefix=k.prefix, scope=k.scope,
        created_at=k.created_at, last_used_at=k.last_used_at,
        revoked_at=k.revoked_at, is_active=k.is_active,
    )


@router.get("/keys", response_model=List[ApiKeyOut])
def list_keys(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rows = db.execute(
        select(ApiKey).where(ApiKey.org_id == admin.org_id)
        .order_by(ApiKey.created_at.desc())
    ).scalars().all()
    return [_key_out(k) for k in rows]


@router.post("/keys", response_model=ApiKeyCreatedOut, status_code=status.HTTP_201_CREATED)
def create_key(
    body: ApiKeyCreateIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Mint a collector key. The secret is shown here and never again."""
    # A household runs one collector. Capping it at one active key keeps the
    # page honest — "this is the key your device uses" rather than a credential
    # inventory — and means a forgotten second key cannot sit around unnoticed.
    org_type = admin.org.org_type if admin.org else OrgType.company.value
    if not has_feature(org_type, "multiple_api_keys"):
        active = db.execute(
            select(ApiKey).where(
                ApiKey.org_id == admin.org_id, ApiKey.revoked_at.is_(None)
            )
        ).scalars().all()
        if active:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "This account type uses a single collector key. Revoke the "
                "existing one first.",
            )

    full, prefix, digest = generate_api_key()
    key = ApiKey(
        org_id=admin.org_id, label=body.label.strip() or "collector",
        prefix=prefix, key_hash=digest, created_by_id=admin.id,
    )
    db.add(key)
    # The label, never the secret. An audit log is exactly the kind of place a
    # credential gets read from later.
    db.add(AuditLog(org_id=admin.org_id, user_id=admin.id, user_label=admin.name,
                    action="key.created", detail=f"Created API key '{key.label}' ({prefix}…)"))
    db.commit()
    db.refresh(key)

    out = _key_out(key)
    return ApiKeyCreatedOut(**out.model_dump(), key=full)


@router.delete("/keys/{key_id}")
def revoke_key(
    key_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Revoke immediately. The row is kept so past audit entries still resolve."""
    key = db.get(ApiKey, key_id)
    # Checked against the caller's org before anything else — without this, a
    # sequential id would let one tenant revoke another's collector.
    if not key or key.org_id != admin.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        db.add(AuditLog(org_id=admin.org_id, user_id=admin.id, user_label=admin.name,
                        action="key.revoked",
                        detail=f"Revoked API key '{key.label}' ({key.prefix}…)"))
        db.commit()
    return {"ok": True}


@router.get("/audit", response_model=List[AuditOut])
def audit_log(
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
    _: User = Depends(require_feature("audit_log")),
):
    """Admin-only, and company-only.

    Entries are still *written* for consumer orgs — they are how an incident
    gets reconstructed after the fact, and that matters regardless of account
    type. Only the reporting surface is gated, so nothing is lost by switching
    a household to a company later.
    """
    rows = db.execute(
        select(AuditLog).where(AuditLog.org_id == admin.org_id)
        .order_by(AuditLog.ts.desc()).limit(min(limit, 500))
    ).scalars().all()
    return [
        AuditOut(id=r.id, user_label=r.user_label, action=r.action,
                 detail=r.detail, ts=int(r.ts.timestamp() * 1000))
        for r in rows
    ]
