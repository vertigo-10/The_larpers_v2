"""Team management. Admin-only, and scoped to the caller's organisation."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AuditLog, Role, User
from ..schemas import AuditOut, InviteIn, UpdateUserIn, UserOut
from ..security import current_user, hash_password, password_problem, require_admin

router = APIRouter(prefix="/api/team", tags=["team"])


def _out(u: User) -> UserOut:
    return UserOut(
        id=u.id, email=u.email, name=u.name, role=u.role, title=u.title,
        initials=u.initials, is_active=u.is_active, org_id=u.org_id,
        org_name=u.org.name if u.org else "", created_at=u.created_at,
        last_login_at=u.last_login_at,
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


@router.get("/audit", response_model=List[AuditOut])
def audit_log(
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    rows = db.execute(
        select(AuditLog).where(AuditLog.org_id == admin.org_id)
        .order_by(AuditLog.ts.desc()).limit(min(limit, 500))
    ).scalars().all()
    return [
        AuditOut(id=r.id, user_label=r.user_label, action=r.action,
                 detail=r.detail, ts=int(r.ts.timestamp() * 1000))
        for r in rows
    ]
