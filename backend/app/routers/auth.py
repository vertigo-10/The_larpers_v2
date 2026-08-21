"""Signup, login, logout, session identity, password change."""

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..engine import ensure_org_defaults
from ..models import AuditLog, Org, OrgSettings, Role, User
from ..schemas import ChangePasswordIn, LoginIn, SignupIn, UpdateMeIn, UserOut
from ..security import (
    create_access_token,
    current_user,
    hash_password,
    optional_current_user,
    password_problem,
    revoke_sessions,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ── brute-force throttle ──────────────────────────────────────────────────
# In-memory and per-process: enough to blunt credential stuffing on a single
# instance. Behind multiple replicas this should move to Redis.
_FAILS: Dict[str, List[float]] = defaultdict(list)
_WINDOW_S = 300.0
_MAX_FAILS = 8


def _throttled(key: str) -> Tuple[bool, int]:
    now = time.time()
    hits = [t for t in _FAILS[key] if now - t < _WINDOW_S]
    _FAILS[key] = hits
    if len(hits) >= _MAX_FAILS:
        return True, int(_WINDOW_S - (now - hits[0]))
    return False, 0


def _record_fail(key: str) -> None:
    _FAILS[key].append(time.time())


def _clear_fails(key: str) -> None:
    _FAILS.pop(key, None)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        httponly=True,  # JavaScript cannot read it, so XSS cannot steal it
        secure=settings.secure_cookies,
        samesite=settings.cookie_samesite,
        max_age=settings.access_token_ttl_minutes * 60,
        path="/",
    )


def _user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        title=user.title,
        initials=user.initials,
        is_active=user.is_active,
        org_id=user.org_id,
        org_name=user.org.name if user.org else "",
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


@router.post("/signup", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def signup(body: SignupIn, response: Response, db: Session = Depends(get_db)):
    """Create an organisation and its first admin."""
    problem = password_problem(body.password)
    if problem:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, problem)

    email = body.email.lower().strip()
    exists = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if exists:
        # Deliberately vague: confirming which emails are registered is an
        # account-enumeration leak.
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Could not create that account. Try signing in instead.",
        )

    org = Org(name=body.org_name.strip())
    db.add(org)
    db.flush()

    user = User(
        org_id=org.id,
        email=email,
        password_hash=hash_password(body.password),
        name=body.name.strip(),
        role=Role.admin.value,  # first user owns the org
        title="Security Operations Lead",
    )
    db.add(user)
    db.add(OrgSettings(org_id=org.id, threshold=settings.default_threshold))
    db.flush()
    db.add(AuditLog(org_id=org.id, user_id=user.id, user_label=user.name,
                    action="org.created", detail=f"Organisation '{org.name}' created"))
    db.commit()
    db.refresh(user)

    ensure_org_defaults(db, org.id)

    _set_session_cookie(response, create_access_token(user))
    return _user_out(user)


@router.post("/login", response_model=UserOut)
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}:{email}"

    blocked, retry_in = _throttled(key)
    if blocked:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Too many failed attempts. Try again in {retry_in} seconds.",
        )

    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

    # Always run a hash comparison, even when the user does not exist, so
    # response timing does not reveal which emails are registered.
    stored = user.password_hash if user else "$2b$12$" + "x" * 53
    ok = verify_password(body.password, stored)

    if not user or not ok or not user.is_active:
        _record_fail(key)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect email or password.")

    _clear_fails(key)
    user.last_login_at = datetime.now(timezone.utc)
    db.add(AuditLog(org_id=user.org_id, user_id=user.id, user_label=user.name,
                    action="auth.login", detail=f"Signed in from {client_ip}"))
    db.commit()
    db.refresh(user)

    _set_session_cookie(response, create_access_token(user))
    return _user_out(user)


@router.post("/logout")
def logout(
    response: Response,
    db: Session = Depends(get_db),
    user: Optional[User] = Depends(optional_current_user),
):
    """End the session properly, not just locally.

    Deleting the cookie only disarms this browser. The token itself stays
    valid until it expires, so anything that captured it — a shared machine,
    a proxy log, a backup — could replay it. Revoking server-side is what
    makes signing out on a shared workstation mean something.
    """
    if user is not None:
        revoke_sessions(user)
        db.add(AuditLog(org_id=user.org_id, user_id=user.id, user_label=user.name,
                        action="auth.logout", detail="Signed out; sessions revoked"))
        db.commit()
    response.delete_cookie(settings.cookie_name, path="/")
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return _user_out(user)


@router.patch("/me", response_model=UserOut)
def update_me(
    body: UpdateMeIn,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Let any signed-in user edit their own display fields.

    Only name and title — the schema has no role or is_active, so this cannot
    become a self-promotion route no matter what the client sends.
    """
    changes = []
    if body.name is not None:
        user.name = body.name.strip()
        changes.append("name")
    if body.title is not None:
        user.title = body.title.strip()
        changes.append("title")

    if changes:
        db.add(AuditLog(org_id=user.org_id, user_id=user.id, user_label=user.name,
                        action="profile.updated", detail=", ".join(changes)))
    db.commit()
    db.refresh(user)
    return _user_out(user)


@router.post("/password")
def change_password(
    body: ChangePasswordIn,
    response: Response,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect.")
    problem = password_problem(body.new_password)
    if problem:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, problem)
    if body.new_password == body.current_password:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "New password must be different from the current one.",
        )

    user.password_hash = hash_password(body.new_password)
    # People change their password *because* they think it leaked. Leaving
    # other sessions alive would defeat the point, so every existing token is
    # revoked and this browser is handed a fresh one.
    revoke_sessions(user)
    db.add(AuditLog(org_id=user.org_id, user_id=user.id, user_label=user.name,
                    action="auth.password_changed",
                    detail="Password updated; other sessions signed out"))
    db.commit()
    db.refresh(user)

    # Minted after the commit, so it carries the bumped version and survives.
    _set_session_cookie(response, create_access_token(user))
    return {"ok": True, "other_sessions_revoked": True}


@router.get("/bootstrap")
def bootstrap(db: Session = Depends(get_db)):
    """Whether any account exists yet — lets the UI show signup vs login."""
    count = db.execute(select(func.count(User.id))).scalar_one()
    return {"has_users": bool(count)}
