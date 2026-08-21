"""Password hashing, session tokens, and the request-auth dependencies.

Design notes:
  * Passwords are hashed with bcrypt (cost 12) via passlib. Plaintext is never
    stored, logged, or returned by any endpoint.
  * Sessions are JWTs delivered in an HTTP-only cookie, so page JavaScript
    cannot read the token and XSS cannot exfiltrate a session.
  * Every token carries the org_id it was issued for; all data queries are
    filtered by it so one tenant can never read another's flows.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Cookie, Depends, HTTPException, status
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import Role, User

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)

ALGORITHM = "HS256"


# ── passwords ─────────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _pwd.verify(plain, hashed)
    except ValueError:
        return False


def password_problem(pw: str) -> Optional[str]:
    """Return a human-readable reason the password is unacceptable, or None.

    Deliberately length-first: length beats character-class rules for real
    resistance to guessing, and complexity rules mostly produce 'P@ssw0rd1'.
    """
    if len(pw) < 12:
        return "Password must be at least 12 characters."
    if len(pw) > 200:
        return "Password must be under 200 characters."
    lowered = pw.lower()
    for weak in ("password", "sentry", "12345678", "qwerty", "letmein", "admin"):
        if weak in lowered:
            return "Password contains a common, easily guessed word."
    return None


# ── tokens ────────────────────────────────────────────────────────────────
def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "org": user.org_id,
        "role": user.role,
        "ver": user.token_version or 0,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_ttl_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def revoke_sessions(user: User) -> None:
    """Invalidate every token already issued to this user.

    Caller commits, then mints a replacement if the current browser should
    survive (a password change) or none at all if it should not (a sign-out).
    """
    user.token_version = (user.token_version or 0) + 1


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


# ── request dependencies ──────────────────────────────────────────────────
_UNAUTH = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
)


def token_is_revoked(user: User, payload: dict) -> bool:
    """True if this token was minted before the user's last revocation.

    A token predating this field entirely has no `ver` claim, so it cannot be
    shown to be current and is refused. That costs everyone one re-login on
    upgrade, which is the safe direction to fail.
    """
    return payload.get("ver") != (user.token_version or 0)


def current_user(
    db: Session = Depends(get_db),
    sentry_session: Optional[str] = Cookie(default=None, alias=settings.cookie_name),
) -> User:
    if not sentry_session:
        raise _UNAUTH
    payload = decode_token(sentry_session)
    if not payload:
        raise _UNAUTH

    user = db.get(User, int(payload.get("sub", 0)))
    if not user or not user.is_active:
        raise _UNAUTH
    # A token minted before the user was moved between orgs must not keep
    # granting access to the old one.
    if user.org_id != payload.get("org"):
        raise _UNAUTH
    if token_is_revoked(user, payload):
        raise _UNAUTH
    return user


def optional_current_user(
    db: Session = Depends(get_db),
    sentry_session: Optional[str] = Cookie(default=None, alias=settings.cookie_name),
) -> Optional[User]:
    """Resolve the caller if the cookie is good, otherwise None.

    Used by logout, which must clear the cookie and return cleanly even when
    the session has already expired — 401-ing a sign-out is a dead end for the
    user, since the UI's 401 handler would bounce them somewhere else.
    """
    try:
        return current_user(db=db, sentry_session=sentry_session)
    except HTTPException:
        return None


def require_role(*allowed: Role):
    """Dependency factory enforcing that the caller holds one of `allowed`."""

    allowed_values = {r.value for r in allowed}

    def _check(user: User = Depends(current_user)) -> User:
        if user.role not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of: {', '.join(sorted(allowed_values))}",
            )
        return user

    return _check


require_admin = require_role(Role.admin)
require_operator = require_role(Role.admin, Role.analyst)
