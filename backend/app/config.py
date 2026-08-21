"""Runtime configuration, sourced entirely from environment variables.

Nothing secret is ever hard-coded here. In production SENTRY_SECRET_KEY must be
set explicitly; if it is missing the app refuses to start rather than silently
falling back to a guessable key, because that key signs the session cookies.
"""

import os
import secrets
import sys
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> backend/artifacts
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_MODEL_DIR = os.path.join(_BACKEND_DIR, "artifacts")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTRY_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── environment ───────────────────────────────────────────────────────
    env: str = "development"
    debug: bool = False

    # ── security ──────────────────────────────────────────────────────────
    secret_key: Optional[str] = None
    access_token_ttl_minutes: int = 60 * 12
    cookie_name: str = "sentry_session"
    cookie_secure: Optional[bool] = None  # defaults to True in production
    cookie_samesite: str = "lax"

    # ── database ──────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./sentry.db"

    # ── CORS ──────────────────────────────────────────────────────────────
    # Comma-separated. Wide open in dev; must be set explicitly in production.
    cors_origins: str = "http://localhost:8777,http://127.0.0.1:8777"

    # ── detection engine ──────────────────────────────────────────────────
    # The simulator generates synthetic *flows*, which are then scored by the
    # real trained model. Unset means "on in development, off in production":
    # an empty dashboard makes a fresh checkout look broken, but a production
    # console inventing attacks is worse than useless — an operator cannot tell
    # a fabricated incident from a real one. Production should receive real
    # flows on POST /api/ingest instead.
    simulator_enabled: Optional[bool] = None
    simulator_interval_ms: int = 1200
    default_threshold: float = 0.85
    retain_flows: int = 5000

    # ── model artifacts ───────────────────────────────────────────────────
    # Anchored to the package, not the working directory. A relative default
    # meant the model only loaded if you happened to launch from backend/, and
    # the failure mode was a silent "model: false" rather than a crash.
    model_dir: str = _DEFAULT_MODEL_DIR

    @property
    def is_production(self) -> bool:
        return self.env.lower() in ("production", "prod")

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def secure_cookies(self) -> bool:
        if self.cookie_secure is not None:
            return self.cookie_secure
        return self.is_production


def _load() -> Settings:
    s = Settings()

    if not s.secret_key:
        if s.is_production:
            sys.stderr.write(
                "\nFATAL: SENTRY_SECRET_KEY is not set.\n"
                "It signs session cookies — without it every session is forgeable.\n"
                "Generate one with:  python -c \"import secrets;print(secrets.token_urlsafe(48))\"\n\n"
            )
            raise SystemExit(1)
        # Ephemeral dev key. Regenerated each boot, so restarting logs everyone
        # out — that is intentional, it keeps a throwaway key from being relied on.
        s.secret_key = secrets.token_urlsafe(48)
        sys.stderr.write(
            "[sentry] WARNING: SENTRY_SECRET_KEY unset — using a temporary "
            "development key. Sessions will not survive a restart.\n"
        )

    if s.simulator_enabled is None:
        s.simulator_enabled = not s.is_production
    elif s.simulator_enabled and s.is_production:
        # Deliberately a warning, not a hard override: a demo or training
        # deployment may want this on, and silently disabling it would look
        # like the engine is broken. But it has to be a conscious choice, so
        # say it loudly at boot.
        sys.stderr.write(
            "\n[sentry] WARNING: the traffic simulator is ENABLED in production.\n"
            "[sentry] Synthetic flows will appear alongside real ones and an\n"
            "[sentry] operator cannot tell them apart. Unset "
            "SENTRY_SIMULATOR_ENABLED\n[sentry] unless this is a demo deployment.\n\n"
        )

    if s.is_production and "*" in s.cors_origins:
        sys.stderr.write(
            "\nFATAL: CORS is set to '*' in production. Credentials are sent as "
            "cookies, so a wildcard origin would let any site read this API.\n"
            "Set SENTRY_CORS_ORIGINS to your dashboard's real origin.\n\n"
        )
        raise SystemExit(1)

    return s


settings = _load()
