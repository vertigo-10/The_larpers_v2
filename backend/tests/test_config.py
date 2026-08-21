"""Startup-time configuration behaviour.

These run the loader in a subprocess rather than importing it, because
`backend.app.config` resolves everything once at import and caches it in a
module-level `settings`. Re-importing in-process would hand back the cached
object and test nothing. The subprocess also gets `cwd` set to a temp
directory so the repo's own .env cannot leak in and mask a wrong default —
which it did on the first pass at this.
"""

import json
import os
import subprocess
import sys

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

_PROBE = (
    "from backend.app.config import settings;"
    "import json,sys;"
    "sys.stdout.write(json.dumps({"
    "'simulator': settings.simulator_enabled,"
    "'production': settings.is_production,"
    "'secure_cookies': settings.secure_cookies}))"
)


def _load_settings(tmp_path, **env):
    """Boot the config loader in a clean environment and report what it decided.

    Returns (parsed_stdout_or_None, stderr, returncode) so a test can assert on
    a refusal to start as easily as on a resolved value.
    """
    clean = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("SENTRY_")
    }
    clean["PYTHONPATH"] = _REPO_ROOT
    clean.update({k: str(v) for k, v in env.items()})

    proc = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=str(tmp_path),  # away from the repo's .env
        env=clean,
        capture_output=True,
        text=True,
    )
    try:
        parsed = json.loads(proc.stdout)
    except json.JSONDecodeError:
        parsed = None
    return parsed, proc.stderr, proc.returncode


def test_simulator_defaults_on_in_development(tmp_path):
    """A fresh checkout should show live traffic, not an empty dashboard."""
    cfg, _, rc = _load_settings(tmp_path, SENTRY_ENV="development")
    assert rc == 0
    assert cfg["simulator"] is True


def test_simulator_defaults_off_in_production(tmp_path):
    """The important half: a real deployment must not fabricate incidents.

    An operator has no way to tell a synthetic attack from a real one, so a
    security console inventing traffic is worse than one showing nothing.
    """
    cfg, _, rc = _load_settings(
        tmp_path, SENTRY_ENV="production", SENTRY_SECRET_KEY="x" * 48
    )
    assert rc == 0
    assert cfg["simulator"] is False


def test_simulator_can_be_forced_on_in_production_but_warns(tmp_path):
    """Demo deployments are legitimate, so this is a warning and not an override.

    Silently disabling it would look like the engine was broken.
    """
    cfg, stderr, rc = _load_settings(
        tmp_path,
        SENTRY_ENV="production",
        SENTRY_SECRET_KEY="x" * 48,
        SENTRY_SIMULATOR_ENABLED="true",
    )
    assert rc == 0
    assert cfg["simulator"] is True
    assert "simulator is ENABLED in production" in stderr


def test_production_refuses_to_start_without_a_secret_key(tmp_path):
    """Falling back to a generated key would silently invalidate every session
    on each restart, and a hard-coded one would make cookies forgeable."""
    cfg, stderr, rc = _load_settings(tmp_path, SENTRY_ENV="production")
    assert rc != 0
    assert "SENTRY_SECRET_KEY" in stderr


def test_production_refuses_wildcard_cors(tmp_path):
    """Credentials ride on these requests, so '*' would let any site read the
    API as the logged-in user."""
    cfg, stderr, rc = _load_settings(
        tmp_path,
        SENTRY_ENV="production",
        SENTRY_SECRET_KEY="x" * 48,
        SENTRY_CORS_ORIGINS="*",
    )
    assert rc != 0
    assert "CORS" in stderr


def test_development_generates_an_ephemeral_key(tmp_path):
    """Convenience in dev, but it must announce itself so nobody comes to rely
    on sessions surviving a restart."""
    cfg, stderr, rc = _load_settings(tmp_path, SENTRY_ENV="development")
    assert rc == 0
    assert "SENTRY_SECRET_KEY unset" in stderr


def test_secure_cookies_track_the_environment(tmp_path):
    """Secure must be on in production; over plain-HTTP localhost it cannot be,
    or the cookie is never sent back and login silently fails."""
    dev, _, _ = _load_settings(tmp_path, SENTRY_ENV="development")
    assert dev["secure_cookies"] is False

    prod, _, _ = _load_settings(
        tmp_path, SENTRY_ENV="production", SENTRY_SECRET_KEY="x" * 48
    )
    assert prod["secure_cookies"] is True


def test_model_dir_is_not_relative_to_the_working_directory(tmp_path):
    """Regression: the default was a bare "artifacts", so the model only loaded
    if you happened to launch from backend/. The failure was silent — health
    just reported model: false — and the test suite missed it because it sets
    SENTRY_MODEL_DIR explicitly."""
    probe = (
        "from backend.app.config import settings;"
        "import os,sys;"
        "sys.stdout.write(settings.model_dir)"
    )
    clean = {k: v for k, v in os.environ.items() if not k.startswith("SENTRY_")}
    clean["PYTHONPATH"] = _REPO_ROOT
    clean["SENTRY_ENV"] = "development"

    proc = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(tmp_path),
        env=clean,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert os.path.isabs(proc.stdout)
    assert os.path.isdir(proc.stdout), "model_dir should point at real artifacts"
