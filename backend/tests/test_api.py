"""End-to-end API tests.

Runs against a throwaway SQLite file with the simulator disabled, so results are
deterministic. The tenant-isolation tests matter most: they are the difference
between a multi-tenant tool and a data breach.
"""

import os
import tempfile

import pytest

# Configure before importing the app — settings are read at import time.
_TMP_DB = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["SENTRY_DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SENTRY_SIMULATOR_ENABLED"] = "false"
os.environ["SENTRY_SECRET_KEY"] = "test-key-not-used-in-production-abcdefghijklmnop"
os.environ["SENTRY_MODEL_DIR"] = os.path.join(
    os.path.dirname(__file__), "..", "artifacts"
)

from fastapi.testclient import TestClient  # noqa: E402

from backend.app.db import init_db  # noqa: E402
from backend.app.main import app  # noqa: E402

GOOD_PW = "correct-horse-battery-staple"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def org_a(client):
    r = client.post("/api/auth/signup", json={
        "email": "admin@alpha.example.com", "password": GOOD_PW,
        "name": "Alpha Admin", "org_name": "Alpha Corp",
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()
    return {"user": r.json(), "cookies": cookies}


@pytest.fixture(scope="module")
def org_b(client):
    r = client.post("/api/auth/signup", json={
        "email": "admin@beta.example.com", "password": GOOD_PW,
        "name": "Beta Admin", "org_name": "Beta Ltd",
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()
    return {"user": r.json(), "cookies": cookies}


# ── auth ──────────────────────────────────────────────────────────────────
def test_signup_creates_admin(org_a):
    assert org_a["user"]["role"] == "admin"
    assert org_a["user"]["org_name"] == "Alpha Corp"


def test_signup_never_returns_password_hash(org_a):
    assert "password_hash" not in org_a["user"]
    assert "password" not in org_a["user"]


def test_weak_password_rejected(client):
    r = client.post("/api/auth/signup", json={
        "email": "weak@alpha.example.com", "password": "short",
        "name": "Weak", "org_name": "Weak Co",
    })
    assert r.status_code == 422  # fails pydantic min_length


def test_common_password_rejected(client):
    r = client.post("/api/auth/signup", json={
        "email": "weak2@alpha.example.com", "password": "sentrypassword123",
        "name": "Weak", "org_name": "Weak Co",
    })
    assert r.status_code == 400
    assert "guessed" in r.json()["detail"].lower()


def test_duplicate_email_does_not_confirm_existence(client, org_a):
    r = client.post("/api/auth/signup", json={
        "email": "admin@alpha.example.com", "password": GOOD_PW,
        "name": "Impostor", "org_name": "Impostor Inc",
    })
    assert r.status_code == 400
    # Must not say "already registered" — that is an enumeration oracle.
    assert "already" not in r.json()["detail"].lower()


def test_login_wrong_password_rejected(client, org_a):
    r = client.post("/api/auth/login",
                    json={"email": "admin@alpha.example.com", "password": "wrong-password-xx"})
    assert r.status_code == 401
    client.cookies.clear()


def test_unauthenticated_requests_rejected(client):
    client.cookies.clear()
    for path in ("/api/status", "/api/flows", "/api/summary", "/api/incidents",
                 "/api/team", "/api/settings"):
        assert client.get(path).status_code == 401, path


def test_session_cookie_is_httponly(client, org_a):
    r = client.post("/api/auth/login",
                    json={"email": "admin@alpha.example.com", "password": GOOD_PW})
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    assert "httponly" in set_cookie.lower()
    client.cookies.clear()


# ── model + detection ─────────────────────────────────────────────────────
def test_status_reports_real_model(client, org_a):
    r = client.get("/api/status", cookies=org_a["cookies"])
    assert r.status_code == 200
    body = r.json()
    assert body["model_ready"] is True
    assert set(body["classes"]) == {"dos_ddos", "normal", "scan"}
    # The dataset must be labelled honestly, not as CIC-IDS2017.
    assert body["dataset"] == "synthetic"
    assert body["dataset_note"]


def test_ingest_scores_with_real_model(client, org_a):
    r = client.post("/api/ingest", cookies=org_a["cookies"], json={"flows": [
        {"src_ip": "203.0.113.9", "dst_port": 80, "protocol": "TCP", "node": "EDGE-01",
         "duration": 0.02, "packets": 40000, "total_bytes": 2_400_000},
        {"src_ip": "10.0.0.5", "dst_port": 443, "protocol": "TCP", "node": "EDGE-01",
         "duration": 12.0, "packets": 180, "total_bytes": 144_000},
    ]})
    assert r.status_code == 200, r.text
    flows = r.json()["flows"]
    assert len(flows) == 2
    assert flows[0]["prediction"] == "dos_ddos"
    assert flows[1]["prediction"] == "normal"
    assert flows[0]["confidence"] > 0.5


def test_attack_opens_an_incident(client, org_a):
    r = client.get("/api/incidents", cookies=org_a["cookies"])
    assert r.status_code == 200
    incidents = r.json()
    assert any(i["src_ip"] == "203.0.113.9" for i in incidents)


def test_incident_can_be_acknowledged(client, org_a):
    incidents = client.get("/api/incidents", cookies=org_a["cookies"]).json()
    target = next(i for i in incidents if i["src_ip"] == "203.0.113.9")
    r = client.post(f"/api/incidents/{target['id']}/action",
                    cookies=org_a["cookies"], json={"action": "acknowledge"})
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"
    assert r.json()["acknowledged_by"] == "Alpha Admin"


# ── tenant isolation ──────────────────────────────────────────────────────
def test_org_b_cannot_see_org_a_flows(client, org_a, org_b):
    a_flows = client.get("/api/flows", cookies=org_a["cookies"]).json()
    b_flows = client.get("/api/flows", cookies=org_b["cookies"]).json()
    assert len(a_flows) >= 2
    assert b_flows == []


def test_org_b_cannot_see_org_a_incidents(client, org_a, org_b):
    b_incidents = client.get("/api/incidents", cookies=org_b["cookies"]).json()
    assert b_incidents == []


def test_org_b_cannot_action_org_a_incident(client, org_a, org_b):
    a_incidents = client.get("/api/incidents", cookies=org_a["cookies"]).json()
    target = a_incidents[0]["id"]
    r = client.post(f"/api/incidents/{target}/action",
                    cookies=org_b["cookies"], json={"action": "resolve"})
    assert r.status_code == 404  # not 403 — do not confirm it exists


def test_org_b_team_list_is_isolated(client, org_b):
    team = client.get("/api/team", cookies=org_b["cookies"]).json()
    assert len(team) == 1
    assert team[0]["email"] == "admin@beta.example.com"


# ── roles ─────────────────────────────────────────────────────────────────
def test_viewer_cannot_mitigate(client, org_a):
    r = client.post("/api/team", cookies=org_a["cookies"], json={
        "email": "viewer@alpha.example.com", "name": "Read Only",
        "role": "viewer", "password": GOOD_PW,
    })
    assert r.status_code == 201

    client.cookies.clear()
    login = client.post("/api/auth/login",
                        json={"email": "viewer@alpha.example.com", "password": GOOD_PW})
    assert login.status_code == 200
    viewer_cookies = dict(client.cookies)
    client.cookies.clear()

    r = client.post("/api/mitigate", cookies=viewer_cookies,
                    json={"src_ip": "203.0.113.9"})
    assert r.status_code == 403

    r = client.patch("/api/settings", cookies=viewer_cookies, json={"threshold": 0.5})
    assert r.status_code == 403


def test_admin_cannot_demote_self(client, org_a):
    me = org_a["user"]
    r = client.patch(f"/api/team/{me['id']}", cookies=org_a["cookies"],
                     json={"role": "viewer"})
    assert r.status_code == 400


def test_admin_can_mitigate(client, org_a):
    r = client.post("/api/mitigate", cookies=org_a["cookies"],
                    json={"src_ip": "203.0.113.9"})
    assert r.status_code == 200
    assert r.json()["count"] >= 1
    # Must be explicit that nothing was actually blocked at the network edge.
    assert r.json()["enforced"] is False


# ── settings ──────────────────────────────────────────────────────────────
def test_settings_roundtrip(client, org_a):
    r = client.patch("/api/settings", cookies=org_a["cookies"],
                     json={"threshold": 0.7, "auto_mitigate": False})
    assert r.status_code == 200
    assert r.json()["threshold"] == 0.7
    assert r.json()["auto_mitigate"] is False


def test_webhook_scheme_validated(client, org_a):
    r = client.patch("/api/settings", cookies=org_a["cookies"],
                     json={"webhook_url": "javascript:alert(1)"})
    assert r.status_code == 422


# ── self-service profile ──────────────────────────────────────────────────
def test_user_can_edit_own_profile(client, org_a):
    r = client.patch("/api/auth/me", cookies=org_a["cookies"],
                     json={"name": "Alpha Admin", "title": "Head of SecOps"})
    assert r.status_code == 200
    assert r.json()["title"] == "Head of SecOps"


def test_profile_edit_cannot_escalate_role(client):
    """The self-service schema has no role field, so a sent one is ignored."""
    client.cookies.clear()
    login = client.post("/api/auth/login",
                        json={"email": "viewer@alpha.example.com", "password": GOOD_PW})
    assert login.status_code == 200
    viewer_cookies = dict(client.cookies)
    client.cookies.clear()

    r = client.patch("/api/auth/me", cookies=viewer_cookies,
                     json={"name": "Sneaky", "role": "admin", "is_active": True})
    assert r.status_code == 200
    assert r.json()["role"] == "viewer"  # unchanged

    # And the role really did not change server-side.
    still_blocked = client.post("/api/mitigate", cookies=viewer_cookies,
                                json={"src_ip": "203.0.113.9"})
    assert still_blocked.status_code == 403


def test_profile_edit_requires_auth(client):
    client.cookies.clear()
    assert client.patch("/api/auth/me", json={"name": "Nobody"}).status_code == 401


# ── session revocation ────────────────────────────────────────────────────
@pytest.fixture
def make_user(client, org_a):
    """Mint a throwaway member of Alpha Corp.

    Each session test gets its own account so none of them depend on a user
    another test happened to create, and so changing a password in one cannot
    strand another.
    """
    counter = {"n": 0}

    def _make():
        counter["n"] += 1
        email = f"session{counter['n']}-{id(counter)}@alpha.example.com"
        r = client.post("/api/team", cookies=org_a["cookies"], json={
            "email": email, "name": "Session Tester",
            "role": "viewer", "password": GOOD_PW,
        })
        assert r.status_code == 201, r.text
        client.cookies.clear()
        return email

    return _make


def _login(client, email, password=GOOD_PW):
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()
    return cookies


def test_logout_revokes_the_token_server_side(client, make_user):
    """Deleting the cookie is not enough — the token itself must stop working.

    A JWT stays valid until it expires, so a captured one could be replayed
    after the user believed they had signed out.
    """
    stolen = _login(client, make_user())

    # The captured cookie works while the session is live.
    assert client.get("/api/summary", cookies=stolen).status_code == 200

    assert client.post("/api/auth/logout", cookies=stolen).status_code == 200
    client.cookies.clear()

    # Replaying it after logout must fail.
    assert client.get("/api/summary", cookies=stolen).status_code == 401


def test_logout_works_without_a_session(client):
    """Signing out when already signed out should not 401 the user into a loop."""
    client.cookies.clear()
    assert client.post("/api/auth/logout").status_code == 200


def test_logout_does_not_revoke_other_users(client, make_user):
    """Revocation is per-user, not a global cutoff."""
    alice = _login(client, make_user())
    bob = _login(client, make_user())

    assert client.post("/api/auth/logout", cookies=alice).status_code == 200
    client.cookies.clear()

    assert client.get("/api/summary", cookies=alice).status_code == 401
    assert client.get("/api/summary", cookies=bob).status_code == 200


def test_password_change_revokes_other_sessions_but_not_this_one(client, make_user):
    NEW_PW = "unrelated-tangerine-lamp-post"
    email = make_user()

    # Two independent sessions for the same account.
    other_device = _login(client, email)
    this_device = _login(client, email)

    r = client.post("/api/auth/password", cookies=this_device,
                    json={"current_password": GOOD_PW, "new_password": NEW_PW})
    assert r.status_code == 200, r.text
    # The response re-issues the cookie so the caller is not signed out of the
    # browser they just used to change the password. Read it off the response
    # rather than the client jar — that is what a browser would honour.
    assert "sentry_session" in r.cookies, r.headers.get("set-cookie")
    refreshed = {"sentry_session": r.cookies["sentry_session"]}
    client.cookies.clear()

    assert client.get("/api/summary", cookies=refreshed).status_code == 200
    # The session on the other device is gone — that is the whole point of
    # changing a password you believe has leaked.
    assert client.get("/api/summary", cookies=other_device).status_code == 401


def test_password_change_rejects_reusing_the_current_password(client, make_user):
    cookies = _login(client, make_user())
    r = client.post("/api/auth/password", cookies=cookies,
                    json={"current_password": GOOD_PW, "new_password": GOOD_PW})
    assert r.status_code == 400
    client.cookies.clear()


# ── caching ───────────────────────────────────────────────────────────────
def test_api_responses_are_not_cacheable(client, org_a):
    """Authenticated JSON must never be stored by the browser.

    Without this the browser heuristically caches GETs: a reload showed a
    stale team roster, and per-account incident data was being written into a
    shared on-disk cache.
    """
    for path in ("/api/team", "/api/incidents", "/api/flows", "/api/summary"):
        r = client.get(path, cookies=org_a["cookies"])
        assert r.status_code == 200, path
        assert "no-store" in r.headers.get("cache-control", ""), path


def test_static_assets_are_still_cacheable(client):
    """The no-store rule is scoped to /api — assets should cache normally."""
    r = client.get("/assets/js/api.js")
    if r.status_code == 404:
        pytest.skip("frontend assets not present in this checkout")
    assert "no-store" not in r.headers.get("cache-control", "")


def test_health_is_public(client):
    client.cookies.clear()
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["model"] is True
