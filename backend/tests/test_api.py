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
os.environ["SENTRY_SIGNUP_MAX_PER_WINDOW"] = "100000"  # the suite creates many orgs from one client
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
        "name": "Alpha Admin", "org_name": "Alpha Corp", "org_type": "company",
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()
    return {"user": r.json(), "cookies": cookies}


@pytest.fixture(scope="module")
def org_b(client):
    r = client.post("/api/auth/signup", json={
        "email": "admin@beta.example.com", "password": GOOD_PW,
        "name": "Beta Admin", "org_name": "Beta Ltd", "org_type": "consumer",
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
        "name": "Weak", "org_name": "Weak Co", "org_type": "company",
    })
    assert r.status_code == 422  # fails pydantic min_length


def test_common_password_rejected(client):
    r = client.post("/api/auth/signup", json={
        "email": "weak2@alpha.example.com", "password": "sentrypassword123",
        "name": "Weak", "org_name": "Weak Co", "org_type": "company",
    })
    assert r.status_code == 400
    assert "guessed" in r.json()["detail"].lower()


def test_duplicate_email_does_not_confirm_existence(client, org_a):
    r = client.post("/api/auth/signup", json={
        "email": "admin@alpha.example.com", "password": GOOD_PW,
        "name": "Impostor", "org_name": "Impostor Inc", "org_type": "company",
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


# ── org type ──────────────────────────────────────────────────────────────
def test_signup_exposes_org_type(org_a, org_b):
    assert org_a["user"]["org_type"] == "company"
    assert org_b["user"]["org_type"] == "consumer"


def test_signup_rejects_invalid_org_type(client):
    r = client.post("/api/auth/signup", json={
        "email": "bad-org-type@alpha.example.com", "password": GOOD_PW,
        "name": "Nope", "org_name": "Nope Co", "org_type": "government",
    })
    assert r.status_code == 422


def test_signup_requires_org_type(client):
    r = client.post("/api/auth/signup", json={
        "email": "no-org-type@alpha.example.com", "password": GOOD_PW,
        "name": "Nope", "org_name": "Nope Co",
    })
    assert r.status_code == 422


def test_company_org_gets_enterprise_node_topology(client, org_a):
    r = client.get("/api/nodes", cookies=org_a["cookies"])
    assert r.status_code == 200
    labels = {n["label"] for n in r.json()}
    assert {"EDGE-01", "DC-LB-01"} <= labels


def test_consumer_org_gets_home_node_topology(client, org_b):
    r = client.get("/api/nodes", cookies=org_b["cookies"])
    assert r.status_code == 200
    labels = {n["label"] for n in r.json()}
    assert labels == {"HOME-ROUTER", "IOT-DEVICES", "PERSONAL-DEVICES"}


# ── org feature sets ──────────────────────────────────────────────────────
def test_features_endpoint_differs_by_org_type(client, org_a, org_b):
    a = client.get("/api/auth/features", cookies=org_a["cookies"]).json()
    b = client.get("/api/auth/features", cookies=org_b["cookies"]).json()

    assert a["org_type"] == "company"
    assert b["org_type"] == "consumer"

    assert a["features"]["audit_log"] is True
    assert b["features"]["audit_log"] is False

    assert a["features"]["roles"] is True
    assert b["features"]["roles"] is False

    # Both keep API keys — a household still has to authenticate its collector.
    assert a["features"]["api_keys"] is True
    assert b["features"]["api_keys"] is True
    assert a["features"]["multiple_api_keys"] is True
    assert b["features"]["multiple_api_keys"] is False


def test_consumer_cannot_read_the_audit_log(client, org_b):
    """Gated server-side, not merely hidden in the sidebar.

    The whole point of the feature table is that it is enforced where it
    matters. A consumer admin hitting the URL directly must be refused.
    """
    r = client.get("/api/team/audit", cookies=org_b["cookies"])
    assert r.status_code == 403
    assert "not available" in r.json()["detail"]


def test_company_can_read_the_audit_log(client, org_a):
    r = client.get("/api/team/audit", cookies=org_a["cookies"])
    assert r.status_code == 200


def test_consumer_cannot_assign_the_analyst_role(client, org_b):
    """A household gets admin/viewer, and the API is the enforcement point."""
    r = client.post("/api/team", cookies=org_b["cookies"], json={
        "email": "analyst@beta.example.com", "name": "Nope",
        "role": "analyst", "password": GOOD_PW,
    })
    assert r.status_code == 400
    assert "not available for this account type" in r.json()["detail"]


def test_consumer_can_still_add_a_viewer(client, org_b):
    r = client.post("/api/team", cookies=org_b["cookies"], json={
        "email": "viewer@beta.example.com", "name": "Housemate",
        "role": "viewer", "password": GOOD_PW,
    })
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "viewer"

    # Removed again so the shared org_b fixture keeps the single-member roster
    # that the tenant-isolation test asserts on.
    assert client.delete(f"/api/team/{r.json()['id']}",
                         cookies=org_b["cookies"]).status_code == 200


def test_company_can_still_assign_the_analyst_role(client, org_a):
    r = client.post("/api/team", cookies=org_a["cookies"], json={
        "email": "analyst@alpha.example.com", "name": "Analyst",
        "role": "analyst", "password": GOOD_PW,
    })
    assert r.status_code == 201, r.text
    assert r.json()["role"] == "analyst"


def test_consumer_is_limited_to_one_active_collector_key(client, org_b):
    first = client.post("/api/team/keys", cookies=org_b["cookies"],
                        json={"label": "home collector"})
    assert first.status_code == 201, first.text

    second = client.post("/api/team/keys", cookies=org_b["cookies"],
                         json={"label": "another"})
    assert second.status_code == 400
    assert "single collector key" in second.json()["detail"]

    # Revoking frees the slot — the cap is on active keys, not lifetime ones.
    key_id = first.json()["id"]
    assert client.delete(f"/api/team/keys/{key_id}",
                         cookies=org_b["cookies"]).status_code == 200
    third = client.post("/api/team/keys", cookies=org_b["cookies"],
                        json={"label": "replacement"})
    assert third.status_code == 201, third.text


def test_company_can_mint_several_keys(client, org_a):
    a = client.post("/api/team/keys", cookies=org_a["cookies"],
                    json={"label": "site-a"})
    b = client.post("/api/team/keys", cookies=org_a["cookies"],
                    json={"label": "site-b"})
    assert a.status_code == 201 and b.status_code == 201


def test_ingest_registers_a_new_node_automatically(client, org_a):
    """A real collector names nodes the demo topology never seeded.

    Without auto-registration the flow would still be scored and stored, but
    the Nodes page — which only lists rows from the nodes table — would never
    show it, making a real deployment look empty even while it works.
    """
    r = client.post("/api/ingest", cookies=org_a["cookies"], json={"flows": [{
        "src_ip": "10.0.0.9", "dst_port": 443, "protocol": "TCP",
        "node": "MACBOOK-JUDE", "duration": 0.02, "packets": 12,
        "total_bytes": 4096,
    }]})
    assert r.status_code == 200, r.text

    listed = client.get("/api/nodes", cookies=org_a["cookies"]).json()
    row = next(n for n in listed if n["label"] == "MACBOOK-JUDE")
    assert row["desc"] == "Detected from live traffic"


def test_ingest_does_not_register_the_unknown_placeholder(client, org_a):
    r = client.post("/api/ingest", cookies=org_a["cookies"], json={"flows": [{
        "src_ip": "10.0.0.10", "dst_port": 80, "duration": 0.01, "packets": 3,
    }]})
    assert r.status_code == 200, r.text

    listed = client.get("/api/nodes", cookies=org_a["cookies"]).json()
    assert all(n["label"] != "unknown" for n in listed)


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


def test_quiet_traffic_scores_zero_threat():
    """
    A batch with no detections must score exactly 0, not a small random
    number. The old implementation returned random.uniform(1.0, 8.0), which
    put a flickering floor under the headline threat gauge on an idle network
    and made "quiet" indistinguishable from "low but real".
    """
    from backend.app.engine import threat_score

    benign = [
        {"prediction": "normal", "confidence": 0.99, "bytes_per_sec": 1000.0},
        {"prediction": "normal", "confidence": 0.97, "bytes_per_sec": 2000.0},
    ]
    # Deterministic across repeats — the old version would vary each call.
    assert [threat_score(benign) for _ in range(5)] == [0.0] * 5
    assert threat_score([]) == 0.0


def test_attack_traffic_scores_above_zero():
    """Anchors the test above: zero must mean "nothing found", not "broken"."""
    from backend.app.engine import threat_score

    attack = [
        {"prediction": "dos_ddos", "confidence": 0.98, "bytes_per_sec": 5e6},
        {"prediction": "dos_ddos", "confidence": 0.95, "bytes_per_sec": 4e6},
    ]
    assert threat_score(attack) > 0.0


def test_live_ingest_records_a_metric_point(client, org_a):
    """
    MetricPoint rows used to be written only by the simulator loop, so a real
    deployment fed by a collector scored flows correctly and showed empty
    throughput/threat charts. Ingesting must move the history forward.
    """
    # /metrics/history returns a SeriesOut object, not a list — len() on the
    # response would count its three keys and never change.
    def history_len():
        body = client.get("/api/metrics/history?points=500",
                          cookies=org_a["cookies"]).json()
        return len(body["labels"])

    before = history_len()

    r = client.post("/api/ingest", cookies=org_a["cookies"], json={"flows": [
        {"src_ip": "198.51.100.7", "dst_port": 443, "protocol": "TCP",
         "node": "EDGE-01", "duration": 8.0, "packets": 200,
         "total_bytes": 160_000},
    ]})
    assert r.status_code == 200, r.text
    assert "metric" in r.json(), "ingest should report the sample it recorded"
    assert r.json()["metric"]["flows"] == 1

    assert history_len() == before + 1, "ingest did not persist a metric point"


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


def test_mitigating_a_source_closes_out_its_incident(client, org_a):
    """The incident must follow its flows, or the UI contradicts itself.

    Both consoles decide whether a row still needs a human by reading
    `mitigated`. If mitigating a source flipped the flows but left the incident
    alone, the page would confirm the block and then keep demanding it.
    """
    incidents = client.get("/api/incidents", cookies=org_a["cookies"]).json()
    target = next(i for i in incidents if i["src_ip"] == "203.0.113.9")
    assert target["mitigated"] is True


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


def test_listed_flows_carry_a_severity(client, org_a):
    """
    The dashboard filters desktop notifications on flow.severity. If the field
    is absent the filter silently degrades to "notify on everything", which is
    exactly the behaviour the min_severity setting exists to prevent — so the
    field being present is worth pinning.
    """
    flows = client.get("/api/flows?limit=25", cookies=org_a["cookies"]).json()
    # isinstance, not just truthiness: an error body like {"detail": ...} is
    # truthy too, and would otherwise sail past this into a confusing TypeError.
    assert isinstance(flows, list), f"expected a list, got {flows!r}"
    assert flows, "expected the fixture org to have flows"
    valid = {"low", "medium", "high", "critical"}
    for f in flows:
        assert "severity" in f, f"flow {f['id']} has no severity"
        assert f["severity"] in valid, f"unexpected severity {f['severity']!r}"


def test_severity_matches_the_engine_rule(client, org_a):
    """
    Severity is recomputed on read rather than stored. That is only safe if the
    recomputation agrees with the engine's own rule, so compare against it
    directly instead of hardcoding expected strings here.
    """
    from backend.app.engine import severity_for

    flows = client.get("/api/flows?limit=25", cookies=org_a["cookies"]).json()
    assert isinstance(flows, list) and flows, f"expected a list, got {flows!r}"
    for f in flows:
        expected = severity_for(f["prediction"], f["confidence"], f["bytes_per_sec"])
        assert f["severity"] == expected, (
            f"flow {f['id']}: API said {f['severity']!r}, "
            f"engine rule says {expected!r}"
        )


def test_flow_search_treats_wildcards_as_literals(client, org_a):
    """A bare "%" in the search box must not match everything.

    LIKE wildcards live inside the bound parameter, so parameterisation alone
    does not neutralise them. Unescaped, typing "%" returns the entire flow
    table — not a SQL injection, but an unintended full dump through a control
    that looks like a filter.
    """
    # Own data, so the assertion does not depend on which tests ran first.
    assert client.post("/api/ingest", cookies=org_a["cookies"], json={"flows": [{
        "src_ip": "10.55.55.55", "dst_port": 8443, "protocol": "TCP",
        "node": "SEARCHTEST", "duration": 0.02, "packets": 6, "total_bytes": 900,
    }]}).status_code == 200

    everything = client.get("/api/flows", cookies=org_a["cookies"]).json()
    assert len(everything) > 0, "fixture produced no flows to search"

    wild = client.get("/api/flows", cookies=org_a["cookies"], params={"q": "%"})
    assert wild.status_code == 200
    assert wild.json() == [], "% should be a literal, not a match-all wildcard"

    # "_" is a literal, so it legitimately matches the underscore in the
    # "dos_ddos" class name — but it must not match rows with no underscore
    # anywhere, which is what the single-character wildcard would do.
    underscore = client.get("/api/flows", cookies=org_a["cookies"],
                            params={"q": "_"}).json()
    assert all(
        "_" in (f["src_ip"] + f["node"] + f["prediction"] + f["id"])
        for f in underscore
    ), "_ matched a row containing no literal underscore"
    assert len(underscore) < len(everything), "_ behaved as a match-all"

    # Escaping must not break ordinary search.
    hit = client.get("/api/flows", cookies=org_a["cookies"],
                     params={"q": "10.55.55.55"}).json()
    assert any(f["src_ip"] == "10.55.55.55" for f in hit)


def test_retention_bounds_flows_without_the_simulator(client, monkeypatch):
    """Retention must work with the simulator off — that is production.

    The trim call used to live inside `if settings.simulator_enabled:` in the
    engine loop, so the only deployments that trimmed anything were the demo
    ones that did not need to. A real install with a collector feeding it grew
    forever, and the only symptom was a full disk.

    Its own org, because the assertion is an exact row count and a shared
    fixture org would make that depend on test ordering.
    """
    from backend.app.config import settings
    from backend.app.db import SessionLocal
    from backend.app.engine import retention_pass
    from backend.app.models import Flow

    assert settings.simulator_enabled is False, "retention must hold with the sim off"

    r = client.post("/api/auth/signup", json={
        "email": "retention@gamma.example.com", "password": GOOD_PW,
        "name": "Retention Admin", "org_name": "Gamma Ltd", "org_type": "company",
    })
    assert r.status_code == 201, r.text
    cookies = dict(r.cookies)
    org_id = r.json()["org_id"]
    client.cookies.clear()

    keep = 40
    monkeypatch.setattr(settings, "retain_flows", keep)

    over = keep + 15
    batch = [{
        "src_ip": f"10.9.{i // 256}.{i % 256}", "dst_port": 443,
        "duration": 0.02, "packets": 4, "total_bytes": 512,
    } for i in range(over)]
    assert client.post("/api/ingest", cookies=cookies,
                       json={"flows": batch}).status_code == 200

    db = SessionLocal()
    try:
        assert db.query(Flow).filter(Flow.org_id == org_id).count() == over
    finally:
        db.close()

    retention_pass()

    db = SessionLocal()
    try:
        after = db.query(Flow).filter(Flow.org_id == org_id).count()
    finally:
        db.close()
    assert after == keep, f"expected the cap to hold at {keep}, got {after}"


def test_websocket_rejects_an_unauthenticated_connection(client):
    from starlette.websockets import WebSocketDisconnect

    client.cookies.clear()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws") as ws:
            ws.receive_text()


def test_websocket_accepts_a_live_session(client, make_user):
    cookies = _login(client, make_user())
    client.cookies.clear()
    with client.websocket_connect("/ws", cookies=cookies) as ws:
        assert ws is not None


def test_websocket_rejects_a_revoked_token(client, make_user):
    """Signing out must also kill the live stream, not just the HTTP session.

    The HTTP routes re-authenticate on every request, so revocation there is
    self-enforcing. A WebSocket authenticates once and then stays open for
    hours, which is precisely where a token that is still cryptographically
    valid but logically dead does the most damage: the captured cookie would
    keep streaming this org's traffic for the rest of the TTL.
    """
    from starlette.websockets import WebSocketDisconnect

    stolen = _login(client, make_user())

    # Live session: the socket opens.
    client.cookies.clear()
    with client.websocket_connect("/ws", cookies=stolen) as ws:
        assert ws is not None

    assert client.post("/api/auth/logout", cookies=stolen).status_code == 200
    client.cookies.clear()

    # Same cookie, after logout: refused.
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", cookies=stolen) as ws:
            ws.receive_text()


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
