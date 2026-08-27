"""Joining an organisation that already exists.

Signup creates an org and hands you the keys to it. Joining is the opposite
problem: someone outside is asking to be let in, and the whole question is
what they can obtain by asking. So these tests are mostly about what a join
*cannot* do — get a session, pick its own role, land in the wrong tenant, or
tell an anonymous caller anything about which organisations exist.

The two routes in are deliberately unequal in provenance but equal in outcome:
an invite is a decision an admin made about one named person, a domain match
is an unverified claim about an email address, and neither one grants access
without a human approving it.
"""

import os
import tempfile

import pytest

_TMP_DB = os.path.join(tempfile.mkdtemp(), "join.db")
os.environ["SENTRY_DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SENTRY_SIMULATOR_ENABLED"] = "false"
os.environ["SENTRY_SIGNUP_MAX_PER_WINDOW"] = "100000"
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


def _signup(client, email, org, org_type="company"):
    client.cookies.clear()
    r = client.post("/api/auth/signup", json={
        "email": email, "password": GOOD_PW, "name": "Admin",
        "org_name": org, "org_type": org_type,
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()
    return cookies


@pytest.fixture(scope="module")
def acme(client):
    """A company org with domain joining switched on."""
    cookies = _signup(client, "boss@acme-join.example", "Acme Join Corp")
    r = client.patch("/api/settings", cookies=cookies,
                     json={"email_domain": "acme-join.example"})
    assert r.status_code == 200, r.text
    return cookies


@pytest.fixture(scope="module")
def rival(client):
    """A second company, so cross-tenant leakage has somewhere to leak to."""
    return _signup(client, "boss@rival-join.example", "Rival Join Ltd")


@pytest.fixture(scope="module")
def household(client):
    return _signup(client, "me@home-join.example", "The Flat", org_type="consumer")


def _invite(client, cookies, email, role="viewer", hours=72):
    r = client.post("/api/team/invites", cookies=cookies,
                    json={"email": email, "role": role, "expires_in_hours": hours})
    assert r.status_code == 201, r.text
    return r.json()


def _join(client, email, code=None, name="Joiner"):
    client.cookies.clear()
    body = {"email": email, "password": GOOD_PW, "name": name, "title": "Analyst"}
    if code is not None:
        body["code"] = code
    return client.post("/api/auth/join", json=body)


# ── issuing invites ───────────────────────────────────────────────────────
def test_invite_code_is_shown_once_and_never_again(client, acme):
    """Only a digest is stored, so the listing genuinely cannot show the code.

    Same contract as the collector keys. If the list view could reproduce it,
    every admin session and every database backup would be a copy of a
    credential that mints logins.
    """
    made = _invite(client, acme, "once@acme-join.example")
    assert made["code"].startswith("sentry_inv_")

    listed = client.get("/api/team/invites", cookies=acme).json()
    row = next(i for i in listed if i["id"] == made["id"])
    assert "code" not in row
    assert made["code"] not in str(listed)
    # The prefix is fine to show — it is what makes a code identifiable in a
    # log without being usable.
    assert row["prefix"] == made["prefix"]


def test_invite_prefix_is_distinct_from_a_collector_key(client, acme):
    """A code that creates logins must not look like one that only ingests.

    They are handled by different people in different places, and confusing
    the two hands out account creation where a capture device was meant.
    """
    inv = _invite(client, acme, "prefixes@acme-join.example")
    key = client.post("/api/team/keys", cookies=acme, json={"label": "c"}).json()
    assert inv["code"].startswith("sentry_inv_")
    assert key["key"].startswith("sentry_ak_")
    assert not inv["code"].startswith("sentry_ak_")


def test_non_admin_cannot_issue_an_invite(client, acme):
    """Issuing an invite is handing out access, so it stays with an admin."""
    inv = _invite(client, acme, "viewer@acme-join.example", role="viewer")
    _join(client, "viewer@acme-join.example", inv["code"])

    pending = client.get("/api/team/pending", cookies=acme).json()
    uid = next(p["id"] for p in pending if p["email"] == "viewer@acme-join.example")
    client.post(f"/api/team/{uid}/approve", cookies=acme)

    client.cookies.clear()
    r = client.post("/api/auth/login", json={
        "email": "viewer@acme-join.example", "password": GOOD_PW})
    assert r.status_code == 200, r.text
    viewer = dict(client.cookies)
    client.cookies.clear()

    r = client.post("/api/team/invites", cookies=viewer,
                    json={"email": "nope@acme-join.example", "role": "admin"})
    assert r.status_code == 403


def test_household_cannot_use_invites_at_all(client, household):
    """A home network has no domain and no queue of applicants.

    Gated on the feature table rather than hidden in the UI, because a hidden
    button has never been a permission.
    """
    r = client.post("/api/team/invites", cookies=household,
                    json={"email": "stranger@example.com", "role": "viewer"})
    assert r.status_code == 403
    assert client.get("/api/team/invites", cookies=household).status_code == 403
    assert client.get("/api/team/pending", cookies=household).status_code == 403


def test_household_cannot_open_itself_to_a_domain(client, household):
    r = client.patch("/api/settings", cookies=household,
                     json={"email_domain": "home-join.example"})
    assert r.status_code == 403


# ── redeeming an invite ───────────────────────────────────────────────────
def test_invite_join_lands_pending_with_no_session(client, acme):
    """Approval is what grants access, so the join returns no cookie.

    A pending user holding a token they cannot use would put the enforcement
    in a filter somebody can forget; not minting one puts it in the absence
    of a credential.
    """
    inv = _invite(client, acme, "pending@acme-join.example", role="analyst")
    r = _join(client, "pending@acme-join.example", inv["code"])
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert body["join_method"] == "invite"
    assert body["org_name"] == "Acme Join Corp"
    # No session cookie came back, and nothing in the body is a token.
    assert "sentry_session" not in {c.name for c in client.cookies.jar}
    assert "token" not in str(body).lower()


def test_pending_user_cannot_sign_in(client, acme):
    inv = _invite(client, acme, "waiting@acme-join.example")
    _join(client, "waiting@acme-join.example", inv["code"])

    client.cookies.clear()
    r = client.post("/api/auth/login", json={
        "email": "waiting@acme-join.example", "password": GOOD_PW})
    assert r.status_code == 403
    # Told plainly, because the password is correct and sending them to a
    # password reset would waste their time. Only reachable once the password
    # has already been verified, so it reveals nothing to a stranger.
    assert "approve" in r.json()["detail"].lower()
    assert not client.cookies


def test_a_wrong_password_on_a_pending_account_still_reads_as_wrong(client, acme):
    """The pending message must not become an oracle.

    If a bad password on a pending account returned "waiting for approval",
    anyone could use the join form to discover which addresses have accounts.
    """
    inv = _invite(client, acme, "oracle@acme-join.example")
    _join(client, "oracle@acme-join.example", inv["code"])

    client.cookies.clear()
    r = client.post("/api/auth/login", json={
        "email": "oracle@acme-join.example", "password": "wrong-password-here"})
    assert r.status_code == 401
    assert "approve" not in r.json()["detail"].lower()


def test_invite_is_spent_at_request_time_not_at_approval(client, acme):
    """Consumed the moment it is redeemed, while the joiner is still pending.

    If it stayed open until an admin got round to deciding, the same code
    would keep working for somebody else in the meantime — which is exactly
    what single-use is supposed to prevent.
    """
    inv = _invite(client, acme, "first@acme-join.example")
    assert _join(client, "first@acme-join.example", inv["code"]).status_code == 201

    listed = client.get("/api/team/invites", cookies=acme).json()
    row = next(i for i in listed if i["id"] == inv["id"])
    assert row["state"] == "used"          # already spent, nobody has approved
    assert row["used_by"] == "Joiner"

    pending = client.get("/api/team/pending", cookies=acme).json()
    assert "first@acme-join.example" in {p["email"] for p in pending}


def test_a_spent_code_cannot_be_redeemed_again(client, acme):
    """Isolates single-use from the other two things that would also stop this.

    Redeeming twice normally trips the address binding or the "email already
    has an account" check first, so those would mask a broken state check.
    Rejecting the first joiner deletes the account and frees the address,
    leaving `used_at` as the only thing standing in the way.
    """
    inv = _invite(client, acme, "recycle@acme-join.example")
    assert _join(client, "recycle@acme-join.example", inv["code"]).status_code == 201

    pending = client.get("/api/team/pending", cookies=acme).json()
    uid = next(p["id"] for p in pending if p["email"] == "recycle@acme-join.example")
    assert client.post(f"/api/team/{uid}/reject", cookies=acme).status_code == 200

    # Same code, same address, no account in the way — and still refused.
    assert _join(client, "recycle@acme-join.example", inv["code"]).status_code == 400


def test_invite_is_bound_to_the_address_it_was_issued_for(client, acme):
    """A forwarded code is not a transferable credential."""
    inv = _invite(client, acme, "intended@acme-join.example")
    r = _join(client, "someone-else@acme-join.example", inv["code"])
    assert r.status_code == 400

    # And it is still usable by the person it was actually for.
    assert _join(client, "intended@acme-join.example", inv["code"]).status_code == 201


def test_revoked_invite_stops_working(client, acme):
    inv = _invite(client, acme, "revoked@acme-join.example")
    assert client.delete(f"/api/team/invites/{inv['id']}", cookies=acme).status_code == 200
    assert _join(client, "revoked@acme-join.example", inv["code"]).status_code == 400


def test_expired_invite_stops_working(client, acme):
    """Expiry is enforced at redemption, not by a sweep job.

    Nothing prunes the table, so a code whose expiry has passed has to be
    refused by the lookup itself or it stays live forever.
    """
    from datetime import timedelta

    from backend.app.db import SessionLocal
    from backend.app.models import Invite, utcnow

    inv = _invite(client, acme, "expired@acme-join.example")
    db = SessionLocal()
    try:
        row = db.get(Invite, inv["id"])
        row.expires_at = utcnow() - timedelta(hours=1)
        db.commit()
    finally:
        db.close()

    assert _join(client, "expired@acme-join.example", inv["code"]).status_code == 400


def test_a_garbage_code_is_refused(client):
    assert _join(client, "nobody@nowhere.example", "sentry_inv_totally-made-up").status_code == 400
    assert _join(client, "nobody@nowhere.example", "not-even-the-right-shape").status_code == 400


def test_every_failure_says_the_same_thing(client, acme):
    """A used code, a wrong address and a fake code are indistinguishable.

    The caller is anonymous. Telling them apart would let someone map which
    companies use the product and confirm when a guessed code was real.
    """
    inv = _invite(client, acme, "same@acme-join.example")
    _join(client, "same@acme-join.example", inv["code"])  # spend it

    spent = _join(client, "other-a@acme-join.example", inv["code"])
    fake = _join(client, "other-b@acme-join.example", "sentry_inv_fabricated")
    no_org = _join(client, "other-c@unknown-domain.example")

    details = {r.json()["detail"] for r in (spent, fake, no_org)}
    assert len(details) == 1, details


# ── domain matching ───────────────────────────────────────────────────────
def test_domain_match_joins_as_the_lowest_role(client, acme):
    """An unverified claim about an address must not pick its own access.

    Nothing here proves the joiner controls that mailbox, so they get viewer
    and an admin raises it if they should have more.
    """
    r = _join(client, "employee@acme-join.example")
    assert r.status_code == 201, r.text
    assert r.json()["join_method"] == "domain"

    pending = client.get("/api/team/pending", cookies=acme).json()
    row = next(p for p in pending if p["email"] == "employee@acme-join.example")
    assert row["role"] == "viewer"
    assert row["status"] == "pending"


def test_domain_joiners_are_marked_as_unverified_in_the_queue(client, acme):
    """The approval screen has to be able to tell the two routes apart.

    An invite means an admin already decided this person belongs. A domain
    match means only that the address they typed ends in the right thing, and
    an admin rubber-stamping the queue needs to see the difference.
    """
    inv = _invite(client, acme, "decided@acme-join.example")
    _join(client, "decided@acme-join.example", inv["code"])
    _join(client, "claimed@acme-join.example")

    pending = client.get("/api/team/pending", cookies=acme).json()
    by_email = {p["email"]: p["join_method"] for p in pending}
    assert by_email["decided@acme-join.example"] == "invite"
    assert by_email["claimed@acme-join.example"] == "domain"


def test_unknown_domain_cannot_join(client):
    assert _join(client, "stranger@not-a-customer.example").status_code == 400


def test_two_orgs_claiming_one_domain_is_refused_not_guessed(client):
    """Nothing stops two orgs typing the same domain, so the join must refuse.

    Silently picking the first match would eventually drop somebody into the
    wrong company's dashboard, and because the join looks like it worked,
    nobody would be able to see that it had happened. An invite still works —
    it names an org outright, so there is nothing to guess.
    """
    one = _signup(client, "boss@contested.example", "Contested One")
    two = _signup(client, "boss2@contested.example", "Contested Two")
    for cookies in (one, two):
        r = client.patch("/api/settings", cookies=cookies,
                         json={"email_domain": "contested.example"})
        assert r.status_code == 200, r.text

    assert _join(client, "who@contested.example").status_code == 400

    inv = _invite(client, two, "named@contested.example")
    r = _join(client, "named@contested.example", inv["code"])
    assert r.status_code == 201
    assert r.json()["org_name"] == "Contested Two"


def test_domain_joining_is_off_until_an_admin_turns_it_on(client, rival):
    """Empty is the only safe default — an org that never asked for domain
    joining must not have it switched on for them."""
    settings = client.get("/api/settings", cookies=rival).json()
    assert settings["email_domain"] == ""
    assert _join(client, "someone@rival-join.example").status_code == 400


def test_domain_joining_can_be_switched_back_off(client, rival):
    """"" is a value, not an omission. If it read as "unset", an admin could
    open the door but never close it."""
    client.patch("/api/settings", cookies=rival, json={"email_domain": "rival-join.example"})
    assert _join(client, "in@rival-join.example").status_code == 201

    r = client.patch("/api/settings", cookies=rival, json={"email_domain": ""})
    assert r.status_code == 200
    assert r.json()["email_domain"] == ""
    assert _join(client, "out@rival-join.example").status_code == 400


def test_a_public_mailbox_provider_is_refused_as_a_domain(client, rival):
    """Setting gmail.com would turn "anyone at our company" into "anyone".

    Approval would still be required, but a request queue full of lookalikes
    is a target in itself, and an admin clicking through a hundred of them
    will eventually approve the wrong one.
    """
    r = client.patch("/api/settings", cookies=rival, json={"email_domain": "gmail.com"})
    assert r.status_code == 422
    assert "public email provider" in r.text


def test_a_domain_must_look_like_a_domain(client, rival):
    for bad in ("acme", "http://acme.com/x", "acme com", "a@acme.com"):
        r = client.patch("/api/settings", cookies=rival, json={"email_domain": bad})
        assert r.status_code == 422, bad


def test_domain_is_normalised(client, rival):
    r = client.patch("/api/settings", cookies=rival,
                     json={"email_domain": "  @Rival-Join.EXAMPLE  "})
    assert r.status_code == 200
    assert r.json()["email_domain"] == "rival-join.example"
    client.patch("/api/settings", cookies=rival, json={"email_domain": ""})


# ── setting the domain during signup ──────────────────────────────────────
# The company signup form asks for it, so it is a second door onto the same
# decision as the settings screen, and it has to be locked the same way.
def test_signup_can_open_domain_joining_immediately(client):
    """One request, not signup-then-PATCH, so there is no window in between."""
    client.cookies.clear()
    r = client.post("/api/auth/signup", json={
        "email": "boss@earlydomain.example", "password": GOOD_PW,
        "name": "Admin", "org_name": "Early Domain Ltd", "org_type": "company",
        "email_domain": "  @EarlyDomain.Example  ",
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()

    assert client.get("/api/settings", cookies=cookies).json()["email_domain"] \
        == "earlydomain.example"
    # And it actually works, rather than merely being stored.
    joined = _join(client, "new@earlydomain.example")
    assert joined.status_code == 201, joined.text
    assert joined.json()["join_method"] == "domain"


def test_signup_refuses_a_public_provider_without_creating_anything(client):
    """The reason this field belongs in signup rather than in a follow-up call.

    Pydantic rejects the body before the handler runs, so a refused domain
    leaves no org and no admin account behind. Were this a PATCH after signup,
    the same mistake would leave a live account whose owner believes they
    configured something that silently never applied.
    """
    client.cookies.clear()
    r = client.post("/api/auth/signup", json={
        "email": "boss@publicdomain.example", "password": GOOD_PW,
        "name": "Admin", "org_name": "Public Domain Ltd", "org_type": "company",
        "email_domain": "gmail.com",
    })
    assert r.status_code == 422
    assert "public email provider" in r.text

    # Nothing was created, so the address is still free.
    r = client.post("/api/auth/signup", json={
        "email": "boss@publicdomain.example", "password": GOOD_PW,
        "name": "Admin", "org_name": "Public Domain Ltd", "org_type": "company",
    })
    assert r.status_code == 201, r.text
    client.cookies.clear()


def test_a_household_cannot_give_itself_a_join_domain(client):
    """Consumer orgs have no invites feature, so they must have no domain either.

    The settings route already refuses this via require_feature, but signup is
    a different door and an unauthenticated one. A household that could set a
    domain would be a self-service join queue on somebody's home network — the
    exact thing the feature table says consumers do not get.
    """
    client.cookies.clear()
    r = client.post("/api/auth/signup", json={
        "email": "me@flatdomain.example", "password": GOOD_PW,
        "name": "Resident", "org_name": "The Other Flat", "org_type": "consumer",
        "email_domain": "flatdomain.example",
    })
    assert r.status_code == 201, r.text
    cookies = dict(client.cookies)
    client.cookies.clear()

    assert client.get("/api/settings", cookies=cookies).json()["email_domain"] == ""
    # The claimed domain matches nothing, so it cannot be joined on.
    assert _join(client, "stranger@flatdomain.example").status_code == 400


# ── approval ──────────────────────────────────────────────────────────────
def test_approval_is_what_grants_access(client, acme):
    inv = _invite(client, acme, "approved@acme-join.example", role="analyst")
    _join(client, "approved@acme-join.example", inv["code"])

    pending = client.get("/api/team/pending", cookies=acme).json()
    uid = next(p["id"] for p in pending if p["email"] == "approved@acme-join.example")

    r = client.post(f"/api/team/{uid}/approve", cookies=acme)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active"
    assert r.json()["role"] == "analyst"

    client.cookies.clear()
    r = client.post("/api/auth/login", json={
        "email": "approved@acme-join.example", "password": GOOD_PW})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active"
    client.cookies.clear()


def test_rejection_frees_the_address_to_try_again(client, acme):
    """Deleted rather than parked in a "rejected" state.

    One wrong guess about which company you work for should not make your
    email address permanently unusable. No access is destroyed here — the
    account was never approved.
    """
    _join(client, "wrong-company@acme-join.example")
    pending = client.get("/api/team/pending", cookies=acme).json()
    uid = next(p["id"] for p in pending if p["email"] == "wrong-company@acme-join.example")

    assert client.post(f"/api/team/{uid}/reject", cookies=acme).status_code == 200
    still = client.get("/api/team/pending", cookies=acme).json()
    assert "wrong-company@acme-join.example" not in {p["email"] for p in still}

    assert _join(client, "wrong-company@acme-join.example").status_code == 201


def test_non_admin_cannot_approve(client, acme):
    inv = _invite(client, acme, "gatekeep@acme-join.example", role="analyst")
    _join(client, "gatekeep@acme-join.example", inv["code"])
    pending = client.get("/api/team/pending", cookies=acme).json()
    uid = next(p["id"] for p in pending if p["email"] == "gatekeep@acme-join.example")

    # An analyst is an operator, not an administrator.
    inv2 = _invite(client, acme, "analyst2@acme-join.example", role="analyst")
    _join(client, "analyst2@acme-join.example", inv2["code"])
    pending = client.get("/api/team/pending", cookies=acme).json()
    aid = next(p["id"] for p in pending if p["email"] == "analyst2@acme-join.example")
    client.post(f"/api/team/{aid}/approve", cookies=acme)

    client.cookies.clear()
    client.post("/api/auth/login", json={
        "email": "analyst2@acme-join.example", "password": GOOD_PW})
    analyst = dict(client.cookies)
    client.cookies.clear()

    assert client.post(f"/api/team/{uid}/approve", cookies=analyst).status_code == 403


def test_approving_twice_is_refused(client, acme):
    inv = _invite(client, acme, "twice@acme-join.example")
    _join(client, "twice@acme-join.example", inv["code"])
    pending = client.get("/api/team/pending", cookies=acme).json()
    uid = next(p["id"] for p in pending if p["email"] == "twice@acme-join.example")

    assert client.post(f"/api/team/{uid}/approve", cookies=acme).status_code == 200
    assert client.post(f"/api/team/{uid}/approve", cookies=acme).status_code == 400


# ── tenancy ───────────────────────────────────────────────────────────────
def test_one_org_cannot_see_or_touch_anothers_invites(client, acme, rival):
    """Sequential ids across tenants are only safe if every lookup is scoped."""
    inv = _invite(client, acme, "scoped@acme-join.example")

    listed = client.get("/api/team/invites", cookies=rival).json()
    assert inv["id"] not in {i["id"] for i in listed}

    r = client.delete(f"/api/team/invites/{inv['id']}", cookies=rival)
    assert r.status_code == 404

    # Still open, so the cross-tenant delete really did nothing.
    mine = client.get("/api/team/invites", cookies=acme).json()
    assert next(i for i in mine if i["id"] == inv["id"])["state"] == "open"


def test_one_org_cannot_approve_anothers_pending_member(client, acme, rival):
    _join(client, "cross-tenant@acme-join.example")
    pending = client.get("/api/team/pending", cookies=acme).json()
    uid = next(p["id"] for p in pending if p["email"] == "cross-tenant@acme-join.example")

    assert client.post(f"/api/team/{uid}/approve", cookies=rival).status_code == 404
    assert client.post(f"/api/team/{uid}/reject", cookies=rival).status_code == 404

    still = client.get("/api/team/pending", cookies=acme).json()
    assert uid in {p["id"] for p in still}


def test_an_invite_cannot_place_someone_in_another_org(client, acme, rival):
    """The org comes from the invite row, never from anything the caller sends."""
    inv = _invite(client, acme, "placed@acme-join.example")
    r = _join(client, "placed@acme-join.example", inv["code"])
    assert r.json()["org_name"] == "Acme Join Corp"

    assert "placed@acme-join.example" not in {
        p["email"] for p in client.get("/api/team/pending", cookies=rival).json()
    }


# ── audit ─────────────────────────────────────────────────────────────────
def test_the_whole_life_of_an_invite_is_audited(client, acme):
    """Issued, requested, approved — each by name, and never the code itself.

    An audit log is exactly the kind of place a credential gets read out of
    later, so only the prefix goes in.
    """
    inv = _invite(client, acme, "audited@acme-join.example", role="analyst")
    _join(client, "audited@acme-join.example", inv["code"])
    pending = client.get("/api/team/pending", cookies=acme).json()
    uid = next(p["id"] for p in pending if p["email"] == "audited@acme-join.example")
    client.post(f"/api/team/{uid}/approve", cookies=acme)

    entries = client.get("/api/team/audit?limit=200", cookies=acme).json()
    actions = {e["action"] for e in entries}
    assert {"invite.created", "team.join_requested", "team.member_approved"} <= actions

    blob = str(entries)
    assert inv["code"] not in blob
    assert inv["prefix"] in blob


def test_revocation_is_audited(client, acme):
    inv = _invite(client, acme, "audit-revoke@acme-join.example")
    client.delete(f"/api/team/invites/{inv['id']}", cookies=acme)
    entries = client.get("/api/team/audit?limit=200", cookies=acme).json()
    assert "invite.revoked" in {e["action"] for e in entries}


def test_audit_timestamps_survive_the_round_trip_through_sqlite(client, acme):
    """An entry written now must read back as now, not as now-minus-the-offset.

    SQLite has no timezone type, so an aware datetime comes back naive and
    .timestamp() then reinterprets it in the server's local zone. On a machine
    at UTC+5:30 that rendered a just-written audit entry as "5h ago". The same
    silent shift decides whether an invite has expired, so this is worth a test
    even though it looks cosmetic on the audit screen.

    Deliberately asserts against real wall-clock time rather than a mocked one:
    the bug only appears when the process's local zone differs from UTC, and a
    frozen clock would hide it.
    """
    import time

    _invite(client, acme, "audit-clock@acme-join.example")
    entries = client.get("/api/team/audit?limit=200", cookies=acme).json()
    newest = max(e["ts"] for e in entries)

    drift_seconds = abs(time.time() - newest / 1000)
    assert drift_seconds < 120, (
        f"newest audit entry is {drift_seconds / 3600:.2f}h from now — "
        "a timezone offset is being applied somewhere in the round trip"
    )
