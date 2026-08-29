"""
Guards on the two-UI split.

SENTRY ships two front ends over one backend: an enterprise console and a
consumer one. Which pages an account may see is decided by `data-org-scope` on
`<body>`, checked in ui.js against the signed-in user's `org_type`.

Like test_static_forms.py these read the markup off disk, because the failures
here are silent. Nothing throws when a page forgets to declare its scope — it
just quietly becomes visible to both account types, and the first person to
notice is a household staring at the enterprise incident console.

The redirect-loop test is the sharpest one. The guard bounces a mismatched
account to `landingFor()`, so if a landing page were ever scoped for the other
account type, the bounce would land on a page that bounces again and the user
could not reach the product at all.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

import pytest

ROOT = Path(__file__).resolve().parents[2]

CONSUMER_PAGES = ["home-index.html", "home-alerts.html", "home-devices.html"]
COMPANY_PAGES = [
    "index.html", "alerts.html", "traffic.html",
    "baseline.html", "nodes.html", "model.html", "reports.html",
]
# Deliberately unscoped: both account types have a profile, a settings page and
# people to manage. They reword themselves per org_type instead of splitting.
SHARED_PAGES = ["profile.html", "team.html", "settings.html"]
# Pre-auth. There is no session to compare a scope against yet.
AUTH_PAGES = ["login.html", "signup.html", "join.html"]

LANDING = {"consumer": "home-index.html", "company": "index.html"}


def _html(page: str) -> str:
    return (ROOT / page).read_text(encoding="utf-8")


def _scope(page: str):
    match = re.search(r"<body\b[^>]*\bdata-org-scope=[\"'](\w+)[\"']", _html(page))
    return match.group(1) if match else None


@pytest.mark.parametrize("page", CONSUMER_PAGES)
def test_consumer_pages_declare_consumer_scope(page: str) -> None:
    assert _scope(page) == "consumer", (
        f"{page} is a consumer page but does not declare "
        'data-org-scope="consumer", so an enterprise account can open it.'
    )


@pytest.mark.parametrize("page", COMPANY_PAGES)
def test_company_pages_declare_company_scope(page: str) -> None:
    assert _scope(page) == "company", (
        f"{page} is an enterprise page but does not declare "
        'data-org-scope="company", so a household can open it.'
    )


@pytest.mark.parametrize("page", SHARED_PAGES + AUTH_PAGES)
def test_shared_and_auth_pages_stay_unscoped(page: str) -> None:
    """A scope here would lock one account type out of a page it needs."""
    assert _scope(page) is None, (
        f"{page} is used by both account types but declares a scope, "
        "which would redirect one of them away from it."
    )


def test_every_page_has_been_assigned_a_scope() -> None:
    """
    The one test that fails when someone adds a page.

    Every other test in this file only checks pages already on a list, so a new
    page would sail past all of them ungated. This asserts the lists cover the
    directory, forcing a deliberate choice about who may see it.
    """
    known = set(CONSUMER_PAGES + COMPANY_PAGES + SHARED_PAGES + AUTH_PAGES)
    on_disk = {p.name for p in ROOT.glob("*.html")}
    unassigned = sorted(on_disk - known)
    assert not unassigned, (
        f"{unassigned} are not listed in this file, so nothing checks which "
        "account type may see them. Add each to the right list."
    )
    assert not sorted(known - on_disk), "listed pages no longer exist on disk"


@pytest.mark.parametrize("org_type,page", sorted(LANDING.items()))
def test_landing_page_does_not_bounce_its_own_account(org_type: str, page: str) -> None:
    """No redirect loop: the page you are sent to must accept you."""
    assert _scope(page) == org_type, (
        f"{org_type} accounts land on {page}, which is scoped "
        f"{_scope(page)!r}. The guard would bounce them straight back off it."
    )


def test_landing_rule_matches_the_pages_on_disk() -> None:
    """
    ui.js owns the rule; this checks it still points at real, correctly
    scoped pages. A rename here is otherwise only caught by a 404 in a browser.
    """
    src = (ROOT / "assets" / "js" / "ui.js").read_text(encoding="utf-8")
    body = re.search(r"function landingFor\(user\)\s*\{(.*?)\}", src, re.S)
    assert body, "landingFor() not found in ui.js"

    targets = set(re.findall(r"[\"']([\w.-]+\.html)[\"']", body.group(1)))
    assert targets == set(LANDING.values()), (
        f"landingFor() returns {sorted(targets)}, but this suite expects "
        f"{sorted(set(LANDING.values()))}."
    )


def test_brand_link_goes_to_the_reader_s_own_dashboard() -> None:
    """
    Clicking the logo must respect the split.

    It is the one link on the page that means "home", so hardcoding it to
    index.html would send every household to the enterprise console. The scope
    guard would bounce them back, but a logo that visibly bounces reads as
    broken. The href has to come from the landing rule, in both the markup
    ui.js renders and the correction it applies once the account is known.
    """
    src = (ROOT / "assets" / "js" / "ui.js").read_text(encoding="utf-8")

    brand = re.search(r'<a class="brand"[^>]*href="\$\{([^}]+)\}"', src)
    assert brand, (
        "the sidebar logo is not an anchor with a templated href — either it is "
        "no longer a link, or its destination has been hardcoded."
    )
    assert "Landing" in brand.group(1) or "landingFor" in brand.group(1), (
        f"the logo's href is built from {brand.group(1)!r} rather than the "
        "landing rule, so it can disagree with landingFor()."
    )
    assert re.search(r'sb-brand[^\n]*\n?[^\n]*landingFor\(user\)', src) or (
        'brand.setAttribute("href", landingFor(user))' in src
    ), (
        "nothing corrects the logo's href once /api/me answers. On the unscoped "
        "pages the initial value is only a guess."
    )


@pytest.mark.parametrize("page", CONSUMER_PAGES + COMPANY_PAGES)
def test_scoped_pages_load_the_script_that_enforces_the_scope(page: str) -> None:
    """The attribute is inert markup unless ui.js runs on the page."""
    assert re.search(r"<script[^>]+assets/js/ui\.js", _html(page)), (
        f"{page} declares a scope but never loads ui.js, so nothing checks it."
    )


@pytest.mark.parametrize("page", CONSUMER_PAGES)
def test_consumer_pages_do_not_link_to_enterprise_pages(page: str) -> None:
    """
    A link across the split is always a dead end: following it lands on a
    scoped page that immediately bounces the reader back.
    """
    hrefs: List[str] = re.findall(r'href=["\']([^"\':#]+\.html)["\']', _html(page))
    crossings = sorted({h for h in hrefs if h in COMPANY_PAGES})
    assert not crossings, (
        f"{page} links to {crossings}, which a consumer account cannot open."
    )
