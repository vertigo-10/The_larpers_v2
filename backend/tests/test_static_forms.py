"""
Guards on the credential-bearing HTML forms.

These are not backend tests in the usual sense — they read the static pages off
disk and assert a property of the markup. They exist because the failure they
catch is silent, serious, and easy to reintroduce.

The bug: `<form>` with no `method` defaults to GET. login.html and signup.html
both rely on auth.js calling preventDefault() and posting via fetch, so in the
happy path the form never submits natively at all. But if a script 404s, throws
before it binds the listener, or the user presses Enter inside that window, the
browser submits the form itself — and a GET submit serialises every named field
into the query string. That was observed in a live run:

    GET /login.html?email=corp%40example.com&password=correct-horse-battery-staple

which lands the plaintext password in browser history, the server access log,
and any outbound Referer. Declaring method="post" makes that outcome
unreachable regardless of what the JavaScript does.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# (page, form id) — every form on the site that carries a password field.
CREDENTIAL_FORMS = [
    ("login.html", "login-form"),
    ("signup.html", "signup-form"),
    ("join.html", "join-form"),
]


def _form_tag(page: str, form_id: str) -> str:
    html = (ROOT / page).read_text(encoding="utf-8")
    match = re.search(rf"<form\b[^>]*\bid=[\"']{re.escape(form_id)}[\"'][^>]*>", html)
    assert match, f"no <form id={form_id}> found in {page}"
    return match.group(0)


@pytest.mark.parametrize("page,form_id", CREDENTIAL_FORMS)
def test_credential_form_declares_post(page: str, form_id: str) -> None:
    tag = _form_tag(page, form_id)
    method = re.search(r"\bmethod=[\"'](\w+)[\"']", tag)
    assert method, (
        f"{page}#{form_id} has no method attribute, so it defaults to GET. "
        "A native submit would put the password in the URL."
    )
    assert method.group(1).lower() == "post", (
        f"{page}#{form_id} submits via {method.group(1).upper()}; "
        "credentials must never be serialised into a query string."
    )


@pytest.mark.parametrize("page,form_id", CREDENTIAL_FORMS)
def test_credential_form_has_a_password_field(page: str, form_id: str) -> None:
    """
    Anchors the test above. If a page stops carrying a password input, the
    method assertion is no longer protecting anything and this suite should be
    revisited rather than passing vacuously.
    """
    html = (ROOT / page).read_text(encoding="utf-8")
    assert 'type="password"' in html, f"{page} no longer has a password input"
