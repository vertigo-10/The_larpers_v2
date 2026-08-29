"""
Guards on how the static pages pull in their assets.

There is no bundler here. Every page hand-writes its own `<script>` and `<link>`
tags with a `?v=` cache-busting token, which means the wiring can drift page by
page and nothing complains — the browser simply serves whatever it already had.

That is not hypothetical. A stale `ui.js` survived a deploy because the token was
bumped on some pages and not others: the markup said one thing, the cached script
did another, and the only symptom was a number on the dashboard that quietly
refused to update. The failure is invisible on the machine that just edited the
file, because that browser fetched it fresh.

So these read the markup off disk and assert two things a human cannot eyeball
across sixteen pages: that every asset reference agrees on one token, and that
the intro overlay is wired in the order it needs to be wired.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Set

import pytest

ROOT = Path(__file__).resolve().parents[2]

PAGES = sorted(p.name for p in ROOT.glob("*.html"))

# Anything referenced with ?v= — scripts and stylesheets alike.
_VERSIONED = re.compile(r'(?:src|href)=["\']([^"\']+?)\?v=(\d+)["\']')
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\'?]+)')


def _html(page: str) -> str:
    return (ROOT / page).read_text(encoding="utf-8")


def test_there_are_pages_to_check() -> None:
    """Stops the whole file silently passing if the glob ever breaks."""
    assert len(PAGES) >= 10, f"only found {PAGES} — the page glob is wrong"


def test_every_page_agrees_on_one_cache_token() -> None:
    """
    One token for the whole site, bumped as a set.

    Per-page tokens would be fine in principle, but in practice they get bumped
    by hand and one gets missed, and the page that was missed keeps serving the
    old JS against new markup. Uniformity is the property that is actually
    checkable, so it is the one enforced.
    """
    by_token: Dict[str, List[str]] = {}
    for page in PAGES:
        for _, token in _VERSIONED.findall(_html(page)):
            by_token.setdefault(token, []).append(page)

    assert by_token, "no ?v= tokens found on any page — has the scheme changed?"
    assert len(by_token) == 1, (
        "asset cache tokens disagree across pages: "
        + "; ".join(
            f"v={tok} on {sorted(set(pages))}" for tok, pages in sorted(by_token.items())
        )
        + ". Bump every page in one pass, or browsers will mix old and new assets."
    )


@pytest.mark.parametrize("page", PAGES)
def test_versioned_assets_exist_on_disk(page: str) -> None:
    """A token on a path that no longer exists is a 404 nobody sees until prod."""
    missing = sorted(
        {path for path, _ in _VERSIONED.findall(_html(page))
         if path.startswith("assets/") and not (ROOT / path).is_file()}
    )
    assert not missing, f"{page} references {missing}, which are not on disk."


@pytest.mark.parametrize("page", PAGES)
def test_local_scripts_are_cache_busted(page: str) -> None:
    """
    An un-versioned local script is the worst case of the bug above: it can be
    cached indefinitely with no way to invalidate it short of a rename.
    """
    unversioned = [
        src for src in _SCRIPT_SRC.findall(_html(page))
        if src.startswith("assets/") and f'{src}?v=' not in _html(page)
    ]
    assert not unversioned, (
        f"{page} loads {unversioned} without a ?v= token, so a stale copy can "
        "be cached with no way to invalidate it."
    )


@pytest.mark.parametrize("page", PAGES)
def test_intro_overlay_is_wired_in(page: str) -> None:
    """Both halves, or the overlay half-runs: a curtain with nothing to remove it."""
    html = _html(page)
    assert "assets/css/intro.css" in html, f"{page} is missing the intro stylesheet"
    assert "assets/js/intro.js" in html, f"{page} is missing intro.js"


@pytest.mark.parametrize("page", PAGES)
def test_intro_script_runs_before_the_page_module(page: str) -> None:
    """
    intro.js has to be first.

    It exists to cover the initial paint. Loaded after config.js/api.js/the page
    module, it would instead drop a full-screen overlay on top of an already
    drawn dashboard — which is not a boot animation, it is an interruption.
    """
    scripts = [s for s in _SCRIPT_SRC.findall(_html(page)) if s.startswith("assets/")]
    assert scripts, f"{page} loads no local scripts at all"
    assert scripts[0].endswith("intro.js"), (
        f"{page} loads {scripts[0]} before intro.js. The overlay must be first, "
        "or it lands on top of a dashboard that has already rendered."
    )


def test_intro_cannot_trap_the_operator() -> None:
    """
    The one property that outranks how the sequence looks.

    A security console that cannot be clicked during an incident is worse than
    one with no branding at all, so the overlay is non-blocking three times over:
    it is pointer-transparent, it animates itself out without needing script, and
    intro.js removes it on a timer. This checks all three are still present —
    each is a one-line deletion away from being lost in a tidy-up.
    """
    css = (ROOT / "assets" / "css" / "intro.css").read_text(encoding="utf-8")
    js = (ROOT / "assets" / "js" / "intro.js").read_text(encoding="utf-8")

    assert re.search(r"\.intro\s*\{[^}]*pointer-events:\s*none", css, re.S), (
        "intro.css no longer sets pointer-events:none on .intro — the overlay "
        "would swallow clicks for the length of the animation."
    )
    assert re.search(r"animation:\s*intro-out[^;]*forwards", css), (
        "the .intro fade-out is no longer `forwards` — if script fails to run, "
        "the overlay never clears and the app is unreachable."
    )
    assert "setTimeout" in js and "LIFETIME_MS" in js, (
        "intro.js lost its removal backstop. animationend does not always fire "
        "in a throttled background tab."
    )


def _intro_js() -> str:
    return (ROOT / "assets" / "js" / "intro.js").read_text(encoding="utf-8")


def test_intro_plays_on_arrival_not_on_every_navigation() -> None:
    """
    The overlay is gated per session, not per document load.

    Every sidebar click here is a full page load. Ungated, the sequence fires on
    all of them, which is how a piece of branding becomes a tic. sessionStorage
    is the right lifetime: it survives navigation within a visit and resets when
    the tab is closed. localStorage would be wrong in the other direction —
    shown once ever, including across browser restarts.
    """
    js = _intro_js()
    assert "sessionStorage" in js, (
        "intro.js no longer gates on sessionStorage, so the animation replays on "
        "every sidebar click."
    )
    assert "localStorage" not in js, (
        "intro.js gates on localStorage, which would show the animation once and "
        "then never again, including after a browser restart."
    )


def test_intro_entry_pages_exist_and_are_entry_points() -> None:
    """
    The gate names pages as strings, so a rename silently disables the animation
    on that page — no error, it simply stops appearing. These are also the only
    pages it should fire on: a mid-session page in this list would put a curtain
    on a sidebar click.
    """
    listed = set(re.findall(r'"([\w.-]+\.html)":\s*"sentry\.intro\.', _intro_js()))
    assert listed, "no entry pages found in intro.js — has the gate been removed?"

    on_disk = {p.name for p in ROOT.glob("*.html")}
    assert listed <= on_disk, (
        f"intro.js gates on {sorted(listed - on_disk)}, which no longer exist. "
        "The animation is silently dead on those pages."
    )

    entry_points = {"login.html", "signup.html", "join.html",
                    "index.html", "home-index.html"}
    assert listed <= entry_points, (
        f"{sorted(listed - entry_points)} are mid-session pages, not arrivals. "
        "Playing the sequence there interrupts navigation."
    )


def test_both_landing_dashboards_get_the_intro() -> None:
    """Consumer and enterprise accounts should have the same arrival, not one."""
    listed = set(re.findall(r'"([\w.-]+\.html)":\s*"sentry\.intro\.', _intro_js()))
    for landing in ("index.html", "home-index.html"):
        assert landing in listed, (
            f"{landing} is a landing page but gets no opening sequence, so one "
            "account type arrives to a plain load and the other does not."
        )


def test_reduced_motion_is_honoured() -> None:
    """The sweep and the blur are exactly what a vestibular trigger looks like."""
    css = (ROOT / "assets" / "css" / "intro.css").read_text(encoding="utf-8")
    block = re.search(
        r"@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{(.*)\}", css, re.S
    )
    assert block, "intro.css has no prefers-reduced-motion block"
    body = block.group(1)
    for selector in (".intro-sweep", ".intro-node"):
        assert selector in body, (
            f"{selector} is not neutralised under prefers-reduced-motion."
        )


def test_pages_do_not_reference_a_missing_stylesheet() -> None:
    """Catches a renamed CSS file, which degrades to an unstyled page."""
    referenced: Set[str] = set()
    for page in PAGES:
        for match in re.findall(r'<link[^>]+href=["\'](assets/[^"\'?]+)', _html(page)):
            referenced.add(match)
    missing = sorted(p for p in referenced if not (ROOT / p).is_file())
    assert not missing, f"stylesheets referenced but not on disk: {missing}"
