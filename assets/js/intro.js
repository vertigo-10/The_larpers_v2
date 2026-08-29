/**
 * Opening sequence.
 *
 * Injects a full-screen overlay that plays once, then removes itself. Loaded
 * first on every page so it covers the initial paint rather than appearing
 * over an already-drawn dashboard.
 *
 * WHERE IT PLAYS
 * --------------
 * On arrival, not on navigation. This is a multi-page app with no client
 * router, so every sidebar click is a full document load; running the sequence
 * on each one turns a piece of branding into a tic.
 *
 * There are exactly two moments that are an arrival rather than a step:
 *
 *   1. The front door — login, signup, join. The first thing a visitor sees.
 *   2. The first dashboard after signing in — index.html or home-index.html.
 *
 * They get separate keys deliberately, so the sequence bookends the login:
 * once on the way in, once when the console appears. Everything past that is
 * navigation within a session and stays silent. Closing the tab and coming
 * back is a new session and plays again.
 *
 * The gate lives here rather than in the page list because a rule spread over
 * sixteen hand-written files drifts. The script loads everywhere and decides
 * for itself; the cost is a few KB on pages that will not use it.
 *
 * WHY IT NEVER BLOCKS
 * -------------------
 * The overlay is `pointer-events: none` from the first frame, so the dashboard
 * underneath is clickable for the whole 1.9 seconds — an operator arriving
 * mid-incident can click straight through it. It fades via a CSS animation with
 * `forwards` fill, so it clears even if this script dies partway. The removal
 * below is cleanup, not the mechanism. See intro.css.
 *
 * Deliberately dependency-free and self-executing: it must run before
 * config.js, api.js and the page module, so it cannot rely on SENTRY_UI.
 */
(function () {
  "use strict";

  var LIFETIME_MS = 2600;   // comfortably past the CSS timeline
  var WORD = "SENTRY";

  // Page → which arrival it counts as. Two keys, so signing in shows the
  // sequence a second time; anything not listed here never shows it at all.
  var GATES = {
    "login.html":      "sentry.intro.door",
    "signup.html":     "sentry.intro.door",
    "join.html":       "sentry.intro.door",
    "index.html":      "sentry.intro.app",
    "home-index.html": "sentry.intro.app"
  };

  // A bare origin serves index.html, so the empty path is the enterprise
  // dashboard rather than an unknown page.
  function pageName() {
    var path = window.location.pathname;
    var last = path.slice(path.lastIndexOf("/") + 1);
    return last || "index.html";
  }

  // The `?intro` escape hatch exists so the sequence can be reviewed from any
  // page without clearing storage by hand.
  var forced = window.location.search.indexOf("intro") !== -1;
  var key = GATES[pageName()];

  if (!forced) {
    if (!key) return;                       // mid-session navigation
    try {
      if (window.sessionStorage.getItem(key) === "1") return;
      window.sessionStorage.setItem(key, "1");
    } catch (e) {
      // Storage throws in private modes and under some cookie policies.
      // Failing closed is right: a missing animation is a cosmetic loss, one
      // that replays on every load is the thing being fixed here.
      return;
    }
  }

  // Node positions are fixed rather than random so the composition is the same
  // every time — a logo that reshuffles itself does not read as a logo. Values
  // are percentages within the square stage.
  var NODES = [
    { x: 50, y: 8,  d: 380 }, { x: 79, y: 21, d: 470 },
    { x: 92, y: 50, d: 560 }, { x: 78, y: 79, d: 650 },
    { x: 50, y: 92, d: 720 }, { x: 21, y: 79, d: 610 },
    { x: 8,  y: 50, d: 520 }, { x: 22, y: 21, d: 430 },
    { x: 66, y: 36, d: 500 }, { x: 34, y: 64, d: 590 }
  ];

  function build() {
    var root = document.createElement("div");
    root.className = "intro";
    // Hidden from assistive tech: it is decorative, and the page heading
    // announced underneath is the thing worth reading.
    root.setAttribute("aria-hidden", "true");

    var stage = document.createElement("div");
    stage.className = "intro-stage";

    var radar = document.createElement("div");
    radar.className = "intro-radar";
    ["r1", "r2", "r3", "r4"].forEach(function (r) {
      var ring = document.createElement("div");
      ring.className = "intro-ring " + r;
      radar.appendChild(ring);
    });
    var sweep = document.createElement("div");
    sweep.className = "intro-sweep";
    radar.appendChild(sweep);

    NODES.forEach(function (n) {
      var dot = document.createElement("div");
      dot.className = "intro-node";
      dot.style.left = n.x + "%";
      dot.style.top = n.y + "%";
      dot.style.animationDelay = n.d + "ms";
      radar.appendChild(dot);
    });

    var mark = document.createElement("div");
    mark.className = "intro-mark";

    var word = document.createElement("div");
    word.className = "intro-word";
    for (var i = 0; i < WORD.length; i++) {
      var clip = document.createElement("span");
      clip.className = "intro-clip";
      var ch = document.createElement("span");
      ch.className = "intro-ch" + (i >= 4 ? " accent" : "");
      ch.textContent = WORD[i];
      // Left-to-right stagger; the eye follows the assembly.
      ch.style.animationDelay = (150 + i * 62) + "ms";
      clip.appendChild(ch);
      word.appendChild(clip);
    }

    var rule = document.createElement("div");
    rule.className = "intro-rule";

    var sub = document.createElement("div");
    sub.className = "intro-sub";
    sub.textContent = "Neural Traffic Defence";

    mark.appendChild(word);
    mark.appendChild(rule);
    mark.appendChild(sub);
    stage.appendChild(radar);
    stage.appendChild(mark);
    root.appendChild(stage);
    return root;
  }

  function mount() {
    if (!document.body) return;
    var el = build();
    document.body.appendChild(el);

    var done = false;
    function remove() {
      if (done) return;
      done = true;
      if (el && el.parentNode) el.parentNode.removeChild(el);
    }

    // Normal path: leave when the fade-out finishes.
    el.addEventListener("animationend", function (ev) {
      if (ev.animationName.indexOf("intro-out") === 0) remove();
    });
    // Backstop, in case animationend never fires — a background tab can throttle
    // rAF and some engines drop the event entirely.
    window.setTimeout(remove, LIFETIME_MS);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else {
    mount();
  }
})();
