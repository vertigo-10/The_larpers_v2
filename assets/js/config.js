/**
 * Static front-end configuration.
 *
 * Everything that describes the *system* (model name, accuracy, classes, org,
 * operator) now comes from the API at runtime — it is deliberately not
 * hard-coded here. A hard-coded number in this file was the origin of the old
 * fabricated "99.2% on CIC-IDS2017" claim, which nothing had ever measured.
 */
window.SENTRY_CONFIG = {
  // Empty string = same origin. The backend serves this dashboard by default,
  // so no configuration is needed. Set it only if you host the UI separately.
  apiBaseUrl: "",

  // Derived from apiBaseUrl below unless explicitly overridden.
  wsUrl: "",

  pollIntervalMs: 4000,
  maxTableRows: 45,
  historyPoints: 90
};

window.SENTRY_SETTINGS_KEY = "sentry.settings";

/**
 * The three classes the deployed model actually predicts.
 *
 * Mirrors backend/app/ml/net.py CLASS_NAMES. The API reports the authoritative
 * list via /api/status; this map only supplies presentation (colour + label).
 */
window.SENTRY_CLASSES = {
  normal:   { label: "Normal",     short: "NORMAL", color: "#2fe08a", tag: "ok",   benign: true },
  dos_ddos: { label: "DoS / DDoS", short: "DDOS",   color: "#ff5064", tag: "bad",  benign: false },
  scan:     { label: "Port scan",  short: "SCAN",   color: "#ffb545", tag: "warn", benign: false }
};

window.SENTRY_BENIGN = "normal";

/**
 * Findings that did not come from the model.
 *
 * Kept out of SENTRY_CLASSES above, which is a mirror of the three labels the
 * network can actually predict and has to stay that way — the flow-table class
 * filter and the Model page's confusion matrix are both built from its keys,
 * and a fourth entry would put a permanently-empty column in both.
 *
 * `scored: false` is what stops the alerts table printing "0%" in the
 * confidence column for these. No model was consulted, so there is no
 * probability; a zero would read as "the detector was completely unsure",
 * which is the opposite of what a rule that fired means.
 */
window.SENTRY_DETECTIONS = {
  slow_dos: {
    label: "Slow DoS", short: "SLOW-DOS", color: "#c06cff",
    tag: "bad", benign: false, scored: false
  }
};

window.SENTRY_SEVERITY = {
  critical: { label: "Critical", color: "#ff5064" },
  high:     { label: "High",     color: "#ff7a45" },
  medium:   { label: "Medium",   color: "#ffb545" },
  low:      { label: "Low",      color: "#6d7d85" }
};

// Local, per-browser preferences only. Anything the whole team shares
// (threshold, auto-mitigate, webhook) lives server-side under /api/settings.
(function () {
  try {
    const saved = JSON.parse(localStorage.getItem(window.SENTRY_SETTINGS_KEY) || "{}");
    ["apiBaseUrl", "wsUrl", "pollIntervalMs", "maxTableRows"]
      .forEach((k) => { if (saved[k] !== undefined) window.SENTRY_CONFIG[k] = saved[k]; });
  } catch (err) {
    console.warn("[sentry] could not read local preferences:", err.message);
  }

  if (!window.SENTRY_CONFIG.wsUrl) {
    const base = window.SENTRY_CONFIG.apiBaseUrl || window.location.origin;
    window.SENTRY_CONFIG.wsUrl = base.replace(/^http/, "ws").replace(/\/$/, "") + "/ws";
  }
})();
