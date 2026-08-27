/**
 * Settings.
 *
 * Two storage tiers, and the page is explicit about which is which:
 *
 *   - Detection, alerting and the org name live server-side under /api/settings
 *     and apply to everyone in the organisation. Admin-only to change.
 *   - Display preferences (poll interval, table size, API base URL) are local to
 *     this browser, because they describe this screen, not the deployment.
 *
 * Non-admins see the shared section read-only rather than getting a 403 after
 * filling the form in.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const cfg = window.SENTRY_CONFIG;
  const KEY = window.SENTRY_SETTINGS_KEY;
  const { esc, icon, fmt, toast } = ui;
  const el = (id) => document.getElementById(id);

  // `in-domain` is only present for account types with the invites feature —
  // applyFeatureGates removes it outright otherwise — so every reference to it
  // has to tolerate a missing node.
  const SHARED = [
    "in-org", "in-domain", "in-threshold", "in-auto", "in-severity",
    "in-webhook", "in-notify"
  ];

  const state = { user: null, server: null, dirty: false };

  ui.mountSidebar("settings");
  el("btn-save").innerHTML = `${icon("check", 12)} Save changes`;
  el("ico-notice").innerHTML = icon("info", 15);

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    state.user = await api.me();
    el("topbar-avatar").textContent = state.user.initials || "··";
    el("topbar-avatar").title = `${state.user.name} · ${state.user.role}`;
    el("crumb").textContent = `/ ${state.user.org_name}`;
    el("role-pill").textContent = state.user.role.toUpperCase();

    applyOrgWording();

    state.server = await api.getSettings();
    paintServer(state.server);
    paintLocal();
    applyRole();
    await checkBackend();
    await initKeys();

    SHARED.concat(["in-poll", "in-rows", "in-api"]).forEach((id) => {
      const node = el(id);
      if (node) node.addEventListener("input", () => { state.dirty = true; });
    });

    // Don't let someone navigate away thinking they saved.
    window.addEventListener("beforeunload", (e) => {
      if (!state.dirty) return;
      e.preventDefault();
      e.returnValue = "";
    });
  }

  function paintServer(s) {
    el("in-org").value = s.org_name || "";
    const domain = el("in-domain");
    if (domain) domain.value = s.email_domain || "";
    el("in-threshold").value = Math.round(s.threshold * 100);
    el("threshold-label").textContent = s.threshold.toFixed(2);
    el("in-auto").checked = s.auto_mitigate;
    el("in-severity").value = s.min_severity;
    el("in-webhook").value = s.webhook_url || "";
    el("in-notify").checked = s.notify_browser;

    el("auto-desc").innerHTML = s.auto_mitigate
      ? `Currently <b style="color:var(--amber)">on</b>. A false positive gets marked
         without review — check the disagreement table on Model Performance before
         relying on this.`
      : `Automatically mark flows above τ as mitigated, without an operator
         pressing anything.`;
  }

  function paintLocal() {
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (_) { /* corrupt, ignore */ }

    el("in-api").value = saved.apiBaseUrl !== undefined ? saved.apiBaseUrl : cfg.apiBaseUrl || "";
    setSelect("in-poll", saved.pollIntervalMs || cfg.pollIntervalMs);
    setSelect("in-rows", saved.maxTableRows || cfg.maxTableRows);
  }

  function setSelect(id, value) {
    const node = el(id);
    const match = Array.prototype.find.call(node.options, (o) => Number(o.value) === Number(value));
    // An unrecognised saved value would otherwise silently select the first
    // option and look like the setting was ignored.
    if (match) node.value = match.value;
    else {
      const opt = document.createElement("option");
      opt.value = value;
      opt.textContent = `${value} (custom)`;
      node.appendChild(opt);
      node.value = String(value);
    }
  }

  // The shared section is the one place this page names the group the settings
  // belong to, and "organisation" is wrong for a household in a way that reads
  // as the wrong product rather than as a typo.
  function applyOrgWording() {
    const copy = ui.orgCopy(state.user.org_type);
    el("org-panel-title").textContent = copy.settingsTitle;
    el("org-name-label").textContent = copy.settingsNameLabel;
    el("org-name-desc").textContent = copy.settingsNameDesc;
    el("scope-text").innerHTML = copy.settingsScope;
  }

  function applyRole() {
    if (state.user.role === "admin") return;
    SHARED.forEach((id) => {
      const node = el(id);
      if (!node) return;
      node.disabled = true;
      node.style.opacity = "0.5";
      node.style.cursor = "not-allowed";
    });
    el("scope-text").innerHTML =
      `Detection and alerting settings are shared across <b>${esc(state.user.org_name)}</b> and
       can only be changed by an admin. Display settings below are yours and are
       stored in this browser.`;
    el("scope-notice").style.background = "rgba(255,181,69,0.06)";
    el("scope-notice").style.borderColor = "rgba(255,181,69,0.22)";
  }

  el("in-threshold").addEventListener("input", (e) => {
    el("threshold-label").textContent = (Number(e.target.value) / 100).toFixed(2);
  });

  // Asking for notification permission has to happen on a real user gesture.
  el("in-notify").addEventListener("change", async (e) => {
    if (!e.target.checked) return;
    if (!("Notification" in window)) {
      e.target.checked = false;
      return toast("This browser has no notification support.", "err");
    }
    const perm = Notification.permission === "granted"
      ? "granted"
      : await Notification.requestPermission();
    if (perm !== "granted") {
      e.target.checked = false;
      el("notify-desc").innerHTML =
        `Blocked by the browser. Allow notifications for this site in your browser
         settings, then turn this back on.`;
      toast("Notification permission denied by the browser.", "err");
    }
  });

  el("btn-save").addEventListener("click", async () => {
    const btn = el("btn-save");
    btn.disabled = true;
    btn.innerHTML = "Saving…";

    // ── local half: always allowed ────────────────────────────────────
    const local = {
      apiBaseUrl: el("in-api").value.trim(),
      pollIntervalMs: Number(el("in-poll").value),
      maxTableRows: Number(el("in-rows").value)
    };
    try {
      localStorage.setItem(KEY, JSON.stringify(local));
    } catch (err) {
      toast("Could not save display settings — browser storage is unavailable.", "err");
    }

    // ── shared half: admin only ───────────────────────────────────────
    if (state.user.role === "admin") {
      const payload = {
        org_name: el("in-org").value.trim(),
        threshold: Number(el("in-threshold").value) / 100,
        auto_mitigate: el("in-auto").checked,
        min_severity: el("in-severity").value,
        webhook_url: el("in-webhook").value.trim(),
        notify_browser: el("in-notify").checked
      };
      // Omitted rather than sent as "" when the field is absent: "" is how an
      // admin turns domain joining off, so sending it unconditionally would
      // clear the setting every time a consumer saved anything.
      const domain = el("in-domain");
      if (domain) payload.email_domain = domain.value.trim();
      try {
        state.server = await api.updateSettings(payload);
        paintServer(state.server);
      } catch (err) {
        btn.disabled = false;
        btn.innerHTML = `${icon("check", 12)} Save changes`;
        return toast(err.message, "err");
      }
    }

    state.dirty = false;
    btn.disabled = false;
    btn.innerHTML = `${icon("check", 12)} Save changes`;
    toast("Settings saved.");

    // Display settings are read at page load, so a reload is the honest way to
    // apply them rather than pretending they took effect everywhere.
    if (local.apiBaseUrl !== (cfg.apiBaseUrl || "")) {
      setTimeout(() => window.location.reload(), 700);
    }
  });

  async function checkBackend() {
    const badge = el("conn-badge");
    badge.textContent = "Testing…";
    try {
      const [health, status] = await Promise.all([api.getHealth(), api.getStatus()]);
      const ok = health.status === "ok";
      badge.textContent = ok ? "HEALTHY" : "DEGRADED";
      badge.style.color = ok ? "var(--green)" : "var(--amber)";
      badge.style.borderColor = ok ? "rgba(47,224,138,0.35)" : "rgba(255,181,69,0.35)";

      const rows = [
        ["Status", health.status],
        ["Database", health.database ? "reachable" : "unreachable"],
        ["Model", health.model ? "loaded" : (status.model_error || "not loaded")],
        ["Model name", status.model_name],
        ["Classes", status.classes.join(", ")],
        ["Training data", status.dataset],
        ["Traffic simulator", status.simulator ? "running" : "off"],
        ["Uptime", fmt.uptime(status.uptime_s)],
        ["Version", status.version]
      ];
      el("backend-info").innerHTML = rows.map(([k, v]) => `
        <div class="kv"><span class="k">${esc(k)}</span><span class="v mono">${esc(v)}</span></div>`).join("");

      el("conn-detail").innerHTML = status.dataset_note
        ? esc(status.dataset_note)
        : "Calls <code>/api/health</code> and reports exactly what comes back.";
    } catch (err) {
      badge.textContent = "UNREACHABLE";
      badge.style.color = "var(--red)";
      badge.style.borderColor = "rgba(255,80,100,0.35)";
      el("backend-info").innerHTML =
        `<div class="section-note">${esc(err.message)}</div>`;
    }
  }

  // ── collector keys ──────────────────────────────────────────────────────
  // The endpoints are admin-only, so the whole panel stays hidden for everyone
  // else rather than rendering and then 403-ing on click.
  async function initKeys() {
    if (state.user.role !== "admin") return;
    el("keys-panel").hidden = false;
    await paintKeys();

    el("btn-new-key").addEventListener("click", async () => {
      const label = prompt(
        "Name this key — something identifying the machine it will run on:",
        "collector"
      );
      if (label === null) return;

      const btn = el("btn-new-key");
      btn.disabled = true;
      try {
        const created = await api.createKey(label.trim() || "collector");
        // Revealed once. There is no second chance to read it, so it is shown
        // until the page is left rather than auto-hidden on a timer.
        el("new-key-value").textContent = created.key;
        el("new-key-reveal").hidden = false;
        await paintKeys();
        toast("Key created — copy it now.");
      } catch (err) {
        toast(err.message || "Could not create key.");
      } finally {
        btn.disabled = false;
      }
    });

    el("btn-copy-key").addEventListener("click", async () => {
      const value = el("new-key-value").textContent;
      try {
        await navigator.clipboard.writeText(value);
        toast("Copied to clipboard.");
      } catch {
        // Clipboard access needs a secure context, so it fails on plain-HTTP
        // hosts. Select the text instead so it can still be copied by hand.
        const range = document.createRange();
        range.selectNodeContents(el("new-key-value"));
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        toast("Select and copy manually.");
      }
    });
  }

  async function paintKeys() {
    const box = el("keys-list");
    try {
      const keys = await api.getKeys();
      if (!keys.length) {
        box.innerHTML = "No collector keys yet.";
        return;
      }
      box.innerHTML = keys.map((k) => {
        const used = k.last_used_at
          ? `last used ${new Date(k.last_used_at).toLocaleString()}`
          : "never used";
        const state_ = k.is_active
          ? `<span class="tag tag-benign">ACTIVE</span>`
          : `<span class="tag tag-ddos">REVOKED</span>`;
        return `
          <div class="kv" style="align-items:center">
            <span class="k">
              ${state_}
              <b style="margin-left:8px">${esc(k.label)}</b>
              <code style="margin-left:8px;font-size:11px">${esc(k.prefix)}…</code>
            </span>
            <span class="v">
              <span style="font-size:11px;color:var(--text-dim)">${esc(used)}</span>
              ${k.is_active
                ? `<button class="btn btn-sm" data-revoke="${k.id}" style="margin-left:10px">Revoke</button>`
                : ""}
            </span>
          </div>`;
      }).join("");

      box.querySelectorAll("[data-revoke]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.getAttribute("data-revoke");
          if (!confirm("Revoke this key? Any collector using it stops immediately.")) return;
          btn.disabled = true;
          try {
            await api.revokeKey(id);
            await paintKeys();
            toast("Key revoked.");
          } catch (err) {
            toast(err.message || "Could not revoke key.");
            btn.disabled = false;
          }
        });
      });
    } catch (err) {
      box.innerHTML = `<span style="color:var(--red)">${esc(err.message)}</span>`;
    }
  }

  el("btn-test").addEventListener("click", async () => {
    const btn = el("btn-test");
    btn.disabled = true;
    await checkBackend();
    btn.disabled = false;
    toast("Connection tested.");
  });
})();
