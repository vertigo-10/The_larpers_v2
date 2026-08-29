/**
 * Shared UI: icons, sidebar, toasts, formatters, escaping.
 *
 * SECURITY NOTE — escapeHtml() is not decoration. Flow fields such as src_ip and
 * node arrive from whatever posts to /api/ingest, which in a real deployment is
 * network data an attacker can influence. Interpolating them into innerHTML
 * unescaped is a stored-XSS vector. Every value rendered into markup goes
 * through esc().
 */
(function () {
  const S = 'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" fill="none"';

  const ICONS = {
    shield: `<path d="M12 2 4 5.5v6c0 4.6 3.2 8.9 8 10.5 4.8-1.6 8-5.9 8-10.5v-6z" ${S}/>`,
    shieldCheck: `<path d="M12 2 4 5.5v6c0 4.6 3.2 8.9 8 10.5 4.8-1.6 8-5.9 8-10.5v-6z" ${S}/><path d="m9 12 2 2 4-4" ${S}/>`,
    search: `<circle cx="11" cy="11" r="7" ${S}/><path d="m20 20-3.5-3.5" ${S}/>`,
    chevron: `<path d="m6 9 6 6 6-6" ${S}/>`,
    activity: `<path d="M3 12h4l3 8 4-16 3 8h4" ${S}/>`,
    radar: `<circle cx="12" cy="12" r="9" ${S}/><circle cx="12" cy="12" r="4" ${S}/><path d="M12 12 19 6" ${S}/>`,
    router: `<rect x="3" y="13" width="18" height="8" rx="2" ${S}/><path d="M7 17h.01M11 17h.01M12 9V6M8 9 6 6M16 9l2-3" ${S}/>`,
    alert: `<path d="M12 3 2 20h20z" ${S}/><path d="M12 10v4M12 17h.01" ${S}/>`,
    chart: `<path d="M4 20V10M10 20V4M16 20v-7M22 20H2" ${S}/>`,
    settings: `<circle cx="12" cy="12" r="3" ${S}/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-2.7 1.1V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 7 19.4l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1A1.6 1.6 0 0 0 3 14a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 4.6 7l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1A1.6 1.6 0 0 0 10 3.1V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 2.7 1.1l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8" ${S}/>`,
    user: `<circle cx="12" cy="8" r="4" ${S}/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6" ${S}/>`,
    users: `<circle cx="9" cy="8" r="3.5" ${S}/><path d="M2 21c1.2-3.5 3.8-5.5 7-5.5s5.8 2 7 5.5" ${S}/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 21c-.4-1.6-1-3-1.9-4.1" ${S}/>`,
    home: `<path d="m3 10 9-7 9 7v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" ${S}/>`,
    book: `<path d="M4 4.5A2.5 2.5 0 0 1 6.5 2H20v18H6.5A2.5 2.5 0 0 0 4 22z" ${S}/>`,
    bell: `<path d="M18 9a6 6 0 1 0-12 0c0 5-2 6-2 6h16s-2-1-2-6" ${S}/><path d="M10.5 20a2 2 0 0 0 3 0" ${S}/>`,
    zap: `<path d="M13 2 4 14h7l-1 8 9-12h-7z" ${S}/>`,
    cpu: `<rect x="6" y="6" width="12" height="12" rx="2" ${S}/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" ${S}/>`,
    globe: `<circle cx="12" cy="12" r="9" ${S}/><path d="M3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18" ${S}/>`,
    lock: `<rect x="4" y="10" width="16" height="11" rx="2" ${S}/><path d="M8 10V7a4 4 0 0 1 8 0v3" ${S}/>`,
    download: `<path d="M12 3v12M7 11l5 5 5-5M4 20h16" ${S}/>`,
    refresh: `<path d="M3 12a9 9 0 0 1 15.5-6.2L21 8M21 3v5h-5M21 12a9 9 0 0 1-15.5 6.2L3 16M3 21v-5h5" ${S}/>`,
    check: `<path d="m4 12 5 5L20 6" ${S}/>`,
    x: `<path d="M6 6l12 12M18 6 6 18" ${S}/>`,
    arrowUp: `<path d="M12 20V4M5 11l7-7 7 7" ${S}/>`,
    arrowDown: `<path d="M12 4v16M5 13l7 7 7-7" ${S}/>`,
    info: `<circle cx="12" cy="12" r="9" ${S}/><path d="M12 11v5M12 8h.01" ${S}/>`,
    expand: `<path d="M4 9V4h5M20 15v5h-5M15 4h5v5M9 20H4v-5" ${S}/>`,
    plus: `<path d="M12 5v14M5 12h14" ${S}/>`,
    trash: `<path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13" ${S}/>`,
    pencil: `<path d="m4 20 4-1 11-11a2 2 0 0 0-3-3L5 16z" ${S}/>`,
    filter: `<path d="M3 5h18l-7 8v6l-4 2v-8z" ${S}/>`,
    camera: `<path d="M4 8h3l2-2h6l2 2h3v12H4z" ${S}/><circle cx="12" cy="13" r="3.2" ${S}/>`,
    logout: `<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" ${S}/><path d="M10 8 6 12l4 4M6 12h11" ${S}/>`,
    file: `<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" ${S}/><path d="M14 3v5h5M9 13h6M9 17h4" ${S}/>`,
    key: `<circle cx="8" cy="14" r="4" ${S}/><path d="m11 11 9-9 2 2-2 2 2 2-3 3-2-2-2 2" ${S}/>`
  };

  function icon(name, size) {
    const s = size || 16;
    return `<svg viewBox="0 0 24 24" width="${s}" height="${s}" aria-hidden="true">${ICONS[name] || ""}</svg>`;
  }

  /** Escape a value for safe interpolation into HTML. */
  function esc(value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Every entry here is a page that exists and works.
  //
  // `only` restricts an entry to one account type. It is presentation, not
  // permission — the pages themselves check, and the API checks under them.
  // What it buys is that a household is not handed a nav full of screens built
  // for a security rota it does not have.
  const NAV = [
    {
      label: "Monitoring", key: "monitoring", icon: "radar", open: true, items: [
        { label: "Home", href: "home-index.html", key: "home",
          icon: "home", only: "consumer" },
        { label: "Live Overview", href: "index.html", key: "dashboard",
          icon: "activity", only: "company" },
        { label: "Alerts & Incidents", href: "alerts.html", key: "alerts",
          icon: "alert", only: "company" },
        { label: "Alerts", href: "home-alerts.html", key: "alerts",
          icon: "alert", only: "consumer" },
        { label: "Traffic Analysis", href: "traffic.html", key: "traffic",
          icon: "globe", only: "company" },
        { label: "Baseline & Anomalies", href: "baseline.html", key: "baseline",
          icon: "chart", only: "company" },
        { label: "Network Nodes", href: "nodes.html", key: "nodes",
          icon: "router", only: "company" },
        { label: "My Devices", href: "home-devices.html", key: "nodes",
          icon: "router", only: "consumer" }
      ]
    },
    {
      label: "Analysis", key: "analysis", icon: "chart", open: true, items: [
        // Detection tuning is a job someone owns in a company. In a household
        // there is nobody to own it, and exposing a threshold slider next to a
        // confusion matrix invites breaking detection by fiddling.
        { label: "Model Performance", href: "model.html", key: "model",
          icon: "cpu", feature: "model_tuning" },
        { label: "Reports", href: "reports.html", key: "reports",
          icon: "file", only: "company" }
      ]
    }
  ];

  /**
   * Where an account belongs after signing in.
   *
   * One function, called from the auth pages and from the page guard below, so
   * "which dashboard is yours" is answered in exactly one place. Two copies of
   * this rule would eventually disagree, and the failure mode is a household
   * staring at an enterprise incident console.
   */
  function landingFor(user) {
    return user && user.org_type === "consumer" ? "home-index.html" : "index.html";
  }

  /**
   * Best guess at the reader's dashboard before /api/me has answered.
   *
   * The sidebar is drawn immediately so the page does not flash an empty rail,
   * which means the brand link needs an href a beat before the account type is
   * known. Scoped pages already declare who they are for, so those are exact.
   * The three shared pages — profile, team, settings — do not, and fall back to
   * the enterprise dashboard; a household clicking through in that window is
   * bounced to their own by the scope guard, so the worst case is one extra
   * redirect, not a wrong destination. The href is corrected below as soon as
   * the real answer arrives.
   */
  function scopedLanding() {
    return landingFor({ org_type: document.body.getAttribute("data-org-scope") });
  }

  const FOOT_NAV = [
    { label: "Profile", href: "profile.html", key: "profile", icon: "user" },
    { label: "Team", href: "team.html", key: "team", icon: "users" },
    { label: "Settings", href: "settings.html", key: "settings", icon: "settings" },
    { label: "Documentation", href: "https://github.com/vertigo-10/The_larpers_v2#readme", key: "docs", icon: "book", external: true }
  ];

  /**
   * The company/consumer choice made at signup is not cosmetic everywhere,
   * but in the shared chrome it mostly is: same pages, same permissions,
   * different words for who's using it. Centralized here so every page pulls
   * from one source rather than each hand-rolling its own copy branch.
   */
  const ORG_COPY = {
    company: {
      teamNav: "Team",
      nodesTitle: "Network Nodes",
      nodesCrumb: "monitored links",
      nodesNotice: "Nodes are the collection points flows are attributed to. " +
        "Throughput and attack counts cover the last five minutes. A node " +
        "turns amber once more than eight flagged flows arrive from it in " +
        "that window.",
      teamTitle: "Team",
      teamCrumb: "organisation",
      teamNotice: "<b>Admin</b> changes settings and manages the team. " +
        "<b>Analyst</b> can mitigate and work incidents. <b>Viewer</b> can " +
        "read everything and change nothing. Members only ever see data " +
        "belonging to this organisation.",
      settingsTitle: "Organisation",
      settingsNameLabel: "Organisation name",
      settingsNameDesc: "Shown across the dashboard and on exported reports.",
      settingsScope: "Settings in <b>Detection</b> and <b>Alerting</b> are shared " +
        "by everyone in your organisation. <b>Display</b> settings are stored in " +
        "this browser only."
    },
    consumer: {
      teamNav: "Household",
      nodesTitle: "My Devices",
      nodesCrumb: "things on your network",
      nodesNotice: "Each entry is a device or group of devices your traffic " +
        "is attributed to — starting with your router. Point the collector " +
        "at a device and it appears here automatically the first time it " +
        "sends traffic. A device turns amber once more than eight flagged " +
        "flows arrive from it in five minutes.",
      teamTitle: "Household",
      teamCrumb: "household",
      teamNotice: "<b>Admin</b> changes settings and manages who's in the " +
        "household. <b>Analyst</b> can mitigate and work incidents. " +
        "<b>Viewer</b> can read everything and change nothing. Everyone " +
        "here only ever sees this household's own data.",
      settingsTitle: "Household",
      settingsNameLabel: "Household name",
      settingsNameDesc: "Shown across the top of every page.",
      settingsScope: "Settings in <b>Detection</b> and <b>Alerting</b> apply to " +
        "everyone in your household. <b>Display</b> settings are stored in this " +
        "browser only."
    }
  };

  /** Copy for the given org type, falling back to the company wording. */
  function orgCopy(orgType) {
    return ORG_COPY[orgType] || ORG_COPY.company;
  }

  /**
   * Drop nav groups left with nothing in them.
   *
   * Called from both gate passes rather than one, because they remove
   * different things: `only:` entries go in applyOrgProfile and `feature:`
   * entries in applyFeatureGates. Pruning after only the first left the
   * consumer sidebar with an "Analysis" header that opened onto nothing —
   * its last child was feature-gated and had not been removed yet.
   */
  function pruneEmptyNavGroups() {
    document.querySelectorAll(".nav-group").forEach((group) => {
      if (!group.querySelector(".nav-sub a")) group.remove();
    });
  }

  /** Relabel the parts of the shared chrome that read differently per org type. */
  function applyOrgProfile(orgType) {
    const copy = orgCopy(orgType);
    const type = orgType || "company";
    document.body.setAttribute("data-org-type", type);

    // Drop nav entries belonging to the other account type. Removed rather
    // than hidden, for the same reason as the feature gates: an inert control
    // left in the tree is how a hidden link eventually gets mistaken for a
    // permission.
    document.querySelectorAll("[data-org-only]").forEach((el) => {
      if (el.getAttribute("data-org-only") !== type) el.remove();
    });
    pruneEmptyNavGroups();

    // Only the team link needs relabelling now. Nodes and alerts are separate
    // NAV entries per account type, each already carrying its own wording, so
    // rewriting their text here would be a no-op that reads like it does work.
    const teamLink = document.querySelector('.nav-item[href="team.html"] span');
    if (teamLink) teamLink.textContent = copy.teamNav;
  }

  /**
   * Hide anything this account type does not have.
   *
   * Markup opts in with `data-requires-feature="name"`, so adding a gated
   * element is a one-attribute change and no new branch here. `data-feature-*`
   * attributes on <body> additionally let CSS react without any JS.
   *
   * Removed from the DOM rather than merely `display:none`, because a hidden
   * control is still tabbable, still reachable by a querySelector, and still
   * looks to a reader like it might be the security boundary. It is not — the
   * API enforces the same table — but leaving inert controls in the tree is
   * how a hidden button eventually gets mistaken for a permission.
   */
  function applyFeatureGates(featureMap) {
    if (!featureMap) return;
    Object.keys(featureMap).forEach((name) => {
      document.body.setAttribute(
        `data-feature-${name.replace(/_/g, "-")}`,
        featureMap[name] ? "on" : "off"
      );
    });
    document.querySelectorAll("[data-requires-feature]").forEach((el) => {
      const needed = el.getAttribute("data-requires-feature");
      if (!featureMap[needed]) el.remove();
    });
    pruneEmptyNavGroups();
  }

  function mountSidebar(activeKey) {
    const el = document.getElementById("sidebar");
    if (!el) return;

    const groups = NAV.map((g, gi) => {
      const hasActive = g.items.some((i) => i.key === activeKey);
      const open = hasActive || g.open;
      const subs = g.items.map((i) => `
        <a href="${i.href}" class="${i.key === activeKey ? "is-active" : ""}"
           ${i.feature ? `data-requires-feature="${esc(i.feature)}"` : ""}
           ${i.only ? `data-org-only="${esc(i.only)}"` : ""}>
          ${icon(i.icon, 12)}<span>${esc(i.label)}</span>
        </a>`).join("");
      return `
        <div class="nav-group">
          <button class="nav-item ${open ? "open" : ""}" data-group="${gi}">
            ${icon(g.icon, 14)}<span>${esc(g.label)}</span>
            <svg class="chev" viewBox="0 0 24 24">${ICONS.chevron}</svg>
          </button>
          <div class="nav-sub ${open ? "open" : ""}" data-sub="${gi}">${subs}</div>
        </div>`;
    }).join("");

    const foot = FOOT_NAV.map((i) => `
      <a href="${i.href}" class="nav-item ${i.key === activeKey ? "active" : ""}"
         ${i.external ? 'target="_blank" rel="noopener noreferrer"' : ""}>
        ${icon(i.icon, 14)}<span>${esc(i.label)}</span>
      </a>`).join("");

    el.innerHTML = `
      <a class="brand" id="sb-brand" href="${esc(scopedLanding())}"
         title="Back to the dashboard">
        <div class="brand-mark">${icon("shieldCheck", 17)}</div>
        <div>
          <div class="brand-name">SENTRY<span>NN</span></div>
          <div class="brand-sub">Threat Detection</div>
        </div>
      </a>

      <div class="node-card">
        <div class="node-card-top">
          <div class="node-icon">${icon("cpu", 13)}</div>
          <div>
            <div class="node-label" id="sb-model">loading…</div>
            <div class="node-delta" id="sb-accuracy">&nbsp;</div>
          </div>
        </div>
        <div class="node-value" id="sb-flows">—<small>flows / min</small></div>
      </div>

      <div class="search">
        ${icon("search", 13)}
        <input type="text" id="sb-search" placeholder="Search IP, port, node…"
               autocomplete="off" spellcheck="false" />
      </div>

      ${groups}
      <div class="nav-divider"></div>
      <div class="nav-label">Workspace</div>
      ${foot}
      <div class="nav-divider"></div>
      <button class="nav-item" id="sb-logout">${icon("logout", 14)}<span>Sign out</span></button>
      <div style="padding:8px 10px;font-size:10.5px;color:#4d5a60;line-height:1.6">
        <div style="display:flex;align-items:center;gap:6px">
          <span class="dot" id="sb-dot"></span><span id="sb-source">Connecting…</span>
        </div>
        <div style="margin-top:4px" id="sb-org">&nbsp;</div>
      </div>`;

    el.querySelectorAll("[data-group]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const sub = el.querySelector(`[data-sub="${btn.dataset.group}"]`);
        if (!sub) return;
        btn.classList.toggle("open");
        sub.classList.toggle("open");
      });
    });

    const logout = document.getElementById("sb-logout");
    if (logout) {
      logout.addEventListener("click", async () => {
        try { await window.SENTRY_API.logout(); } catch (_) {}
        window.location.href = "login.html";
      });
    }

    // Sidebar search jumps to the dashboard with the query applied, so it works
    // from any page.
    const search = document.getElementById("sb-search");
    if (search) {
      search.addEventListener("keydown", (e) => {
        if (e.key !== "Enter") return;
        const q = search.value.trim();
        if (!q) return;
        if (window.SENTRY_ON_SEARCH) window.SENTRY_ON_SEARCH(q);
        else window.location.href = `index.html?q=${encodeURIComponent(q)}`;
      });
    }

    hydrateSidebar();
  }

  /** Fill the sidebar with real values from the API. */
  async function hydrateSidebar() {
    const api = window.SENTRY_API;
    if (!api) return;
    try {
      const [status, user, featureSet] = await Promise.all([
        api.getStatus(), api.me(), api.features(),
      ]);
      const model = document.getElementById("sb-model");
      const acc = document.getElementById("sb-accuracy");
      const org = document.getElementById("sb-org");

      // A page can declare which account type it is written for. Landing on
      // the wrong one is not a security failure — every endpoint behind it is
      // scoped and gated independently — but a household dropped into the
      // enterprise incident console has no idea what it is looking at.
      // `replace` rather than `href` so the back button does not bounce them
      // straight back into it.
      const scope = document.body.getAttribute("data-org-scope");
      if (scope && user.org_type && scope !== user.org_type) {
        window.location.replace(landingFor(user));
        return;
      }

      // Now the account type is known for certain, so the brand link can stop
      // guessing. Matters on the three unscoped pages, where the guess above is
      // the enterprise dashboard regardless of who is reading.
      const brand = document.getElementById("sb-brand");
      if (brand) brand.setAttribute("href", landingFor(user));

      if (model) model.textContent = status.model_name || "model";
      if (org) org.textContent = user.org_name || "";
      applyOrgProfile(user.org_type);
      applyFeatureGates(featureSet && featureSet.features);

      if (acc) {
        if (!status.model_ready) {
          acc.textContent = "model unavailable";
          acc.style.color = "var(--red)";
        } else if (typeof status.accuracy === "number") {
          // Always paired with the dataset, so the number is never read as a
          // real-world claim.
          acc.textContent =
            `${status.accuracy}% on ${status.dataset_label || status.dataset}`;
          acc.title = status.dataset_note || "";
        } else {
          acc.textContent = "not evaluated";
        }
      }
    } catch (err) {
      if (err && err.status === 401) return; // redirect already in flight
      const src = document.getElementById("sb-source");
      if (src) src.textContent = "Backend unreachable";
    }

    // Keep flows/min fresh
    const tick = async () => {
      try {
        const s = await api.getSummary();
        const flows = document.getElementById("sb-flows");
        if (flows) flows.innerHTML = `${fmt.num(s.flows_per_min)}<small>flows / min</small>`;
      } catch (_) { /* surfaced elsewhere */ }
    };
    tick();
    setInterval(tick, 10000);
  }

  /** Reflect live-stream state in the sidebar footer. */
  function setStreamState(connected) {
    const dot = document.getElementById("sb-dot");
    const src = document.getElementById("sb-source");
    if (dot) dot.className = connected ? "dot pulse" : "dot";
    if (dot) dot.style.background = connected ? "" : "var(--red)";
    if (src) src.textContent = connected ? "Live stream connected" : "Stream disconnected";
  }

  let toastTimer;
  function toast(msg, kind) {
    let el = document.querySelector(".toast");
    if (!el) {
      el = document.createElement("div");
      el.className = "toast";
      document.body.appendChild(el);
    }
    el.className = `toast ${kind === "err" ? "err" : ""}`;
    el.innerHTML = `${icon(kind === "err" ? "alert" : "check", 15)}<span>${esc(msg)}</span>`;
    requestAnimationFrame(() => el.classList.add("show"));
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 3200);
  }

  /** Coarse magnitude of a millisecond gap, without a direction on it. */
  function span(ms) {
    const s = Math.max(0, ms / 1000);
    if (s < 60) return `${Math.floor(s)}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    if (s < 86400) return `${Math.floor(s / 3600)}h`;
    return `${Math.floor(s / 86400)}d`;
  }

  const fmt = {
    num: (n, d = 0) =>
      Number(n || 0).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d }),
    bytes(n) {
      n = Number(n) || 0;
      if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB/s";
      if (n >= 1e6) return (n / 1e6).toFixed(2) + " MB/s";
      if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB/s";
      return Math.round(n) + " B/s";
    },
    /** An absolute volume, as opposed to `bytes`, which is a rate. */
    size(n) {
      n = Number(n) || 0;
      if (n >= 1e12) return (n / 1e12).toFixed(2) + " TB";
      if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB";
      if (n >= 1e6) return (n / 1e6).toFixed(2) + " MB";
      if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB";
      return Math.round(n) + " B";
    },
    time(ts) {
      return new Date(ts).toLocaleTimeString("en-GB", { hour12: false });
    },
    datetime(ts) {
      const d = new Date(ts);
      return `${d.toLocaleDateString("en-GB")} ${d.toLocaleTimeString("en-GB", { hour12: false })}`;
    },
    ago(ts) {
      return `${span(Date.now() - ts)} ago`;
    },
    /**
     * Counterpart to `ago` for a time that has not arrived yet, such as an
     * invite expiry. `ago` clamps a negative gap to zero, so pointing it at a
     * future timestamp reports every still-valid credential as "0s" — which
     * reads as already expired, the opposite of the truth.
     */
    until(ts) {
      return `${span(ts - Date.now())} from now`;
    },
    dur(s) {
      s = Number(s) || 0;
      return s < 1 ? `${(s * 1000).toFixed(0)} ms` : `${s.toFixed(2)} s`;
    },
    uptime(sec) {
      sec = Number(sec) || 0;
      const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
      return `${d}d ${h}h ${m}m`;
    }
  };

  /** Presentation metadata for a predicted class, tolerant of unknown labels. */
  function classMeta(label) {
    return (
      window.SENTRY_CLASSES[label] || {
        label: label, short: String(label || "?").toUpperCase(),
        color: "#6d7d85", tag: "warn", benign: false
      }
    );
  }

  function severityMeta(sev) {
    return window.SENTRY_SEVERITY[sev] || { label: sev, color: "#6d7d85" };
  }

  /** Full-page error state — used when the API cannot be reached at all. */
  function fatalBanner(message) {
    let bar = document.getElementById("sentry-fatal");
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "sentry-fatal";
      bar.className = "fatal-bar";
      document.body.prepend(bar);
    }
    bar.innerHTML = `${icon("alert", 14)}<span>${esc(message)}</span>`;
  }

  function clearFatal() {
    const bar = document.getElementById("sentry-fatal");
    if (bar) bar.remove();
  }

  // One entry per class the model can actually predict, and nothing else. A
  // friendly line for a label that cannot occur reads as coverage the product
  // does not have; unknown labels fall through to the honest default below.
  //
  // Lives here rather than on the home page because all three consumer screens
  // describe the same incidents. Two copies would eventually word the same
  // detection differently on two pages, and a household comparing them has no
  // way to tell which one is the real answer.
  const PLAIN_CLASS = {
    dos_ddos: {
      what: "A device was flooded with traffic",
      sub: "Something sent far more connections than normal, which is how an " +
           "attempt to knock a device offline looks."
    },
    scan: {
      what: "Something was probing your network",
      sub: "A device went door-to-door looking for open ports. On its own it " +
           "is not damage, but it is usually what comes first."
    }
  };

  function plainClass(label) {
    return PLAIN_CLASS[label] || {
      what: "Unusual activity",
      sub: "This did not match how your network normally behaves."
    };
  }

  /**
   * Whether an incident is finished with, from the reader's point of view.
   *
   * Shared for the same reason as the copy above: the home banner and the event
   * list once disagreed, which put a red "6 things need your attention"
   * directly over six rows each marked "Dealt with". A home user who is told to
   * act, looks, and finds nothing to do learns to stop reading the banner.
   */
  const isHandled = (i) => i.status === "resolved" || Boolean(i.mitigated);
  const isSerious = (i) => i.severity === "critical" || i.severity === "high";

  /**
   * The one sentence at the top of a consumer page.
   *
   * Ordered worst-first, and the reason is always stated: "you're fine" with
   * nothing behind it is indistinguishable from a broken page, which is the
   * failure this product least wants to have.
   *
   * Shared by home and alerts. Someone who reads a red banner and clicks
   * through to see the detail must not be met by a calmer sentence computed a
   * different way — the discrepancy teaches them that one of the two screens is
   * lying, and they have no way to tell which.
   *
   * Expects the standard hero markup: #hero, #hero-ring, #hero-line, #hero-why.
   */
  function renderVerdict(summary, incidents) {
    const outstanding = incidents.filter((i) => !isHandled(i));
    const serious = outstanding.filter(isSerious);
    const handledSerious = incidents.filter((i) => isHandled(i) && isSerious(i));
    const hero = document.getElementById("hero");
    let tone, mark, line, why;

    if (serious.length) {
      tone = "is-bad";
      mark = "alert";
      // Says "serious" out loud because this counts only the critical and high
      // ones, while the list underneath counts everything still outstanding.
      // Without the word, the alerts page shows two different totals for what
      // reads as the same sentence and the reader cannot tell which to believe.
      line = serious.length === 1
        ? "Something serious needs your attention"
        : `${serious.length} serious things need your attention`;
      why = "A device on your network is behaving the way an attack does. " +
            "Open the alert below to see what it was and block it.";
    } else if (outstanding.length) {
      tone = "is-warn";
      mark = "alert";
      line = "Worth a look, but nothing urgent";
      why = `${outstanding.length} thing${outstanding.length === 1 ? "" : "s"} ` +
            `looked unusual and ${outstanding.length === 1 ? "has" : "have"} not ` +
            `been dealt with yet. Nothing has been rated serious.`;
    } else if (!summary.flows_per_min) {
      // Told apart from "safe" on purpose. No traffic means nothing is being
      // checked, and reporting that as green would be the single most
      // misleading thing this page could do.
      tone = "is-warn";
      mark = "info";
      line = "Not seeing any traffic";
      why = "Nothing has been checked in the last minute, so this is not a " +
            "clean bill of health — it means the collector is not sending. " +
            "Check that it is running.";
    } else if (handledSerious.length) {
      // Green, because nothing is waiting on the reader — but it would be a lie
      // to say the network "looks fine" on a day something tried to knock a
      // device offline and got stopped. They should know it happened.
      tone = "is-ok";
      mark = "shieldCheck";
      line = "Handled without you";
      why = `${handledSerious.length} serious thing${handledSerious.length === 1 ? "" : "s"} ` +
            `happened recently and ${handledSerious.length === 1 ? "was" : "were"} ` +
            `blocked automatically. Nothing is waiting on you — the details are below.`;
    } else {
      tone = "is-ok";
      mark = "shieldCheck";
      line = "Your network looks fine";
      why = `Everything crossing your router in the last minute was checked ` +
            `and came back normal. ${fmt.num(summary.attacks_blocked)} ` +
            `thing${summary.attacks_blocked === 1 ? " has" : "s have"} been ` +
            `blocked in total.`;
    }

    hero.className = `home-hero ${tone}`;
    document.getElementById("hero-ring").innerHTML = icon(mark, 28);
    document.getElementById("hero-line").textContent = line;
    document.getElementById("hero-why").textContent = why;
  }

  /**
   * Record a decision to block a source, and be honest about what that buys.
   *
   * SENTRY reads a feed of flows. It does not sit in the path of the traffic
   * and has no route to the router, so it cannot drop a packet. The API says so
   * itself — /api/mitigate returns `enforced: false` and a note about wiring up
   * an enforcement hook, and its docstring is explicit that it "does not pretend
   * to have blocked traffic it cannot reach".
   *
   * A consumer button that said "Blocked" and stopped there would be the most
   * dangerous copy in this product: someone reads it, believes the thing is
   * stopped, and stops looking. So the boundary is stated before the click and
   * the address that still needs blocking is repeated after it.
   *
   * The `enforced` flag is read back rather than assumed, so that connecting a
   * real enforcement hook later upgrades this wording on its own instead of
   * leaving the product permanently under-claiming what it does.
   */
  async function blockSource(srcIp) {
    const proceed = window.confirm(
      `Block ${srcIp}?\n\n` +
      `SENTRY will mark everything from this address as dealt with, and it ` +
      `will stop counting against your network's status.\n\n` +
      `It cannot cut the connection itself — SENTRY watches your traffic, it ` +
      `does not sit in the middle of it. To actually stop this, block ${srcIp} ` +
      `in your router's settings.`
    );
    if (!proceed) return false;

    const res = await window.SENTRY_API.mitigate(null, srcIp);
    const n = res.count || 0;
    toast(
      res.enforced
        ? `Blocked ${srcIp} at the network edge.`
        : `Marked ${n} connection${n === 1 ? "" : "s"} from ${srcIp} as dealt ` +
          `with. Block it on your router to stop it for real.`,
      "ok"
    );
    return true;
  }

  window.SENTRY_UI = {
    icon, esc, mountSidebar, setStreamState, toast, fmt,
    classMeta, severityMeta, fatalBanner, clearFatal, ICONS,
    orgCopy, applyOrgProfile, applyFeatureGates, landingFor,
    plainClass, isHandled, isSerious, renderVerdict, blockSource
  };
})();
