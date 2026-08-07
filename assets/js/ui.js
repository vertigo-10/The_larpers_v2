(function () {
  const cfg = window.SENTRY_CONFIG;
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
    arrowUp: `<path d="M12 20V4M5 11l7-7 7 7" ${S}/>`,
    arrowDown: `<path d="M12 4v16M5 13l7 7 7-7" ${S}/>`,
    info: `<circle cx="12" cy="12" r="9" ${S}/><path d="M12 11v5M12 8h.01" ${S}/>`,
    expand: `<path d="M4 9V4h5M20 15v5h-5M15 4h5v5M9 20H4v-5" ${S}/>`,
    plus: `<path d="M12 5v14M5 12h14" ${S}/>`,
    pencil: `<path d="m4 20 4-1 11-11a2 2 0 0 0-3-3L5 16z" ${S}/>`,
    text: `<path d="M4 6h16M9 6v14M15 12h5M17 12v8" ${S}/>`,
    cloud: `<path d="M6 18a4 4 0 0 1 .6-8 6 6 0 0 1 11.2 1.6A3.5 3.5 0 0 1 17.5 18z" ${S}/>`,
    camera: `<path d="M4 8h3l2-2h6l2 2h3v12H4z" ${S}/><circle cx="12" cy="13" r="3.2" ${S}/>`,
    filter: `<path d="M3 5h18l-7 8v6l-4 2v-8z" ${S}/>`,
    key: `<circle cx="8" cy="14" r="4" ${S}/><path d="m11 11 9-9 2 2-2 2 2 2-3 3-2-2-2 2" ${S}/>`,
    github: `<path d="M9 19c-4 1.5-4-2.5-6-3m12 5v-3.9a3.4 3.4 0 0 0-1-2.6c3.1-.3 6.4-1.5 6.4-7A5.4 5.4 0 0 0 19 3.8a5 5 0 0 0-.1-3.7S17.7-.2 15 1.6a13 13 0 0 0-6.9 0C5.4-.2 4.2.1 4.2.1a5 5 0 0 0-.1 3.7A5.4 5.4 0 0 0 2.6 7.6c0 5.4 3.3 6.6 6.4 7a3.4 3.4 0 0 0-1 2.5V21" ${S} transform="translate(0 2)"/>`
  };

  function icon(name, size) {
    const s = size || 16;
    return `<svg viewBox="0 0 24 24" width="${s}" height="${s}" aria-hidden="true">${ICONS[name] || ""}</svg>`;
  }

  const NAV = [
    {
      label: "Monitoring", key: "monitoring", icon: "radar", open: true, items: [
        { label: "Live Overview", href: "index.html", key: "dashboard", icon: "activity" },
        { label: "Threat Feed", href: "index.html#feed", key: "feed", icon: "alert" },
        { label: "Traffic Map", href: "index.html#map", key: "map", icon: "globe" }
      ]
    },
    {
      label: "Infrastructure", key: "infra", icon: "router", items: [
        { label: "Routers", href: "index.html#routers", key: "routers", icon: "router" },
        { label: "Subnets", href: "index.html#subnets", key: "subnets", icon: "globe" },
        { label: "Port Watch", href: "index.html#ports", key: "ports", icon: "lock" }
      ]
    },
    {
      label: "Model", key: "model", icon: "cpu", items: [
        { label: "Inference Log", href: "index.html#inference", key: "inference", icon: "activity" },
        { label: "Class Accuracy", href: "index.html#accuracy", key: "accuracy", icon: "chart" },
        { label: "Retraining", href: "index.html#retrain", key: "retrain", icon: "refresh" }
      ]
    },
    { label: "Reports", key: "reports", icon: "chart", items: [] }
  ];

  const FOOT_NAV = [
    { label: "Profile", href: "profile.html", key: "profile", icon: "user" },
    { label: "Settings", href: "settings.html", key: "settings", icon: "settings" },
    { label: "Documentation", href: "README.md", key: "docs", icon: "book" }
  ];

  function mountSidebar(activeKey) {
    const el = document.getElementById("sidebar");
    if (!el) return;

    const groups = NAV.map((g, gi) => {
      const hasActive = g.items.some(i => i.key === activeKey);
      const open = hasActive || g.open;
      const subs = g.items.map(i => `
        <a href="${i.href}" class="${i.key === activeKey ? "is-active" : ""}">
          ${icon(i.icon, 12)}<span>${i.label}</span>
        </a>`).join("");
      return `
        <div class="nav-group">
          <button class="nav-item ${open ? "open" : ""}" data-group="${gi}">
            ${icon(g.icon, 14)}<span>${g.label}</span>${g.items.length ? `<svg class="chev" viewBox="0 0 24 24">${ICONS.chevron}</svg>` : ""}
          </button>
          ${g.items.length ? `<div class="nav-sub ${open ? "open" : ""}" data-sub="${gi}">${subs}</div>` : ""}
        </div>`;
    }).join("");

    const foot = FOOT_NAV.map(i => `
      <a href="${i.href}" class="nav-item ${i.key === activeKey ? "active" : ""}">
        ${icon(i.icon, 14)}<span>${i.label}</span>
      </a>`).join("");

    el.innerHTML = `
      <div class="brand">
        <div class="brand-mark">${icon("shieldCheck", 17)}</div>
        <div>
          <div class="brand-name">SENTRY<span>NN</span></div>
          <div class="brand-sub">DDoS Detection</div>
        </div>
      </div>

      <div class="node-card">
        <div class="node-card-top">
          <div class="node-icon">${icon("cpu", 13)}</div>
          <div>
            <div class="node-label">${cfg.model.name}</div>
            <div class="node-delta" id="sb-accuracy">▲ ${cfg.model.accuracy}% acc</div>
          </div>
        </div>
        <div class="node-value" id="sb-flows">12,480<small>flows / min</small></div>
      </div>

      <div class="search">
        ${icon("search", 13)}
        <input type="text" placeholder="Search IP, port, node…" />
      </div>

      ${groups}
      <div class="nav-divider"></div>
      <div class="nav-label">Workspace</div>
      <a href="index.html" class="nav-item ${activeKey === "dashboard" ? "active" : ""}">${icon("home", 14)}<span>Dashboard</span></a>
      ${foot}
      <div class="nav-divider"></div>
      <div style="padding:8px 10px;font-size:10.5px;color:#4d5a60;line-height:1.6">
        <div style="display:flex;align-items:center;gap:6px">
          <span class="dot pulse"></span><span id="sb-source">Mock data stream</span>
        </div>
        <div style="margin-top:4px">${cfg.org}</div>
      </div>`;

    el.querySelectorAll("[data-group]").forEach(btn => {
      btn.addEventListener("click", () => {
        const sub = el.querySelector(`[data-sub="${btn.dataset.group}"]`);
        if (!sub) return;
        btn.classList.toggle("open");
        sub.classList.toggle("open");
      });
    });

    const src = document.getElementById("sb-source");
    if (src && window.SENTRY_API.isLive()) src.textContent = "Live model stream";
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
    el.innerHTML = `${icon(kind === "err" ? "alert" : "check", 15)}<span>${msg}</span>`;
    requestAnimationFrame(() => el.classList.add("show"));
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove("show"), 2600);
  }

  const fmt = {
    num: (n, d = 0) => Number(n).toLocaleString("en-US", { minimumFractionDigits: d, maximumFractionDigits: d }),
    bytes(n) {
      if (n >= 1e9) return (n / 1e9).toFixed(2) + " GB/s";
      if (n >= 1e6) return (n / 1e6).toFixed(2) + " MB/s";
      if (n >= 1e3) return (n / 1e3).toFixed(1) + " KB/s";
      return Math.round(n) + " B/s";
    },
    time(ts) {
      const d = new Date(ts);
      return d.toLocaleTimeString("en-GB", { hour12: false });
    },
    dur(s) { return s < 1 ? `${(s * 1000).toFixed(0)} ms` : `${s.toFixed(2)} s`; },
    uptime(sec) {
      const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
      return `${d}d ${h}h ${m}m`;
    }
  };

  window.SENTRY_UI = { icon, mountSidebar, toast, fmt, ICONS };
})();
