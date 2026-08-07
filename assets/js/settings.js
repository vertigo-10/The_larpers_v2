(function () {
  const cfg = window.SENTRY_CONFIG;
  const KEY = window.SENTRY_SETTINGS_KEY;
  const { icon, mountSidebar, toast } = window.SENTRY_UI;

  const el = (id) => document.getElementById(id);

  function load() {
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (_) {}

    el("in-api").value = cfg.apiBaseUrl || "";
    el("in-ws").value = cfg.wsUrl || "";
    el("in-mock").checked = cfg.useMockData;
    el("in-org").value = cfg.org;
    el("in-operator").value = cfg.operator.name;
    el("in-poll").value = String(cfg.pollIntervalMs);
    el("in-rows").value = String(cfg.maxTableRows);
    el("in-threshold").value = Math.round((saved.threshold ?? 0.85) * 100);
    el("threshold-out").textContent = (saved.threshold ?? 0.85).toFixed(2);
    el("in-auto").checked = saved.autoMitigate ?? true;
    el("in-webhook").value = saved.webhook || "";
    el("in-notify").checked = saved.notify ?? false;
    if (saved.severity) el("in-severity").value = saved.severity;
  }

  function collect() {
    return {
      apiBaseUrl: el("in-api").value.trim(),
      wsUrl: el("in-ws").value.trim(),
      useMockData: el("in-mock").checked,
      pollIntervalMs: Number(el("in-poll").value),
      maxTableRows: Number(el("in-rows").value),
      org: el("in-org").value.trim() || "Unnamed Org",
      operator: { ...cfg.operator, name: el("in-operator").value.trim() || cfg.operator.name },
      threshold: Number(el("in-threshold").value) / 100,
      autoMitigate: el("in-auto").checked,
      webhook: el("in-webhook").value.trim(),
      notify: el("in-notify").checked,
      severity: el("in-severity").value
    };
  }

  function save() {
    const next = collect();
    const name = next.operator.name.trim();
    next.operator.initials = name.split(/\s+/).map(w => w[0]).slice(0, 2).join("").toUpperCase() || "OP";
    localStorage.setItem(KEY, JSON.stringify(next));
    toast("Settings saved");
    setTimeout(() => location.reload(), 700);
  }

  async function testConnection() {
    const base = el("in-api").value.trim();
    const badge = el("conn-badge");
    const detail = el("conn-detail");

    if (!base) {
      badge.textContent = "No URL set";
      badge.className = "pill";
      detail.textContent = "Enter the base URL of your detection service first.";
      return;
    }

    badge.textContent = "Testing…";
    badge.className = "pill";

    try {
      const res = await fetch(`${base.replace(/\/$/, "")}/api/status`, { headers: { Accept: "application/json" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      badge.textContent = "Connected";
      badge.className = "pill live";
      detail.innerHTML = `Reached <code>${base}</code> — model <code>${data.model || "unknown"}</code>, framework <code>${data.framework || "n/a"}</code>.`;
      toast("Detection service reachable");
    } catch (err) {
      badge.textContent = "Unreachable";
      badge.className = "pill";
      badge.style.color = "var(--red)";
      detail.innerHTML = `Could not reach <code>${base}/api/status</code> — ${err.message}. Check the service is running and that CORS allows this origin.`;
      toast("Connection failed", "err");
    }
  }

  function exportConfig() {
    const blob = new Blob([JSON.stringify(collect(), null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sentry-settings.json";
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Configuration downloaded");
  }

  function init() {
    mountSidebar("settings");
    el("btn-save").innerHTML = `${icon("check", 12)} Save changes`;
    el("btn-reset").innerHTML = `${icon("refresh", 12)} Reset`;
    el("topbar-avatar").textContent = cfg.operator.initials;

    load();

    el("in-threshold").addEventListener("input", (e) => {
      el("threshold-out").textContent = (e.target.value / 100).toFixed(2);
    });

    el("btn-save").addEventListener("click", save);
    el("btn-test").addEventListener("click", testConnection);
    el("btn-export-cfg").addEventListener("click", exportConfig);

    el("btn-reset").addEventListener("click", () => {
      localStorage.removeItem(KEY);
      toast("Reset to defaults");
      setTimeout(() => location.reload(), 700);
    });

    el("in-notify").addEventListener("change", async (e) => {
      if (e.target.checked && "Notification" in window) {
        const perm = await Notification.requestPermission();
        if (perm !== "granted") {
          e.target.checked = false;
          toast("Notification permission denied", "err");
        }
      }
    });
  }

  init();
})();
