/**
 * Alerts & Incidents.
 *
 * An incident is a correlated group of flagged flows from one source, so this
 * page is where an operator actually works: acknowledge, mitigate, resolve.
 * Every action is attributed server-side to the signed-in user and written to
 * the audit log — see Team → Audit trail.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt, toast, classMeta, severityMeta } = ui;
  const el = (id) => document.getElementById(id);

  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

  const state = { incidents: [], status: "all", user: null, query: "" };

  ui.mountSidebar("alerts");
  el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;
  el("btn-export").innerHTML = `${icon("download", 12)} Export`;
  el("ico-notice").innerHTML = icon("info", 15);

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    state.user = await api.me();
    el("topbar-avatar").textContent = state.user.initials || "··";
    el("topbar-avatar").title = `${state.user.name} · ${state.user.role}`;
    await load();

    // New flagged flows can open or extend an incident, so refresh on the live
    // feed rather than making the operator press Refresh.
    api.on("flow", (f) => {
      if (!classMeta(f.prediction).benign) scheduleReload();
    });
    api.on("status", ui.setStreamState);
    api.connectStream();

    setInterval(load, 30000);
  }

  let reloadTimer;
  function scheduleReload() {
    clearTimeout(reloadTimer);
    reloadTimer = setTimeout(load, 2500); // coalesce bursts
  }

  async function load() {
    try {
      state.incidents = await api.getIncidents(state.status, 200);
      render();
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load incidents.");
    }
  }

  function render() {
    renderStats();
    renderTable();
  }

  function renderStats() {
    const all = state.incidents;
    const count = (fn) => all.filter(fn).length;
    const cards = [
      { k: "Shown", v: fmt.num(all.length), d: `status: ${state.status}`, cls: "" },
      { k: "Critical", v: fmt.num(count((i) => i.severity === "critical")),
        d: "highest confidence + volume", cls: count((i) => i.severity === "critical") ? "down" : "up" },
      { k: "Unacknowledged", v: fmt.num(count((i) => i.status === "open")),
        d: "nobody has picked these up", cls: count((i) => i.status === "open") ? "down" : "up" },
      { k: "Mitigated", v: fmt.num(count((i) => i.mitigated)), d: "marked for blocking", cls: "up" }
    ];
    el("stat-strip").innerHTML = cards.map((c) => `
      <div class="stat">
        <div class="k">${esc(c.k)}</div>
        <div class="v ${c.cls}">${esc(c.v)}</div>
        <div class="d dim">${esc(c.d)}</div>
      </div>`).join("");
  }

  function renderTable() {
    const body = el("inc-body");
    let rows = state.incidents.slice();

    if (state.query) {
      const q = state.query.toLowerCase();
      rows = rows.filter((i) =>
        `${i.src_ip} ${i.node} ${i.label} ${i.severity}`.toLowerCase().indexOf(q) !== -1);
    }

    // Worst first, then most recent — an operator reads top-down.
    rows.sort((a, b) =>
      (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || (b.last_seen_at - a.last_seen_at));

    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="11" class="empty-state">${
        state.query
          ? `No incidents match “${esc(state.query)}”.`
          : "No incidents. Nothing the model flagged has correlated into one yet."
      }</td></tr>`;
      return;
    }

    const canAct = state.user.role !== "viewer";

    body.innerHTML = rows.map((i) => {
      const sev = severityMeta(i.severity);
      const cls = classMeta(i.label);
      return `
        <tr>
          <td>
            <div class="flow-cell">
              <span class="sev-dot" style="background:${sev.color}"></span>
              <span style="color:${sev.color};font-weight:700;font-size:11px">${esc(sev.label.toUpperCase())}</span>
            </div>
          </td>
          <td class="mono">${esc(i.src_ip)}</td>
          <td><span class="tag" style="background:${cls.color}1f;color:${cls.color}">${esc(cls.short)}</span></td>
          <td>${esc(i.node)}</td>
          <td class="mono">${esc(fmt.num(i.flow_count))}</td>
          <td class="mono">${Math.round(i.peak_confidence * 100)}%</td>
          <td class="mono">${esc(fmt.bytes(i.peak_bps))}</td>
          <td title="${esc(fmt.datetime(i.opened_at))}">${esc(fmt.ago(i.opened_at))}</td>
          <td title="${esc(fmt.datetime(i.last_seen_at))}">${esc(fmt.ago(i.last_seen_at))}</td>
          <td>${statusChip(i)}</td>
          <td>
            <div class="row-actions">
              ${canAct ? actions(i) : `<span class="chip">READ ONLY</span>`}
            </div>
          </td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-action]").forEach((btn) => {
      btn.addEventListener("click", () =>
        act(Number(btn.dataset.id), btn.dataset.action, btn));
    });
  }

  function statusChip(i) {
    if (i.status === "resolved") {
      return `<span class="chip ok">${icon("check", 10)} RESOLVED</span>`;
    }
    if (i.status === "acknowledged") {
      return `<span class="chip info" title="${esc(i.acknowledged_by || "")}">ACK${
        i.acknowledged_by ? ` · ${esc(i.acknowledged_by)}` : ""}</span>`;
    }
    return `<span class="chip bad">OPEN</span>`;
  }

  function actions(i) {
    const out = [];
    if (i.status === "open") {
      out.push(`<button class="row-btn ghost" data-action="acknowledge" data-id="${i.id}">ACK</button>`);
    }
    if (!i.mitigated) {
      out.push(`<button class="row-btn danger" data-action="mitigate" data-id="${i.id}">MITIGATE</button>`);
    }
    if (i.status !== "resolved") {
      out.push(`<button class="row-btn" data-action="resolve" data-id="${i.id}">RESOLVE</button>`);
    } else {
      out.push(`<button class="row-btn ghost" data-action="reopen" data-id="${i.id}">REOPEN</button>`);
    }
    return out.join("");
  }

  const VERB = {
    acknowledge: "Acknowledged",
    resolve: "Resolved",
    reopen: "Reopened",
    mitigate: "Mitigated"
  };

  async function act(id, action, btn) {
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "…";
    try {
      const updated = await api.incidentAction(id, action);
      toast(`${VERB[action]} incident from ${updated.src_ip}.`);
      await load();
    } catch (err) {
      toast(err.message, "err");
      btn.disabled = false;
      btn.textContent = label;
    }
  }

  el("status-tabs").querySelectorAll("[data-status]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.status = btn.dataset.status;
      el("status-tabs").querySelectorAll("button").forEach((b) =>
        b.classList.toggle("on", b === btn));
      load();
    });
  });

  el("btn-refresh").addEventListener("click", async () => {
    await load();
    toast("Refreshed from the API.");
  });

  el("btn-export").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify({
      exported_at: new Date().toISOString(),
      org: state.user.org_name,
      status_filter: state.status,
      incidents: state.incidents
    }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sentry-incidents-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Exported incidents as JSON.");
  });

  window.SENTRY_ON_SEARCH = function (q) {
    state.query = q;
    el("crumb").textContent = q ? `/ search: ${q}` : "/ grouped by source";
    renderTable();
  };
})();
