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
          <td>${statusChip(i)}${
            i.mitigation_tier ? ` ${tierChip(i)}` : ""}</td>
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
    body.querySelectorAll("[data-ban]").forEach((btn) => {
      btn.addEventListener("click", () => openBan(Number(btn.dataset.ban)));
    });
  }

  /**
   * The escalation tier, as a chip.
   *
   * Deliberately never reads "Banned" or "Throttled". SENTRY watches traffic
   * and has no path to the router, so every tier is a decision it recorded and
   * nothing more — the API says `enforced: false` on all of them. "Ban recorded"
   * is two characters longer and is the difference between a page an operator
   * can trust and one that tells them traffic stopped when it did not.
   */
  function tierChip(i) {
    if (!i.mitigation_tier) return "";
    if (i.mitigation_tier === "throttle") {
      // A critical incident built from two flows gets the gentlest limit, which
      // looks like a contradiction sitting next to a CRITICAL chip. Severity is
      // the detection verdict; the response is damped until there is enough
      // traffic to be sure it is not noise. Said here so the row explains
      // itself rather than looking broken.
      const damped = i.flow_count < 5
        ? ` Held at the gentlest limit while the incident is still only ${
            i.flow_count} flow${i.flow_count === 1 ? "" : "s"}.`
        : "";
      return `<span class="chip" title="Rate limit recorded${
        i.rate_limit_rps ? ` at ${i.rate_limit_rps} rps` : ""
      }. Not applied by SENTRY.${damped}">THROTTLE RECORDED</span>`;
    }
    if (i.mitigation_tier === "repeat_offender") {
      return `<span class="chip bad" title="This source has tripped the auto-response
        several times inside the repeat-offender window.">REPEAT OFFENDER</span>`;
    }
    // ban. `until`, not `ago` — the expiry is in the future, and `ago` clamps a
    // negative gap to zero, which would print every live ban as "0s ago" and
    // read as already lapsed.
    const left = i.mitigation_expires_at
      ? ` · ${esc(fmt.until(i.mitigation_expires_at))}`
      : " · permanent";
    return `<span class="chip bad" title="Recorded in SENTRY only — apply the block
      at your router or firewall.">BAN RECORDED${left}</span>`;
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
    // Offered even on an already-banned incident, so a duration can be changed
    // or a timed ban made permanent without having to resolve and reopen.
    if (i.status !== "resolved") {
      out.push(`<button class="row-btn danger" data-ban="${i.id}">${
        i.mitigation_tier === "ban" ? "EDIT BAN" : "BAN"}</button>`);
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

  // ── ban modal ───────────────────────────────────────────────────────────
  // Same markup and open/close behaviour as the Team page's add-member modal,
  // rather than a second dialog pattern that behaves almost but not quite the
  // same way.
  const banModal = el("ban-modal");
  el("ico-ban").innerHTML = icon("shield", 15);
  el("ico-ban-notice").innerHTML = icon("info", 15);

  function openBan(id) {
    const inc = state.incidents.find((i) => i.id === id);
    if (!inc) return toast("That incident is no longer in the list.", "err");

    banModal.dataset.incident = String(id);
    el("ban-err").classList.remove("show");
    el("ban-src").textContent = inc.src_ip;

    const cls = classMeta(inc.label);
    const sev = severityMeta(inc.severity);
    // Every field here came with the incident. Nothing is fetched on open, so
    // the modal cannot show a spinner or fail halfway.
    el("ban-summary").textContent =
      `${cls.label} · ${fmt.num(inc.flow_count)} flow${inc.flow_count === 1 ? "" : "s"}`
      + ` · peak ${fmt.bytes(inc.peak_bps)} · seen on ${inc.node}`;
    el("ban-sev-chip").innerHTML =
      `<span class="chip" style="color:${sev.color};border-color:${sev.color}55">${
        esc(sev.label.toUpperCase())}</span>`;

    // Reopening on an existing ban starts from that ban, not from the default,
    // so "edit" does not silently mean "reset to 24 hours".
    if (inc.mitigation_tier === "ban" && !inc.mitigation_expires_at) {
      el("ban-duration").value = "permanent";
    } else {
      el("ban-duration").value = "1440";
    }
    syncCustom();
    banModal.classList.add("show");
    el("ban-duration").focus();
  }

  const closeBan = () => banModal.classList.remove("show");

  function syncCustom() {
    const custom = el("ban-duration").value === "custom";
    el("ban-custom-field").style.display = custom ? "" : "none";
    if (custom) el("ban-custom").focus();
  }

  el("ban-duration").addEventListener("change", syncCustom);
  el("ban-close").addEventListener("click", closeBan);
  el("ban-cancel").addEventListener("click", closeBan);
  banModal.addEventListener("click", (e) => { if (e.target === banModal) closeBan(); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && banModal.classList.contains("show")) closeBan();
  });

  function banError(msg) {
    const box = el("ban-err");
    box.textContent = msg;
    box.classList.add("show");
  }

  el("ban-save").addEventListener("click", async () => {
    const id = Number(banModal.dataset.incident);
    const choice = el("ban-duration").value;

    let minutes = null; // null is permanent, and is sent as an absent key
    if (choice === "custom") {
      minutes = Number(el("ban-custom").value);
      if (!Number.isFinite(minutes) || minutes <= 0) {
        return banError("Enter a duration in minutes — 0.5 is thirty seconds.");
      }
      if (minutes > 525600) {
        // Caught here as well as server-side so the operator gets a sentence
        // instead of a validation payload naming a field they never saw.
        return banError("Longer than a year — choose Permanent instead.");
      }
    } else if (choice !== "permanent") {
      minutes = Number(choice);
    }

    const btn = el("ban-save");
    btn.disabled = true;
    btn.textContent = "Recording…";
    try {
      const updated = await api.incidentAction(id, "ban", minutes);
      closeBan();
      // The toast repeats the caveat. It is the only part of this flow some
      // operators will read, and "Banned 198.51.100.77" on its own is the exact
      // sentence that would leave them thinking the traffic had stopped.
      toast(
        `Ban recorded for ${updated.src_ip}${
          minutes == null ? " (permanent)" : ""
        } — apply it at your router to take effect.`
      );
      await load();
    } catch (err) {
      banError(err.message || "Could not record the ban.");
    } finally {
      btn.disabled = false;
      btn.textContent = "Record ban";
    }
  });

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
