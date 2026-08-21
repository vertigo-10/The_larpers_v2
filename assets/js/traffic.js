/**
 * Traffic analysis — who is talking, and what the traffic is made of.
 *
 * The sort control matters more than it looks. A source that tops the volume
 * ranking is usually a backup or a download; a source that tops the flow-count
 * ranking with almost no volume is usually a flood; a source that tops the port
 * ranking is usually a scan. Being able to flip between the three is how an
 * operator tells those apart, so the default is "by threat" and the others are
 * one click away.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const cfg = window.SENTRY_CONFIG;
  const { esc, icon, fmt, toast, classMeta } = ui;
  const el = (id) => document.getElementById(id);

  const SORTS = {
    threat: { label: "by threat", key: (t) => [t.attack_flows > 0, t.attack_flows, t.total_bytes] },
    bytes: { label: "by volume", key: (t) => [t.total_bytes] },
    flows: { label: "by flow count", key: (t) => [t.flows] },
    ports: { label: "by ports touched", key: (t) => [t.ports, t.flows] }
  };

  const state = { window: 15, sort: "threat", payload: null, timer: null, canMitigate: false };

  ui.mountSidebar("traffic");
  el("ico-notice").innerHTML = icon("info", 15);
  el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    const user = await api.me();
    el("topbar-avatar").textContent = user.initials || "··";
    el("topbar-avatar").title = `${user.name} · ${user.role}`;
    el("crumb").textContent = `/ ${user.org_name}`;
    // /api/mitigate is operator-only. A viewer gets no button rather than a
    // button that 403s.
    state.canMitigate = user.role === "admin" || user.role === "analyst";

    el("in-window").addEventListener("change", (e) => {
      state.window = Number(e.target.value);
      load();
    });

    el("btn-refresh").addEventListener("click", () => load());

    document.querySelectorAll("[data-sort]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.sort = btn.getAttribute("data-sort");
        el("sort-pill").textContent = SORTS[state.sort].label;
        paintTalkers();
      });
    });

    await load();

    // Polled rather than streamed: these are windowed aggregates, and
    // recomputing them on every arriving flow would be a lot of query for a
    // number that barely moves between one flow and the next.
    state.timer = setInterval(load, Math.max(cfg.pollIntervalMs || 4000, 8000) * 2);
  }

  async function load() {
    const btn = el("btn-refresh");
    btn.disabled = true;
    try {
      const [talkers, traffic] = await Promise.all([
        api.getTalkers({ window: state.window, limit: 50 }),
        api.getTrafficBreakdown(state.window)
      ]);
      state.payload = talkers;
      paintStats(talkers);
      paintTalkers();
      paintProtocols(traffic.protocols);
      paintPorts(traffic.ports);
    } catch (err) {
      if (err.status === 401) return;
      toast(err.message || "Could not load traffic data.", "err");
    } finally {
      btn.disabled = false;
    }
  }

  function paintStats(p) {
    const attacking = p.talkers.filter((t) => t.attack_flows > 0);
    const loudest = p.talkers.reduce(
      (best, t) => (t.bytes_share > (best ? best.bytes_share : -1) ? t : best), null);

    const stats = [
      ["Flows", fmt.num(p.total_flows), `in the last ${p.window_minutes}m`],
      ["Unique sources", fmt.num(p.unique_sources), "distinct addresses"],
      ["Volume", fmt.size(p.total_bytes), "across all sources"],
      ["Attacking sources", fmt.num(attacking.length),
        attacking.length ? "shown at the top of the table" : "none in this window"],
      ["Busiest source", loudest ? `${loudest.bytes_share}%` : "—",
        loudest ? `of volume from ${esc(loudest.src_ip)}` : "no traffic yet"]
    ];

    el("stat-strip").innerHTML = stats.map(([k, v, d]) => `
      <div class="stat">
        <div class="k">${esc(k)}</div>
        <div class="v">${v}</div>
        <div class="d">${d}</div>
      </div>`).join("");
  }

  function paintTalkers() {
    const body = el("talker-body");
    const note = el("talker-note");
    if (!state.payload) return;

    const rows = state.payload.talkers.slice();
    const keyOf = SORTS[state.sort].key;
    rows.sort((a, b) => {
      const ka = keyOf(a), kb = keyOf(b);
      for (let i = 0; i < ka.length; i++) {
        if (ka[i] !== kb[i]) return ka[i] > kb[i] ? -1 : 1;
      }
      return 0;
    });

    if (!rows.length) {
      body.innerHTML = "";
      note.textContent = state.payload.total_flows
        ? "No sources in this window."
        : "No traffic recorded yet. Point a collector at this server, or enable the simulator, to see flows here.";
      return;
    }

    note.innerHTML = `Showing ${rows.length} of ${fmt.num(state.payload.unique_sources)}
      source${state.payload.unique_sources === 1 ? "" : "s"} seen in the last
      ${state.payload.window_minutes} minutes, ${esc(SORTS[state.sort].label)}.`;

    body.innerHTML = rows.map((t) => {
      const meta = classMeta(t.top_prediction);
      const attacking = t.attack_flows > 0;
      return `
        <tr${attacking ? ' style="background:rgba(255,80,100,0.04)"' : ""}>
          <td class="mono">${esc(t.src_ip)}</td>
          <td>
            <span class="tag tag-${meta.tag}">${esc(meta.short)}</span>
            ${attacking ? `<span class="mono" style="font-size:10.5px;color:var(--text-dim);margin-left:6px">${(t.max_confidence * 100).toFixed(1)}%</span>` : ""}
          </td>
          <td class="mono">${fmt.num(t.flows)}</td>
          <td class="mono"${attacking ? ' style="color:var(--red)"' : ""}>
            ${t.attack_flows ? `${fmt.num(t.attack_flows)} <small style="color:var(--muted)">(${t.attack_share}%)</small>` : "—"}
          </td>
          <td class="mono">${fmt.num(t.packets)}</td>
          <td class="mono">${fmt.size(t.total_bytes)}</td>
          <td class="mono">${t.bytes_share}%</td>
          <td class="mono">${fmt.num(t.ports)}</td>
          <td style="font-size:11px;color:var(--text-dim)">${esc(t.nodes.join(", ")) || "—"}</td>
          <td style="font-size:11px;color:var(--text-dim)">${fmt.ago(t.last_seen * 1000)}</td>
          <td>${mitigationCell(t, attacking)}</td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-mitigate]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const ip = btn.getAttribute("data-mitigate");
        // Mitigation is a record, not an enforcement — nothing here touches a
        // firewall. Saying so plainly beats an operator assuming the traffic
        // stopped.
        if (!confirm(
          `Mark traffic from ${ip} as mitigated?\n\n` +
          `This records the decision and closes the related incidents. It does ` +
          `not block anything at the network level.`
        )) return;
        btn.disabled = true;
        try {
          await api.mitigate(null, ip);
          toast(`Marked ${ip} as mitigated.`);
          await load();
        } catch (err) {
          toast(err.message || "Could not mitigate.", "err");
          btn.disabled = false;
        }
      });
    });
  }

  /**
   * With auto-mitigate on, every attacking source arrives already marked. A
   * button reading "Mitigated" on all of them would tell an operator the attack
   * was dealt with, when all that happened is a row was flagged in a database.
   * The label says what actually occurred and the tooltip says what did not.
   */
  function mitigationCell(t, attacking) {
    if (!attacking) return "";
    if (t.mitigated >= t.attack_flows) {
      return `<span class="tag tag-benign"
        title="Recorded as mitigated in SENTRY. Nothing was blocked at the network level.">LOGGED</span>`;
    }
    if (!state.canMitigate) return "";
    return `<button class="btn btn-sm" data-mitigate="${esc(t.src_ip)}">Mitigate</button>`;
  }

  function paintProtocols(rows) {
    el("proto-body").innerHTML = rows.length
      ? rows.map((p) => `
          <tr>
            <td class="mono">${esc(p.protocol)}</td>
            <td class="mono">${fmt.num(p.flows)}</td>
            <td class="mono">${fmt.size(p.total_bytes)}</td>
            <td class="mono"${p.attack_flows ? ' style="color:var(--red)"' : ""}>
              ${p.attack_flows ? fmt.num(p.attack_flows) : "—"}
            </td>
          </tr>`).join("")
      : `<tr><td colspan="4" class="section-note">No traffic in this window.</td></tr>`;
  }

  function paintPorts(rows) {
    el("port-body").innerHTML = rows.length
      ? rows.map((p) => `
          <tr>
            <td class="mono">${p.port}</td>
            <td style="font-size:11px;color:var(--text-dim)">${esc(p.service) || "—"}</td>
            <td class="mono">${fmt.num(p.flows)}</td>
            <td class="mono">${fmt.num(p.sources)}</td>
            <td class="mono"${p.attack_flows ? ' style="color:var(--red)"' : ""}>
              ${p.attack_flows ? fmt.num(p.attack_flows) : "—"}
            </td>
          </tr>`).join("")
      : `<tr><td colspan="5" class="section-note">No traffic in this window.</td></tr>`;
  }
})();
