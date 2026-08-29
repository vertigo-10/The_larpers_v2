/**
 * Live Overview.
 *
 * Data flow: an initial REST snapshot, then a WebSocket feed that appends. If
 * the socket drops we fall back to polling so the page still reflects reality,
 * and the header says which mode it is in. Nothing on this page is generated
 * client-side — if the API is down, the page shows an error, not a green chart.
 *
 * Every rendered flow field goes through esc(); flows can carry attacker-chosen
 * strings (src_ip, node) all the way from /api/ingest into this table.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const cfg = window.SENTRY_CONFIG;
  const { esc, icon, fmt, toast, classMeta } = ui;

  const el = (id) => document.getElementById(id);

  const state = {
    flows: [],
    tab: "live",
    node: "all",
    query: new URLSearchParams(window.location.search).get("q") || "",
    points: cfg.historyPoints,
    paused: false,
    classFilter: new Set(Object.keys(window.SENTRY_CLASSES)),
    settings: null,
    user: null,
    pollTimer: null
  };

  let mainChart, classChart, nodeChart, portChart;

  // ── boot ────────────────────────────────────────────────────────────────
  ui.mountSidebar("dashboard");
  paintStaticIcons();

  init().catch((err) => {
    if (err && err.status === 401) return; // api.js is already redirecting
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    state.user = await api.me();
    paintUser(state.user);

    const [status, settings] = await Promise.all([api.getStatus(), api.getSettings()]);
    state.settings = settings;
    paintStatus(status);
    paintSettings(settings);
    applyRole(state.user.role);

    if (state.query) el("crumb").textContent = `/ search: ${state.query}`;

    buildCharts();
    await refreshAll();

    api.on("flow", onLiveFlow);
    api.on("metric", onLiveMetric);
    api.on("status", (up) => {
      ui.setStreamState(up);
      setStreamPill(up);
      if (up) stopPolling(); else startPolling();
    });
    api.connectStream();

    // A safety net: even with the socket up, re-sync aggregates periodically so
    // counters cannot drift away from the database.
    setInterval(() => { if (!state.paused) refreshAggregates(); }, 15000);
  }

  // ── static chrome ───────────────────────────────────────────────────────
  function paintStaticIcons() {
    el("btn-threats").innerHTML = `${icon("alert", 12)} Threats`;
    el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;
    el("btn-export").innerHTML = `${icon("download", 12)} Export`;
    el("btn-pause").innerHTML = `${icon("activity", 12)} Pause`;
    el("btn-csv").innerHTML = `${icon("download", 12)} CSV`;
    el("tool-expand").innerHTML = icon("expand", 13);
    el("tool-filter").innerHTML = icon("filter", 13);
    el("tool-camera").innerHTML = icon("camera", 13);
    el("asset-ico").innerHTML = icon("globe", 11);
    el("ico-info").innerHTML = icon("info", 12);
  }

  function paintUser(user) {
    el("topbar-avatar").textContent = user.initials || "··";
    el("topbar-avatar").title = `${user.name} · ${user.role}`;
  }

  function paintStatus(status) {
    el("foot-model").textContent = `${status.model_name} · ${status.framework}`;
    el("foot-latency").textContent = status.model_ready ? "model loaded" : "model down";
    el("foot-latency").style.color = status.model_ready ? "" : "var(--red)";

    const pill = el("class-pill");
    pill.textContent =
      `${status.classes.length} classes · ${status.dataset_label || status.dataset}`;
    pill.title = status.dataset_note || "";

    if (!status.model_ready) {
      ui.fatalBanner(`Detection model unavailable: ${status.model_error || "unknown error"}`);
    }
    if (status.simulator) {
      el("crumb").textContent = "/ all nodes · simulated traffic";
      el("crumb").title =
        "The traffic generator is on. Flow characteristics are synthetic; every " +
        "verdict shown is still produced by the real model.";
    }
  }

  function paintSettings(s) {
    el("threshold-val").value = s.threshold.toFixed(2);
    el("threshold-slider").value = Math.round(s.threshold * 100);
    el("chk-auto").checked = s.auto_mitigate;
    el("chk-alert").checked =
      s.notify_browser && "Notification" in window && Notification.permission === "granted";
  }

  /** Viewers get a read-only console rather than buttons that 403. */
  function applyRole(role) {
    if (role !== "viewer") return;
    ["btn-mitigate", "threshold-slider", "chk-auto"].forEach((id) => {
      const node = el(id);
      if (!node) return;
      node.disabled = true;
      node.style.opacity = "0.45";
      node.style.cursor = "not-allowed";
      node.title = "Your role is read-only.";
    });
    el("console-note").textContent =
      "You have read-only access. Ask an admin to change detection settings.";
  }

  function setStreamPill(up) {
    const pill = el("stream-pill");
    const dot = el("stream-dot");
    el("stream-text").textContent = up ? "Live" : "Polling";
    pill.classList.toggle("live", up);
    dot.classList.toggle("pulse", up);
    dot.style.background = up ? "" : "var(--amber)";
    pill.title = up
      ? "Receiving flows over the WebSocket."
      : "WebSocket unavailable — falling back to periodic polling.";
  }

  // ── polling fallback ────────────────────────────────────────────────────
  function startPolling() {
    if (state.pollTimer) return;
    state.pollTimer = setInterval(() => { if (!state.paused) refreshAll(); }, cfg.pollIntervalMs);
  }
  function stopPolling() {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }

  // ── data ────────────────────────────────────────────────────────────────
  async function refreshAll() {
    try {
      await Promise.all([refreshFlows(), refreshChart(), refreshAggregates()]);
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Lost contact with the backend.");
    }
  }

  async function refreshFlows() {
    state.flows = await api.getFlows({
      limit: cfg.maxTableRows,
      tab: state.tab,
      q: state.query,
      node: state.node
    });
    renderFlows();
  }

  async function refreshChart() {
    const series = await api.getHistory(state.points);
    mainChart.data.labels = series.labels.map((t) => fmt.time(t));
    mainChart.data.datasets[0].data = series.throughput;
    mainChart.data.datasets[1].data = series.threat;
    mainChart.update("none");

    const tp = series.throughput;
    el("meta-high").textContent = tp.length ? `${Math.max.apply(null, tp).toFixed(2)} Mbps` : "—";
    el("meta-low").textContent = tp.length ? `${Math.min.apply(null, tp).toFixed(2)} Mbps` : "—";

    const latest = tp.length ? tp[tp.length - 1] : 0;
    const threat = series.threat.length ? series.threat[series.threat.length - 1] : 0;
    setHeadline(latest, threat);
  }

  async function refreshAggregates() {
    const [summary, classes, nodes, ports, nodeList] = await Promise.all([
      api.getSummary(), api.getClassBreakdown(), api.getNodeTraffic(),
      api.getPortActivity(), api.getNodes()
    ]);

    renderStats(summary);
    el("meta-nodes").textContent =
      state.node === "all" ? `${summary.nodes_online}/${summary.nodes_total} nodes` : state.node;
    el("confidence-val").textContent = summary.avg_confidence.toFixed(2);
    el("confidence-val").className =
      "big-metric " + (summary.avg_confidence >= 0.9 ? "risk-high"
        : summary.avg_confidence >= 0.7 ? "risk-med" : "risk-low");

    classChart.data.labels = classes.labels.map((l) => classMeta(l).label);
    classChart.data.datasets[0].data = classes.values;
    classChart.data.datasets[0].backgroundColor = classes.labels.map((l) => classMeta(l).color);
    classChart.update("none");
    el("meta-vol").textContent = fmt.num(classes.values.reduce((a, b) => a + b, 0));

    nodeChart.data.labels = nodes.labels;
    nodeChart.data.datasets[0].data = nodes.values;
    nodeChart.update("none");

    portChart.data.labels = ports.labels;
    portChart.data.datasets[0].data = ports.values;
    portChart.update("none");

    renderNodeChips(nodeList);
  }

  // ── live stream handlers ────────────────────────────────────────────────
  function onLiveFlow(flow) {
    if (state.paused) return;
    if (!matchesView(flow)) return;

    state.flows.unshift(flow);
    if (state.flows.length > cfg.maxTableRows) state.flows.pop();
    renderFlows(flow.id);

    const meta = classMeta(flow.prediction);
    if (!meta.benign && flow.confidence >= (state.settings.threshold || 0.85)) {
      notify(flow);
    }
  }

  function onLiveMetric(m) {
    if (state.paused) return;
    mainChart.data.labels.push(fmt.time(m.ts));
    mainChart.data.datasets[0].data.push(m.throughput);
    mainChart.data.datasets[1].data.push(m.threat);
    while (mainChart.data.labels.length > state.points) {
      mainChart.data.labels.shift();
      mainChart.data.datasets[0].data.shift();
      mainChart.data.datasets[1].data.shift();
    }
    mainChart.update("none");
    setHeadline(m.throughput, m.threat);
  }

  /** Does an incoming live flow belong in the table as currently filtered? */
  function matchesView(flow) {
    if (state.tab === "flagged" && classMeta(flow.prediction).benign) return false;
    if (state.tab === "mitigated" && !flow.mitigated) return false;
    if (state.node !== "all" && flow.node !== state.node) return false;
    if (!state.classFilter.has(flow.prediction)) return false;
    if (state.query) {
      const hay = `${flow.src_ip} ${flow.node} ${flow.prediction} ${flow.dst_port} ${flow.id}`;
      if (hay.toLowerCase().indexOf(state.query.toLowerCase()) === -1) return false;
    }
    return true;
  }

  function setHeadline(mbps, threat) {
    el("headline-val").textContent = Number(mbps || 0).toFixed(2);
    el("meta-threat").textContent = Number(threat || 0).toFixed(1);

    const alarm = threat >= 50;
    el("headline").classList.toggle("alarm", alarm);
    el("v-threat").classList.toggle("on", alarm);
    el("v-clear").classList.toggle("on", !alarm);
    el("meta-threat").className = "k " + (alarm ? "down" : "up");
  }

  // ── rendering ───────────────────────────────────────────────────────────
  function renderStats(s) {
    const cards = [
      { k: "Flows / min", v: fmt.num(s.flows_per_min), d: "scored by the model", cls: "" },
      { k: "Mitigated", v: fmt.num(s.attacks_blocked), d: "flows marked for blocking", cls: "up" },
      { k: "Open incidents", v: fmt.num(s.open_incidents), d: "grouped by source IP",
        cls: s.open_incidents > 0 ? "down" : "up" },
      { k: "Mean confidence", v: s.avg_confidence.toFixed(3), d: "last 60 seconds", cls: "" },
      { k: "Threat level", v: s.threat_level, d: `${s.nodes_online}/${s.nodes_total} nodes online`,
        cls: s.threat_level === "NOMINAL" ? "up" : "down" }
    ];
    el("stat-strip").innerHTML = cards.map((c) => `
      <div class="stat">
        <div class="k">${esc(c.k)}</div>
        <div class="v ${c.cls}">${esc(c.v)}</div>
        <div class="d dim">${esc(c.d)}</div>
      </div>`).join("");
  }

  function renderFlows(flashId) {
    const body = el("flow-body");
    const rows = state.flows.filter((f) => state.classFilter.has(f.prediction));

    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="11" class="empty-state">${
        state.query
          ? `No flows match “${esc(state.query)}”.`
          : "No flows recorded yet. Traffic appears here as the model scores it."
      }</td></tr>`;
      return;
    }

    const canAct = state.user.role !== "viewer";

    body.innerHTML = rows.map((f) => {
      const meta = classMeta(f.prediction);
      const flash = f.id === flashId ? (meta.benign ? "flash" : "flash-alert") : "";
      const conf = Math.round(f.confidence * 100);
      return `
        <tr class="${flash}">
          <td>
            <div class="flow-cell">
              <span class="flow-dot" style="background:${meta.color}"></span>
              <div>
                <div class="flow-name mono">${esc(f.id)}</div>
                <div class="dim" style="font-size:10px">${esc(fmt.time(f.ts))}</div>
              </div>
            </div>
          </td>
          <td class="mono">${esc(f.src_ip)}</td>
          <td>${esc(f.node)}</td>
          <td class="mono">${esc(f.dst_port)}</td>
          <td>${esc(f.protocol)}</td>
          <td class="mono">${esc(fmt.dur(f.duration))}</td>
          <td class="mono">${esc(fmt.num(f.packets))}</td>
          <td class="mono">${esc(fmt.bytes(f.bytes_per_sec))}</td>
          <td><span class="tag" style="background:${meta.color}1f;color:${meta.color}">${esc(meta.short)}</span></td>
          <td>
            <div class="conf-bar">
              <div class="conf-track"><div class="conf-fill" style="width:${conf}%;background:${meta.color}"></div></div>
              <span class="mono" style="font-size:10.5px">${conf}%</span>
            </div>
          </td>
          <td>
            <div class="row-actions">
              ${f.mitigated
                ? `<span class="chip ok">${icon("check", 10)} MITIGATED</span>`
                : meta.benign
                  ? `<span class="chip">CLEAR</span>`
                  : canAct
                    ? `<button class="row-btn danger" data-mitigate="${esc(f.src_ip)}">MITIGATE</button>`
                    : `<span class="chip warn">FLAGGED</span>`}
            </div>
          </td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-mitigate]").forEach((btn) => {
      btn.addEventListener("click", () => mitigate(btn.dataset.mitigate, btn));
    });
  }

  function renderNodeChips(nodes) {
    const chips = [{ label: "all", mbps: null, attacks: 0 }].concat(nodes);
    el("node-chips").innerHTML = chips.map((n) => `
      <button class="node-chip ${state.node === n.label ? "on" : ""}" data-node="${esc(n.label)}">
        <span>${esc(n.label === "all" ? "All nodes" : n.label)}</span>
        ${n.mbps === null ? "" : `<span class="v">${n.mbps.toFixed(2)}</span>`}
        ${n.attacks ? `<span class="v" style="color:var(--red)">${n.attacks}&#9888;</span>` : ""}
      </button>`).join("");

    el("node-chips").querySelectorAll("[data-node]").forEach((chip) => {
      chip.addEventListener("click", () => {
        state.node = chip.dataset.node;
        el("asset-name").textContent =
          state.node === "all" ? "ALL NODES" : state.node.toUpperCase();
        el("scope-input").value = state.node === "all" ? "all nodes" : state.node;
        refreshFlows();
        refreshAggregates();
      });
    });
  }

  // ── actions ─────────────────────────────────────────────────────────────
  async function mitigate(srcIp, btn) {
    if (btn) { btn.disabled = true; btn.textContent = "…"; }
    try {
      const res = await api.mitigate(null, srcIp);
      toast(`${res.count} flow(s) from ${srcIp} marked mitigated — not enforced at the edge.`);
      await refreshFlows();
      await refreshAggregates();
    } catch (err) {
      toast(err.message, "err");
      if (btn) { btn.disabled = false; btn.textContent = "MITIGATE"; }
    }
  }

  // Matches _SEVERITY_RANK in backend/app/engine.py. Kept as an explicit map
  // rather than an array index so an unknown value from a future server is
  // caught by the -1 below instead of silently sorting as "low".
  const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

  /**
   * The org's "minimum severity to alert on" setting. Until this existed the
   * dropdown was stored, validated and displayed but read by nothing — the
   * settings page described behaviour the product did not have.
   */
  function meetsMinSeverity(flow) {
    const min = SEVERITY_RANK[state.settings && state.settings.min_severity];
    if (min === undefined) return true;      // unset or unrecognised: don't suppress
    const actual = SEVERITY_RANK[flow.severity];
    if (actual === undefined) return true;   // older payload without severity
    return actual >= min;
  }

  function notify(flow) {
    if (!el("chk-alert").checked) return;
    if (!meetsMinSeverity(flow)) return;
    if (!("Notification" in window) || Notification.permission !== "granted") return;
    const meta = classMeta(flow.prediction);
    new Notification(`SENTRY — ${meta.label} detected`, {
      body: `${flow.src_ip} → port ${flow.dst_port} on ${flow.node} · ${Math.round(flow.confidence * 100)}% confidence`,
      tag: `sentry-${flow.src_ip}`
    });
  }

  function downloadBlob(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function stamp() {
    return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  }

  // ── controls ────────────────────────────────────────────────────────────
  el("btn-threats").addEventListener("click", () => switchTab("flagged"));

  el("btn-refresh").addEventListener("click", async () => {
    const btn = el("btn-refresh");
    btn.disabled = true;
    await refreshAll();
    btn.disabled = false;
    toast("Refreshed from the API.");
  });

  el("btn-export").addEventListener("click", () => {
    const payload = {
      exported_at: new Date().toISOString(),
      org: state.user.org_name,
      view: { tab: state.tab, node: state.node, query: state.query },
      flows: state.flows
    };
    downloadBlob(JSON.stringify(payload, null, 2),
      `sentry-flows-${stamp()}.json`, "application/json");
    toast("Exported the current view as JSON.");
  });

  el("btn-csv").addEventListener("click", () => {
    const cols = ["id", "ts", "src_ip", "dst_port", "protocol", "node",
                  "duration", "packets", "bytes_per_sec", "prediction",
                  "confidence", "mitigated"];
    // Quote every field and double internal quotes — a node label containing a
    // comma must not shift every later column.
    const cell = (v) => `"${String(v === undefined || v === null ? "" : v).replace(/"/g, '""')}"`;
    const lines = [cols.join(",")].concat(
      state.flows.map((f) =>
        cols.map((c) => cell(c === "ts" ? new Date(f.ts).toISOString() : f[c])).join(","))
    );
    downloadBlob(lines.join("\n"), `sentry-flows-${stamp()}.csv`, "text/csv");
    toast(`Exported ${state.flows.length} rows as CSV.`);
  });

  el("btn-pause").addEventListener("click", () => {
    state.paused = !state.paused;
    const btn = el("btn-pause");
    btn.innerHTML = state.paused ? `${icon("zap", 12)} Resume` : `${icon("activity", 12)} Pause`;
    btn.style.borderColor = state.paused ? "rgba(255,181,69,0.4)" : "";
    btn.style.color = state.paused ? "var(--amber)" : "";
    if (!state.paused) refreshAll();
    toast(state.paused ? "Live updates paused." : "Live updates resumed.");
  });

  el("table-tabs").querySelectorAll("[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  function switchTab(tab) {
    state.tab = tab;
    el("table-tabs").querySelectorAll("[data-tab]").forEach((b) =>
      b.classList.toggle("on", b.dataset.tab === tab));
    refreshFlows();
  }

  el("range-seg").querySelectorAll("[data-points]").forEach((btn) => {
    btn.addEventListener("click", () => {
      el("range-seg").querySelectorAll("button").forEach((b) => b.classList.remove("on"));
      btn.classList.add("on");
      state.points = Number(btn.dataset.points);
      refreshChart();
    });
  });

  el("console-tabs").querySelectorAll("[data-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      el("console-tabs").querySelectorAll("button").forEach((b) => b.classList.remove("on"));
      btn.classList.add("on");
      el("console-note").textContent = btn.dataset.mode === "auto"
        ? "Applies to every flow the model scored above τ."
        : "Manual mode: nothing is mitigated until you press ENGAGE.";
    });
  });

  el("scope-reset").addEventListener("click", () => {
    state.node = "all";
    el("asset-name").textContent = "ALL NODES";
    el("scope-input").value = "all nodes";
    refreshFlows();
    refreshAggregates();
  });

  // Threshold: reflect instantly, persist on release.
  el("threshold-slider").addEventListener("input", (e) => {
    el("threshold-val").value = (Number(e.target.value) / 100).toFixed(2);
  });
  el("threshold-slider").addEventListener("change", async (e) => {
    const value = Number(e.target.value) / 100;
    try {
      await api.setThreshold(value);
      state.settings.threshold = value;
      toast(`Detection threshold set to ${value.toFixed(2)}.`);
    } catch (err) {
      toast(err.message, "err");
      el("threshold-slider").value = Math.round(state.settings.threshold * 100);
      el("threshold-val").value = state.settings.threshold.toFixed(2);
    }
  });

  el("chk-auto").addEventListener("change", async (e) => {
    try {
      state.settings = await api.updateSettings({ auto_mitigate: e.target.checked });
      toast(e.target.checked
        ? "Auto-mitigate on — flagged flows are marked automatically."
        : "Auto-mitigate off.");
    } catch (err) {
      toast(err.message, "err");
      e.target.checked = state.settings.auto_mitigate;
    }
  });

  // Desktop alerts need an explicit browser permission; asking only on the
  // user's click is what keeps the prompt from being suppressed.
  el("chk-alert").addEventListener("change", async (e) => {
    if (!e.target.checked) {
      try { await api.updateSettings({ notify_browser: false }); } catch (_) {}
      return toast("Desktop alerts off.");
    }
    if (!("Notification" in window)) {
      e.target.checked = false;
      return toast("This browser has no notification support.", "err");
    }
    const perm = Notification.permission === "granted"
      ? "granted"
      : await Notification.requestPermission();
    if (perm !== "granted") {
      e.target.checked = false;
      return toast("Notification permission denied by the browser.", "err");
    }
    try {
      await api.updateSettings({ notify_browser: true });
      toast("Desktop alerts on for high-confidence detections.");
    } catch (err) {
      toast(err.message, "err");
    }
  });

  el("btn-mitigate").addEventListener("click", async () => {
    const targets = state.flows.filter(
      (f) => !classMeta(f.prediction).benign && !f.mitigated
    );
    if (!targets.length) return toast("Nothing flagged in the current view.", "err");

    const ips = Array.from(new Set(targets.map((f) => f.src_ip)));
    const btn = el("btn-mitigate");
    btn.disabled = true;
    btn.classList.add("armed");
    btn.textContent = "ENGAGING…";
    try {
      let count = 0;
      for (const ip of ips) {
        const res = await api.mitigate(null, ip);
        count += res.count;
      }
      toast(`${count} flow(s) across ${ips.length} source(s) marked mitigated.`);
      await refreshFlows();
      await refreshAggregates();
    } catch (err) {
      toast(err.message, "err");
    } finally {
      btn.disabled = false;
      btn.classList.remove("armed");
      btn.textContent = "ENGAGE MITIGATION";
    }
  });

  // Fullscreen the chart panel.
  el("tool-expand").addEventListener("click", () => {
    const panel = el("chart-panel");
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else if (panel.requestFullscreen) {
      panel.requestFullscreen().catch(() => toast("Fullscreen was blocked.", "err"));
    } else {
      toast("This browser does not support fullscreen.", "err");
    }
  });
  document.addEventListener("fullscreenchange", () => {
    const panel = el("chart-panel");
    panel.style.background = document.fullscreenElement ? "var(--bg)" : "";
    panel.style.padding = document.fullscreenElement ? "20px" : "";
    if (mainChart) mainChart.resize();
  });

  // Class filter popover.
  el("tool-filter").addEventListener("click", (e) => {
    const existing = document.querySelector(".popover");
    if (existing) return existing.remove();

    const pop = document.createElement("div");
    pop.className = "popover";
    pop.innerHTML = `<div class="ph">Show classes</div>` +
      Object.keys(window.SENTRY_CLASSES).map((key) => {
        const meta = classMeta(key);
        return `
          <label class="check">
            <input type="checkbox" data-class="${esc(key)}" ${state.classFilter.has(key) ? "checked" : ""} />
            <span class="box"><svg viewBox="0 0 24 24">${ui.ICONS.check}</svg></span>
            <span style="color:${meta.color}">${esc(meta.label)}</span>
          </label>`;
      }).join("");

    document.body.appendChild(pop);
    const r = e.currentTarget.getBoundingClientRect();
    pop.style.top = `${r.bottom + 6}px`;
    pop.style.left = `${Math.max(8, r.right - pop.offsetWidth)}px`;

    pop.querySelectorAll("[data-class]").forEach((box) => {
      box.addEventListener("change", () => {
        if (box.checked) state.classFilter.add(box.dataset.class);
        else state.classFilter.delete(box.dataset.class);
        renderFlows();
      });
    });

    setTimeout(() => {
      document.addEventListener("click", function close(ev) {
        if (pop.contains(ev.target)) return;
        pop.remove();
        document.removeEventListener("click", close);
      });
    }, 0);
  });

  // Chart snapshot.
  el("tool-camera").addEventListener("click", () => {
    const canvas = el("mainChart");
    // Chart.js draws on a transparent canvas; flatten it onto the panel colour
    // so the PNG is readable outside a dark viewer.
    const out = document.createElement("canvas");
    out.width = canvas.width;
    out.height = canvas.height;
    const ctx = out.getContext("2d");
    ctx.fillStyle = "#0f1315";
    ctx.fillRect(0, 0, out.width, out.height);
    ctx.drawImage(canvas, 0, 0);
    out.toBlob((blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sentry-throughput-${stamp()}.png`;
      a.click();
      URL.revokeObjectURL(url);
      toast("Chart saved as PNG.");
    });
  });

  // Sidebar search targets this page directly instead of navigating.
  window.SENTRY_ON_SEARCH = function (q) {
    state.query = q;
    el("crumb").textContent = q ? `/ search: ${q}` : "/ all nodes";
    refreshFlows();
  };

  // ── charts ──────────────────────────────────────────────────────────────
  function buildCharts() {
    const grid = "rgba(255,255,255,0.045)";
    const tick = { color: "#6d7d85", font: { size: 10, family: "JetBrains Mono" } };
    const noLegend = { legend: { display: false } };

    mainChart = new Chart(el("mainChart"), {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Throughput (Mbps)", data: [], borderColor: "#2fe08a",
            backgroundColor: "rgba(47,224,138,0.10)", borderWidth: 2,
            fill: true, tension: 0.34, pointRadius: 0, yAxisID: "y"
          },
          {
            label: "Threat score", data: [], borderColor: "#ff5064",
            borderWidth: 1.6, borderDash: [4, 3], fill: false,
            tension: 0.3, pointRadius: 0, yAxisID: "y1"
          }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#141a1d", borderColor: "#1e2629", borderWidth: 1,
            titleColor: "#e7eef1", bodyColor: "#9daab1", padding: 10
          }
        },
        scales: {
          x: { grid: { color: grid }, ticks: Object.assign({ maxTicksLimit: 8 }, tick) },
          y: { position: "left", grid: { color: grid }, ticks: tick, beginAtZero: true },
          y1: { position: "right", min: 0, max: 100, grid: { drawOnChartArea: false }, ticks: tick }
        }
      }
    });

    classChart = new Chart(el("classChart"), {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 0 }] },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "62%",
        plugins: {
          legend: {
            position: "right",
            labels: { color: "#9daab1", boxWidth: 9, font: { size: 10.5 }, padding: 9 }
          }
        }
      }
    });

    nodeChart = new Chart(el("nodeChart"), {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#4fb8f7", borderRadius: 4 }] },
      options: {
        responsive: true, maintainAspectRatio: false, plugins: noLegend,
        scales: {
          x: { grid: { display: false }, ticks: tick },
          y: { grid: { color: grid }, ticks: tick, beginAtZero: true }
        }
      }
    });

    portChart = new Chart(el("portChart"), {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#a97bff", borderRadius: 4 }] },
      options: {
        responsive: true, maintainAspectRatio: false, indexAxis: "y", plugins: noLegend,
        scales: {
          x: { grid: { color: grid }, ticks: tick, beginAtZero: true },
          y: { grid: { display: false }, ticks: tick }
        }
      }
    });
  }
})();
