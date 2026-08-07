(function () {
  const cfg = window.AEGIS_CONFIG;
  const api = window.AEGIS_API;
  const { icon, mountSidebar, toast, fmt } = window.AEGIS_UI;

  const CLASS_COLORS = {
    "BENIGN": "#2fe08a",
    "DDoS": "#ff5064",
    "DoS Hulk": "#ffb545",
    "PortScan": "#a97bff",
    "Bot": "#4fb8f7",
    "FTP-Patator": "#5fd0c4"
  };
  const CLASS_TAG = {
    "BENIGN": "tag-benign",
    "DDoS": "tag-ddos",
    "DoS Hulk": "tag-dos",
    "PortScan": "tag-scan",
    "Bot": "tag-brute",
    "FTP-Patator": "tag-brute"
  };

  const RANGE_POINTS = { "5m": 45, "15m": 90, "1h": 140, "24h": 200 };

  const store = {
    flows: [],
    events: [],
    tab: "live",
    paused: false,
    threshold: 0.85,
    range: "15m",
    activeNode: "all",
    lastThreat: 0,
    peak: 0,
    floor: Infinity,
    packets: 0
  };

  let mainChart, classChart, nodeChart, portChart;

  /* ── chart setup ─────────────────────────────────── */
  Chart.defaults.color = "#6d7d85";
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.font.size = 10;
  Chart.defaults.animation.duration = 320;

  function gradient(ctx, area, hex, top, bottom) {
    const g = ctx.createLinearGradient(0, area.top, 0, area.bottom);
    g.addColorStop(0, hex + top);
    g.addColorStop(1, hex + bottom);
    return g;
  }

  const tooltipStyle = {
    backgroundColor: "#141a1d",
    borderColor: "#2b3439",
    borderWidth: 1,
    titleColor: "#e7eef1",
    bodyColor: "#9daab1",
    padding: 10,
    cornerRadius: 8,
    displayColors: true,
    boxWidth: 8,
    boxHeight: 8,
    usePointStyle: true
  };

  function buildMainChart(seed) {
    const el = document.getElementById("mainChart");
    mainChart = new Chart(el, {
      type: "line",
      data: {
        labels: seed.labels.map(fmt.time),
        datasets: [
          {
            label: "Throughput",
            data: seed.throughput,
            borderColor: "#2fe08a",
            borderWidth: 1.6,
            pointRadius: 0,
            pointHoverRadius: 4,
            pointHoverBackgroundColor: "#2fe08a",
            tension: 0.32,
            fill: true,
            backgroundColor: (c) => {
              const { ctx, chartArea } = c.chart;
              if (!chartArea) return "transparent";
              return gradient(ctx, chartArea, "#2fe08a", "40", "00");
            },
            yAxisID: "y"
          },
          {
            label: "Threat score",
            data: seed.threat,
            borderColor: "#ff5064",
            borderWidth: 1.4,
            pointRadius: 0,
            pointHoverRadius: 4,
            tension: 0.3,
            fill: true,
            backgroundColor: (c) => {
              const { ctx, chartArea } = c.chart;
              if (!chartArea) return "transparent";
              return gradient(ctx, chartArea, "#ff5064", "26", "00");
            },
            yAxisID: "y1"
          },
          {
            label: "Threshold",
            data: seed.labels.map(() => store.threshold * 100),
            borderColor: "#4fb8f7",
            borderWidth: 1,
            borderDash: [5, 5],
            pointRadius: 0,
            fill: false,
            yAxisID: "y1"
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: {
            ...tooltipStyle,
            callbacks: {
              label: (c) => {
                if (c.datasetIndex === 0) return ` Throughput  ${fmt.num(c.raw, 1)} Mbps`;
                if (c.datasetIndex === 1) return ` Threat score  ${fmt.num(c.raw, 1)} / 100`;
                return ` Threshold  ${fmt.num(c.raw, 0)}`;
              }
            }
          }
        },
        scales: {
          x: {
            grid: { color: "rgba(255,255,255,0.028)", drawTicks: false },
            border: { display: false },
            ticks: { maxTicksLimit: 9, padding: 6 }
          },
          y: {
            position: "right",
            grid: { color: "rgba(255,255,255,0.028)", drawTicks: false },
            border: { display: false },
            ticks: { padding: 8, callback: (v) => fmt.num(v) }
          },
          y1: {
            position: "left",
            min: 0, max: 100,
            grid: { display: false },
            border: { display: false },
            ticks: { padding: 6, maxTicksLimit: 5, color: "#5b686e" }
          }
        }
      }
    });
  }

  function buildClassChart(data) {
    classChart = new Chart(document.getElementById("classChart"), {
      type: "bar",
      data: {
        labels: data.labels,
        datasets: [{
          data: data.values,
          backgroundColor: data.labels.map(l => (CLASS_COLORS[l] || "#4fb8f7") + "cc"),
          borderRadius: 4,
          barThickness: 13
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { ...tooltipStyle, callbacks: { label: (c) => ` ${fmt.num(c.raw)} flows` } }
        },
        scales: {
          x: {
            type: "logarithmic",
            grid: { color: "rgba(255,255,255,0.03)" },
            border: { display: false },
            ticks: { callback: (v) => ([1, 10, 100, 1000, 10000].includes(v) ? fmt.num(v) : "") }
          },
          y: { grid: { display: false }, border: { display: false }, ticks: { font: { size: 10 } } }
        }
      }
    });
  }

  function buildNodeChart(data) {
    nodeChart = new Chart(document.getElementById("nodeChart"), {
      type: "doughnut",
      data: {
        labels: data.labels,
        datasets: [{
          data: data.values,
          backgroundColor: ["#2fe08a", "#17b86b", "#4fb8f7", "#a97bff", "#ffb545"],
          borderColor: "#0f1315",
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "62%",
        plugins: {
          legend: {
            position: "right",
            labels: { boxWidth: 8, boxHeight: 8, usePointStyle: true, pointStyle: "circle", padding: 9, font: { size: 10 } }
          },
          tooltip: { ...tooltipStyle, callbacks: { label: (c) => ` ${c.label}  ${fmt.num(c.raw)} Mbps` } }
        }
      }
    });
  }

  function buildPortChart(data) {
    portChart = new Chart(document.getElementById("portChart"), {
      type: "bar",
      data: {
        labels: data.labels.map(p => ":" + p),
        datasets: [{
          data: data.values,
          backgroundColor: (c) => {
            const { ctx, chartArea } = c.chart;
            if (!chartArea) return "#2fe08a";
            return gradient(ctx, chartArea, "#2fe08a", "ff", "1a");
          },
          borderRadius: 4,
          barPercentage: 0.62
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { ...tooltipStyle, callbacks: { label: (c) => ` ${fmt.num(c.raw)} flows/min` } }
        },
        scales: {
          x: { grid: { display: false }, border: { display: false } },
          y: { grid: { color: "rgba(255,255,255,0.03)" }, border: { display: false }, ticks: { maxTicksLimit: 5 } }
        }
      }
    });
  }

  /* ── rendering ───────────────────────────────────── */
  function renderStats(s) {
    document.getElementById("stat-strip").innerHTML = `
      ${stat("Flows / min", fmt.num(s.flows_per_min), `▲ live ingest`, "up")}
      ${stat("Attacks blocked", fmt.num(s.attacks_blocked), "last 24h", "dim")}
      ${stat("Avg confidence", (s.avg_confidence * 100).toFixed(1) + "%", `model ${cfg.model.accuracy}% acc`, "dim")}
      ${stat("Inference latency", s.inference_ms + " ms", "per flow", "dim")}
      ${stat("Nodes online", `${s.nodes_online}/${s.nodes_total}`, s.threat_level, s.phase ? "down" : "up")}`;
  }

  function stat(k, v, d, cls) {
    return `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div><div class="d ${cls}">${d}</div></div>`;
  }

  function renderNodeChips(nodes) {
    const el = document.getElementById("node-chips");
    el.innerHTML = nodes.map(n => `
      <button class="node-chip ${n.label === store.activeNode ? "on" : ""}" data-node="${n.label}">
        <span class="flow-dot" style="background:${n.status === "ok" ? "#2fe08a" : "#ffb545"}"></span>
        <span>${n.label}</span>
        <span class="v ${n.status === "ok" ? "up" : "down"}">${n.mbps} Mbps</span>
      </button>`).join("");

    el.querySelectorAll("[data-node]").forEach(b => {
      b.addEventListener("click", () => {
        store.activeNode = store.activeNode === b.dataset.node ? "all" : b.dataset.node;
        document.getElementById("asset-name").textContent =
          store.activeNode === "all" ? "ALL NODES" : store.activeNode;
        el.querySelectorAll("[data-node]").forEach(x => x.classList.toggle("on", x.dataset.node === store.activeNode));
        renderTable();
      });
    });
  }

  function flowRow(f, isNew) {
    const color = CLASS_COLORS[f.prediction] || "#4fb8f7";
    const malicious = f.prediction !== "BENIGN";
    const cls = isNew ? (malicious ? "flash-alert" : "flash") : "";
    return `
      <tr class="${cls}">
        <td><div class="flow-cell"><span class="flow-dot" style="background:${color}"></span><span class="flow-name">${f.id}</span></div></td>
        <td class="mono">${f.src_ip}</td>
        <td>${f.node}</td>
        <td class="mono">${f.dst_port}</td>
        <td>${f.protocol}</td>
        <td class="mono">${fmt.dur(f.duration)}</td>
        <td class="mono">${fmt.num(f.packets)}</td>
        <td class="mono">${fmt.bytes(f.bytes_per_sec)}</td>
        <td><span class="tag ${CLASS_TAG[f.prediction] || "tag-brute"}">${f.prediction}</span></td>
        <td>
          <div class="conf-bar">
            <span class="mono">${f.confidence.toFixed(3)}</span>
            <span class="conf-track"><span class="conf-fill" style="width:${f.confidence * 100}%;background:${color}"></span></span>
          </div>
        </td>
        <td>
          <div class="row-actions">
            ${malicious
              ? `<button class="row-btn danger" data-block="${f.id}">${f.mitigated ? "BLOCKED" : "BLOCK"}</button>`
              : `<button class="row-btn" data-allow="${f.id}">ALLOW</button>`}
            <button class="row-btn ghost" data-detail="${f.id}">DETAILS</button>
          </div>
        </td>
      </tr>`;
  }

  function eventRow(e) {
    return `
      <tr>
        <td class="mono">${fmt.time(e.ts)}</td>
        <td colspan="9" style="color:${e.color}">${e.text}</td>
        <td></td>
      </tr>`;
  }

  function visibleFlows() {
    let rows = store.flows;
    if (store.activeNode !== "all") rows = rows.filter(f => f.node === store.activeNode);
    if (store.tab === "flagged") rows = rows.filter(f => f.prediction !== "BENIGN");
    if (store.tab === "mitigated") rows = rows.filter(f => f.mitigated);
    return rows.slice(0, cfg.maxTableRows);
  }

  function renderTable(newId) {
    const body = document.getElementById("flow-body");
    if (store.tab === "log") {
      body.innerHTML = store.events.length
        ? store.events.slice(0, cfg.maxTableRows).map(eventRow).join("")
        : `<tr><td colspan="11" class="empty-state">No model events yet.</td></tr>`;
      return;
    }
    const rows = visibleFlows();
    body.innerHTML = rows.length
      ? rows.map(f => flowRow(f, f.id === newId)).join("")
      : `<tr><td colspan="11" class="empty-state">No flows match this filter.</td></tr>`;

    body.querySelectorAll("[data-block]").forEach(b => {
      b.addEventListener("click", async () => {
        const f = store.flows.find(x => x.id === b.dataset.block);
        if (!f) return;
        await api.mitigate(f.id, f.src_ip);
        f.mitigated = true;
        logEvent(`Mitigation rule pushed for ${f.src_ip} (${f.prediction})`, "#ff5064");
        toast(`Blocked ${f.src_ip}`);
        renderTable();
      });
    });
    body.querySelectorAll("[data-allow]").forEach(b => {
      b.addEventListener("click", () => {
        const f = store.flows.find(x => x.id === b.dataset.allow);
        logEvent(`Flow ${b.dataset.allow} whitelisted by operator`, "#2fe08a");
        toast(`Allowed ${f ? f.src_ip : b.dataset.allow}`);
      });
    });
    body.querySelectorAll("[data-detail]").forEach(b => {
      b.addEventListener("click", () => {
        const f = store.flows.find(x => x.id === b.dataset.detail);
        if (f) toast(`${f.id} · ${f.packets} pkts · ${f.protocol} :${f.dst_port} · p=${f.confidence.toFixed(3)}`);
      });
    });
  }

  function logEvent(text, color) {
    store.events.unshift({ ts: Date.now(), text, color: color || "#9daab1" });
    if (store.events.length > 120) store.events.pop();
    if (store.tab === "log") renderTable();
  }

  function setVerdict(threat) {
    const isThreat = threat >= store.threshold * 100 * 0.45;
    document.getElementById("v-threat").classList.toggle("on", isThreat);
    document.getElementById("v-clear").classList.toggle("on", !isThreat);
    document.getElementById("headline").classList.toggle("alarm", isThreat);
    const btn = document.getElementById("btn-mitigate");
    btn.classList.toggle("armed", isThreat);
    btn.textContent = isThreat ? "ENGAGE MITIGATION" : "SYSTEM NOMINAL";
  }

  /* ── live loop ───────────────────────────────────── */
  async function tickMetrics() {
    if (store.paused) return;
    const p = await api.getPoint();
    const d = mainChart.data;
    d.labels.push(fmt.time(p.ts));
    d.datasets[0].data.push(p.throughput);
    d.datasets[1].data.push(p.threat);
    d.datasets[2].data.push(store.threshold * 100);
    const cap = RANGE_POINTS[store.range];
    while (d.labels.length > cap) {
      d.labels.shift();
      d.datasets.forEach(ds => ds.data.shift());
    }
    mainChart.update("none");

    store.lastThreat = p.threat;
    store.peak = Math.max(store.peak, p.throughput);
    store.floor = Math.min(store.floor, p.throughput);

    document.getElementById("headline-val").textContent = fmt.num(p.throughput, 1);
    document.getElementById("meta-high").textContent = fmt.num(store.peak, 1);
    document.getElementById("meta-low").textContent = fmt.num(store.floor, 1);
    document.getElementById("meta-threat").textContent = p.threat.toFixed(1);
    setVerdict(p.threat);

    if (p.threat > 60 && Math.random() < 0.4) {
      logEvent(`Volumetric anomaly on ${cfg.nodes[0].label} — threat score ${p.threat.toFixed(1)}`, "#ffb545");
    }

    const s = await api.getSummary();
    renderStats(s);
    document.getElementById("foot-latency").textContent = s.inference_ms + " ms";
    document.getElementById("confidence-val").textContent = s.avg_confidence.toFixed(3);
    const conf = document.getElementById("confidence-val");
    conf.className = "big-metric " + (s.phase === 2 ? "risk-high" : s.phase === 1 ? "risk-med" : "risk-low");
    const sbFlows = document.getElementById("sb-flows");
    if (sbFlows) sbFlows.innerHTML = `${fmt.num(s.flows_per_min)}<small>flows / min</small>`;
    document.getElementById("btn-threats").innerHTML =
      `${icon("alert", 12)} ${fmt.num(store.flows.filter(f => f.prediction !== "BENIGN").length)} flagged`;

    updateSourceBadge();
  }

  // A monitoring tool must never imply synthetic data is real traffic.
  function updateSourceBadge() {
    const degraded = api.isLive() && api.isDegraded();
    const pill = document.getElementById("stream-pill");
    const sb = document.getElementById("sb-source");
    if (store.paused) return;

    if (degraded) {
      pill.className = "pill";
      pill.style.color = "#ffb545";
      pill.innerHTML = `<span class="dot" style="background:#ffb545"></span> Backend unreachable — demo data`;
      if (sb) sb.textContent = "Backend unreachable";
    } else {
      pill.className = "pill live";
      pill.style.color = "";
      pill.innerHTML = `<span class="dot pulse"></span> ${api.isLive() ? "Live" : "Demo"}`;
      if (sb) sb.textContent = api.isLive() ? "Live model stream" : "Demo data stream";
    }
  }

  async function tickFlow() {
    if (store.paused) return;
    const f = await api.getFlow();
    store.flows.unshift(f);
    store.packets += f.packets;
    if (store.flows.length > 300) store.flows.pop();
    document.getElementById("meta-vol").textContent = fmt.num(store.packets);
    if (f.prediction !== "BENIGN" && f.confidence > 0.97) {
      logEvent(`${f.prediction} detected from ${f.src_ip} → :${f.dst_port} (p=${f.confidence.toFixed(3)})`, "#ff5064");
    }
    renderTable(f.id);
  }

  async function tickAnalytics() {
    if (store.paused) return;
    const [c, n, p, ns] = await Promise.all([
      api.getClassBreakdown(), api.getNodeTraffic(), api.getPortActivity(), api.getNodeStats()
    ]);
    classChart.data.datasets[0].data = c.values;
    classChart.update("none");
    nodeChart.data.datasets[0].data = n.values;
    nodeChart.update("none");
    portChart.data.datasets[0].data = p.values;
    portChart.update("none");
    renderNodeChips(ns);
  }

  /* ── controls ────────────────────────────────────── */
  function wireControls() {
    document.getElementById("asset-ico").innerHTML = icon("globe", 11);
    document.getElementById("tool-expand").innerHTML = icon("expand", 13);
    document.getElementById("tool-filter").innerHTML = icon("filter", 13);
    document.getElementById("tool-camera").innerHTML = icon("camera", 13);
    document.getElementById("ico-info").innerHTML = icon("info", 12);
    document.getElementById("btn-refresh").innerHTML = `${icon("refresh", 12)} Resync`;
    document.getElementById("btn-export").innerHTML = `${icon("download", 12)} Export`;
    document.getElementById("btn-threats").innerHTML = `${icon("alert", 12)} 0 flagged`;
    document.getElementById("btn-pause").innerHTML = `${icon("activity", 12)} Pause`;
    document.getElementById("btn-csv").innerHTML = `${icon("download", 12)} CSV`;
    document.getElementById("foot-model").textContent = `${cfg.model.name} · ${cfg.model.framework}`;

    const slider = document.getElementById("threshold-slider");
    slider.addEventListener("input", () => {
      store.threshold = slider.value / 100;
      document.getElementById("threshold-val").value = store.threshold.toFixed(2);
      mainChart.data.datasets[2].data = mainChart.data.labels.map(() => store.threshold * 100);
      mainChart.update("none");
      setVerdict(store.lastThreat);
    });
    slider.addEventListener("change", async () => {
      await api.setThreshold(store.threshold);
      logEvent(`Detection threshold set to τ=${store.threshold.toFixed(2)}`, "#4fb8f7");
      toast(`Threshold τ = ${store.threshold.toFixed(2)}`);
    });

    document.querySelectorAll("#range-seg button").forEach(b => {
      b.addEventListener("click", async () => {
        document.querySelectorAll("#range-seg button").forEach(x => x.classList.remove("on"));
        b.classList.add("on");
        store.range = b.dataset.range;
        const seed = await api.getHistory(RANGE_POINTS[store.range]);
        mainChart.data.labels = seed.labels.map(fmt.time);
        mainChart.data.datasets[0].data = seed.throughput;
        mainChart.data.datasets[1].data = seed.threat;
        mainChart.data.datasets[2].data = seed.labels.map(() => store.threshold * 100);
        mainChart.update();
      });
    });

    document.querySelectorAll("#table-tabs [data-tab]").forEach(b => {
      b.addEventListener("click", () => {
        document.querySelectorAll("#table-tabs [data-tab]").forEach(x => x.classList.remove("on"));
        b.classList.add("on");
        store.tab = b.dataset.tab;
        renderTable();
      });
    });

    document.querySelectorAll(".console-tabs button").forEach(b => {
      b.addEventListener("click", () => {
        document.querySelectorAll(".console-tabs button").forEach(x => x.classList.remove("on"));
        b.classList.add("on");
        const auto = b.dataset.mode === "auto";
        document.getElementById("chk-auto").checked = auto;
        logEvent(`Response mode switched to ${auto ? "autonomous" : "manual"}`, "#4fb8f7");
      });
    });

    document.querySelectorAll("[data-scope]").forEach(b => {
      b.addEventListener("click", () => {
        document.getElementById("scope-input").value = b.dataset.scope + "-networks";
      });
    });

    document.getElementById("btn-pause").addEventListener("click", (e) => {
      store.paused = !store.paused;
      e.currentTarget.innerHTML = `${icon("activity", 12)} ${store.paused ? "Resume" : "Pause"}`;
      document.getElementById("stream-pill").innerHTML =
        `<span class="dot ${store.paused ? "" : "pulse"}" style="background:${store.paused ? "#ffb545" : "#2fe08a"}"></span> ${store.paused ? "Paused" : "Live"}`;
    });

    document.getElementById("btn-refresh").addEventListener("click", async () => {
      const seed = await api.getHistory(RANGE_POINTS[store.range]);
      mainChart.data.labels = seed.labels.map(fmt.time);
      mainChart.data.datasets[0].data = seed.throughput;
      mainChart.data.datasets[1].data = seed.threat;
      mainChart.update();
      toast("Resynced with detection service");
    });

    document.getElementById("btn-mitigate").addEventListener("click", async () => {
      const targets = store.flows.filter(f => f.prediction !== "BENIGN" && !f.mitigated);
      for (const f of targets) { await api.mitigate(f.id, f.src_ip); f.mitigated = true; }
      logEvent(`Bulk mitigation applied to ${targets.length} flows`, "#ff5064");
      toast(targets.length ? `Mitigated ${targets.length} flows` : "No active threats to mitigate");
      renderTable();
    });

    document.getElementById("btn-csv").addEventListener("click", exportCsv);
    document.getElementById("btn-export").addEventListener("click", exportCsv);
  }

  function exportCsv() {
    const cols = ["id", "ts", "src_ip", "node", "dst_port", "protocol", "duration", "packets", "bytes_per_sec", "prediction", "confidence", "mitigated"];
    const lines = [cols.join(",")].concat(
      store.flows.map(f => cols.map(c => (c === "ts" ? new Date(f.ts).toISOString() : f[c])).join(","))
    );
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `aegis-flows-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast(`Exported ${store.flows.length} flows`);
  }

  /* ── boot ────────────────────────────────────────── */
  async function init() {
    mountSidebar("dashboard");
    document.getElementById("topbar-avatar").textContent = cfg.operator.initials;
    document.getElementById("meta-nodes").textContent = cfg.nodes.length;

    const seed = await api.getHistory(RANGE_POINTS[store.range]);
    buildMainChart(seed);
    store.peak = Math.max(...seed.throughput);
    store.floor = Math.min(...seed.throughput);

    const [c, n, p, ns] = await Promise.all([
      api.getClassBreakdown(), api.getNodeTraffic(), api.getPortActivity(), api.getNodeStats()
    ]);
    buildClassChart(c);
    buildNodeChart(n);
    buildPortChart(p);
    renderNodeChips(ns);

    wireControls();
    renderStats(await api.getSummary());

    const initial = await api.getFlows(22);
    store.flows = initial.sort((a, b) => b.ts - a.ts);
    store.packets = store.flows.reduce((s, f) => s + f.packets, 0);
    renderTable();

    logEvent(`Model ${cfg.model.name} loaded — ${cfg.model.dataset}, ${cfg.model.accuracy}% val. accuracy`, "#2fe08a");
    logEvent(`Monitoring ${cfg.nodes.length} network links for ${cfg.org}`, "#4fb8f7");

    if (api.isLive()) {
      api.connectStream();
      api.onFlow(f => { store.flows.unshift(f); renderTable(f.id); });
    }

    setInterval(tickMetrics, cfg.pollIntervalMs);
    setInterval(tickFlow, cfg.flowIntervalMs);
    setInterval(tickAnalytics, cfg.pollIntervalMs * 3);
  }

  init();
})();
