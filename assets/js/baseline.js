/**
 * Baseline and anomalies.
 *
 * The hard part of this page is not the chart, it is refusing to imply
 * certainty the backend does not have. A baseline needs days of traffic before
 * it means anything, and an empty anomaly table during that period reads as
 * "verified clean" when it actually means "no opinion yet". So warmth is shown
 * before the results, and the empty state changes wording depending on whether
 * the profile is warm.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt, toast, severityMeta } = ui;
  const el = (id) => document.getElementById(id);

  const state = {
    metric: "flows",
    status: "open",
    day: 0,          // 0 = weekday, 1 = weekend
    payload: null,
    anomalies: [],
    canAck: false,
    chart: null,
    timer: null
  };

  ui.mountSidebar("baseline");
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
    state.canAck = user.role === "admin" || user.role === "analyst";

    buildChart();

    el("in-metric").addEventListener("change", (e) => {
      state.metric = e.target.value;
      load();
    });
    el("btn-refresh").addEventListener("click", () => load());

    document.querySelectorAll("[data-status]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.status = btn.getAttribute("data-status");
        load();
      });
    });

    document.querySelectorAll("[data-day]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.day = Number(btn.getAttribute("data-day"));
        el("profile-pill").textContent = state.day ? "weekend" : "weekday";
        paintProfile();
      });
    });

    await load();

    // The backend only produces a new observation once per baseline window, so
    // polling faster than that would just re-fetch an unchanged answer.
    const period = (state.payload && state.payload.window_seconds) || 300;
    state.timer = setInterval(load, Math.min(period, 120) * 1000);
  }

  async function load() {
    const btn = el("btn-refresh");
    btn.disabled = true;
    try {
      const [profile, anomalies] = await Promise.all([
        api.getBaseline(state.metric),
        api.getAnomalies(state.status, 100)
      ]);
      state.payload = profile;
      state.anomalies = anomalies;
      paintWarmup();
      paintStats();
      paintAnomalies();
      paintProfile();
    } catch (err) {
      if (err.status === 401) return;
      toast(err.message || "Could not load baseline data.", "err");
    } finally {
      btn.disabled = false;
    }
  }

  /**
   * Shown above everything else while the profile is still learning. An
   * operator who reads "0 anomalies" without this has been told the network is
   * clean, which is not what an unwarmed baseline knows.
   */
  function paintWarmup() {
    const w = state.payload.warmth;
    const host = el("warmup-notice");
    if (w.percent >= 100) {
      host.innerHTML = "";
      return;
    }
    host.innerHTML = `
      <div class="notice" style="margin-top:10px;border-color:rgba(255,180,60,0.28)">
        <span>${icon("info", 15)}</span>
        <span>
          <b>Still learning.</b> ${fmt.num(w.slots_ready)} of ${fmt.num(w.slots_total)}
          time slots (${w.percent}%) have the ${w.min_samples} observations they need
          before they will report anything. Until a slot is ready it stays silent, so
          an empty anomaly list here means <b>no opinion yet</b> rather than all clear.
        </span>
      </div>`;
  }

  function paintStats() {
    const p = state.payload;
    const open = state.anomalies.filter((a) => a.status === "open");
    const worst = open.reduce(
      (best, a) => (Math.abs(a.peak_deviation) > (best ? Math.abs(best.peak_deviation) : -1) ? a : best),
      null);
    const current = p.current.values[state.metric];
    const slot = (p.slots || []).find((s) => s.bucket === p.current.bucket);

    const stats = [
      ["Window", `${Math.round(p.window_seconds / 60)}m`, "per observation"],
      ["Baseline warmth", `${p.warmth.percent}%`,
        `${fmt.num(p.warmth.slots_ready)} of ${fmt.num(p.warmth.slots_total)} slots ready`],
      ["Right now", metricValue(current),
        slot && slot.ready ? `expected ${metricValue(slot.mean)}` : "this slot is still learning"],
      ["Open anomalies", fmt.num(open.length),
        open.length ? "listed below" : "none currently"],
      ["Largest deviation", worst ? `${worst.peak_deviation.toFixed(1)}σ` : "—",
        worst ? esc(worst.metric_label) : "nothing outside the baseline"]
    ];

    el("stat-strip").innerHTML = stats.map(([k, v, d]) => `
      <div class="stat">
        <div class="k">${esc(k)}</div>
        <div class="v">${v}</div>
        <div class="d">${d}</div>
      </div>`).join("");
  }

  function metricValue(v) {
    if (v === undefined || v === null) return "—";
    return state.metric === "bytes" ? fmt.size(v) : fmt.num(Math.round(v));
  }

  function paintAnomalies() {
    const body = el("anomaly-body");
    const note = el("anomaly-note");
    const rows = state.anomalies;

    if (!rows.length) {
      body.innerHTML = "";
      note.textContent = state.payload.warmth.percent > 0
        ? `No ${state.status === "all" ? "" : state.status + " "}anomalies. The slots that are ready have seen nothing outside their normal range.`
        : "Nothing yet — the baseline has not finished its first observations.";
      return;
    }

    note.innerHTML = `Deviation is measured in standard deviations from the value
      learned for this time of week. Anything past ${state.payload.z_threshold}σ is
      reported; a continuing condition extends one row rather than opening a new one
      each window.`;

    body.innerHTML = rows.map((a) => {
      const sev = severityMeta(a.severity);
      const up = a.direction === "spike";
      const arrow = up ? "var(--red)" : "var(--amber)";
      return `
        <tr${a.status === "open" ? ' style="background:rgba(255,80,100,0.04)"' : ""}>
          <td>
            <div class="flow-cell">
              <span style="color:${arrow};display:flex">${icon(up ? "arrowUp" : "arrowDown", 12)}</span>
              <span class="flow-name">${esc(a.metric_label)} ${up ? "spike" : "drop"}</span>
            </div>
          </td>
          <td>
            <span style="color:${sev.color};font-weight:700;font-size:11px">
              ${esc(sev.label.toUpperCase())}
            </span>
          </td>
          <td class="mono">${valueFor(a.metric, a.observed)}</td>
          <td class="mono" style="color:var(--text-dim)">${valueFor(a.metric, a.expected)}</td>
          <td class="mono"${up ? ' style="color:var(--red)"' : ""}>${a.deviation.toFixed(1)}σ</td>
          <td class="mono">${a.windows} window${a.windows === 1 ? "" : "s"}</td>
          <td style="font-size:11px;color:var(--text-dim)">${esc(fmt.ago(a.ts * 1000))}</td>
          <td style="font-size:11px;color:var(--text-dim)">${esc(fmt.ago(a.last_seen_at * 1000))}</td>
          <td>${statusChip(a)}</td>
          <td>${ackCell(a)}</td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-ack]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        try {
          await api.acknowledgeAnomaly(Number(btn.getAttribute("data-ack")));
          toast("Anomaly acknowledged.");
          await load();
        } catch (err) {
          toast(err.message || "Could not acknowledge.", "err");
          btn.disabled = false;
        }
      });
    });
  }

  function statusChip(a) {
    if (a.status === "resolved") {
      return `<span class="chip ok">${icon("check", 10)} RESOLVED</span>`;
    }
    if (a.status === "acknowledged") {
      return `<span class="chip info" title="${esc(a.acknowledged_by || "")}">ACK${
        a.acknowledged_by ? ` · ${esc(a.acknowledged_by)}` : ""}</span>`;
    }
    return `<span class="chip bad">OPEN</span>`;
  }

  function ackCell(a) {
    if (!state.canAck || a.status !== "open") return "";
    return `<button class="btn btn-sm" data-ack="${a.id}">Acknowledge</button>`;
  }

  function valueFor(metric, v) {
    return metric === "bytes" ? fmt.size(v) : fmt.num(Math.round(v));
  }

  // ── chart ───────────────────────────────────────────────────────────────
  function buildChart() {
    const grid = "rgba(255,255,255,0.045)";
    const tick = { color: "#6d7d85", font: { size: 10, family: "JetBrains Mono" } };

    state.chart = new Chart(el("profileChart"), {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Alert threshold", data: [], borderColor: "rgba(255,80,100,0.55)",
            borderWidth: 1.4, borderDash: [4, 3], fill: false, tension: 0.3,
            pointRadius: 0
          },
          {
            label: "Learned normal", data: [], borderColor: "#4fb8f7",
            backgroundColor: "rgba(79,184,247,0.10)", borderWidth: 2,
            fill: false, tension: 0.34, pointRadius: 0
          },
          {
            label: "Not yet learned", data: [], borderColor: "rgba(140,155,163,0.45)",
            borderWidth: 1.4, borderDash: [2, 3], fill: false, tension: 0.34,
            pointRadius: 0
          }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: {
          legend: {
            labels: { color: "#9daab1", boxWidth: 10, font: { size: 10.5 }, padding: 10 }
          },
          tooltip: {
            backgroundColor: "#141a1d", borderColor: "#1e2629", borderWidth: 1,
            titleColor: "#e7eef1", bodyColor: "#9daab1", padding: 10
          }
        },
        scales: {
          x: { grid: { color: grid }, ticks: Object.assign({ maxTicksLimit: 12 }, tick) },
          y: { grid: { color: grid }, ticks: tick, beginAtZero: true }
        }
      }
    });
  }

  /**
   * Warm and cold hours are drawn as separate series rather than one line with
   * a styled segment. A single line would imply the whole day has been learned
   * when most of it may not have been, and that is exactly the impression this
   * page must not give.
   */
  function paintProfile() {
    const slots = state.payload.slots || [];
    const offset = state.day * 24;
    const byHour = {};
    slots.forEach((s) => {
      if (s.bucket >= offset && s.bucket < offset + 24) byHour[s.bucket - offset] = s;
    });

    const labels = [];
    const threshold = [];
    const warm = [];
    const cold = [];

    for (let h = 0; h < 24; h++) {
      labels.push(`${String(h).padStart(2, "0")}:00`);
      const s = byHour[h];
      if (!s || !s.samples) {
        threshold.push(null); warm.push(null); cold.push(null);
        continue;
      }
      if (s.ready) {
        warm.push(s.mean);
        cold.push(null);
        threshold.push(s.mean + state.payload.z_threshold * s.sigma);
      } else {
        warm.push(null);
        cold.push(s.mean);
        threshold.push(null);
      }
    }

    state.chart.data.labels = labels;
    state.chart.data.datasets[0].data = threshold;
    state.chart.data.datasets[1].data = warm;
    state.chart.data.datasets[2].data = cold;
    state.chart.update();

    const ready = Object.values(byHour).filter((s) => s.ready).length;
    const label = state.day ? "weekend" : "weekday";
    el("profile-title").textContent =
      `Learned profile — ${el("in-metric").selectedOptions[0].text.toLowerCase()}`;
    el("profile-note").textContent = ready
      ? `${ready} of 24 ${label} hours have enough observations to be scored against. `
        + `The dashed red line is where an observation becomes an anomaly.`
      : `No ${label} hour has enough observations yet. Values shown are what has been `
        + `seen so far, not a baseline that will be scored against.`;
  }
})();
