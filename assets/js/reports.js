/**
 * Reports.
 *
 * A period summary an operator can hand to someone who does not watch the live
 * dashboard. Everything is aggregated server-side over the requested window.
 *
 * Note the deliberate wording throughout: flows are "flagged", not "attacks
 * blocked". SENTRY records a decision; it does not enforce it at the network
 * edge unless a deployment wires that up.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt, toast, classMeta } = ui;
  const el = (id) => document.getElementById(id);

  const state = { days: 7, report: null, user: null };
  let classChart, incChart;

  ui.mountSidebar("reports");
  el("btn-csv").innerHTML = `${icon("download", 12)} CSV`;
  el("btn-print").innerHTML = `${icon("file", 12)} Print / PDF`;
  el("ico-notice").innerHTML = icon("info", 15);

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    state.user = await api.me();
    el("topbar-avatar").textContent = state.user.initials || "··";
    el("topbar-avatar").title = `${state.user.name} · ${state.user.role}`;
    buildCharts();
    await load();
  }

  async function load() {
    try {
      state.report = await api.getReport(state.days);
      render(state.report);
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not generate the report.");
    }
  }

  function render(r) {
    el("crumb").textContent = `/ last ${r.period_days} day${r.period_days === 1 ? "" : "s"}`;
    el("report-header").innerHTML =
      `<b>${esc(r.org)}</b> — ${esc(fmt.num(r.totals.flows))} flows scored between ` +
      `${esc(fmt.datetime(r.generated_at - r.period_days * 86400000))} and ` +
      `${esc(fmt.datetime(r.generated_at))}.`;

    const t = r.totals;
    const cards = [
      { k: "Flows scored", v: fmt.num(t.flows), d: "through the model", cls: "" },
      { k: "Flagged", v: fmt.num(t.attacks), d: "predicted as non-benign",
        cls: t.attacks ? "down" : "up" },
      { k: "Attack rate", v: `${t.attack_rate_pct}%`, d: "of all scored flows", cls: "" },
      { k: "Mitigated", v: fmt.num(t.mitigated), d: "recorded, not enforced", cls: "up" },
      { k: "Incidents opened", v: fmt.num(r.incidents.opened), d: "correlated groups", cls: "" },
      { k: "Incidents resolved", v: fmt.num(r.incidents.resolved), d: "closed by an operator",
        cls: "up" }
    ];
    el("totals").innerHTML = cards.map((c) => `
      <div class="stat">
        <div class="k">${esc(c.k)}</div>
        <div class="v ${c.cls}">${esc(c.v)}</div>
        <div class="d dim">${esc(c.d)}</div>
      </div>`).join("");

    classChart.data.labels = r.by_class.map((c) => classMeta(c.label).label);
    classChart.data.datasets[0].data = r.by_class.map((c) => c.count);
    classChart.data.datasets[0].backgroundColor = r.by_class.map((c) => classMeta(c.label).color);
    classChart.update();

    incChart.data.datasets[0].data = [r.incidents.opened, r.incidents.resolved];
    incChart.update();

    renderSources(r);
  }

  function renderSources(r) {
    const body = el("src-body");
    if (!r.top_sources.length) {
      body.innerHTML = `<tr><td colspan="5" class="empty-state">
        No flagged traffic in this period.
      </td></tr>`;
      return;
    }

    const total = r.totals.attacks || 1;
    const canAct = state.user.role !== "viewer";

    body.innerHTML = r.top_sources.map((s, i) => {
      const pct = (s.count / total) * 100;
      return `
        <tr>
          <td class="mono dim">${i + 1}</td>
          <td class="mono">${esc(s.src_ip)}</td>
          <td class="mono">${esc(fmt.num(s.count))}</td>
          <td>
            <div class="conf-bar">
              <div class="conf-track" style="width:90px">
                <div class="conf-fill" style="width:${Math.min(100, pct)}%;background:var(--red)"></div>
              </div>
              <span class="mono" style="font-size:10.5px">${pct.toFixed(1)}%</span>
            </div>
          </td>
          <td>
            <div class="row-actions">
              ${canAct
                ? `<button class="row-btn danger" data-ip="${esc(s.src_ip)}">MITIGATE</button>`
                : `<span class="chip">READ ONLY</span>`}
            </div>
          </td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-ip]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        btn.textContent = "…";
        try {
          const res = await api.mitigate(null, btn.dataset.ip);
          toast(`${res.count} flow(s) from ${btn.dataset.ip} marked mitigated.`);
          await load();
        } catch (err) {
          toast(err.message, "err");
          btn.disabled = false;
          btn.textContent = "MITIGATE";
        }
      });
    });
  }

  el("range-seg").querySelectorAll("[data-days]").forEach((btn) => {
    btn.addEventListener("click", () => {
      el("range-seg").querySelectorAll("button").forEach((b) => b.classList.remove("on"));
      btn.classList.add("on");
      state.days = Number(btn.dataset.days);
      load();
    });
  });

  el("btn-csv").addEventListener("click", () => {
    const r = state.report;
    if (!r) return;
    const cell = (v) => `"${String(v === null || v === undefined ? "" : v).replace(/"/g, '""')}"`;
    const lines = [
      ["SENTRY report"], [""],
      ["Organisation", r.org],
      ["Period (days)", r.period_days],
      ["Generated", new Date(r.generated_at).toISOString()],
      [""],
      ["Flows scored", r.totals.flows],
      ["Flagged", r.totals.attacks],
      ["Attack rate %", r.totals.attack_rate_pct],
      ["Mitigated (recorded, not enforced)", r.totals.mitigated],
      ["Incidents opened", r.incidents.opened],
      ["Incidents resolved", r.incidents.resolved],
      [""],
      ["Class", "Flows"]
    ].concat(
      r.by_class.map((c) => [c.label, c.count]),
      [[""], ["Top flagged source", "Flagged flows"]],
      r.top_sources.map((s) => [s.src_ip, s.count])
    );
    const csv = lines.map((row) => row.map(cell).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sentry-report-${r.period_days}d-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Report exported as CSV.");
  });

  // The browser's own print dialog covers "save as PDF" on every platform,
  // which is cheaper and more reliable than bundling a PDF library.
  el("btn-print").addEventListener("click", () => window.print());

  function buildCharts() {
    const grid = "rgba(255,255,255,0.045)";
    const tick = { color: "#6d7d85", font: { size: 10, family: "JetBrains Mono" } };

    classChart = new Chart(el("classChart"), {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 5 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: tick },
          y: { grid: { color: grid }, ticks: tick, beginAtZero: true }
        }
      }
    });

    incChart = new Chart(el("incChart"), {
      type: "doughnut",
      data: {
        labels: ["Opened", "Resolved"],
        datasets: [{ data: [0, 0], backgroundColor: ["#ff5064", "#2fe08a"], borderWidth: 0 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: "60%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#9daab1", boxWidth: 9, font: { size: 11 }, padding: 12 }
          }
        }
      }
    });
  }
})();
