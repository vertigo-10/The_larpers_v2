/**
 * Model Performance.
 *
 * This page exists to stop the dashboard from being read as a real-world
 * accuracy claim. The deployed network scores 100% on its held-out split, which
 * is not a good result — it means the synthetic classes are trivially separable.
 * That caveat is rendered first, before any number, and is not dismissable.
 *
 * The "live agreement" section is a different measurement: it compares what the
 * traffic generator intended against what the model independently predicted, so
 * it is a genuine signal about served inference rather than a replay of training
 * metrics.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt, toast, classMeta } = ui;
  const el = (id) => document.getElementById(id);

  ui.mountSidebar("model");
  el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;
  el("ico-warn").innerHTML = icon("alert", 15);
  el("ico-warn").querySelector("svg").style.color = "var(--amber)";

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    const user = await api.me();
    el("topbar-avatar").textContent = user.initials || "··";
    el("topbar-avatar").title = `${user.name} · ${user.role}`;
    await load();
    setInterval(load, 30000);
  }

  async function load() {
    try {
      const [status, metrics] = await Promise.all([api.getStatus(), api.getModelMetrics()]);
      render(status, metrics);
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load model metrics.");
    }
  }

  function render(status, m) {
    const t = m.training || {};

    if (!m.ready) {
      ui.fatalBanner(`Model not loaded: ${m.error || "unknown error"}`);
    }

    el("honesty-text").innerHTML =
      `<b>Provenance:</b> ${esc(t.dataset_note ||
        "No dataset note recorded — treat every score below as unverified.")}`;

    el("crumb").textContent = `/ ${status.model_name} · ${status.architecture || "MLP"}`;

    // ── headline numbers ──────────────────────────────────────────────
    const cards = [
      { k: "Test accuracy", v: t.accuracy !== undefined ? `${t.accuracy}%` : "—",
        d: `on ${esc(t.dataset || "unknown")} data`, cls: "" },
      { k: "Mean confidence", v: t.mean_confidence !== undefined ? `${t.mean_confidence}%` : "—",
        d: "how sure it is when it decides", cls: "" },
      { k: "Live agreement",
        v: m.live.agreement_pct === null ? "—" : `${m.live.agreement_pct}%`,
        d: m.live.scored ? `over ${fmt.num(m.live.scored)} simulated flows` : "no simulated flows yet",
        cls: "" },
      { k: "Status", v: m.ready ? "LOADED" : "DOWN",
        d: m.ready ? `${esc(t.framework || "PyTorch")}` : esc(m.error || ""),
        cls: m.ready ? "up" : "down" }
    ];
    el("stat-strip").innerHTML = cards.map((c) => `
      <div class="stat">
        <div class="k">${esc(c.k)}</div>
        <div class="v ${c.cls}">${esc(c.v)}</div>
        <div class="d dim">${c.d}</div>
      </div>`).join("");

    el("split-pill").textContent = t.test_samples
      ? `${fmt.num(t.test_samples)} test / ${fmt.num(t.train_samples)} train`
      : "no split recorded";

    // ── per class ─────────────────────────────────────────────────────
    const per = t.per_class || {};
    const names = Object.keys(per);
    el("perclass-body").innerHTML = names.length
      ? names.map((name) => {
          const p = per[name];
          const meta = classMeta(name);
          return `
            <tr>
              <td>
                <div class="flow-cell">
                  <span class="flow-dot" style="background:${meta.color}"></span>
                  <span class="flow-name">${esc(meta.label)}</span>
                </div>
              </td>
              <td class="mono">${esc(p.precision)}%</td>
              <td class="mono">${esc(p.recall)}%</td>
              <td class="mono">${esc(p.f1)}%</td>
              <td class="mono">${esc(fmt.num(p.support))}</td>
            </tr>`;
        }).join("")
      : `<tr><td colspan="5" class="empty-state">No per-class metrics were recorded at training time.</td></tr>`;

    // ── architecture + features ───────────────────────────────────────
    const arch = [
      ["Name", status.model_name],
      ["Framework", t.framework || status.framework],
      ["Architecture", t.architecture || status.architecture || "—"],
      ["Classes", status.classes.map((c) => classMeta(c).label).join(", ")],
      ["Epochs", t.epochs !== undefined ? String(t.epochs) : "—"],
      ["Trained", t.trained_at ? fmt.datetime(t.trained_at) : "—"],
      ["Dataset", t.dataset || "unknown"],
      ["Server uptime", fmt.uptime(status.uptime_s)],
      ["API version", status.version]
    ];
    el("arch-list").innerHTML = arch.map(([k, v]) => `
      <div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join("");

    const features = t.features || [];
    el("feature-list").innerHTML = features.length
      ? features.map((f, i) => `
          <div class="kv">
            <span class="k mono">${i + 1}</span>
            <span class="v mono">${esc(f)}</span>
          </div>`).join("")
      : `<div class="section-note">No feature list recorded.</div>`;

    renderMatrix(t, status.classes);
    renderLive(m.live);
  }

  function renderMatrix(t, classes) {
    const cm = t.confusion_matrix;
    const names = t.classes || classes;
    if (!cm || !cm.length) {
      el("matrix-box").innerHTML =
        `<div class="empty-state">No confusion matrix was recorded at training time.</div>`;
      return;
    }

    const head = names.map((n) => `<th>${esc(classMeta(n).short)}</th>`).join("");
    const rows = cm.map((row, i) => {
      const cells = row.map((v, j) => {
        const cls = v === 0 ? "" : i === j ? "hit" : "miss";
        return `<td class="mono ${cls}">${esc(fmt.num(v))}</td>`;
      }).join("");
      return `<tr><th style="text-align:left">${esc(classMeta(names[i]).label)}</th>${cells}</tr>`;
    }).join("");

    el("matrix-box").innerHTML = `
      <table class="matrix">
        <thead><tr><th></th>${head}</tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div class="section-note" style="padding:12px 0 0">
        A perfectly diagonal matrix on synthetic data is a warning sign, not a
        win: it means the generated classes never overlap. Real captured traffic
        will not look like this.
      </div>`;
  }

  function renderLive(live) {
    el("live-pill").textContent = live.scored
      ? `${fmt.num(live.agreed)} / ${fmt.num(live.scored)} agreed`
      : "no data";

    if (!live.scored) {
      el("live-box").innerHTML = `<div class="empty-state" style="padding:24px">
        No simulated flows scored yet. Ingested traffic has no ground truth, so
        it cannot be measured here.
      </div>`;
      return;
    }

    // Only disagreements are worth showing — the diagonal is the boring case.
    const misses = live.matrix.filter((r) => r.truth !== r.predicted)
      .sort((a, b) => b.count - a.count);

    el("live-box").innerHTML = `
      <div style="font-size:12px;color:var(--text-dim);line-height:1.65;margin-bottom:12px">
        ${esc(live.note)}
      </div>
      ${misses.length ? `
        <div class="field-label">Disagreements</div>
        <table class="matrix" style="width:100%">
          <thead><tr><th style="text-align:left">Generator intended</th><th style="text-align:left">Model predicted</th><th>Flows</th></tr></thead>
          <tbody>
            ${misses.map((r) => `
              <tr>
                <td style="text-align:left">${esc(classMeta(r.truth).label)}</td>
                <td style="text-align:left;color:${classMeta(r.predicted).color}">${esc(classMeta(r.predicted).label)}</td>
                <td class="mono">${esc(fmt.num(r.count))}</td>
              </tr>`).join("")}
          </tbody>
        </table>
        <div class="section-note" style="padding:12px 0 0">
          A benign flow predicted as an attack is a false positive. With
          auto-mitigate enabled those get marked for blocking, so this number is
          the one to watch before turning enforcement on.
        </div>`
        : `<div class="chip ok">${icon("check", 10)} No disagreements recorded</div>`}`;
  }

  el("btn-refresh").addEventListener("click", async () => {
    await load();
    toast("Refreshed model metrics.");
  });
})();
