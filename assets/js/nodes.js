/**
 * Network Nodes.
 *
 * Each tile is one collection point. Selecting a tile filters the flow table
 * below it — the same /api/flows endpoint the dashboard uses, with `node` set,
 * so filtering happens in SQL rather than by shipping every flow to the browser.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt, toast, classMeta } = ui;
  const el = (id) => document.getElementById(id);

  const state = { nodes: [], selected: "all", query: "" };

  ui.mountSidebar("nodes");
  el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;
  el("ico-notice").innerHTML = icon("info", 15);

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    const user = await api.me();
    el("topbar-avatar").textContent = user.initials || "··";
    el("topbar-avatar").title = `${user.name} · ${user.role}`;

    await load();
    api.on("status", ui.setStreamState);
    api.connectStream();
    setInterval(load, 12000);
  }

  async function load() {
    try {
      state.nodes = await api.getNodes();
      renderTiles();
      await loadFlows();
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load nodes.");
    }
  }

  function renderTiles() {
    const grid = el("node-grid");
    if (!state.nodes.length) {
      grid.innerHTML = `<div class="panel empty-state">
        No nodes registered yet. Nodes appear as flows arrive that name them.
      </div>`;
      return;
    }

    const peak = Math.max.apply(null, state.nodes.map((n) => n.mbps).concat([0.01]));

    grid.innerHTML = state.nodes.map((n) => {
      const on = state.selected === n.label;
      const tone = n.status === "warn" ? "warn" : n.status === "down" ? "bad" : "ok";
      const color = tone === "ok" ? "var(--green)" : tone === "warn" ? "var(--amber)" : "var(--red)";
      return `
        <button class="node-tile" data-node="${esc(n.label)}"
                style="text-align:left;width:100%;${on ? "border-color:rgba(47,224,138,0.35)" : ""}">
          <div class="top">
            <div class="node-icon">${icon("router", 13)}</div>
            <div style="flex:1;min-width:0">
              <div class="name">${esc(n.label)}</div>
              <div class="desc">${esc(n.desc || "monitored link")}</div>
            </div>
            <span class="chip ${tone}">${esc((n.status || "ok").toUpperCase())}</span>
          </div>
          <div class="figs">
            <div class="fig">
              <div class="k">Throughput</div>
              <div class="v">${n.mbps.toFixed(2)}<span class="dim" style="font-size:10px"> Mbps</span></div>
            </div>
            <div class="fig">
              <div class="k">Flagged · 5m</div>
              <div class="v" style="color:${n.attacks ? "var(--red)" : "var(--green)"}">${esc(fmt.num(n.attacks))}</div>
            </div>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:${Math.min(100, (n.mbps / peak) * 100)}%;background:${color}"></div>
          </div>
        </button>`;
    }).join("");

    grid.querySelectorAll("[data-node]").forEach((tile) => {
      tile.addEventListener("click", () => {
        // Clicking the selected tile clears the filter.
        state.selected = state.selected === tile.dataset.node ? "all" : tile.dataset.node;
        el("sel-pill").textContent = state.selected === "all" ? "all nodes" : state.selected;
        renderTiles();
        loadFlows();
      });
    });
  }

  async function loadFlows() {
    const flows = await api.getFlows({ limit: 40, tab: "live", node: state.selected, q: state.query });
    const body = el("flow-body");

    if (!flows.length) {
      body.innerHTML = `<tr><td colspan="8" class="empty-state">
        No recent flows${state.selected === "all" ? "" : ` on ${esc(state.selected)}`}.
      </td></tr>`;
      return;
    }

    body.innerHTML = flows.map((f) => {
      const meta = classMeta(f.prediction);
      const conf = Math.round(f.confidence * 100);
      return `
        <tr>
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
          <td class="mono">${esc(f.dst_port)}</td>
          <td>${esc(f.protocol)}</td>
          <td class="mono">${esc(fmt.num(f.packets))}</td>
          <td class="mono">${esc(fmt.bytes(f.bytes_per_sec))}</td>
          <td><span class="tag" style="background:${meta.color}1f;color:${meta.color}">${esc(meta.short)}</span></td>
          <td>
            <div class="conf-bar">
              <div class="conf-track"><div class="conf-fill" style="width:${conf}%;background:${meta.color}"></div></div>
              <span class="mono" style="font-size:10.5px">${conf}%</span>
            </div>
          </td>
        </tr>`;
    }).join("");
  }

  el("btn-refresh").addEventListener("click", async () => {
    await load();
    toast("Refreshed from the API.");
  });

  window.SENTRY_ON_SEARCH = function (q) {
    state.query = q;
    loadFlows();
  };
})();
