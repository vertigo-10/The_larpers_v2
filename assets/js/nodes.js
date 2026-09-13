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

  // `canRename` and `canRemove` mirror the two different server-side guards:
  // renaming is require_operator (admin or analyst), removal is require_admin.
  // They are drawn from the same distinction rather than one "can manage" flag
  // because collapsing them would show an analyst a delete button that always
  // 403s — an offer the API will not honour.
  //
  // This is presentation only. The API enforces both independently, so hiding a
  // control is a courtesy to the user, never the thing keeping them out.
  const state = {
    nodes: [], selected: "all", query: "",
    canRename: false, canRemove: false,
    editing: null, deleting: null
  };

  ui.mountSidebar("nodes");
  el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;
  el("ico-notice").innerHTML = icon("info", 15);
  el("ico-edit").innerHTML = icon("pencil", 15);
  el("ico-del").innerHTML = icon("trash", 15);

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    const user = await api.me();
    el("topbar-avatar").textContent = user.initials || "··";
    el("topbar-avatar").title = `${user.name} · ${user.role}`;
    state.canRename = user.role === "admin" || user.role === "analyst";
    state.canRemove = user.role === "admin";

    const copy = ui.orgCopy(user.org_type);
    el("page-title").textContent = copy.nodesTitle;
    el("crumb").textContent = `/ ${copy.nodesCrumb}`;
    el("notice-text").textContent = copy.nodesNotice;

    await load();
    api.on("status", ui.setStreamState);
    api.connectStream();
    setInterval(load, 12000);
  }

  /** Is a dialog currently up? */
  function modalOpen() {
    return el("edit-modal").classList.contains("show")
      || el("del-modal").classList.contains("show");
  }

  async function load() {
    try {
      state.nodes = await api.getNodes();
      // The twelve-second poll rebuilds every tile, which throws away the
      // action buttons and any focus sitting on one. Harmless while the page is
      // idle, but if a dialog is open the user is mid-edit on a row this would
      // replace underneath them — and tabbing between the name and description
      // fields would lose focus to a background repaint.
      if (!modalOpen()) renderTiles();
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
      const acts = [
        state.canRename
          ? `<button class="node-act" data-rename="${n.id}"
                     title="Rename ${esc(n.label)}"
                     aria-label="Rename ${esc(n.label)}">${icon("pencil", 12)}</button>`
          : "",
        state.canRemove
          ? `<button class="node-act danger" data-remove="${n.id}"
                     title="Remove ${esc(n.label)}"
                     aria-label="Remove ${esc(n.label)}">${icon("trash", 12)}</button>`
          : ""
      ].join("");
      return `
      <div class="node-tile-wrap">
        <button class="node-tile${acts ? " has-actions" : ""}" data-node="${esc(n.label)}"
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
        </button>
        ${acts ? `<div class="node-actions">${acts}</div>` : ""}
      </div>`;
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

    const byId = (id) => state.nodes.find((n) => String(n.id) === String(id));
    grid.querySelectorAll("[data-rename]").forEach((btn) => {
      btn.addEventListener("click", () => openEdit(byId(btn.dataset.rename)));
    });
    grid.querySelectorAll("[data-remove]").forEach((btn) => {
      btn.addEventListener("click", () => openDelete(byId(btn.dataset.remove)));
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
          <td class="mono">${esc(fmt.dest(f.dst_ip, f.dst_port))}</td>
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

  // ── rename ────────────────────────────────────────────────────────────
  const editModal = el("edit-modal");
  const closeEdit = () => editModal.classList.remove("show");

  function openEdit(row) {
    if (!row) return;
    state.editing = row;
    el("edit-err").classList.remove("show");
    el("e-label").value = row.label;
    el("e-desc").value = row.desc || "";
    editModal.classList.add("show");
    el("e-label").focus();
    el("e-label").select();
  }

  el("edit-close").addEventListener("click", closeEdit);
  el("edit-cancel").addEventListener("click", closeEdit);
  editModal.addEventListener("click", (ev) => {
    if (ev.target === editModal) closeEdit();
  });

  el("edit-save").addEventListener("click", async () => {
    const row = state.editing;
    if (!row) return;
    const err = el("edit-err");
    const fail = (msg) => { err.textContent = msg; err.classList.add("show"); };
    err.classList.remove("show");

    const label = el("e-label").value.trim();
    if (!label) return fail("A node needs a name.");

    const desc = el("e-desc").value.trim();
    if (label === row.label && desc === (row.desc || "")) {
      closeEdit();
      return;
    }

    try {
      await api.updateNode(row.id, { label: label, description: desc });
      // The old name may be the current filter, and it no longer exists.
      // Following the rename keeps the flow table showing the same device
      // rather than silently emptying.
      if (state.selected === row.label) {
        state.selected = label;
        el("sel-pill").textContent = label;
      }
      closeEdit();
      toast(label === row.label
        ? "Description updated."
        : `Renamed to ${label}. Past flows and incidents moved with it.`);
      await load();
    } catch (ex) {
      if (ex && ex.status === 401) return;
      // 409 is the name-clash case and the server's message already names the
      // offender, so it is shown as-is rather than replaced with a generic one.
      fail(ex.message || "Could not save the node.");
    }
  });

  // ── removal ───────────────────────────────────────────────────────────
  const delModal = el("del-modal");
  const closeDel = () => delModal.classList.remove("show");

  function openDelete(row) {
    if (!row) return;
    state.deleting = row;
    el("del-err").classList.remove("show");
    el("d-confirm").value = "";
    el("del-blurb").textContent =
      `${row.label} is carrying ${row.mbps.toFixed(2)} Mbps and has ` +
      `${fmt.num(row.attacks)} flagged flows in the last five minutes.`;
    delModal.classList.add("show");
    el("d-confirm").focus();
  }

  el("del-close").addEventListener("click", closeDel);
  el("del-cancel").addEventListener("click", closeDel);
  delModal.addEventListener("click", (ev) => {
    if (ev.target === delModal) closeDel();
  });

  el("del-confirm").addEventListener("click", async () => {
    const row = state.deleting;
    if (!row) return;
    const err = el("del-err");
    err.classList.remove("show");

    // Typed confirmation rather than a yes/no box, matching the exporters page.
    // Removing a node takes a device off the monitored inventory, and a gap in
    // coverage is not something to be one stray click away from.
    if (el("d-confirm").value.trim() !== row.label) {
      err.textContent = `Type ${row.label} exactly to confirm.`;
      err.classList.add("show");
      return;
    }

    try {
      await api.deleteNode(row.id);
      // The filter pointed at something that is gone. Left alone it would show
      // an empty table under a node name that is no longer in the grid.
      if (state.selected === row.label) {
        state.selected = "all";
        el("sel-pill").textContent = "all nodes";
      }
      closeDel();
      toast(`${row.label} removed. Its flows and incidents are kept.`);
      await load();
    } catch (ex) {
      if (ex && ex.status === 401) return;
      err.textContent = ex.message || "Could not remove the node.";
      err.classList.add("show");
    }
  });

  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    closeEdit();
    closeDel();
  });

  el("btn-refresh").addEventListener("click", async () => {
    await load();
    toast("Refreshed from the API.");
  });

  window.SENTRY_ON_SEARCH = function (q) {
    state.query = q;
    loadFlows();
  };
})();
