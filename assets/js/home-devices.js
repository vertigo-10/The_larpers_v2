/**
 * Consumer devices.
 *
 * nodes.html answers "what is each collection point carrying". This page
 * answers "is this thing behaving", which is the question someone asks about
 * their own TV. Same /api/nodes and /api/incidents underneath — a friendlier
 * endpoint computing its own answer is how a household ends up being reassured
 * about a device the enterprise view would have flagged.
 *
 * Alerts are folded into the device they were seen on rather than living only
 * on the alerts page, because "which of my things is the problem" is not
 * answerable from a flat list when every row says the same device name.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt } = ui;
  const el = (id) => document.getElementById(id);

  ui.mountSidebar("nodes");
  el("ico-notice").innerHTML = icon("info", 15);
  el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;
  el("btn-refresh").addEventListener("click", () => load());

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    const user = await api.me();
    el("topbar-avatar").textContent = user.initials || "··";
    el("topbar-avatar").title = user.name;
    el("crumb").textContent = `/ ${user.org_name}`;

    await load();
    api.on("status", ui.setStreamState);
    api.on("flow", scheduleRefresh);
    api.connectStream();
    setInterval(load, 15000);
  }

  let pending = null;
  function scheduleRefresh() {
    if (pending) return;
    pending = setTimeout(() => { pending = null; load(); }, 4000);
  }

  let state = { nodes: [], incidents: [] };

  async function load() {
    try {
      const [nodes, incidents] = await Promise.all([
        api.getNodes(),
        api.getIncidents("all", 100),
      ]);
      state = { nodes, incidents };
      renderStats();
      renderDevices();
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load your devices.");
    }
  }

  function renderStats() {
    const { nodes, incidents } = state;
    const busy = nodes.filter((n) => n.mbps >= 0.01);
    const troubled = nodes.filter((n) => n.status === "warn").length;
    const outstanding = incidents.filter((i) => !ui.isHandled(i)).length;
    const needAttention = nodes.filter((n) => openOn(n.label).length);
    const total = nodes.reduce((sum, n) => sum + n.mbps, 0);

    const cards = [
      {
        k: "Devices seen",
        v: fmt.num(nodes.length),
        d: busy.length
          ? `${fmt.num(busy.length)} sending traffic right now`
          : "None sending anything at the moment"
      },
      {
        k: "Need a look",
        v: fmt.num(needAttention.length),
        d: needAttention.length
          ? "Start with these"
          : troubled
            ? "Busy devices, but nothing left for you to do"
            : "Every device is acting normally"
      },
      {
        k: "Using right now",
        v: `${total.toFixed(2)} Mbps`,
        d: outstanding
          ? `${fmt.num(outstanding)} alert${outstanding === 1 ? "" : "s"} still open`
          : "Nothing waiting on you"
      }
    ];

    el("device-stats").innerHTML = cards.map((c) => `
      <div class="stat">
        <div class="k">${esc(c.k)}</div>
        <div class="v">${esc(c.v)}</div>
        <div class="d dim">${esc(c.d)}</div>
      </div>`).join("");
  }

  /** Incidents grouped by the device they were seen on, newest first. */
  function incidentsByNode(label) {
    return state.incidents
      .filter((i) => i.node === label)
      .sort((a, b) => b.last_seen_at - a.last_seen_at);
  }

  const openOn = (label) => incidentsByNode(label).filter((i) => !ui.isHandled(i));

  /**
   * What to say about a device, and what colour to say it in.
   *
   * Driven by whether anything is still waiting on the reader, not by the
   * node's own `status`. The API sets that to "warn" whenever more than eight
   * flagged flows arrive in five minutes, which with auto-mitigate on is true
   * more or less permanently — every one of those flows is flagged and then
   * immediately handled. Colouring the device amber for that put "Behaving
   * oddly · Look at these first" on a row whose own text said everything had
   * been dealt with, which is the same contradiction the home banner had.
   *
   * The busy-but-handled case still gets said out loud rather than shown as
   * plain green. A device that is being hit constantly and defended is not the
   * same as a quiet one, and flattening the two hides something true.
   */
  function deviceState(n) {
    if (openOn(n.label).length) return { text: "Needs a look", color: "var(--amber)" };
    if (n.status === "warn") return { text: "Busy, all handled", color: "var(--blue)" };
    if (n.mbps >= 0.01) return { text: "Active", color: "var(--green)" };
    return { text: "Quiet", color: "var(--muted)" };
  }

  function renderDevices() {
    const box = el("devices");
    if (!state.nodes.length) {
      box.innerHTML = `<div class="empty-state">
        No devices yet. They appear here the first time they send traffic.
      </div>`;
      return;
    }

    box.innerHTML = state.nodes.map((n, idx) => {
      const mine = incidentsByNode(n.label);
      const open = mine.filter((i) => !ui.isHandled(i));
      const state_ = deviceState(n);

      return `
        <div class="plain-row">
          <div class="line">
            <span class="sev-dot" style="background:${esc(state_.color)}"></span>
            <span class="what">${esc(n.label)}</span>
            ${open.length
              ? `<span class="chip bad">${esc(fmt.num(open.length))} to look at</span>`
              : ""}
            <span class="when">${esc(state_.text)}</span>
          </div>
          <div class="sub">${describe(n, mine, open)}</div>
          <button class="disclose" data-detail="${idx}">
            Show technical detail ${icon("chevron", 11)}
          </button>
          <div class="plain-detail" id="detail-${idx}">
            <b>Throughput</b> ${esc(n.mbps.toFixed(2))} Mbps &nbsp;·&nbsp;
            <b>Flagged connections</b> ${esc(fmt.num(n.attacks))} in the last 5 min<br />
            <b>Reported status</b> ${esc(n.status)} &nbsp;·&nbsp;
            <b>Alerts on record</b> ${esc(fmt.num(mine.length))}
            ${mine.length ? renderIncidents(mine.slice(0, 5)) : ""}
          </div>
        </div>`;
    }).join("");

    box.querySelectorAll("[data-detail]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const panel = el(`detail-${btn.getAttribute("data-detail")}`);
        const shown = panel.classList.toggle("show");
        btn.classList.toggle("open", shown);
        btn.childNodes[0].nodeValue = shown ? "Hide technical detail " : "Show technical detail ";
      });
    });

    box.querySelectorAll("[data-block]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        try {
          if (await ui.blockSource(btn.getAttribute("data-block"))) await load();
        } catch (err) {
          ui.toast(err.message || "Could not record that.", "err");
        } finally {
          btn.disabled = false;
        }
      });
    });
  }

  /** One sentence covering what this device is and how it has been behaving. */
  function describe(n, mine, open) {
    const busy = n.mbps >= 0.01;
    const usage = busy
      ? `using ${esc(n.mbps.toFixed(2))} Mbps right now`
      : "not sending much right now";

    let behaviour;
    if (open.length) {
      const p = ui.plainClass(open[0].label);
      behaviour = `${esc(p.what.toLowerCase())} — and nobody has dealt with it yet`;
    } else if (mine.length) {
      // Worth saying out loud. A device that was attacked and defended looks
      // identical to one nothing ever happened to unless the page says so.
      behaviour = `${esc(fmt.num(mine.length))} thing${mine.length === 1 ? "" : "s"} ` +
                  `${mine.length === 1 ? "was" : "were"} flagged here and ` +
                  `${mine.length === 1 ? "has" : "have"} been dealt with`;
    } else {
      behaviour = "nothing has looked wrong here";
    }

    return `${esc(n.desc || "On your network")} — ${usage}, and ${behaviour}.`;
  }

  function renderIncidents(list) {
    return `<div class="mini-list">${list.map((i) => {
      const p = ui.plainClass(i.label);
      const done = ui.isHandled(i);
      return `
        <div class="mini-row">
          <span class="what">${esc(p.what)}</span>
          <span class="dim">${esc(i.src_ip)} · ${esc(fmt.ago(i.last_seen_at))}</span>
          ${done
            ? '<span class="chip ok">Dealt with</span>'
            : `<button class="btn btn-sm btn-ghost" data-block="${esc(i.src_ip)}">Block this device</button>`}
        </div>`;
    }).join("")}</div>`;
  }
})();
