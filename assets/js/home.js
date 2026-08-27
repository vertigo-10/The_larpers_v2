/**
 * Consumer home.
 *
 * The whole page answers one question — is anything wrong with my network —
 * and everything under the verdict is the evidence for it. Two rules follow
 * from that:
 *
 *   - Plain language first, technical detail behind a disclosure. The numbers
 *     are not removed, because a household member who wants to know which port
 *     something was talking on deserves an answer. They are just never the
 *     first thing on screen.
 *   - The verdict is derived from the same data the enterprise dashboard
 *     renders, not from a separate, friendlier endpoint. A softer summary
 *     computed by a different rule is how a home account ends up being told
 *     everything is fine during something that is not.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt } = ui;
  const el = (id) => document.getElementById(id);

  ui.mountSidebar("home");
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
    // A new flow can change the verdict, so the page refreshes on one rather
    // than only on the timer. Throttled, because a busy network would
    // otherwise re-render on every packet burst.
    api.on("flow", scheduleRefresh);
    api.connectStream();
    setInterval(load, 15000);
  }

  let pending = null;
  function scheduleRefresh() {
    if (pending) return;
    pending = setTimeout(() => { pending = null; load(); }, 4000);
  }

  async function load() {
    try {
      // The verdict is judged on the whole list and only the display is
      // trimmed. Asking for the eight most recent and deciding from those said
      // "nothing is waiting on you" whenever the newest eight happened to be
      // handled, while nineteen older ones were still open and both other
      // consumer pages said so — a green banner covering an unresolved network.
      const [summary, incidents, nodes] = await Promise.all([
        api.getSummary(),
        api.getIncidents("all", 100),
        api.getNodes(),
      ]);
      ui.renderVerdict(summary, incidents);
      renderStats(summary, nodes);
      renderEvents(incidents.slice(0, 8));
      renderDevices(nodes);
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load your network.");
    }
  }

  function renderStats(summary, nodes) {
    const busiest = nodes.slice().sort((a, b) => b.mbps - a.mbps)[0];
    const cards = [
      {
        k: "Devices being watched",
        v: fmt.num(nodes.length),
        d: busiest && busiest.mbps
          ? `Busiest right now: ${busiest.label}`
          : "Nothing sending much at the moment"
      },
      {
        k: "Blocked so far",
        v: fmt.num(summary.attacks_blocked),
        d: summary.attacks_blocked
          ? "Connections stopped before they got anywhere"
          : "Nothing has needed blocking"
      },
      {
        k: "Checked in the last minute",
        v: fmt.num(summary.flows_per_min),
        d: "Every connection is scored as it happens"
      }
    ];
    el("home-stats").innerHTML = cards.map((c) => `
      <div class="stat">
        <div class="k">${esc(c.k)}</div>
        <div class="v">${esc(c.v)}</div>
        <div class="d dim">${esc(c.d)}</div>
      </div>`).join("");
  }

  function renderEvents(incidents) {
    const box = el("events");
    if (!incidents.length) {
      box.innerHTML = `<div class="empty-state">
        Nothing has happened yet. That is the right answer.
      </div>`;
      return;
    }

    box.innerHTML = incidents.map((i, n) => {
      const p = ui.plainClass(i.label);
      const sev = ui.severityMeta(i.severity);
      const dealt = ui.isHandled(i);
      return `
        <div class="plain-row">
          <div class="line">
            <span class="sev-dot" style="background:${esc(sev.color)}"></span>
            <span class="what">${esc(p.what)}</span>
            ${dealt ? '<span class="chip">Dealt with</span>' : ""}
            <span class="when">${esc(fmt.ago(i.last_seen_at))}</span>
          </div>
          <div class="sub">${esc(p.sub)}</div>
          <button class="disclose" data-detail="${n}">
            Show technical detail ${icon("chevron", 11)}
          </button>
          <div class="plain-detail" id="detail-${n}">
            <b>Source</b> ${esc(i.src_ip)} &nbsp;·&nbsp;
            <b>Seen on</b> ${esc(i.node)}<br />
            <b>Model verdict</b> ${esc(ui.classMeta(i.label).label)}
            at ${esc((i.peak_confidence * 100).toFixed(1))}% confidence<br />
            <b>Connections</b> ${esc(fmt.num(i.flow_count))} &nbsp;·&nbsp;
            <b>Peak rate</b> ${esc(fmt.bytes(i.peak_bps))}<br />
            <b>First seen</b> ${esc(fmt.datetime(i.opened_at))}
          </div>
        </div>`;
    }).join("");

    box.querySelectorAll("[data-detail]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const panel = el(`detail-${btn.getAttribute("data-detail")}`);
        const open = panel.classList.toggle("show");
        btn.classList.toggle("open", open);
        btn.childNodes[0].nodeValue = open ? "Hide technical detail " : "Show technical detail ";
      });
    });
  }

  function renderDevices(nodes) {
    const box = el("devices");
    if (!nodes.length) {
      box.innerHTML = `<div class="empty-state">
        No devices yet. They appear here the first time they send traffic.
      </div>`;
      return;
    }

    box.innerHTML = nodes.map((n) => {
      const busy = n.mbps >= 0.01;
      const state = n.status === "warn"
        ? { text: "Behaving oddly", color: "var(--amber)" }
        : busy
          ? { text: "Active", color: "var(--green)" }
          : { text: "Quiet", color: "var(--muted)" };
      return `
        <div class="plain-row">
          <div class="line">
            <span class="sev-dot" style="background:${esc(state.color)}"></span>
            <span class="what">${esc(n.label)}</span>
            <span class="when">${esc(state.text)}</span>
          </div>
          <div class="sub">
            ${esc(n.desc || "On your network")} —
            ${busy ? `using ${esc(n.mbps.toFixed(2))} Mbps right now` : "not sending much right now"}${
              n.attacks ? `, and ${esc(fmt.num(n.attacks))} of its recent connections looked wrong` : ""
            }.
          </div>
        </div>`;
    }).join("");
  }
})();
