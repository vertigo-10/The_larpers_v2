/**
 * Consumer alerts.
 *
 * The enterprise page is a work queue: severity filters, acknowledge, assign,
 * reopen. A household has no rota to hand an incident to, so the only two
 * states worth distinguishing here are "somebody still needs to look at this"
 * and "this is finished with" — and the page opens on the first.
 *
 * Everything on screen comes from the same /api/incidents the enterprise
 * console reads. The plain wording is a translation of that record, never a
 * softer verdict computed alongside it.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt } = ui;
  const el = (id) => document.getElementById(id);

  // Opens on what needs doing. Someone arriving from a red banner is looking
  // for the thing to act on, and a full history buries it under rows that are
  // already handled.
  let showAll = false;
  let state = { summary: null, incidents: [] };

  ui.mountSidebar("alerts");
  el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;
  el("btn-refresh").addEventListener("click", () => load());
  el("btn-scope").addEventListener("click", () => {
    showAll = !showAll;
    render();
  });

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

  async function load() {
    try {
      const [summary, incidents] = await Promise.all([
        api.getSummary(),
        api.getIncidents("all", 100),
      ]);
      state = { summary, incidents };
      render();
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load your alerts.");
    }
  }

  function render() {
    const { summary, incidents } = state;
    if (!summary) return;

    ui.renderVerdict(summary, incidents);

    const outstanding = incidents.filter((i) => !ui.isHandled(i));
    const visible = showAll ? incidents : outstanding;

    el("list-title").textContent = showAll
      ? `Everything we've spotted`
      : `Needs your attention`;
    el("btn-scope").textContent = showAll
      ? `Only what needs me (${outstanding.length})`
      : `Show everything (${incidents.length})`;

    renderList(visible, outstanding.length);
  }

  function renderList(list, outstandingCount) {
    const box = el("alerts");

    if (!list.length) {
      // The two empty states mean opposite things and must not share wording.
      // "Nothing needs you" on a network with nothing on it at all would be a
      // clean bill of health the data does not support.
      box.innerHTML = `<div class="empty-state">${
        showAll
          ? "Nothing has been flagged yet. That is the right answer."
          : outstandingCount === 0 && state.incidents.length
            ? "Nothing needs you right now — everything flagged has been dealt with."
            : "Nothing needs your attention."
      }</div>`;
      return;
    }

    box.innerHTML = list.map((i, n) => {
      const p = ui.plainClass(i.label);
      const sev = ui.severityMeta(i.severity);
      const dealt = ui.isHandled(i);
      return `
        <div class="plain-row">
          <div class="line">
            <span class="sev-dot" style="background:${esc(sev.color)}"></span>
            <span class="what">${esc(p.what)}</span>
            ${dealt ? '<span class="chip ok">Dealt with</span>' : ""}
            <span class="when">${esc(fmt.ago(i.last_seen_at))}</span>
          </div>
          <div class="sub">
            ${esc(p.sub)} Seen on <b>${esc(i.node)}</b>, coming from
            <b>${esc(i.src_ip)}</b>.
          </div>
          <div class="row-actions">
            <button class="disclose" data-detail="${n}">
              Show technical detail ${icon("chevron", 11)}
            </button>
            ${dealt
              ? ""
              : `<button class="btn btn-sm btn-ghost" data-block="${esc(i.src_ip)}">Block this device</button>`}
          </div>
          <div class="plain-detail" id="detail-${n}">
            <b>Source</b> ${esc(i.src_ip)} &nbsp;·&nbsp;
            <b>Seen on</b> ${esc(i.node)}<br />
            <b>Model verdict</b> ${esc(ui.classMeta(i.label).label)}
            at ${esc((i.peak_confidence * 100).toFixed(1))}% confidence<br />
            <b>Rated</b> ${esc(sev.label)} &nbsp;·&nbsp;
            <b>Connections</b> ${esc(fmt.num(i.flow_count))} &nbsp;·&nbsp;
            <b>Peak rate</b> ${esc(fmt.bytes(i.peak_bps))}<br />
            <b>First seen</b> ${esc(fmt.datetime(i.opened_at))} &nbsp;·&nbsp;
            <b>Last seen</b> ${esc(fmt.datetime(i.last_seen_at))}
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
})();
