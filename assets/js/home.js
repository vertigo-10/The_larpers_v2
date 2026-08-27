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
      const [summary, incidents, nodes] = await Promise.all([
        api.getSummary(),
        api.getIncidents("all", 8),
        api.getNodes(),
      ]);
      renderVerdict(summary, incidents);
      renderStats(summary, nodes);
      renderEvents(incidents);
      renderDevices(nodes);
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load your network.");
    }
  }

  /**
   * Whether an incident is finished with, from the reader's point of view.
   *
   * Shared by the verdict and the event list because the two disagreed: the
   * banner counted anything not "resolved" while the list called a mitigated
   * incident "Dealt with". With auto-mitigate on, that put a red "6 things need
   * your attention" directly above six rows each marked "Dealt with" — and a
   * home user who is told to act, looks, and finds nothing to do learns to stop
   * reading the banner.
   */
  const isHandled = (i) => i.status === "resolved" || Boolean(i.mitigated);
  const isSerious = (i) => i.severity === "critical" || i.severity === "high";

  /**
   * The one sentence at the top.
   *
   * Ordered worst-first, and the reason is always stated: "you're fine" with
   * nothing behind it is indistinguishable from a broken page, which is the
   * failure this product least wants to have.
   */
  function renderVerdict(summary, incidents) {
    const outstanding = incidents.filter((i) => !isHandled(i));
    const serious = outstanding.filter(isSerious);
    const handledSerious = incidents.filter((i) => isHandled(i) && isSerious(i));
    const hero = el("hero");
    let tone, mark, line, why;

    if (serious.length) {
      tone = "is-bad";
      mark = "alert";
      line = serious.length === 1
        ? "Something needs your attention"
        : `${serious.length} things need your attention`;
      why = `A device on your network is behaving the way an attack does. ` +
            `Open the alert below to see what it was and block it.`;
    } else if (outstanding.length) {
      tone = "is-warn";
      mark = "alert";
      line = "Worth a look, but nothing urgent";
      why = `${outstanding.length} thing${outstanding.length === 1 ? "" : "s"} ` +
            `looked unusual and ${outstanding.length === 1 ? "has" : "have"} not ` +
            `been dealt with yet. Nothing has been rated serious.`;
    } else if (!summary.flows_per_min) {
      // Told apart from "safe" on purpose. No traffic means nothing is being
      // checked, and reporting that as green would be the single most
      // misleading thing this page could do.
      tone = "is-warn";
      mark = "info";
      line = "Not seeing any traffic";
      why = "Nothing has been checked in the last minute, so this is not a " +
            "clean bill of health — it means the collector is not sending. " +
            "Check that it is running.";
    } else if (handledSerious.length) {
      // Green, because nothing is waiting on the reader — but it would be a lie
      // to say the network "looks fine" on a day something tried to knock a
      // device offline and got stopped. They should know it happened.
      tone = "is-ok";
      mark = "shieldCheck";
      line = "Handled without you";
      why = `${handledSerious.length} serious thing${handledSerious.length === 1 ? "" : "s"} ` +
            `happened recently and ${handledSerious.length === 1 ? "was" : "were"} ` +
            `blocked automatically. Nothing is waiting on you — the details are below.`;
    } else {
      tone = "is-ok";
      mark = "shieldCheck";
      line = "Your network looks fine";
      why = `Everything crossing your router in the last minute was checked ` +
            `and came back normal. ${fmt.num(summary.attacks_blocked)} ` +
            `thing${summary.attacks_blocked === 1 ? " has" : "s have"} been ` +
            `blocked in total.`;
    }

    hero.className = `home-hero ${tone}`;
    el("hero-ring").innerHTML = icon(mark, 28);
    el("hero-line").textContent = line;
    el("hero-why").textContent = why;
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

  // One entry per class the model can actually predict, and nothing else. A
  // friendly line for a label that cannot occur reads as coverage the product
  // does not have; unknown labels fall through to the honest default below.
  const PLAIN = {
    dos_ddos: {
      what: "A device was flooded with traffic",
      sub: "Something sent far more connections than normal, which is how an " +
           "attempt to knock a device offline looks."
    },
    scan: {
      what: "Something was probing your network",
      sub: "A device went door-to-door looking for open ports. On its own it " +
           "is not damage, but it is usually what comes first."
    }
  };

  function plainFor(label) {
    return PLAIN[label] || {
      what: "Unusual activity",
      sub: "This did not match how your network normally behaves."
    };
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
      const p = plainFor(i.label);
      const sev = ui.severityMeta(i.severity);
      const dealt = isHandled(i);
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
