/**
 * Flow sources — the devices that send us NetFlow/IPFIX.
 *
 * This page manages the one piece of configuration that decides tenancy. The
 * protocol has no authentication: a datagram arrives and the only thing
 * separating a customer's firewall from a stranger's laptop is the source IP
 * in the packet header. Registering an address here is what says "flows from
 * there are ours", so every write is admin-only server-side and this file
 * mirrors that by not offering buttons that would 403.
 *
 * Two presentation rules are load-bearing rather than cosmetic:
 *
 *   1. The drop counters are never summed. `dropped_buffer_full` means we are
 *      overloaded and losing traffic we were asked to analyse;
 *      `dropped_unregistered` means something is sending that nobody claimed.
 *      One is a capacity incident, the other is a configuration or trespass
 *      question, and a single "dropped" figure would hide whichever is smaller
 *      behind whichever is larger.
 *
 *   2. "No flows" and "40,000 flows dropped" look identical on a dashboard and
 *      need opposite responses, so the note under the strip says which one is
 *      happening in words rather than leaving the operator to read counters.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt, toast } = ui;
  const el = (id) => document.getElementById(id);

  const state = {
    me: null,
    exporters: [],
    unclaimed: [],
    status: null,
    editing: null,      // the row being edited, or null when registering new
    deleting: null,
    query: "",
    // Source addresses last seen in a pre-`live` state, so the flip to live can
    // be announced once. A device coming online is the moment this whole page
    // exists to produce, and it happens while the operator is looking at the
    // router rather than the browser.
    pending: new Set()
  };

  // How often the table refreshes. Faster than the other pages on purpose: an
  // operator is typically here *because* they just pasted config into a device
  // and are waiting to see it register.
  const POLL_MS = 6000;

  const STATES = {
    live:     { tone: "ok",   label: "Live",     note: "packets arriving" },
    waiting:  { tone: "info", label: "Waiting",  note: "registered, nothing received yet" },
    silent:   { tone: "warn", label: "Silent",   note: "nothing for over 10 minutes" },
    disabled: { tone: "",     label: "Disabled", note: "registered but ignored" }
  };

  ui.mountSidebar("exporters");
  el("btn-refresh").innerHTML = `${icon("refresh", 12)} Refresh`;
  el("ico-notice").innerHTML = icon("feed", 15);
  el("ico-edit").innerHTML = icon("router", 15);
  el("ico-del").innerHTML = icon("trash", 15);
  el("edit-close").innerHTML = icon("x", 14);
  el("del-close").innerHTML = icon("x", 14);
  el("btn-copy").innerHTML = `${icon("file", 11)} Copy`;

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    state.me = await api.me();
    el("topbar-avatar").textContent = state.me.initials || "··";
    el("topbar-avatar").title = `${state.me.name} · ${state.me.role}`;

    const copy = ui.orgCopy(state.me.org_type);
    document.title = `${copy.exportersTitle} — SENTRY NN`;
    el("page-title").textContent = copy.exportersTitle;
    el("crumb").textContent = `/ ${copy.exportersCrumb}`;
    el("notice-text").textContent = copy.exportersNotice;
    el("btn-add").innerHTML = `${icon("plus", 12)} ${esc(copy.exportersAddBtn)}`;

    // Registering, editing and removing are all admin-only on the API. A
    // viewer gets the same page without the controls rather than a page whose
    // every button returns 403.
    if (state.me.role !== "admin") el("btn-add").style.display = "none";

    buildVendorPicker();
    el("collector-host").value = window.location.hostname || "sentry.example.com";

    await load();
    // Again, deliberately. `load` renders the snippet on its success path only,
    // and the setup instructions are the one thing on this page still worth
    // reading when the API is unreachable — quite possibly the reason someone
    // opened it.
    renderSnippet();
    setInterval(load, POLL_MS);
  }

  async function load() {
    try {
      // Independent of each other, and the unclaimed list is admin-only — a
      // viewer's 403 there must not blank the device table they may read.
      const [status, exporters] = await Promise.all([
        api.getCollectorStatus(),
        api.getExporters()
      ]);
      state.status = status;
      state.exporters = exporters;

      if (state.me.role === "admin") {
        try {
          state.unclaimed = await api.getUnclaimedExporters();
        } catch (err) {
          if (!err || err.status !== 403) throw err;
        }
      }

      renderStrip();
      renderExporters();
      renderUnclaimed();
      renderSnippet();
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load flow sources.");
    }
  }

  // ── collector health ──────────────────────────────────────────────────
  function renderStrip() {
    const s = state.status || {};
    const st = s.stats || {};
    const n = (key) => Number(st[key] || 0);

    let listen = { v: "Off", cls: "dim", d: "not accepting flow records" };
    if (!s.enabled) {
      listen.d = "NetFlow ingest is switched off in configuration";
    } else if (s.listening) {
      listen = {
        v: "Listening",
        cls: "",
        d: `udp ${(s.ports || []).join(", ") || "—"}`
      };
    } else {
      listen = { v: "Down", cls: "", d: "enabled, but no port could be bound" };
    }

    const cards = [
      { k: "Collector", v: listen.v, d: listen.d,
        color: s.enabled && s.listening ? "var(--green)" : "var(--red)" },
      { k: "Packets in", v: fmt.num(n("packets")), d: "since the process started" },
      { k: "Flows in", v: fmt.num(n("flows")), d: "records decoded and scored" },
      // Kept apart deliberately — see the file header.
      { k: "Dropped · overloaded", v: fmt.num(n("dropped_buffer_full")),
        d: "queue was full", color: n("dropped_buffer_full") ? "var(--red)" : "" },
      { k: "Dropped · unregistered", v: fmt.num(n("dropped_unregistered")),
        d: "sender not claimed", color: n("dropped_unregistered") ? "var(--amber)" : "" },
      { k: "Malformed", v: fmt.num(n("malformed")),
        d: "could not be parsed", color: n("malformed") ? "var(--amber)" : "" }
    ];

    el("collector-strip").innerHTML = cards.map((c) => `
      <div class="stat">
        <div class="k">${esc(c.k)}</div>
        <div class="v" ${c.color ? `style="color:${c.color}"` : ""}>${esc(c.v)}</div>
        <div class="d dim">${esc(c.d)}</div>
      </div>`).join("");

    el("collector-note").innerHTML = collectorNote(s, st);
  }

  /**
   * The counters in a sentence.
   *
   * Written as prose because the numbers alone do not distinguish the two
   * failures that matter. Silence and saturation both show a flat dashboard;
   * only one of them is the operator's problem to fix at the router.
   */
  function collectorNote(s, st) {
    const n = (key) => Number(st[key] || 0);
    const parts = [];

    if (!s.enabled) {
      return "The collector is disabled, so nothing you register here will " +
        "receive traffic yet. Set <code>SENTRY_NETFLOW_ENABLED=true</code> on " +
        "the server and restart it.";
    }
    if (!s.listening) {
      return "NetFlow ingest is enabled but no port could be bound — usually " +
        "another process already holds it, or the port is privileged. Nothing " +
        "is being received.";
    }

    if (n("dropped_buffer_full")) {
      parts.push(
        `<b>${esc(fmt.num(n("dropped_buffer_full")))} flow records were dropped ` +
        "because the processing queue was full.</b> That is traffic we were " +
        "asked to analyse and did not — reduce sampling on the noisiest device, " +
        "or give the collector more headroom."
      );
    }
    if (n("dropped_unregistered")) {
      // The counter is cumulative since the process started, so it keeps the
      // packets a device sent before it was claimed. Blaming a misconfiguration
      // whenever it is non-zero would leave a permanent warning on a page where
      // everything is working, which is how a warning stops being read. The
      // diagnosis is only offered when there is actually a device not
      // delivering.
      const settling = state.exporters.some((e) => e.state !== "live" && e.enabled);
      parts.push(
        `${esc(fmt.num(n("dropped_unregistered")))} packets came from addresses ` +
        "nobody has registered and were discarded." +
        (settling
          ? " If a device you set up is not appearing, this is almost always " +
            "why: it is exporting from a different address than the one " +
            "registered. Compare the address in its own logs against the list " +
            "below."
          : " Every device you registered is delivering, so these are from " +
            "before they were claimed, or from something else on the network " +
            "that exports flows and is not yours to collect.")
      );
    }
    if (n("awaiting_template")) {
      parts.push(
        `${esc(fmt.num(n("awaiting_template")))} records are waiting on a ` +
        "template. NetFlow v9 and IPFIX describe their own layout in a separate " +
        "packet the device sends every few minutes, so a short wait after a " +
        "restart is normal."
      );
    }
    if (!n("packets")) {
      parts.push(
        "No packets have reached the collector at all. Check that UDP is open " +
        "to it on the ports above — this is the step a firewall usually eats, " +
        "and the device will report success regardless because nothing " +
        "acknowledges NetFlow."
      );
    }
    if (!parts.length) {
      parts.push("Receiving cleanly — no drops, nothing malformed.");
    }
    return parts.join(" ");
  }

  // ── registered devices ────────────────────────────────────────────────
  function renderExporters() {
    const body = el("exporter-body");
    const isAdmin = state.me.role === "admin";

    let rows = state.exporters;
    if (state.query) {
      const q = state.query.toLowerCase();
      rows = rows.filter((e) =>
        `${e.name} ${e.source_ip} ${e.node_label}`.toLowerCase().indexOf(q) !== -1);
    }

    const liveCount = state.exporters.filter((e) => e.state === "live").length;
    el("count-pill").textContent =
      `${state.exporters.length} registered · ${liveCount} live`;

    announceArrivals();

    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="9" class="empty-state">
        ${state.exporters.length
          ? "No device matches that search."
          : "No devices registered. Until one is, every flow record reaching " +
            "the collector is discarded as unclaimed."}
      </td></tr>`;
      return;
    }

    body.innerHTML = rows.map((e) => {
      const meta = STATES[e.state] || { tone: "", label: e.state, note: "" };
      const last = e.last_seen_at
        ? fmt.ago(new Date(e.last_seen_at).getTime())
        : "never";
      return `
        <tr>
          <td>
            <div class="flow-name">${esc(e.name || e.source_ip)}</div>
            ${e.last_error
              ? `<div class="dim" style="font-size:10px;color:var(--amber)">${esc(e.last_error)}</div>`
              : ""}
          </td>
          <td class="mono">${esc(e.source_ip)}</td>
          <td class="mono">${esc(e.node_label)}</td>
          <td>${esc(e.version || "—")}</td>
          <td class="mono">${e.sampling_rate > 1 ? `1:${esc(String(e.sampling_rate))}` : "full"}</td>
          <td>
            <span class="chip ${esc(meta.tone)}" title="${esc(meta.note)}">${esc(meta.label)}</span>
          </td>
          <td class="dim">${esc(last)}</td>
          <td class="mono">${esc(fmt.num(e.flows_received))}</td>
          <td style="text-align:right;white-space:nowrap">
            ${isAdmin ? `
              <button class="pill" data-act="toggle" data-id="${esc(String(e.id))}"
                      style="height:24px;font-size:10.5px">
                ${e.enabled ? "Disable" : "Enable"}
              </button>
              <button class="pill" data-act="edit" data-id="${esc(String(e.id))}"
                      style="height:24px;font-size:10.5px">Edit</button>
              <button class="pill" data-act="del" data-id="${esc(String(e.id))}"
                      style="height:24px;font-size:10.5px;color:var(--red)">Remove</button>
            ` : `<span class="dim" style="font-size:10.5px">admin only</span>`}
          </td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-act]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const row = state.exporters.find((e) => String(e.id) === btn.dataset.id);
        if (!row) return;
        if (btn.dataset.act === "edit") openEdit(row);
        else if (btn.dataset.act === "del") openDelete(row);
        else toggleEnabled(row);
      });
    });
  }

  /**
   * Say so out loud the first time a device delivers.
   *
   * Without this the only signal is a chip quietly changing colour in a table
   * the operator is not looking at, because they are at the router. Fires once
   * per device: `pending` is only added to while the state is pre-`live`.
   */
  function announceArrivals() {
    state.exporters.forEach((e) => {
      if (e.state === "live" && state.pending.has(e.source_ip)) {
        state.pending.delete(e.source_ip);
        toast(`${e.name || e.source_ip} is sending flows.`);
      } else if (e.state !== "live") {
        state.pending.add(e.source_ip);
      }
    });
  }

  async function toggleEnabled(row) {
    try {
      await api.updateExporter(row.id, { enabled: !row.enabled });
      toast(row.enabled
        ? `${row.name || row.source_ip} will be ignored.`
        : `${row.name || row.source_ip} will be ingested again.`);
      await load();
    } catch (err) {
      if (err && err.status === 401) return;
      toast(err.message || "Could not update the device.", "err");
    }
  }

  // ── unclaimed senders ─────────────────────────────────────────────────
  function renderUnclaimed() {
    const panel = el("unclaimed-panel");
    if (state.me.role !== "admin" || !state.unclaimed.length) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    el("unclaimed-pill").textContent =
      `${state.unclaimed.length} visible to you`;

    el("unclaimed-body").innerHTML = state.unclaimed.map((u) => `
      <tr>
        <td class="mono">${esc(u.source_ip)}</td>
        <td>${esc(u.version || "—")}</td>
        <td class="dim">${esc(fmt.ago(new Date(u.first_seen_at).getTime()))}</td>
        <td class="dim">${esc(fmt.ago(new Date(u.last_seen_at).getTime()))}</td>
        <td class="mono">${esc(fmt.num(u.packets_received))}</td>
        <td style="text-align:right">
          <button class="pill" data-claim="${esc(u.source_ip)}"
                  style="height:24px;font-size:10.5px">Claim</button>
        </td>
      </tr>`).join("");

    el("unclaimed-body").querySelectorAll("[data-claim]").forEach((btn) => {
      // Opens the register form pre-filled rather than claiming on the click.
      // Naming the device and setting its sampling rate are part of getting
      // this right, and a one-click claim skips both.
      btn.addEventListener("click", () => {
        openEdit(null);
        el("e-ip").value = btn.dataset.claim;
        el("e-name").focus();
      });
    });
  }

  // ── register / edit ───────────────────────────────────────────────────
  const editModal = el("edit-modal");
  const closeEdit = () => editModal.classList.remove("show");

  function openEdit(row) {
    state.editing = row;
    el("edit-err").classList.remove("show");
    el("edit-title").textContent = row ? "Edit device" : "Register a device";
    el("edit-save").textContent = row ? "Save changes" : "Register device";

    // The source address is the tenancy decision, and changing it is not an
    // edit — it is claiming a different device. The API has no path for it
    // either, so the field is locked rather than offered and then rejected.
    el("e-ip").value = row ? row.source_ip : "";
    el("e-ip").readOnly = Boolean(row);
    el("e-name").value = row ? row.name : "";
    el("e-node").value = row ? row.node_label : "";
    el("e-sampling").value = row ? row.sampling_rate : 1;
    el("e-enabled").value = row ? String(row.enabled) : "true";

    editModal.classList.add("show");
    (row ? el("e-name") : el("e-ip")).focus();
  }

  el("btn-add").addEventListener("click", () => openEdit(null));
  el("edit-close").addEventListener("click", closeEdit);
  el("edit-cancel").addEventListener("click", closeEdit);
  editModal.addEventListener("click", (ev) => {
    if (ev.target === editModal) closeEdit();
  });

  el("edit-save").addEventListener("click", async () => {
    const err = el("edit-err");
    const fail = (msg) => { err.textContent = msg; err.classList.add("show"); };
    err.classList.remove("show");

    const sampling = parseInt(el("e-sampling").value, 10);
    if (!Number.isFinite(sampling) || sampling < 1) {
      return fail("Sampling rate must be 1 or more. Use 1 if the device does " +
        "not sample.");
    }

    const payload = {
      name: el("e-name").value.trim(),
      node_label: el("e-node").value.trim(),
      sampling_rate: sampling,
      enabled: el("e-enabled").value === "true"
    };

    try {
      if (state.editing) {
        await api.updateExporter(state.editing.id, payload);
        toast("Device updated.");
      } else {
        const ip = el("e-ip").value.trim();
        if (!ip) return fail("Enter the address the device exports from.");
        await api.createExporter(Object.assign({ source_ip: ip }, payload));
        // Registered but not yet heard from, so the arrival toast can fire.
        state.pending.add(ip);
        toast("Device registered. It will show as live once a packet arrives.");
      }
      closeEdit();
      await load();
    } catch (ex) {
      if (ex && ex.status === 401) return;
      fail(ex.message || "Could not save the device.");
    }
  });

  // ── removal ───────────────────────────────────────────────────────────
  const delModal = el("del-modal");
  const closeDel = () => delModal.classList.remove("show");

  function openDelete(row) {
    state.deleting = row;
    el("del-err").classList.remove("show");
    el("d-confirm").value = "";
    el("del-blurb").textContent =
      `${row.name || row.source_ip} is registered at ${row.source_ip} and has ` +
      `reported ${fmt.num(row.flows_received)} flows.`;
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

    // Typed confirmation rather than a yes/no box. Un-registering an address
    // silently stops ingest from a device that keeps reporting success at its
    // own end, so the gap in coverage is invisible from both sides.
    if (el("d-confirm").value.trim() !== row.source_ip) {
      err.textContent = `Type ${row.source_ip} exactly to confirm.`;
      err.classList.add("show");
      return;
    }

    try {
      await api.deleteExporter(row.id);
      state.pending.delete(row.source_ip);
      closeDel();
      toast(`${row.name || row.source_ip} removed. Its past flows are kept.`);
      await load();
    } catch (ex) {
      if (ex && ex.status === 401) return;
      err.textContent = ex.message || "Could not remove the device.";
      err.classList.add("show");
    }
  });

  // ── vendor configuration snippets ─────────────────────────────────────
  /**
   * What to paste into the device.
   *
   * Every one of these is the minimum that produces flow records on the wire,
   * not a full hardening guide — the point is to get a first packet through so
   * the row above flips to live, because that is the step where setups stall.
   *
   * The active timeout is set to 60s throughout. Left at a vendor default of
   * up to 30 minutes, a long-lived connection is not reported until it ends,
   * which for a slow-rate denial of service is precisely the window that
   * matters and precisely when it would go unreported.
   */
  const VENDORS = [
    {
      id: "cisco", label: "Cisco IOS — NetFlow v9",
      note: "Applied per interface. `ip flow-export source` matters more than " +
        "it looks: it fixes which address the records arrive from, and that " +
        "is the address to register above.",
      lines: (host, port) => [
        "flow-export version 9",
        `ip flow-export destination ${host} ${port}`,
        "ip flow-export source Loopback0",
        "ip flow-cache timeout active 1",
        "ip flow-cache timeout inactive 15",
        "!",
        "interface GigabitEthernet0/0",
        " ip flow ingress",
        " ip flow egress"
      ]
    },
    {
      id: "mikrotik", label: "MikroTik RouterOS — Traffic Flow v9",
      note: "RouterOS exports from the address of the interface it routes to " +
        "the collector through, so on a multi-WAN router check which one that " +
        "is before registering.",
      lines: (host, port) => [
        "/ip traffic-flow set enabled=yes \\",
        "    active-flow-timeout=1m inactive-flow-timeout=15s",
        `/ip traffic-flow target add dst-address=${host} port=${port} version=9`
      ]
    },
    {
      id: "pfsense", label: "pfSense / OPNsense — softflowd",
      note: "Install the softflowd package, then set it per interface. On " +
        "OPNsense the same settings live under Reporting → NetFlow.",
      lines: (host, port) => [
        "# System → Package Manager → install softflowd",
        "# Services → softflowd:",
        "#   Interface        WAN",
        `#   Host             ${host}`,
        `#   Port             ${port}`,
        "#   NetFlow version  9",
        "#   Max active       60   (seconds)",
        "#   Max lifetime     15"
      ]
    },
    {
      id: "fortinet", label: "FortiGate — FortiOS NetFlow",
      note: "FortiOS needs the collector set globally and then enabled per " +
        "interface; setting only the first half is the usual reason nothing " +
        "arrives.",
      lines: (host, port) => [
        "config system netflow",
        `    set collector-ip ${host}`,
        `    set collector-port ${port}`,
        "    set active-flow-timeout 60",
        "    set inactive-flow-timeout 15",
        "end",
        "",
        "config system interface",
        "    edit \"wan1\"",
        "        set netflow-sampler both",
        "    next",
        "end"
      ]
    },
    {
      id: "ubiquiti", label: "Ubiquiti EdgeRouter — VyOS flow-accounting",
      note: "EdgeOS shares VyOS's flow-accounting stack. Commit and save, or " +
        "it is lost on the next reboot.",
      lines: (host, port) => [
        "configure",
        "set system flow-accounting interface eth0",
        "set system flow-accounting netflow version 9",
        `set system flow-accounting netflow server ${host} port ${port}`,
        "set system flow-accounting netflow timeout expiry-interval 60",
        "commit ; save",
        "exit"
      ]
    },
    {
      id: "vyos", label: "VyOS — IPFIX",
      note: "VyOS can speak IPFIX rather than v9. SENTRY decodes both; IPFIX " +
        "is the newer standard and is preferred where the device offers it.",
      lines: (host, port) => [
        "configure",
        "set system flow-accounting interface eth0",
        "set system flow-accounting netflow version 10",
        `set system flow-accounting netflow server ${host} port ${port}`,
        "set system flow-accounting netflow timeout expiry-interval 60",
        "commit ; save",
        "exit"
      ]
    }
  ];

  function buildVendorPicker() {
    el("vendor").innerHTML = VENDORS.map((v) =>
      `<option value="${esc(v.id)}">${esc(v.label)}</option>`).join("");
  }

  function currentVendor() {
    return VENDORS.find((v) => v.id === el("vendor").value) || VENDORS[0];
  }

  function snippetText() {
    const vendor = currentVendor();
    const host = el("collector-host").value.trim() || "sentry.example.com";
    const ports = (state.status && state.status.ports) || [];
    return vendor.lines(host, ports[0] || 2055).join("\n");
  }

  function renderSnippet() {
    const vendor = currentVendor();
    // Rendered as text, not markup. These strings are partly built from a
    // field the operator types into, and a snippet box is the last place that
    // should be interpreting angle brackets.
    el("snippet").textContent = snippetText();
    el("vendor-note").innerHTML =
      `${esc(vendor.note)} Register the address the device sends <i>from</i>, ` +
      "which is often not the address you configured as its destination.";
  }

  el("vendor").addEventListener("change", renderSnippet);
  el("collector-host").addEventListener("input", renderSnippet);

  el("btn-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(snippetText());
      toast("Configuration copied.");
    } catch (err) {
      // Clipboard access is refused outside a secure context, which includes
      // plain http on a LAN address — a very likely way to reach this page.
      toast("Could not copy — select the text and copy it manually.", "err");
    }
  });

  el("btn-refresh").addEventListener("click", async () => {
    await load();
    toast("Refreshed from the API.");
  });

  window.SENTRY_ON_SEARCH = function (q) {
    state.query = q;
    renderExporters();
  };
})();
