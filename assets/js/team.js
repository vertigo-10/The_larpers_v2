/**
 * Team management + audit trail.
 *
 * The server enforces every rule here (admin-only writes, no self-demotion, no
 * removing the last admin). The UI mirrors those rules so buttons that would
 * fail are not offered — but the UI is not the enforcement point, and a hidden
 * button is never treated as a permission.
 *
 * The audit trail is admin-only server-side, so a non-admin simply does not see
 * that panel rather than seeing it fail to load.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt, toast } = ui;
  const el = (id) => document.getElementById(id);

  const ROLES = {
    admin:   { label: "Admin",   tone: "bad",  note: "full control" },
    analyst: { label: "Analyst", tone: "info", note: "can mitigate" },
    viewer:  { label: "Viewer",  tone: "",     note: "read only" }
  };

  const state = {
    me: null, members: [], pending: [], invites: [], query: "",
    features: null,
    // Overwritten from the server in init(). The full enum is only the right
    // default for a company, so start from the narrow set and widen.
    assignableRoles: ["admin", "viewer"]
  };

  ui.mountSidebar("team");
  el("btn-add").innerHTML = `${icon("plus", 12)} Add member`;
  el("ico-notice").innerHTML = icon("users", 15);
  el("ico-add").innerHTML = icon("user", 15);
  el("add-close").innerHTML = icon("x", 14);
  // These belong to the invites panels, which applyFeatureGates removes
  // entirely for account types without the feature.
  if (el("btn-invite")) el("btn-invite").innerHTML = `${icon("key", 11)} New invite`;
  if (el("ico-invite")) el("ico-invite").innerHTML = icon("key", 15);
  if (el("invite-close")) el("invite-close").innerHTML = icon("x", 14);

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    state.me = await api.me();
    // Fetched before anything renders so the gated panels never flash in and
    // then vanish. `applyFeatureGates` removes them outright.
    const featureSet = await api.features();
    state.features = featureSet.features;
    state.assignableRoles = featureSet.assignable_roles;
    ui.applyFeatureGates(state.features);
    el("topbar-avatar").textContent = state.me.initials || "··";
    el("topbar-avatar").title = `${state.me.name} · ${state.me.role}`;
    el("crumb").textContent = `/ ${state.me.org_name}`;

    const copy = ui.orgCopy(state.me.org_type);
    el("page-title").textContent = copy.teamTitle;
    el("notice-text").innerHTML = copy.teamNotice;

    const isAdmin = state.me.role === "admin";
    if (!isAdmin) {
      el("btn-add").style.display = "none";
      // May already be gone if this account type has no audit log at all.
      const audit = el("audit-panel");
      if (audit) audit.style.display = "none";
    }

    // Roles the API will actually accept for this org type — the dropdown is
    // built from the server's list rather than from the full enum, so it
    // cannot offer a choice that is guaranteed to 400.
    const roleSelect = el("m-role");
    if (roleSelect) {
      roleSelect.innerHTML = state.assignableRoles.map((r) =>
        `<option value="${esc(r)}">${esc((ROLES[r] || { label: r }).label)}</option>`
      ).join("");
    }

    await loadTeam();
    // Both are admin-only server side, so a non-admin is shown nothing rather
    // than a panel that fails to load.
    if (isAdmin && api.hasFeature("invites")) {
      await loadPending();
      await loadInvites();
    } else {
      ["pending-panel", "invites-panel"].forEach((id) => {
        const panel = el(id);
        if (panel) panel.style.display = "none";
      });
    }
    if (isAdmin && api.hasFeature("audit_log")) await loadAudit();
  }

  async function loadTeam() {
    try {
      state.members = await api.getTeam();
      renderTeam();
      ui.clearFatal();
    } catch (err) {
      if (err && err.status === 401) return;
      ui.fatalBanner(err.message || "Could not load the team.");
    }
  }

  function renderTeam() {
    const body = el("team-body");
    const isAdmin = state.me.role === "admin";

    let rows = state.members;
    if (state.query) {
      const q = state.query.toLowerCase();
      rows = rows.filter((m) =>
        `${m.name} ${m.email} ${m.role}`.toLowerCase().indexOf(q) !== -1);
    }

    const active = state.members.filter((m) => m.is_active).length;
    el("count-pill").textContent =
      `${state.members.length} member${state.members.length === 1 ? "" : "s"} · ${active} active`;

    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="7" class="empty-state">No members match that search.</td></tr>`;
      return;
    }

    body.innerHTML = rows.map((m) => {
      const role = ROLES[m.role] || { label: m.role, tone: "" };
      const isSelf = m.id === state.me.id;
      return `
        <tr>
          <td>
            <div class="flow-cell">
              <span class="avatar" style="width:26px;height:26px;font-size:10px">${esc(m.initials)}</span>
              <div>
                <div class="flow-name">${esc(m.name)}${isSelf ? ` <span class="dim" style="font-weight:400">(you)</span>` : ""}</div>
                <div class="dim" style="font-size:10px">${esc(m.title || "")}</div>
              </div>
            </div>
          </td>
          <td class="mono">${esc(m.email)}</td>
          <td>
            ${isAdmin && !isSelf
              ? `<select class="sel-input" style="min-width:0;padding:5px 8px;font-size:11px" data-role="${m.id}">
                   ${state.assignableRoles.map((r) =>
                     `<option value="${esc(r)}" ${m.role === r ? "selected" : ""}>${esc((ROLES[r] || { label: r }).label)}</option>`).join("")}
                 </select>`
              : `<span class="chip ${role.tone}">${esc(role.label.toUpperCase())}</span>`}
          </td>
          <td>
            ${m.is_active
              ? `<span class="chip ok">ACTIVE</span>`
              : `<span class="chip warn">SUSPENDED</span>`}
          </td>
          <td title="${esc(fmt.datetime(m.created_at))}">${esc(fmt.ago(new Date(m.created_at).getTime()))}</td>
          <td>${m.last_login_at
                ? `<span title="${esc(fmt.datetime(m.last_login_at))}">${esc(fmt.ago(new Date(m.last_login_at).getTime()))}</span>`
                : `<span class="dim">never</span>`}</td>
          <td>
            <div class="row-actions">
              ${isAdmin && !isSelf ? `
                <button class="row-btn ghost" data-toggle="${m.id}">
                  ${m.is_active ? "SUSPEND" : "REACTIVATE"}
                </button>
                <button class="row-btn danger" data-remove="${m.id}">REMOVE</button>`
                : `<span class="chip">—</span>`}
            </div>
          </td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-role]").forEach((sel) => {
      sel.addEventListener("change", async () => {
        const id = Number(sel.dataset.role);
        const previous = state.members.find((m) => m.id === id).role;
        try {
          await api.updateMember(id, { role: sel.value });
          toast(`Role updated to ${ROLES[sel.value].label}.`);
          await loadTeam();
          await loadAudit();
        } catch (err) {
          toast(err.message, "err");
          sel.value = previous;
        }
      });
    });

    body.querySelectorAll("[data-toggle]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = Number(btn.dataset.toggle);
        const member = state.members.find((m) => m.id === id);
        btn.disabled = true;
        try {
          await api.updateMember(id, { is_active: !member.is_active });
          toast(member.is_active
            ? `${member.name} suspended — they can no longer sign in.`
            : `${member.name} reactivated.`);
          await loadTeam();
          await loadAudit();
        } catch (err) {
          toast(err.message, "err");
          btn.disabled = false;
        }
      });
    });

    body.querySelectorAll("[data-remove]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = Number(btn.dataset.remove);
        const member = state.members.find((m) => m.id === id);
        // Deleting a person is not undoable, so it gets an explicit confirm.
        if (!window.confirm(
          `Remove ${member.name} (${member.email}) from ${state.me.org_name}?\n\n` +
          `They lose access immediately. This cannot be undone.`)) return;
        btn.disabled = true;
        try {
          await api.removeMember(id);
          toast(`${member.name} removed.`);
          await loadTeam();
          await loadAudit();
        } catch (err) {
          toast(err.message, "err");
          btn.disabled = false;
        }
      });
    });
  }

  // ── the approval queue ──────────────────────────────────────────────────
  // How somebody arrived is shown, not buried, because the two routes are not
  // equally trustworthy: an invite is a decision an admin already made about
  // one named person, and a domain match is an unverified claim about an email
  // address. The approver is the only thing standing between the two.
  const JOIN_METHOD = {
    invite: { label: "Invite code", tone: "ok",
              note: "Redeemed a code you issued to this address." },
    domain: { label: "Email domain", tone: "warn",
              note: "Matched your company domain. Nothing has verified that " +
                    "they own this address — confirm they are who they say." }
  };

  async function loadPending() {
    const panel = el("pending-panel");
    if (!panel) return;
    try {
      state.pending = await api.getPending();
      renderPending();
    } catch (err) {
      if (err && err.status === 401) return;
      el("pending-body").innerHTML =
        `<tr><td colspan="6" class="empty-state">${esc(err.message)}</td></tr>`;
    }
  }

  function renderPending() {
    const body = el("pending-body");
    if (!body) return;
    const n = state.pending.length;
    el("pending-pill").textContent = n
      ? `${n} waiting`
      : "nobody waiting";

    if (!n) {
      body.innerHTML = `<tr><td colspan="6" class="empty-state">
        No one is waiting. Requests appear here when somebody redeems an
        invite code or signs up on your email domain.
      </td></tr>`;
      return;
    }

    body.innerHTML = state.pending.map((p) => {
      const how = JOIN_METHOD[p.join_method] ||
        { label: p.join_method, tone: "", note: "" };
      const role = ROLES[p.role] || { label: p.role, tone: "" };
      return `
        <tr>
          <td>
            <div class="flow-cell">
              <span class="avatar" style="width:26px;height:26px;font-size:10px">${esc(p.initials)}</span>
              <div>
                <div class="flow-name">${esc(p.name)}</div>
                <div class="dim" style="font-size:10px">${esc(p.title || "")}</div>
              </div>
            </div>
          </td>
          <td class="mono">${esc(p.email)}</td>
          <td title="${esc(how.note)}">
            <span class="chip ${esc(how.tone)}">${esc(how.label.toUpperCase())}</span>
          </td>
          <td><span class="chip ${esc(role.tone)}">${esc(role.label.toUpperCase())}</span></td>
          <td title="${esc(fmt.datetime(p.created_at))}">${esc(fmt.ago(new Date(p.created_at).getTime()))}</td>
          <td>
            <div class="row-actions">
              <button class="row-btn" data-approve="${p.id}">APPROVE</button>
              <button class="row-btn danger" data-reject="${p.id}">REJECT</button>
            </div>
          </td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-approve]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = Number(btn.dataset.approve);
        const person = state.pending.find((p) => p.id === id);
        // Approving a domain match is the one decision on this page that acts
        // on an unverified claim, so it is the one that asks twice.
        if (person.join_method === "domain" && !window.confirm(
          `Let ${person.name} (${person.email}) into ${state.me.org_name} as ` +
          `${person.role}?\n\nThey matched your email domain. Nothing has ` +
          `verified that they own this address.`)) return;
        btn.disabled = true;
        try {
          await api.approveMember(id);
          toast(`${person.name} can now sign in.`);
          await refreshAll();
        } catch (err) {
          toast(err.message, "err");
          btn.disabled = false;
        }
      });
    });

    body.querySelectorAll("[data-reject]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = Number(btn.dataset.reject);
        const person = state.pending.find((p) => p.id === id);
        if (!window.confirm(
          `Reject ${person.name} (${person.email})?\n\n` +
          `Their request is deleted. They can ask again, but the invite code ` +
          `they used is already spent — they would need a new one.`)) return;
        btn.disabled = true;
        try {
          await api.rejectMember(id);
          toast(`Request from ${person.name} rejected.`);
          await refreshAll();
        } catch (err) {
          toast(err.message, "err");
          btn.disabled = false;
        }
      });
    });
  }

  // ── invite codes ────────────────────────────────────────────────────────
  const INVITE_STATE = {
    open:    { label: "Open",    tone: "ok" },
    used:    { label: "Used",    tone: "info" },
    expired: { label: "Expired", tone: "" },
    revoked: { label: "Revoked", tone: "bad" }
  };

  async function loadInvites() {
    const panel = el("invites-panel");
    if (!panel) return;
    try {
      state.invites = await api.getInvites();
      renderInvites();
    } catch (err) {
      if (err && err.status === 401) return;
      el("invites-body").innerHTML =
        `<tr><td colspan="7" class="empty-state">${esc(err.message)}</td></tr>`;
    }
  }

  function renderInvites() {
    const body = el("invites-body");
    if (!body) return;
    if (!state.invites.length) {
      body.innerHTML = `<tr><td colspan="7" class="empty-state">
        No codes issued yet.
      </td></tr>`;
      return;
    }

    body.innerHTML = state.invites.map((i) => {
      const st = INVITE_STATE[i.state] || { label: i.state, tone: "" };
      const role = ROLES[i.role] || { label: i.role, tone: "" };
      const expires = new Date(i.expires_at).getTime();
      return `
        <tr>
          <td class="mono dim">${esc(i.prefix)}…</td>
          <td class="mono">${esc(i.invitee_email)}</td>
          <td><span class="chip ${esc(role.tone)}">${esc(role.label.toUpperCase())}</span></td>
          <td>
            <span class="chip ${esc(st.tone)}">${esc(st.label.toUpperCase())}</span>
            ${i.used_by ? `<span class="dim" style="font-size:10px"> by ${esc(i.used_by)}</span>` : ""}
          </td>
          <td title="${esc(fmt.datetime(i.expires_at))}">
            ${i.state === "open"
              ? esc(fmt.until(expires))
              : `<span class="dim">—</span>`}
          </td>
          <td>${esc(i.created_by || "—")}</td>
          <td>
            <div class="row-actions">
              ${i.state === "open"
                ? `<button class="row-btn danger" data-revoke="${i.id}">REVOKE</button>`
                : `<span class="chip">—</span>`}
            </div>
          </td>
        </tr>`;
    }).join("");

    body.querySelectorAll("[data-revoke]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const id = Number(btn.dataset.revoke);
        const inv = state.invites.find((i) => i.id === id);
        if (!window.confirm(
          `Revoke the code issued to ${inv.invitee_email}?\n\n` +
          `It stops working immediately. Anyone already holding it can no ` +
          `longer use it.`)) return;
        btn.disabled = true;
        try {
          await api.revokeInvite(id);
          toast("Code revoked.");
          await refreshAll();
        } catch (err) {
          toast(err.message, "err");
          btn.disabled = false;
        }
      });
    });
  }

  /** After any decision, every panel on this page can be stale. */
  async function refreshAll() {
    await loadTeam();
    await loadPending();
    await loadInvites();
    await loadAudit();
  }

  async function loadAudit() {
    if (state.me.role !== "admin") return;
    if (!api.hasFeature("audit_log")) return;  // panel has been removed
    try {
      const rows = await api.getAudit(120);
      const body = el("audit-body");
      if (!rows.length) {
        body.innerHTML = `<tr><td colspan="4" class="empty-state">Nothing recorded yet.</td></tr>`;
        return;
      }
      body.innerHTML = rows.map((r) => `
        <tr>
          <td class="mono" title="${esc(fmt.datetime(r.ts))}">${esc(fmt.ago(r.ts))}</td>
          <td>${esc(r.user_label)}</td>
          <td><span class="chip ${actionTone(r.action)}">${esc(r.action)}</span></td>
          <td>${esc(r.detail)}</td>
        </tr>`).join("");
    } catch (err) {
      if (err && err.status === 401) return;
      const body = el("audit-body");
      if (body) {
        body.innerHTML =
          `<tr><td colspan="4" class="empty-state">${esc(err.message)}</td></tr>`;
      }
    }
  }

  function actionTone(action) {
    if (action.indexOf("removed") !== -1 || action.indexOf("mitigat") !== -1) return "bad";
    if (action.indexOf("added") !== -1 || action.indexOf("created") !== -1) return "ok";
    if (action.indexOf("login") !== -1) return "";
    return "info";
  }

  // ── add-member modal ────────────────────────────────────────────────────
  const modal = el("add-modal");
  const openModal = () => {
    ["m-name", "m-email", "m-pass"].forEach((id) => { el(id).value = ""; });
    // Least-privilege default that this org type actually has. "analyst" does
    // not exist in a household, so defaulting to it would preselect an option
    // the API is guaranteed to reject.
    const roles = state.assignableRoles || ["viewer"];
    const preferred = ["viewer", "analyst", "admin"].find((r) => roles.indexOf(r) !== -1);
    el("m-role").value = preferred || roles[0];
    el("add-err").classList.remove("show");
    modal.classList.add("show");
    el("m-name").focus();
  };
  const closeModal = () => modal.classList.remove("show");

  el("btn-add").addEventListener("click", openModal);
  el("add-close").addEventListener("click", closeModal);
  el("add-cancel").addEventListener("click", closeModal);
  modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal.classList.contains("show")) closeModal();
  });

  el("add-save").addEventListener("click", async () => {
    const data = {
      name: el("m-name").value.trim(),
      email: el("m-email").value.trim(),
      role: el("m-role").value,
      password: el("m-pass").value
    };
    const err = el("add-err");
    const fail = (msg) => { err.textContent = msg; err.classList.add("show"); };

    if (!data.name || !data.email) return fail("Name and email are required.");
    if (data.password.length < 12) return fail("The initial password must be at least 12 characters.");

    const btn = el("add-save");
    btn.disabled = true;
    btn.textContent = "Adding…";
    try {
      const member = await api.addMember(data);
      closeModal();
      toast(`${member.name} added as ${ROLES[member.role].label}.`);
      await loadTeam();
      await loadAudit();
    } catch (e2) {
      fail(e2.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Add member";
    }
  });

  // ── invite modal ────────────────────────────────────────────────────────
  // Guarded as a block: applyFeatureGates removes the whole thing for account
  // types without invites, and there is nothing to wire up in that case.
  const inviteModal = el("invite-modal");
  if (inviteModal) {
    const err = el("invite-err");
    const fail = (msg) => { err.textContent = msg; err.classList.add("show"); };

    const openInvite = () => {
      el("i-email").value = "";
      el("i-expiry").value = "72";
      el("i-role").innerHTML = state.assignableRoles.map((r) =>
        `<option value="${esc(r)}">${esc((ROLES[r] || { label: r }).label)} — ${esc((ROLES[r] || {}).note || "")}</option>`
      ).join("");
      const preferred = ["viewer", "analyst", "admin"]
        .find((r) => state.assignableRoles.indexOf(r) !== -1);
      el("i-role").value = preferred || state.assignableRoles[0];

      // Reset out of the reveal state, so reopening never shows a stale code.
      el("invite-form").hidden = false;
      el("invite-result").hidden = true;
      el("i-code").value = "";
      el("invite-save").hidden = false;
      el("invite-cancel").textContent = "Cancel";
      err.classList.remove("show");
      inviteModal.classList.add("show");
      el("i-email").focus();
    };
    const closeInvite = () => inviteModal.classList.remove("show");

    el("btn-invite").addEventListener("click", openInvite);
    el("invite-close").addEventListener("click", closeInvite);
    el("invite-cancel").addEventListener("click", closeInvite);
    inviteModal.addEventListener("click", (e) => {
      if (e.target === inviteModal) closeInvite();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && inviteModal.classList.contains("show")) closeInvite();
    });

    el("i-code").addEventListener("click", (e) => e.target.select());

    el("invite-save").addEventListener("click", async () => {
      const data = {
        email: el("i-email").value.trim(),
        role: el("i-role").value,
        expires_in_hours: Number(el("i-expiry").value)
      };
      if (!data.email) return fail("Enter the address this code is for.");

      const btn = el("invite-save");
      btn.disabled = true;
      btn.textContent = "Creating…";
      try {
        const made = await api.createInvite(data);
        // Swap the form for the code rather than closing: this response is the
        // only time the code exists in readable form anywhere.
        el("invite-form").hidden = true;
        el("invite-result").hidden = false;
        el("i-code").value = made.code;
        el("i-code").select();
        btn.hidden = true;
        el("invite-cancel").textContent = "Done";
        err.classList.remove("show");
        await refreshAll();
      } catch (e2) {
        fail(e2.message);
      } finally {
        btn.disabled = false;
        btn.textContent = "Create code";
      }
    });
  }

  window.SENTRY_ON_SEARCH = function (q) {
    state.query = q;
    renderTeam();
  };
})();
