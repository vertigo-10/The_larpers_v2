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
    me: null, members: [], query: "",
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

  window.SENTRY_ON_SEARCH = function (q) {
    state.query = q;
    renderTeam();
  };
})();
