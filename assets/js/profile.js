/**
 * Profile.
 *
 * The account page for the signed-in user: their real record, editable display
 * fields, and a password change that goes through the server's own strength
 * rules rather than a duplicate set here.
 *
 * The audit trail is admin-only server-side. Rather than showing a panel that
 * fails to load for analysts and viewers, the panel is replaced with a note
 * explaining why — an unexplained empty table reads as a bug.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;
  const { esc, icon, fmt, toast } = ui;
  const el = (id) => document.getElementById(id);

  const ROLES = {
    admin: {
      label: "Admin", tone: "bad",
      perms: [
        ["View live traffic and incidents", true],
        ["Mitigate flows and work incidents", true],
        ["Change detection settings", true],
        ["Manage team members", true],
        ["Read the audit trail", true]
      ]
    },
    analyst: {
      label: "Analyst", tone: "info",
      perms: [
        ["View live traffic and incidents", true],
        ["Mitigate flows and work incidents", true],
        ["Change detection settings", false],
        ["Manage team members", false],
        ["Read the audit trail", false]
      ]
    },
    viewer: {
      label: "Viewer", tone: "",
      perms: [
        ["View live traffic and incidents", true],
        ["Mitigate flows and work incidents", false],
        ["Change detection settings", false],
        ["Manage team members", false],
        ["Read the audit trail", false]
      ]
    }
  };

  const state = { user: null };

  ui.mountSidebar("profile");
  el("btn-settings").innerHTML = `${icon("settings", 12)} Settings`;

  init().catch((err) => {
    if (err && err.status === 401) return;
    ui.fatalBanner(err.message || "Cannot reach the SENTRY backend.");
  });

  async function init() {
    state.user = await api.me(true);
    const status = await api.getStatus().catch(() => null);
    render(state.user, status);
    loadActivity();
  }

  function render(u, status) {
    const role = ROLES[u.role] || { label: u.role, tone: "", perms: [] };

    el("topbar-avatar").textContent = u.initials || "··";
    el("pf-initials").textContent = u.initials || "··";
    el("pf-name").textContent = u.name;
    el("pf-title").textContent = u.title || "—";

    el("pf-badges").innerHTML = `
      <span class="chip ${role.tone}">${esc(role.label.toUpperCase())}</span>
      <span class="chip ${u.is_active ? "ok" : "warn"}">${u.is_active ? "ACTIVE" : "SUSPENDED"}</span>`;

    el("in-name").value = u.name;
    el("in-title").value = u.title || "";
    el("in-email").value = u.email;

    const session = [
      ["Organisation", u.org_name],
      ["Email", u.email],
      ["Role", role.label],
      ["Member since", fmt.datetime(u.created_at)],
      ["Last sign-in", u.last_login_at ? fmt.datetime(u.last_login_at) : "this is your first"],
      ["Backend", status ? `v${status.version}` : "unreachable"],
      ["Server uptime", status ? fmt.uptime(status.uptime_s) : "—"],
      ["Traffic source", status ? (status.simulator ? "simulator" : "ingested only") : "—"]
    ];
    el("pf-session").innerHTML = session.map(([k, v]) => `
      <div class="kv"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join("");

    el("pf-perms").innerHTML = role.perms.map(([label, allowed]) => `
      <div class="kv">
        <span class="k">${esc(label)}</span>
        <span class="v" style="color:${allowed ? "var(--green)" : "var(--muted)"}">
          ${icon(allowed ? "check" : "x", 13)}
        </span>
      </div>`).join("");
  }

  async function loadActivity() {
    const body = el("pf-actions");
    if (state.user.role !== "admin") {
      el("activity-panel").querySelector(".table-scroll").innerHTML = `
        <div class="section-note" style="padding:18px 15px">
          The audit trail is readable by admins only, so your own history is not
          shown here. Your actions are still recorded — ask an admin if you need
          a copy.
        </div>`;
      return;
    }
    try {
      const rows = await api.getAudit(200);
      const mine = rows.filter((r) => r.user_label === state.user.name).slice(0, 60);
      if (!mine.length) {
        body.innerHTML = `<tr><td colspan="3" class="empty-state">Nothing recorded for you yet.</td></tr>`;
        return;
      }
      body.innerHTML = mine.map((r) => `
        <tr>
          <td class="mono" title="${esc(fmt.datetime(r.ts))}">${esc(fmt.ago(r.ts))}</td>
          <td><span class="chip info">${esc(r.action)}</span></td>
          <td>${esc(r.detail)}</td>
        </tr>`).join("");
    } catch (err) {
      body.innerHTML = `<tr><td colspan="3" class="empty-state">${esc(err.message)}</td></tr>`;
    }
  }

  function fail(id, msg) {
    const box = el(id);
    box.textContent = msg;
    box.classList.add("show");
  }
  function clear(id) {
    el(id).classList.remove("show");
  }

  // ── save display details ────────────────────────────────────────────────
  el("btn-save-details").addEventListener("click", async () => {
    clear("detail-err");
    const name = el("in-name").value.trim();
    const title = el("in-title").value.trim();
    if (!name) return fail("detail-err", "A display name is required.");

    const btn = el("btn-save-details");
    btn.disabled = true;
    btn.textContent = "Saving…";
    try {
      // PATCH /api/auth/me — not the admin team route, so an analyst or viewer
      // can edit their own details without holding admin rights.
      state.user = await api.updateProfile({ name, title });
      render(state.user, await api.getStatus().catch(() => null));
      toast("Profile updated.");
    } catch (err) {
      fail("detail-err", err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Save details";
    }
  });

  // ── change password ─────────────────────────────────────────────────────
  const pwNew = el("in-new");
  pwNew.addEventListener("input", () => {
    const n = pwNew.value.length;
    const hint = el("pw-hint");
    if (!n) {
      hint.textContent = "At least 12 characters. Length beats symbols.";
      hint.style.color = "";
    } else if (n < 12) {
      hint.textContent = `${12 - n} more character${12 - n === 1 ? "" : "s"} needed.`;
      hint.style.color = "var(--amber)";
    } else {
      hint.textContent = "Long enough.";
      hint.style.color = "var(--green)";
    }
  });

  el("btn-save-pw").addEventListener("click", async () => {
    clear("pw-err");
    const current = el("in-current").value;
    const next = pwNew.value;
    const confirm = el("in-confirm").value;

    if (!current || !next) return fail("pw-err", "Fill in both password fields.");
    if (next !== confirm) return fail("pw-err", "The two new passwords do not match.");
    if (next.length < 12) return fail("pw-err", "New password must be at least 12 characters.");
    if (next === current) return fail("pw-err", "The new password must differ from the current one.");

    const btn = el("btn-save-pw");
    btn.disabled = true;
    btn.textContent = "Updating…";
    try {
      await api.changePassword({ current_password: current, new_password: next });
      ["in-current", "in-new", "in-confirm"].forEach((id) => { el(id).value = ""; });
      el("pw-hint").textContent = "At least 12 characters. Length beats symbols.";
      el("pw-hint").style.color = "";
      toast("Password updated.");
    } catch (err) {
      fail("pw-err", err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "Update password";
    }
  });

  el("btn-signout").addEventListener("click", async () => {
    try { await api.logout(); } catch (_) { /* clear the client side regardless */ }
    window.location.href = "login.html";
  });
})();
