/**
 * Login + signup.
 *
 * One file drives both pages; it picks its behaviour from which form is
 * present. Two things worth noting:
 *
 *   - The `next` parameter is only ever used as a *relative* path. Reflecting
 *     an arbitrary attacker-supplied URL back into a redirect is an open-redirect
 *     bug, and on a security console it is a convincing phishing primitive.
 *   - Server-side validation errors are shown verbatim rather than replaced with
 *     a friendly generic, because the password rules live on the server and the
 *     user cannot fix what they cannot see.
 */
(function () {
  const api = window.SENTRY_API;
  const ui = window.SENTRY_UI;

  const mark = document.getElementById("brand-mark");
  if (mark) mark.innerHTML = ui.icon("shieldCheck", 17);

  const errBox = document.getElementById("err");
  function showError(msg) {
    if (!errBox) return;
    errBox.textContent = msg;
    errBox.classList.add("show");
  }
  function clearError() {
    if (errBox) errBox.classList.remove("show");
  }

  /**
   * Only same-origin relative paths are allowed. Anything with a scheme, a
   * protocol-relative prefix, or a backslash is discarded.
   */
  function safeNext() {
    const raw = new URLSearchParams(window.location.search).get("next");
    if (!raw) return "index.html";
    if (!raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) return "index.html";
    if (/^\/+[a-z][a-z0-9+.-]*:/i.test(raw)) return "index.html";
    return raw;
  }

  async function submit(button, fn) {
    clearError();
    button.disabled = true;
    const label = button.textContent;
    button.textContent = "Working…";
    try {
      await fn();
      window.location.href = safeNext();
    } catch (err) {
      showError(err.message || "Something went wrong. Try again.");
      button.disabled = false;
      button.textContent = label;
    }
  }

  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    // If the visitor is already signed in, don't make them do it twice.
    api.me().then(() => { window.location.href = safeNext(); }).catch(() => {});

    // A fresh deployment has no accounts at all — point the first visitor at
    // signup instead of a login form they cannot possibly satisfy.
    api.bootstrap().then((b) => {
      if (!b.has_users) window.location.href = "signup.html";
    }).catch(() => {
      showError("Cannot reach the SENTRY backend. Check that the API is running.");
    });

    loginForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const email = document.getElementById("email").value.trim();
      const password = document.getElementById("password").value;
      if (!email || !password) return showError("Enter your email and password.");
      submit(document.getElementById("submit"), () => api.login({ email, password }));
    });
  }

  const signupForm = document.getElementById("signup-form");
  if (signupForm) {
    const pw = document.getElementById("password");
    const hint = document.getElementById("pw-hint");

    // Org-type picker: two cards, one selected at a time, feeding a hidden
    // input so the rest of the form logic doesn't need to know about it.
    const picker = document.getElementById("org-type-picker");
    const orgTypeInput = document.getElementById("org_type");
    const orgNameLabel = document.getElementById("org_name-label");
    const orgNameField = document.getElementById("org_name");
    const ORG_TYPE_COPY = {
      company: { label: "Organisation name", placeholder: "Acme Networks" },
      consumer: { label: "Household name", placeholder: "The Mekat House" }
    };
    if (picker) {
      picker.querySelectorAll("[data-org-type]").forEach((btn) => {
        btn.addEventListener("click", () => {
          picker.querySelectorAll("[data-org-type]").forEach((b) => b.classList.remove("selected"));
          btn.classList.add("selected");
          const type = btn.getAttribute("data-org-type");
          orgTypeInput.value = type;
          const copy = ORG_TYPE_COPY[type] || ORG_TYPE_COPY.company;
          orgNameLabel.textContent = copy.label;
          orgNameField.placeholder = copy.placeholder;
        });
      });
    }

    // Live feedback that mirrors the server's rule, so the failure is caught
    // before a round trip rather than after.
    pw.addEventListener("input", () => {
      const n = pw.value.length;
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

    signupForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const data = {
        org_name: document.getElementById("org_name").value.trim(),
        org_type: orgTypeInput ? orgTypeInput.value : "company",
        name: document.getElementById("name").value.trim(),
        email: document.getElementById("email").value.trim(),
        password: pw.value
      };
      if (!data.org_name || !data.name || !data.email || !data.password) {
        return showError("Fill in every field.");
      }
      if (data.password.length < 12) {
        return showError("Password must be at least 12 characters.");
      }
      submit(document.getElementById("submit"), () => api.signup(data));
    });
  }
})();
