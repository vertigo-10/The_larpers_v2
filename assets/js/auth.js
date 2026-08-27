/**
 * Login, signup, and join-an-existing-org.
 *
 * One file drives all three pages; it picks its behaviour from which form is
 * present. Things worth noting:
 *
 *   - The `next` parameter is only ever used as a *relative* path. Reflecting
 *     an arbitrary attacker-supplied URL back into a redirect is an open-redirect
 *     bug, and on a security console it is a convincing phishing primitive.
 *   - Where you land when there is no `next` depends on the account type, and
 *     that decision lives in ui.landingFor() rather than here, so the page
 *     guard and the auth pages cannot come to different conclusions.
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
    errBox.scrollIntoView({ block: "nearest" });
  }
  function clearError() {
    if (errBox) errBox.classList.remove("show");
  }

  const val = (id) => {
    const el = document.getElementById(id);
    return el ? el.value.trim() : "";
  };
  const raw = (id) => {
    const el = document.getElementById(id);
    return el ? el.value : "";
  };

  /**
   * Only same-origin relative paths are allowed. Anything with a scheme, a
   * protocol-relative prefix, or a backslash is discarded. Returns null when
   * there is nothing usable, so the caller falls back to the account's own
   * landing page rather than to a hardcoded one.
   */
  function safeNext() {
    const v = new URLSearchParams(window.location.search).get("next");
    if (!v) return null;
    if (!v.startsWith("/") || v.startsWith("//") || v.includes("\\")) return null;
    if (/^\/+[a-z][a-z0-9+.-]*:/i.test(v)) return null;
    return v;
  }

  /** Where this account goes now that it holds a session. */
  function land(user) {
    window.location.href = safeNext() || ui.landingFor(user);
  }

  /**
   * Runs a submit with the button locked and any failure put on screen.
   *
   * Deliberately does not re-enable the button on success: every caller either
   * navigates away or replaces the form, and a button that comes back to life
   * for a moment in between is a duplicate submit waiting to happen.
   */
  async function run(button, fn) {
    clearError();
    button.disabled = true;
    const label = button.textContent;
    button.textContent = "Working…";
    try {
      await fn();
    } catch (err) {
      showError(err.message || "Something went wrong. Try again.");
      button.disabled = false;
      button.textContent = label;
    }
  }

  /**
   * Live password feedback mirroring the server's rule, so the failure is
   * caught before a round trip rather than after. Bound by attribute because
   * the signup form has one of these per branch.
   */
  document.querySelectorAll("[data-pw-hint]").forEach((hint) => {
    const input = hint.parentElement.querySelector("input[type=password]");
    if (!input) return;
    input.addEventListener("input", () => {
      const n = input.value.length;
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
  });

  // ── login ──────────────────────────────────────────────────────────────
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    // If the visitor is already signed in, don't make them do it twice.
    api.me().then(land).catch(() => {});

    // A fresh deployment has no accounts at all — point the first visitor at
    // signup instead of a login form they cannot possibly satisfy.
    api.bootstrap().then((b) => {
      if (!b.has_users) window.location.href = "signup.html";
    }).catch(() => {
      showError("Cannot reach the SENTRY backend. Check that the API is running.");
    });

    loginForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const email = val("email");
      const password = raw("password");
      if (!email || !password) return showError("Enter your email and password.");
      run(document.getElementById("submit"), async () => {
        land(await api.login({ email, password }));
      });
    });
  }

  // ── signup ─────────────────────────────────────────────────────────────
  const signupForm = document.getElementById("signup-form");
  if (signupForm) {
    const steps = {};
    signupForm.querySelectorAll("[data-step]").forEach((el) => {
      steps[el.getAttribute("data-step")] = el;
    });

    const titleEl = document.getElementById("auth-title");
    const subEl = document.getElementById("auth-sub");
    const COPY = {
      choose: {
        title: "What are you protecting?",
        sub: "This decides how the whole product reads — which screens you get, " +
             "what the words on them mean, and who else can be let in."
      },
      consumer: {
        title: "Set up your home network",
        sub: "Four things and you're done. Nothing here needs to be changed later."
      },
      "company-1": {
        title: "Create your account",
        sub: "You'll be the first administrator, so this account can approve " +
             "everyone who comes after it."
      },
      "company-2": {
        title: "Tell us about your organisation",
        sub: "This is what appears on reports and in the audit trail, and it " +
             "decides how colleagues get in."
      }
    };

    // A stack rather than a fixed order, so Back retraces the route actually
    // taken instead of guessing at one. The company branch is two steps deep
    // and the household branch is one, and both share this button.
    const trail = [];
    let step = "choose";

    function show(name) {
      clearError();
      Object.keys(steps).forEach((k) => { steps[k].hidden = k !== name; });
      step = name;
      const copy = COPY[name];
      if (copy && titleEl && subEl) {
        titleEl.textContent = copy.title;
        subEl.textContent = copy.sub;
      }
      const first = steps[name].querySelector("input");
      if (first) first.focus();
    }

    signupForm.querySelectorAll("[data-back]").forEach((btn) => {
      btn.addEventListener("click", () => show(trail.pop() || "choose"));
    });

    // ── step 1: which kind of account ──
    const picker = document.getElementById("org-type-picker");
    let choice = "company";
    picker.querySelectorAll("[data-choice]").forEach((btn) => {
      btn.addEventListener("click", () => {
        picker.querySelectorAll("[data-choice]").forEach((b) => b.classList.remove("selected"));
        btn.classList.add("selected");
        choice = btn.getAttribute("data-choice");
      });
    });

    document.getElementById("btn-choose").addEventListener("click", () => {
      // Joining is not a signup at all — it creates no organisation and returns
      // no session — so it gets its own page rather than a fifth step here.
      if (choice === "join") {
        window.location.href = "join.html";
        return;
      }
      trail.push("choose");
      show(choice === "consumer" ? "consumer" : "company-1");
    });

    // ── company step 1 → step 2 ──
    // Checked here rather than at the end, so a typo in the email is caught on
    // the step that contains the email rather than on a later screen the user
    // then has to navigate back out of.
    document.getElementById("btn-company-next").addEventListener("click", () => {
      const missing = !val("name_company") || !val("email_company") || !raw("password_company");
      if (missing) return showError("Fill in every field.");
      if (raw("password_company").length < 12) {
        return showError("Password must be at least 12 characters.");
      }
      clearError();
      trail.push("company-1");
      show("company-2");
    });

    // Both branches end in a real submit button, so one handler dispatches on
    // whichever step is showing. Pressing Enter in a field lands here too,
    // which is why the choose step is not a submit button at all.
    signupForm.addEventListener("submit", (e) => {
      e.preventDefault();
      if (step === "consumer") return submitConsumer();
      if (step === "company-2") return submitCompany();
    });

    function submitConsumer() {
      const data = {
        org_type: "consumer",
        org_name: val("org_name_consumer"),
        name: val("name_consumer"),
        email: val("email_consumer"),
        password: raw("password_consumer")
      };
      if (!data.org_name || !data.name || !data.email || !data.password) {
        return showError("Fill in every field.");
      }
      if (data.password.length < 12) {
        return showError("Password must be at least 12 characters.");
      }
      run(steps.consumer.querySelector("[data-submit]"), async () => {
        land(await api.signup(data));
      });
    }

    function submitCompany() {
      const data = {
        org_type: "company",
        org_name: val("org_name_company"),
        name: val("name_company"),
        email: val("email_company"),
        password: raw("password_company"),
        title: val("title_company"),
        // Sent with the signup rather than PATCHed afterwards: if the server
        // refuses the domain, nothing is created, and the admin fixes it here
        // instead of ending up with a live account and a setting that silently
        // never applied.
        email_domain: val("email_domain_company")
      };
      if (!data.org_name) return showError("Enter your organisation's name.");
      run(steps["company-2"].querySelector("[data-submit]"), async () => {
        land(await api.signup(data));
      });
    }

    show("choose");
  }

  // ── join an existing organisation ──────────────────────────────────────
  const joinForm = document.getElementById("join-form");
  if (joinForm) {
    joinForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const data = {
        name: val("join_name"),
        email: val("join_email"),
        password: raw("join_password"),
        title: val("join_title"),
        code: val("join_code")
      };
      if (!data.name || !data.email || !data.password) {
        return showError("Fill in your name, email and password.");
      }
      if (data.password.length < 12) {
        return showError("Password must be at least 12 characters.");
      }

      run(document.getElementById("submit"), async () => {
        const res = await api.join(data);
        // No redirect, because there is no session and no page this account
        // can open yet. Replacing the form rather than leaving it disabled
        // makes it obvious that the thing to do now is wait.
        joinForm.remove();
        const alt = document.getElementById("alt");
        const done = document.createElement("div");
        done.className = "auth-done";
        const head = document.createElement("div");
        head.className = "t";
        head.textContent = "Request sent";
        const body = document.createElement("div");
        // textContent, not innerHTML: org_name is whatever somebody typed at
        // signup, and this is the one place it reaches a page belonging to a
        // person from outside that organisation.
        body.textContent = res.message;
        done.appendChild(head);
        done.appendChild(body);
        alt.parentNode.insertBefore(done, alt);
      });
    });
  }
})();
