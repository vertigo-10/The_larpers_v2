/**
 * API client.
 *
 * Two rules this file exists to enforce:
 *   1. There is no mock fallback. If the backend is unreachable the UI says so
 *      and renders nothing rather than inventing traffic. The previous version
 *      silently substituted random data — for a security tool that means
 *      showing a calm, green dashboard during an outage.
 *   2. Every request carries the session cookie, and a 401 bounces to the login
 *      page, so no view ever renders half-authenticated.
 */
(function () {
  const cfg = window.SENTRY_CONFIG;

  const state = {
    socket: null,
    connected: false,
    listeners: { flow: [], metric: [], status: [] },
    reconnectDelay: 1000,
    lastError: null,
    user: null,
    features: null
  };

  const AUTH_PAGES = ["/login.html", "/signup.html", "/join.html"];
  const onAuthPage = () => AUTH_PAGES.some((p) => window.location.pathname.endsWith(p));

  function url(path) {
    return `${(cfg.apiBaseUrl || "").replace(/\/$/, "")}${path}`;
  }

  class ApiError extends Error {
    constructor(message, status, body) {
      super(message);
      this.status = status;
      this.body = body;
    }
  }

  async function request(path, options = {}) {
    const opts = Object.assign(
      {
        credentials: "include", // session cookie
        headers: Object.assign(
          { Accept: "application/json" },
          options.body ? { "Content-Type": "application/json" } : {}
        )
      },
      options
    );

    let res;
    try {
      res = await fetch(url(path), opts);
    } catch (err) {
      state.lastError = `Cannot reach the API (${err.message})`;
      throw new ApiError(state.lastError, 0, null);
    }

    if (res.status === 401) {
      state.user = null;
      // Cleared alongside the user: the next session may be a different
      // account type, and a stale map would render the wrong feature set.
      state.features = null;
      if (!onAuthPage()) {
        const next = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.href = `login.html?next=${next}`;
      }
      throw new ApiError("Not authenticated", 401, null);
    }

    let body = null;
    const text = await res.text();
    if (text) {
      try { body = JSON.parse(text); } catch (_) { body = text; }
    }

    if (!res.ok) {
      const detail =
        (body && body.detail) || (typeof body === "string" ? body : `HTTP ${res.status}`);
      // Pydantic prefixes anything raised by a field validator with
      // "Value error, ". Our validators are written as sentences meant for the
      // person filling the form, so the prefix is pure noise on screen.
      const message = Array.isArray(detail)
        ? detail
            .map((d) => (d.msg || JSON.stringify(d)).replace(/^Value error,\s*/, ""))
            .join("; ")
        : detail;
      throw new ApiError(message, res.status, body);
    }

    state.lastError = null;
    return body;
  }

  const get = (p) => request(p);
  const post = (p, data) => request(p, { method: "POST", body: JSON.stringify(data || {}) });
  const patch = (p, data) => request(p, { method: "PATCH", body: JSON.stringify(data || {}) });
  const del = (p) => request(p, { method: "DELETE" });

  const api = {
    ApiError,

    // ── auth ────────────────────────────────────────────────────────────
    signup: (data) => post("/api/auth/signup", data),
    /**
     * Ask to join an org that already exists.
     *
     * Unlike signup and login this returns no session — the response is a
     * pending-status object, and the caller must show it rather than redirect
     * into a dashboard the account cannot open yet.
     */
    join: (data) => post("/api/auth/join", data),
    login: (data) => post("/api/auth/login", data),
    logout: () => post("/api/auth/logout"),
    changePassword: (data) => post("/api/auth/password", data),
    bootstrap: () => get("/api/auth/bootstrap"),

    async me(force) {
      if (state.user && !force) return state.user;
      state.user = await get("/api/auth/me");
      return state.user;
    },

    /**
     * What this account type offers. Cached like `me` because it is read on
     * every page render and cannot change without a reload.
     *
     * This is advisory only — it decides what to *draw*. The API enforces the
     * same table independently, so a consumer account that guesses a gated URL
     * still gets a 403 rather than an audit log.
     */
    async features(force) {
      if (state.features && !force) return state.features;
      state.features = await get("/api/auth/features");
      return state.features;
    },
    /** Convenience predicate. Defaults to hiding when the map is unavailable. */
    hasFeature(name) {
      const f = state.features && state.features.features;
      return Boolean(f && f[name]);
    },
    // Self-service profile edit. Separate from updateMember (admin-only) on
    // purpose: this route cannot change role or active status.
    async updateProfile(data) {
      state.user = await patch("/api/auth/me", data);
      return state.user;
    },
    cachedUser: () => state.user,

    // ── status + metrics ────────────────────────────────────────────────
    getStatus: () => get("/api/status"),
    getHealth: () => get("/api/health"),
    getSummary: () => get("/api/summary"),
    getHistory: (points) => get(`/api/metrics/history?points=${points}`),
    getCurrent: () => get("/api/metrics/current"),

    // ── flows ───────────────────────────────────────────────────────────
    getFlows({ limit = 50, tab = "live", q = "", node = "all" } = {}) {
      const params = new URLSearchParams({ limit, tab });
      if (q) params.set("q", q);
      if (node && node !== "all") params.set("node", node);
      return get(`/api/flows?${params.toString()}`);
    },
    ingest: (flows) => post("/api/ingest", { flows }),

    // ── analytics ───────────────────────────────────────────────────────
    getClassBreakdown: () => get("/api/analytics/classes"),
    getNodeTraffic: () => get("/api/analytics/nodes"),
    getPortActivity: () => get("/api/analytics/ports"),
    getNodes: () => get("/api/nodes"),

    // `window` is in minutes. The server caps it, so a caller cannot ask for a
    // range that would table-scan the whole flow history.
    getTalkers({ window = 15, limit = 25 } = {}) {
      return get(`/api/analytics/talkers?window=${window}&limit=${limit}`);
    },
    getTrafficBreakdown: (window = 15) => get(`/api/analytics/traffic?window=${window}`),

    // ── baseline + anomalies ────────────────────────────────────────────
    getAnomalies: (status = "all", limit = 100) =>
      get(`/api/anomalies?status=${status}&limit=${limit}`),
    acknowledgeAnomaly: (id) => post(`/api/anomalies/${id}/acknowledge`),
    getBaseline: (metric = "flows") => get(`/api/baseline?metric=${metric}`),

    // ── incidents ───────────────────────────────────────────────────────
    getIncidents: (status = "all", limit = 100) =>
      get(`/api/incidents?status=${status}&limit=${limit}`),
    // `durationMinutes` only applies to "ban". Omitted entirely rather than
    // sent as null when there is none: a permanent ban and a non-ban action
    // both have no clock, and the server rejects the key on anything but a ban.
    incidentAction: (id, action, durationMinutes) => post(
      `/api/incidents/${id}/action`,
      durationMinutes == null ? { action } : { action, duration_minutes: durationMinutes }
    ),

    // ── actions ─────────────────────────────────────────────────────────
    mitigate: (flowId, srcIp) => post("/api/mitigate", { flow_id: flowId, src_ip: srcIp }),
    setThreshold: (value) => post("/api/model/threshold", { threshold: value }),
    getModelMetrics: () => get("/api/model/metrics"),

    // ── settings + team ─────────────────────────────────────────────────
    getSettings: () => get("/api/settings"),
    updateSettings: (data) => patch("/api/settings", data),
    getTeam: () => get("/api/team"),
    addMember: (data) => post("/api/team", data),
    updateMember: (id, data) => patch(`/api/team/${id}`, data),
    removeMember: (id) => del(`/api/team/${id}`),
    getAudit: (limit = 100) => get(`/api/team/audit?limit=${limit}`),

    // ── invites + the approval queue ────────────────────────────────────
    // createInvite is the only call that returns a usable code, and only in
    // its response — like a collector key, it is stored hashed and the listing
    // can show nothing but the prefix.
    getInvites: () => get("/api/team/invites"),
    createInvite: (data) => post("/api/team/invites", data),
    revokeInvite: (id) => del(`/api/team/invites/${id}`),
    getPending: () => get("/api/team/pending"),
    approveMember: (id) => post(`/api/team/${id}/approve`),
    rejectMember: (id) => post(`/api/team/${id}/reject`),

    // ── collector keys ──────────────────────────────────────────────────
    // createKey is the only call that ever returns a usable secret, and only
    // in its response — it is stored hashed, so there is no way to re-read it.
    getKeys: () => get("/api/team/keys"),
    createKey: (label) => post("/api/team/keys", { label }),
    revokeKey: (id) => del(`/api/team/keys/${id}`),

    // ── flow exporters ──────────────────────────────────────────────────
    // NetFlow has no authentication, so registering a source address is the
    // decision about whose traffic we ingest. Every write here is admin-only
    // server-side.
    getExporters: () => get("/api/exporters"),
    createExporter: (data) => post("/api/exporters", data),
    updateExporter: (id, data) => patch(`/api/exporters/${id}`, data),
    deleteExporter: (id) => del(`/api/exporters/${id}`),
    // Already filtered server-side to senders this org can prove adjacency to.
    // An empty list is the normal answer and must not be read as an error —
    // most orgs will never see anything here.
    getUnclaimedExporters: () => get("/api/exporters/unclaimed"),
    getCollectorStatus: () => get("/api/exporters/status"),

    // ── reports ─────────────────────────────────────────────────────────
    getReport: (days = 7) => get(`/api/reports/summary?days=${days}`),

    // ── live stream ─────────────────────────────────────────────────────
    on(event, fn) {
      if (state.listeners[event]) state.listeners[event].push(fn);
    },

    connectStream() {
      if (state.socket && state.socket.readyState <= 1) return;
      try {
        const socket = new WebSocket(cfg.wsUrl);
        state.socket = socket;

        socket.onopen = () => {
          state.connected = true;
          state.reconnectDelay = 1000;
          state.listeners.status.forEach((fn) => fn(true));
        };

        socket.onmessage = (ev) => {
          let msg;
          try { msg = JSON.parse(ev.data); } catch (_) { return; }
          const handlers = state.listeners[msg.type];
          if (handlers) handlers.forEach((fn) => fn(msg.data));
        };

        socket.onclose = () => {
          state.connected = false;
          state.listeners.status.forEach((fn) => fn(false));
          // Exponential backoff, capped — avoids hammering a restarting server.
          if (!onAuthPage()) {
            setTimeout(() => api.connectStream(), state.reconnectDelay);
            state.reconnectDelay = Math.min(state.reconnectDelay * 2, 30000);
          }
        };

        socket.onerror = () => socket.close();
      } catch (err) {
        console.warn("[sentry] websocket failed:", err.message);
      }
    },

    isStreamConnected: () => state.connected,
    lastError: () => state.lastError
  };

  window.SENTRY_API = api;
})();
