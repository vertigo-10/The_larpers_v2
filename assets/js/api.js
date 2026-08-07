(function () {
  const cfg = window.AEGIS_CONFIG;
  const mock = window.AEGIS_MOCK;

  const live = { connected: false, socket: null, listeners: [], degraded: false };

  function url(path) { return `${cfg.apiBaseUrl.replace(/\/$/, "")}${path}`; }

  async function get(path) {
    const res = await fetch(url(path), { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  }

  // Every endpoint falls back to the mock engine so the UI runs standalone
  // before the PyTorch service is wired up.
  async function withFallback(path, fallback) {
    if (cfg.useMockData || !cfg.apiBaseUrl) return fallback();
    try {
      const data = await get(path);
      live.degraded = false;
      return data;
    } catch (err) {
      live.degraded = true;
      console.warn(`[aegis] ${path} unavailable, using mock:`, err.message);
      return fallback();
    }
  }

  const api = {
    isLive: () => !cfg.useMockData && !!cfg.apiBaseUrl,

    getStatus: () => withFallback("/api/status", () => ({
      model: cfg.model.name,
      framework: cfg.model.framework,
      dataset: cfg.model.dataset,
      accuracy: cfg.model.accuracy,
      uptime_s: 372840,
      source: "mock"
    })),

    getHistory: (points) => withFallback(`/api/metrics/history?points=${points}`,
      () => mock.seedHistory(points)),

    getPoint: () => withFallback("/api/metrics/current", () => mock.nextPoint()),

    getSummary: () => withFallback("/api/summary", () => mock.summary()),

    getFlows: (limit) => withFallback(`/api/flows?limit=${limit}`,
      () => Array.from({ length: limit }, () => mock.nextFlow())),

    getFlow: () => withFallback("/api/flows/next", () => mock.nextFlow()),

    getClassBreakdown: () => withFallback("/api/analytics/classes", () => mock.classBreakdown()),

    getNodeTraffic: () => withFallback("/api/analytics/nodes", () => mock.nodeTraffic()),

    getPortActivity: () => withFallback("/api/analytics/ports", () => mock.portActivity()),

    getNodeStats: () => withFallback("/api/nodes", () => mock.nodeStats()),

    async mitigate(flowId, srcIp) {
      if (!api.isLive()) return { ok: true, flow_id: flowId, action: "blocked", source: "mock" };
      const res = await fetch(url("/api/mitigate"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ flow_id: flowId, src_ip: srcIp })
      });
      return res.json();
    },

    async setThreshold(value) {
      if (!api.isLive()) return { ok: true, threshold: value, source: "mock" };
      const res = await fetch(url("/api/model/threshold"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ threshold: value })
      });
      return res.json();
    },

    onFlow(fn) { live.listeners.push(fn); },

    connectStream() {
      if (!cfg.wsUrl || cfg.useMockData) return false;
      try {
        live.socket = new WebSocket(cfg.wsUrl);
        live.socket.onopen = () => { live.connected = true; };
        live.socket.onclose = () => { live.connected = false; };
        live.socket.onmessage = (ev) => {
          try { live.listeners.forEach(fn => fn(JSON.parse(ev.data))); } catch (_) {}
        };
        return true;
      } catch (err) {
        console.warn("[aegis] websocket failed:", err.message);
        return false;
      }
    },

    streamConnected: () => live.connected,

    isDegraded: () => live.degraded
  };

  window.AEGIS_API = api;
})();
