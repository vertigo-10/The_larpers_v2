window.SENTRY_CONFIG = {
  apiBaseUrl: "",
  wsUrl: "",
  useMockData: true,
  pollIntervalMs: 2000,
  flowIntervalMs: 1400,
  maxTableRows: 45,
  historyPoints: 90,
  org: "Northgate Systems",
  operator: { name: "Jude Mekat", role: "Security Operations Lead", initials: "JM" },
  model: { name: "sentry-ddos-v1", framework: "PyTorch", dataset: "CIC-IDS2017", accuracy: 99.2 },
  classes: ["BENIGN", "DDoS", "DoS Hulk", "PortScan", "Bot", "FTP-Patator"],
  nodes: [
    { id: "edge-01", label: "EDGE-01", desc: "Core edge router" },
    { id: "edge-02", label: "EDGE-02", desc: "Failover edge router" },
    { id: "dc-lb-01", label: "DC-LB-01", desc: "Datacenter load balancer" },
    { id: "vpn-gw", label: "VPN-GW", desc: "Remote access gateway" },
    { id: "api-tier", label: "API-TIER", desc: "Public API subnet" },
    { id: "db-tier", label: "DB-TIER", desc: "Database subnet" },
    { id: "cdn-pop", label: "CDN-POP", desc: "CDN point of presence" },
    { id: "iot-seg", label: "IOT-SEG", desc: "IoT segment" }
  ]
};

window.SENTRY_SETTINGS_KEY = "sentry.settings";

// Settings page writes overrides here so the backend can be pointed at a real
// service without editing this file.
(function () {
  try {
    const saved = JSON.parse(localStorage.getItem(window.SENTRY_SETTINGS_KEY) || "{}");
    ["apiBaseUrl", "wsUrl", "useMockData", "pollIntervalMs", "flowIntervalMs", "maxTableRows", "org"]
      .forEach(k => { if (saved[k] !== undefined) window.SENTRY_CONFIG[k] = saved[k]; });
    if (saved.operator) Object.assign(window.SENTRY_CONFIG.operator, saved.operator);
  } catch (err) {
    console.warn("[sentry] could not read saved settings:", err.message);
  }
})();
