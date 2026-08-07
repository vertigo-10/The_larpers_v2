(function () {
  const cfg = window.AEGIS_CONFIG;

  const state = {
    baseline: 640,
    attackPhase: 0,
    attackTicks: 0,
    flowSeq: 4821,
    blocked: 1284,
    nodeLoad: {}
  };

  cfg.nodes.forEach((n, i) => { state.nodeLoad[n.id] = 180 + i * 55 + rand(0, 90); });

  function rand(a, b) { return a + Math.random() * (b - a); }
  function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
  function ip() {
    return Math.random() < 0.35
      ? `10.${Math.floor(rand(0, 4))}.${Math.floor(rand(0, 255))}.${Math.floor(rand(1, 254))}`
      : `${Math.floor(rand(11, 223))}.${Math.floor(rand(0, 255))}.${Math.floor(rand(0, 255))}.${Math.floor(rand(1, 254))}`;
  }

  // Attack phase drives every generator so charts, verdict and table agree.
  function tickPhase() {
    if (state.attackTicks > 0) {
      state.attackTicks--;
      if (state.attackTicks === 0) state.attackPhase = 0;
    } else if (Math.random() < 0.055) {
      state.attackPhase = Math.random() < 0.6 ? 1 : 2;
      state.attackTicks = Math.floor(rand(8, 22));
    }
  }

  function throughputAt(i, total) {
    const t = i / total;
    const wave = Math.sin(t * 7) * 55 + Math.sin(t * 19) * 24 + Math.cos(t * 3.3) * 38;
    return Math.max(60, state.baseline + wave + rand(-38, 38));
  }

  function seedHistory(points) {
    const now = Date.now();
    const labels = [], throughput = [], threat = [];
    let spikeAt = Math.floor(points * 0.82);
    for (let i = 0; i < points; i++) {
      const ts = now - (points - i) * 4000;
      labels.push(ts);
      let tp = throughputAt(i, points);
      let th = rand(2, 11);
      if (i >= spikeAt && i < spikeAt + 7) {
        const k = (i - spikeAt) / 7;
        tp += 1450 * Math.sin(k * Math.PI) + rand(0, 180);
        th = 55 + 40 * Math.sin(k * Math.PI);
      }
      throughput.push(+tp.toFixed(1));
      threat.push(+th.toFixed(1));
    }
    return { labels, throughput, threat };
  }

  function nextPoint() {
    tickPhase();
    const a = state.attackPhase;
    let tp = state.baseline + rand(-70, 90) + Math.sin(Date.now() / 9000) * 90;
    let th = rand(1.5, 9);
    if (a === 1) { tp += rand(600, 1150); th = rand(42, 68); }
    if (a === 2) { tp += rand(1400, 2600); th = rand(72, 96); }
    return { ts: Date.now(), throughput: +tp.toFixed(1), threat: +th.toFixed(1), phase: a };
  }

  function nextFlow() {
    const a = state.attackPhase;
    const malicious = a === 2 ? Math.random() < 0.72 : a === 1 ? Math.random() < 0.42 : Math.random() < 0.06;
    const node = pick(cfg.nodes);
    let label, dstPort, duration, packets, bytes, proto, conf;

    if (malicious) {
      label = a === 2 ? pick(["DDoS", "DoS Hulk", "DDoS"]) : pick(["DDoS", "PortScan", "Bot", "DoS Hulk", "FTP-Patator"]);
      if (label === "PortScan") {
        dstPort = Math.floor(rand(1, 9000)); duration = rand(0.001, 0.09);
        packets = Math.floor(rand(1, 4)); bytes = rand(40, 320);
      } else if (label === "FTP-Patator") {
        dstPort = 21; duration = rand(0.4, 4.2);
        packets = Math.floor(rand(8, 40)); bytes = rand(400, 3200);
      } else {
        dstPort = pick([80, 443, 8080, 53]); duration = rand(0.002, 0.35);
        packets = Math.floor(rand(180, 4200)); bytes = rand(9000, 260000);
      }
      proto = label === "DDoS" && Math.random() < 0.3 ? "UDP" : "TCP";
      conf = rand(0.882, 0.999);
    } else {
      label = "BENIGN";
      dstPort = pick([80, 443, 443, 443, 22, 3306, 8443, 5432, 53]);
      duration = rand(0.05, 22);
      packets = Math.floor(rand(4, 160));
      bytes = rand(300, 48000);
      proto = Math.random() < 0.86 ? "TCP" : "UDP";
      conf = rand(0.74, 0.996);
    }

    if (malicious) state.blocked++;

    return {
      id: `FLW-${++state.flowSeq}`,
      ts: Date.now(),
      src_ip: ip(),
      dst_port: dstPort,
      protocol: proto,
      node: node.label,
      duration: +duration.toFixed(3),
      packets,
      bytes_per_sec: +(bytes / Math.max(duration, 0.001)).toFixed(0),
      prediction: label,
      confidence: +conf.toFixed(4),
      mitigated: malicious && conf > 0.95
    };
  }

  function summary() {
    const a = state.attackPhase;
    return {
      flows_per_min: Math.floor(rand(11000, 14500) + a * 9000),
      attacks_blocked: state.blocked,
      avg_confidence: +rand(0.94, 0.988).toFixed(3),
      inference_ms: +rand(0.9, 2.6).toFixed(2),
      nodes_online: cfg.nodes.length,
      nodes_total: cfg.nodes.length,
      threat_level: a === 2 ? "CRITICAL" : a === 1 ? "ELEVATED" : "NOMINAL",
      phase: a
    };
  }

  function classBreakdown() {
    const a = state.attackPhase;
    return {
      labels: ["BENIGN", "DDoS", "DoS Hulk", "PortScan", "Bot", "FTP-Patator"],
      values: [
        Math.floor(rand(7200, 9400)),
        Math.floor(rand(20, 90) + a * 780),
        Math.floor(rand(10, 60) + a * 340),
        Math.floor(rand(40, 180) + a * 90),
        Math.floor(rand(5, 45) + a * 60),
        Math.floor(rand(2, 30) + a * 25)
      ]
    };
  }

  function nodeTraffic() {
    return {
      labels: cfg.nodes.slice(0, 5).map(n => n.label),
      values: cfg.nodes.slice(0, 5).map(n => {
        state.nodeLoad[n.id] = Math.max(60, state.nodeLoad[n.id] + rand(-30, 34));
        return Math.round(state.nodeLoad[n.id]);
      })
    };
  }

  function portActivity() {
    const a = state.attackPhase;
    return {
      labels: ["80", "443", "22", "53", "3306", "8080", "21"],
      values: [
        Math.floor(rand(900, 1500) + a * 900),
        Math.floor(rand(2100, 3300) + a * 1500),
        Math.floor(rand(60, 200)),
        Math.floor(rand(300, 800) + a * 400),
        Math.floor(rand(80, 260)),
        Math.floor(rand(200, 620) + a * 300),
        Math.floor(rand(10, 90) + a * 60)
      ]
    };
  }

  function nodeStats() {
    return cfg.nodes.map(n => ({
      label: n.label,
      desc: n.desc,
      mbps: Math.round(state.nodeLoad[n.id]),
      status: Math.random() < 0.94 ? "ok" : "warn"
    }));
  }

  window.AEGIS_MOCK = {
    seedHistory, nextPoint, nextFlow, summary,
    classBreakdown, nodeTraffic, portActivity, nodeStats,
    phase: () => state.attackPhase
  };
})();
