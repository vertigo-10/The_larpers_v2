(function () {
  const cfg = window.AEGIS_CONFIG;
  const api = window.AEGIS_API;
  const { icon, mountSidebar, toast, fmt } = window.AEGIS_UI;

  const TAGS = {
    "DDoS": "tag-ddos", "DoS Hulk": "tag-dos", "PortScan": "tag-scan",
    "Bot": "tag-brute", "FTP-Patator": "tag-brute", "BENIGN": "tag-benign"
  };

  function stat(k, v, d, cls) {
    return `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div><div class="d ${cls || "dim"}">${d}</div></div>`;
  }

  function buildActivityChart() {
    const labels = [], reviewed = [], escalated = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000);
      labels.push(d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" }));
      reviewed.push(Math.floor(40 + Math.random() * 90));
      escalated.push(Math.floor(2 + Math.random() * 18));
    }

    new Chart(document.getElementById("activityChart"), {
      type: "bar",
      data: {
        labels,
        datasets: [
          { label: "Reviewed", data: reviewed, backgroundColor: "#2fe08acc", borderRadius: 4, barPercentage: 0.6 },
          { label: "Escalated", data: escalated, backgroundColor: "#ff5064cc", borderRadius: 4, barPercentage: 0.6 }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top", align: "end",
            labels: { boxWidth: 8, boxHeight: 8, usePointStyle: true, pointStyle: "circle", padding: 12, font: { size: 10 } }
          },
          tooltip: {
            backgroundColor: "#141a1d", borderColor: "#2b3439", borderWidth: 1,
            titleColor: "#e7eef1", bodyColor: "#9daab1", padding: 10, cornerRadius: 8,
            usePointStyle: true, boxWidth: 8, boxHeight: 8
          }
        },
        scales: {
          x: { stacked: true, grid: { display: false }, border: { display: false }, ticks: { font: { size: 9 } } },
          y: { stacked: true, grid: { color: "rgba(255,255,255,0.03)" }, border: { display: false }, ticks: { maxTicksLimit: 5 } }
        }
      }
    });
  }

  async function init() {
    mountSidebar("profile");

    const op = cfg.operator;
    document.getElementById("btn-settings").innerHTML = `${icon("settings", 12)} Settings`;
    document.getElementById("topbar-avatar").textContent = op.initials;
    document.getElementById("pf-initials").textContent = op.initials;
    document.getElementById("pf-name").textContent = op.name;
    document.getElementById("pf-role").textContent = op.role;
    document.getElementById("pf-org").textContent = cfg.org;
    document.getElementById("pf-source").textContent = api.isLive() ? "Live detection API" : "Mock stream";
    document.getElementById("pf-lastlogin").textContent =
      new Date(Date.now() - 5400000).toLocaleString("en-GB", { hour12: false });

    const status = await api.getStatus();
    document.getElementById("pf-uptime").textContent = fmt.uptime(status.uptime_s || 0);

    const s = await api.getSummary();
    document.getElementById("pf-stats").innerHTML = `
      ${stat("Alerts reviewed", "1,042", "▲ 12% vs last period", "up")}
      ${stat("Mitigations", fmt.num(s.attacks_blocked), "auto + manual", "dim")}
      ${stat("False positives", "23", "▼ 4% vs last period", "up")}
      ${stat("Avg response", "38 s", "time to action", "dim")}`;

    const nodes = await api.getNodeStats();
    document.getElementById("pf-scope-count").textContent = `${nodes.length} links`;
    document.getElementById("pf-scope").innerHTML = nodes.map(n => `
      <div class="kv">
        <span class="k" style="display:flex;align-items:center;gap:9px">
          <span class="flow-dot" style="background:${n.status === "ok" ? "#2fe08a" : "#ffb545"}"></span>
          <b style="color:var(--text);font-weight:600">${n.label}</b>
          <span>${n.desc}</span>
        </span>
        <span class="v mono ${n.status === "ok" ? "up" : "down"}">${n.mbps} Mbps</span>
      </div>`).join("");

    const flows = await api.getFlows(14);
    document.getElementById("pf-actions").innerHTML = flows.map((f, i) => {
      const malicious = f.prediction !== "BENIGN";
      const action = malicious ? (i % 4 === 0 ? "Escalated" : "Blocked") : "Whitelisted";
      return `
        <tr>
          <td class="mono">${fmt.time(f.ts - i * 420000)}</td>
          <td style="color:var(--text)">${action}</td>
          <td class="mono">${f.src_ip}<span class="dim"> :${f.dst_port}</span></td>
          <td><span class="tag ${TAGS[f.prediction] || "tag-brute"}">${f.prediction}</span></td>
          <td style="text-align:right" class="${malicious ? "down" : "up"}">${malicious ? "rule pushed" : "no action"}</td>
        </tr>`;
    }).join("");

    buildActivityChart();

    document.getElementById("btn-signout").addEventListener("click", () => {
      toast("Sign-out is not wired to an auth provider yet", "err");
    });
  }

  init();
})();
