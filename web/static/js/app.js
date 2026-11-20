// NDACS dashboard. All attacker-controlled text (honeypot data!) goes through esc().
const $ = (s) => document.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt = (n) => Number(n || 0).toLocaleString();
const time = (iso) => iso ? iso.replace("T", " ").slice(5) : "–";
const COLORS = {BENIGN:"#2fcf8f",DoS:"#ff7a45",DDoS:"#ff4d6d",PortScan:"#f2b33d",BruteForce:"#a78bfa",WebAttack:"#3fb6ff",
  Bot:"#e879f9",Infiltration:"#f43f5e","SYN-Flood":"#fb923c","Honeypot-Contact":"#94a3b8",Manual:"#64748b"};
const color = (l) => COLORS[l] || "#8193a8";
Chart.defaults.color = "#8193a8"; Chart.defaults.borderColor = "#223043"; Chart.defaults.font.family = "Inter, Segoe UI, sans-serif";

async function api(path, opts = {}) {
  const r = await fetch(path, {headers: {"Content-Type": "application/json", "X-CSRF-Token": window.CSRF}, ...opts});
  if (r.status === 401) { location.href = "/login"; return null; }
  return r.json();
}
const tag = (l) => `<span class="tag" style="background:${color(l)}22;color:${color(l)}">${esc(l)}</span>`;
const sev = (s) => `<span class="tag sev-${esc(s)}">${esc(s || "–")}</span>`;
const conf = (c) => `<span class="conf"><i style="width:${(c*100).toFixed(0)}%"></i></span>${(c*100).toFixed(1)}%`;
const act = (a) => `<span class="act ${/block|redirect/.test(a) && !/dry|simulated/.test(a) ? "blocked" : ""}">${esc(a)}</span>`;

// ---------------------------------------------------------------- navigation
let view = "overview";
document.querySelectorAll("nav button").forEach((b) => b.onclick = () => {
  document.querySelectorAll("nav button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  view = b.dataset.view; $("#v-" + view).classList.add("active");
  $("#title").textContent = b.textContent.replace(/[^A-Za-z ]/g, "").replace(/\d+/g, "").trim();
  refresh();
});

// ---------------------------------------------------------------- charts
const timeline = new Chart($("#c-timeline"), {type: "line", data: {labels: [], datasets: [
  {label: "Benign", data: [], borderColor: "#2fcf8f", backgroundColor: "#2fcf8f22", fill: true, tension: .3, pointRadius: 0},
  {label: "Malicious", data: [], borderColor: "#ff4d6d", backgroundColor: "#ff4d6d33", fill: true, tension: .3, pointRadius: 0}]},
  options: {maintainAspectRatio: false, interaction: {mode: "index", intersect: false}, scales: {y: {beginAtZero: true}}}});
const dist = new Chart($("#c-dist"), {type: "doughnut", data: {labels: [], datasets: [{data: [], backgroundColor: [], borderWidth: 0}]},
  options: {maintainAspectRatio: false, cutout: "62%", plugins: {legend: {position: "right"}}}});
const hpChart = new Chart($("#c-hp"), {type: "bar", data: {labels: [], datasets: [{data: [], backgroundColor: "#a78bfa"}]},
  options: {maintainAspectRatio: false, plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true}}}});
let xaiChart = null;

// ---------------------------------------------------------------- overview
let lastStatus = {};
function fmtUp(s) { const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60); return h ? `${h}h ${m}m` : `${m}m ${s % 60}s`; }
async function loadSummary() {
  const d = await api("/api/summary"); if (!d) return;
  const st = d.status || {}; lastStatus = st;
  $("#st-mode").textContent = st.mode || "–";
  $("#st-model").textContent = st.model_loaded ? "CNN-LSTM" : "rules only";
  $("#st-xai").textContent = st.explainer || "–";
  $("#st-resp").textContent = st.response_mode || "–";
  $("#st-db").textContent = st.database || "–";
  $("#st-up").textContent = st.uptime_s != null ? fmtUp(st.uptime_s) : "–";
  $("#warn-nomodel").hidden = st.model_loaded !== false;
  $("#warn-synth").hidden = !String(st.model_dataset || "").startsWith("SYNTHETIC");
  $("#k-flows").textContent = fmt(d.flows); $("#k-mal").textContent = fmt(d.malicious_flows);
  $("#k-alerts").textContent = fmt(d.alerts); $("#k-blocked").textContent = fmt(d.blocked);
  $("#k-hp").textContent = fmt(d.honeypot_events);
  const nb = $("#nav-alerts"); nb.hidden = !d.alerts; nb.textContent = d.alerts > 999 ? "999+" : d.alerts;
  timeline.data.labels = d.timeline.map((t) => t.t);
  timeline.data.datasets[0].data = d.timeline.map((t) => t.benign);
  timeline.data.datasets[1].data = d.timeline.map((t) => t.malicious);
  timeline.update("none");
  const ent = Object.entries(d.distribution).sort((a, b) => b[1] - a[1]);
  dist.data.labels = ent.map((e) => e[0]); dist.data.datasets[0].data = ent.map((e) => e[1]);
  dist.data.datasets[0].backgroundColor = ent.map((e) => color(e[0])); dist.update("none");
  const max = Math.max(1, ...d.top_attackers.map((a) => a.count));
  $("#l-top").innerHTML = d.top_attackers.map((a) => `<div class="it"><span class="mono">${esc(a.ip)}</span>
    <span class="bar"><i style="width:${a.count / max * 100}%"></i></span><b>${fmt(a.count)}</b></div>`).join("") || `<div class="empty">No attackers yet</div>`;
  const sel = $("#f-label"); Object.keys(d.distribution).forEach((l) => {
    if (![...sel.options].some((o) => o.value === l)) sel.add(new Option(l, l)); });
}

async function loadLatest() {
  const rows = await api("/api/alerts?limit=8"); if (!rows) return;
  $("#t-latest").innerHTML = rows.map((a) => `<tr class="click" data-id="${a.id}"><td class="mono">${time(a.last_seen)}</td>
    <td class="mono">${esc(a.src_ip)}</td><td>${tag(a.label)}</td><td>${sev(a.severity)}</td><td>${(a.confidence*100).toFixed(0)}%</td><td>${act(a.action)}</td></tr>`).join("")
    || `<tr><td colspan="6" class="empty">No alerts yet – the network looks clean.</td></tr>`;
}

// ---------------------------------------------------------------- traffic feed
async function loadFeed() {
  const rows = await api("/api/feed"); if (!rows) return;
  const st = lastStatus;
  $("#traffic-meta").textContent = st.packets != null ? `· ${fmt(st.packets)} packets captured · ${fmt(st.active_flows)} active flows · queue ${st.queue}` : `· ${st.mode || ""} mode`;
  $("#t-feed").innerHTML = rows.map((f) => `<tr class="${f.malicious ? "row-bad" : ""}"><td class="mono">${esc(f.t)}</td>
    <td class="mono">${esc(f.src)}:${esc(f.sport ?? "")}${f.intel ? ' <span class="tag sev-high" title="seen by honeypot / earlier alert">intel</span>' : ""}</td>
    <td class="mono">${esc(f.dst)}:${esc(f.dport)}</td><td>${esc(f.proto)}</td><td>${fmt(f.pkts)}</td><td>${fmt(f.bytes)}</td>
    <td>${tag(f.label)}</td><td>${conf(f.conf)}</td></tr>`).join("") || `<tr><td colspan="8" class="empty">Waiting for traffic…</td></tr>`;
}

// ---------------------------------------------------------------- alerts
async function loadAlerts() {
  const q = new URLSearchParams({limit: 300, label: $("#f-label").value, severity: $("#f-sev").value});
  const rows = await api("/api/alerts?" + q); if (!rows) return;
  $("#t-alerts").innerHTML = rows.map((a) => `<tr class="click" data-id="${a.id}"><td class="muted">${a.id}</td><td class="mono">${time(a.ts)}</td>
    <td class="mono">${esc(a.src_ip)}</td><td class="mono">${esc(a.dst_ip || "")}${a.dst_port != null ? ":" + esc(a.dst_port) : ""}</td>
    <td>${tag(a.label)}</td><td>${sev(a.severity)}</td><td>${conf(a.confidence)}</td><td>${esc(a.source)}${a.explained ? " ✦" : ""}</td>
    <td>${fmt(a.count)}</td><td>${act(a.action)}</td></tr>`).join("") || `<tr><td colspan="10" class="empty">No alerts</td></tr>`;
}
$("#f-label").onchange = loadAlerts; $("#f-sev").onchange = loadAlerts;
document.addEventListener("click", (e) => { const tr = e.target.closest("tr.click"); if (tr) openAlert(tr.dataset.id); });

let modalTimer = null;
async function openAlert(id) {
  const a = await api("/api/alerts/" + id); if (!a) return;
  $("#modal").classList.add("open");
  $("#d-title").innerHTML = `${tag(a.label)} &nbsp;Alert #${a.id}`;
  $("#d-sev").innerHTML = sev(a.severity);
  $("#d-kv").innerHTML = [["Source", a.src_ip + (a.src_port ? ":" + a.src_port : "")], ["Target", (a.dst_ip || "") + (a.dst_port != null ? ":" + a.dst_port : "")],
    ["Confidence", (a.confidence * 100).toFixed(2) + "%"], ["Detected by", a.source], ["First seen", time(a.ts)], ["Last seen", time(a.last_seen)],
    ["Occurrences", fmt(a.count)], ["Response", a.action]].map(([k, v]) => `<div><span>${k}</span><b class="mono">${esc(v)}</b></div>`).join("");
  $("#d-block").onclick = async () => { const r = await api("/api/block", {method: "POST", body: JSON.stringify({ip: a.src_ip})}); alert(`${a.src_ip}: ${r.result || r.error}`); };
  const ex = a.explanation;
  if (!ex) {
    $("#d-text").textContent = "Computing explanation (SHAP)…"; $("#d-probs").innerHTML = ""; $("#d-method").textContent = "–";
    if (xaiChart) { xaiChart.destroy(); xaiChart = null; }
    clearTimeout(modalTimer); modalTimer = setTimeout(() => $("#modal").classList.contains("open") && openAlert(id), 1500);
  } else {
    $("#d-text").textContent = ex.text; $("#d-method").textContent = ex.method;
    $("#d-probs").innerHTML = (ex.probabilities || []).map(([c, p]) => `<tr><td>${tag(c)}</td><td>${conf(p)}</td></tr>`).join("")
      || `<tr><td colspan="2" class="muted">Rule-based detection (no model probabilities)</td></tr>`;
    const f = ex.factors || [];
    if (xaiChart) xaiChart.destroy();
    xaiChart = new Chart($("#c-xai"), {type: "bar", data: {labels: f.map((x) => `${x.feature} = ${x.display}`),
      datasets: [{data: f.map((x) => x.contribution), backgroundColor: f.map((x) => x.contribution >= 0 ? "#ff4d6d" : "#3fb6ff")}]},
      options: {indexAxis: "y", maintainAspectRatio: false, plugins: {legend: {display: false}},
        scales: {x: {title: {display: true, text: ex.method === "RULE" ? "rule evidence" : "contribution to prediction"}}, y: {ticks: {font: {size: 11}}}}}});
  }
  $("#d-feat").innerHTML = a.features ? Object.entries(a.features).map(([k, v]) => `<tr><td>${esc(k)}</td><td style="text-align:right">${fmt(Math.round(v * 100) / 100)}</td></tr>`).join("")
    : `<tr><td class="muted">No flow features (rule / honeypot detection)</td></tr>`;
}
$("#d-close").onclick = () => $("#modal").classList.remove("open");
$("#modal").onclick = (e) => { if (e.target.id === "modal") $("#modal").classList.remove("open"); };
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#modal").classList.remove("open"); });

// ---------------------------------------------------------------- response
async function loadBlocked() {
  const rows = await api("/api/blocked"); if (!rows) return;
  $("#t-blocked").innerHTML = rows.map((b) => `<tr><td class="mono">${esc(b.ip)}</td><td>${esc(b.mode)}</td><td>${tag(b.reason)}</td>
    <td class="mono">${time(b.ts)}</td><td class="mono">${time(b.expires)}</td><td>${b.active ? '<b style="color:var(--crit)">active</b>' : '<span class="muted">released</span>'}</td>
    <td>${b.active ? `<button class="btn ghost sm" data-unblock="${esc(b.ip)}">Release</button>` : ""}</td></tr>`).join("")
    || `<tr><td colspan="7" class="empty">No IPs contained</td></tr>`;
}
document.addEventListener("click", async (e) => {
  const ip = e.target.dataset && e.target.dataset.unblock; if (!ip) return;
  await api("/api/unblock", {method: "POST", body: JSON.stringify({ip})}); loadBlocked();
});
$("#m-go").onclick = async () => {
  const r = await api("/api/block", {method: "POST", body: JSON.stringify({ip: $("#m-ip").value, mode: $("#m-mode").value, minutes: +$("#m-min").value})});
  $("#m-res").textContent = r.result ? `→ ${r.result}` : r.error; loadBlocked();
};

// ---------------------------------------------------------------- honeypot
async function loadHoneypot() {
  const d = await api("/api/honeypot"); if (!d) return;
  $("#h-events").textContent = d.events.length >= 200 ? "200+" : fmt(d.events.length);
  $("#h-ips").textContent = fmt(d.attackers.length); $("#h-creds").textContent = fmt(d.credentials.length);
  $("#h-svc").textContent = d.services.join("  ") || "off";
  $("#t-creds").innerHTML = d.credentials.map((c) => `<tr><td class="mono">${esc(c.username)}</td><td class="mono">${esc(c.password)}</td><td>${c.count}</td></tr>`).join("")
    || `<tr><td colspan="3" class="empty">No login attempts captured yet</td></tr>`;
  hpChart.data.labels = Object.keys(d.by_service); hpChart.data.datasets[0].data = Object.values(d.by_service); hpChart.update("none");
  $("#t-hp").innerHTML = d.events.map((e) => {
    let data = e.data || ""; try { const j = JSON.parse(data); data = (j.request || "") + (j.attacks && j.attacks.length ? "  ⚠ " + j.attacks.join(", ") : ""); } catch (_) {}
    return `<tr><td class="mono">${time(e.ts)}</td><td class="mono">${esc(e.src_ip)}</td><td>${esc(e.service)}</td><td>${esc(e.event)}</td>
      <td class="mono">${esc(e.username ?? "")}</td><td class="mono">${esc(e.password ?? "")}</td><td class="mono" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(data)}</td></tr>`;
  }).join("") || `<tr><td colspan="7" class="empty">The honeypot is waiting for visitors…</td></tr>`;
}

// ---------------------------------------------------------------- model
let modelLoaded = false;
async function loadModel() {
  if (modelLoaded) return; const m = await api("/api/model"); if (!m) return; modelLoaded = true;
  if (!m.accuracy) { $("#m-kpis").innerHTML = `<div class="card empty" style="grid-column:1/-1">No evaluation report yet – run scripts/train.py</div>`; return; }
  const pct = (v) => (v * 100).toFixed(2) + "%";
  $("#m-kpis").innerHTML = [["Accuracy", pct(m.accuracy), "ok"], ["Macro F1", pct(m.f1_macro), ""], ["Detection rate", pct(m.detection_rate), "ok"],
    ["False positive rate", pct(m.false_positive_rate), "bad"], ["Latency / flow", m.latency_ms_per_flow.toFixed(3) + " ms", "vio"]]
    .map(([l, v, c]) => `<div class="card kpi ${c}"><div class="v">${v}</div><div class="l">${l}</div></div>`).join("");
  $("#t-perclass").innerHTML = Object.entries(m.per_class).map(([c, r]) => `<tr><td>${tag(c)}</td><td>${r.precision.toFixed(4)}</td>
    <td>${r.recall.toFixed(4)}</td><td><b>${r["f1-score"].toFixed(4)}</b></td><td>${fmt(r.support)}</td></tr>`).join("");
  $("#t-compare").innerHTML = Object.entries(m.comparison || {}).map(([n, r]) => `<tr><td><b>${esc(n)}</b></td><td>${pct(r.accuracy)}</td>
    <td>${pct(r.f1_macro)}</td><td>${pct(r.detection_rate)}</td><td>${pct(r.false_positive_rate)}</td></tr>`).join("");
  $("#m-info").textContent = `Dataset: ${m.dataset} · epochs: ${m.epochs_run} · training time: ${(m.train_time_s / 60).toFixed(1)} min`;
  $("#m-imgs").innerHTML = m.images.map((i) => `<a href="/reports/${i}" target="_blank"><img src="/reports/${i}" alt="${i}"></a>`).join("");
}

// ---------------------------------------------------------------- polling
async function refresh() {
  try {
    await loadSummary();
    if (view === "overview") await loadLatest();
    else if (view === "traffic") await loadFeed();
    else if (view === "alerts") await loadAlerts();
    else if (view === "response") await loadBlocked();
    else if (view === "honeypot") await loadHoneypot();
    else if (view === "model") await loadModel();
  } catch (e) { console.warn(e); }
}
refresh(); setInterval(refresh, 2000);
