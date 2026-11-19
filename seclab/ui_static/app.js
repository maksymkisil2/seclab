"use strict";
// seclab UI. No frameworks, no innerHTML with data: everything goes through textContent / DOM APIs.

const PROFILES = ["vulnerable", "baseline", "hardened"];
const DIFFS = ["easy", "medium", "hard"];
const VULN_CLASSES = ["sqli", "xss", "idor", "traversal", "admin"]; // must match agent/lab
const ATTACK_CATS = ["sqli", "idor", "traversal", "admin", "creds"]; // must match agent catalogue
const SVGNS = "http://www.w3.org/2000/svg";
const $ = (sel, root = document) => root.querySelector(sel);

const state = { token: null, scenarios: [], labs: [], selected: null, results: {}, tab: "topo", topo: {} };

// ---- token -----------------------------------------------------------------------
(function initToken() {
  const m = location.hash.match(/(?:^#|&)t=([A-Za-z0-9_-]+)/);
  if (m) {
    sessionStorage.setItem("seclab-token", m[1]);
    history.replaceState(null, "", location.pathname);
  }
  state.token = sessionStorage.getItem("seclab-token");
})();

async function api(method, path, body) {
  const opts = { method, headers: { "X-Seclab-Token": state.token || "" } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  let data = null;
  try { data = await r.json(); } catch (_) { /* non-json */ }
  if (r.status === 401) setConn(false, "unauthorized");
  if (!r.ok) throw new Error((data && data.error) || `HTTP ${r.status}`);
  return data;
}

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children) n.append(c);
  return n;
}

function svg(tag, attrs = {}, text) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text !== undefined) n.textContent = text;
  return n;
}

function setConn(ok, text) {
  const c = $("#conn");
  c.textContent = text;
  c.className = "pill " + (ok ? "ok" : "bad");
}

function toast(text, kind = "", spinning = false) {
  const t = el("div", { class: "toast " + kind });
  if (spinning) t.append(el("span", { class: "spin" }), " ");
  t.append(text);
  $("#toasts").append(t);
  if (!spinning) setTimeout(() => t.remove(), kind === "bad" ? 15000 : 5000);
  return t;
}

// ---- jobs --------------------------------------------------------------------------
async function trackJob(job, label) {
  const t = toast(`${label}…`, "", true);
  refreshLabs();
  for (;;) {
    await new Promise((r) => setTimeout(r, 1000));
    let j;
    try { j = await api("GET", `/api/jobs/${job.id}`); } catch (e) { t.remove(); toast(`${label}: ${e.message}`, "bad"); return null; }
    if (j.state === "running") continue;
    t.remove();
    const secs = Math.round(j.finished - j.started);
    if (j.state === "done") toast(`${label}: done (${secs}s)`, "ok");
    if (j.lab) delete state.topo[j.lab];
    else toast(`${label}: failed\n${j.error}`, "bad");
    refreshLabs();
    return j;
  }
}

async function startJob(method, path, body, label) {
  try {
    const job = await api(method, path, body);
    return await trackJob(job, label);
  } catch (e) {
    toast(`${label}: ${e.message}`, "bad");
    return null;
  }
}

// ---- scenarios ---------------------------------------------------------------------
async function loadScenarios() {
  state.scenarios = await api("GET", "/api/scenarios");
  const box = $("#scenarios");
  box.replaceChildren();
  for (const s of state.scenarios) {
    const card = $("#tpl-scenario").content.cloneNode(true);
    $(".s-name", card).textContent = s.name;
    $(".s-kind", card).textContent = s.kind;
    $(".s-desc", card).textContent = s.description;
    $(".s-meta", card).textContent = `${s.segments.length} segments · ${s.nodes.length} nodes · ` +
      s.forwards.map((f) => f.host_port).join(", ");
    const form = $("form", card);
    const sel = form.elements.profile;
    for (const p of PROFILES) sel.append(el("option", { value: p }, p));
    const dsel = form.elements.difficulty;
    for (const d of DIFFS) dsel.append(el("option", { value: d }, d));
    dsel.value = "medium";
    if (s.kind === "web") dsel.classList.add("hidden");
    form.elements.name.placeholder = s.name;
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const name = form.elements.name.value.trim() || s.name;
      const body = { scenario: s.name, profile: sel.value, name, difficulty: dsel.value,
                     port_offset: parseInt(form.elements.port_offset.value || "0", 10) };
      state.selected = name;
      startJob("POST", "/api/labs", body, `up ${name} (${sel.value})`);
    });
    box.append(card);
  }
}

// ---- labs --------------------------------------------------------------------------
async function refreshLabs(force = false) {
  let labs;
  try {
    labs = await api("GET", "/api/labs");
    setConn(true, "connected");
  } catch (e) {
    if (state.token) setConn(false, "offline");
    return;
  }
  // polling runs every few seconds: re-render only when something actually changed
  const sig = JSON.stringify(labs);
  if (!force && sig === state.labsSig) return;
  state.labsSig = sig;
  state.labs = labs;
  renderLabs();
  renderDetail();
}

function stateClass(s) { return s === "up" ? "ok" : s === "degraded" ? "warn" : "bad"; }

function renderLabs() {
  const tbody = $("#labs tbody");
  tbody.replaceChildren();
  $("#labs-empty").classList.toggle("hidden", state.labs.length > 0);
  for (const lab of state.labs) {
    const acts = el("div", { class: "actions" });
    const btn = (text, cls, fn, title) => {
      const b = el("button", { class: cls, title: title || text }, text);
      b.disabled = lab.busy;
      b.addEventListener("click", (ev) => { ev.stopPropagation(); fn(); });
      acts.append(b);
    };
    if (lab.kind === "topology" && lab.state !== "down") btn("audit", "ghost", () => runCheck(lab.name));
    if (lab.kind !== "?") btn("reset", "ghost", () => startJob("POST", `/api/labs/${lab.name}/reset`, {}, `reset ${lab.name}`));
    if (lab.state !== "down") btn("down", "ghost", () => startJob("POST", `/api/labs/${lab.name}/down`, {}, `down ${lab.name}`));
    btn("purge", "danger", () => {
      if (confirm(`Remove lab '${lab.name}' with configs, keys and certificates?`))
        startJob("POST", `/api/labs/${lab.name}/down`, { purge: true }, `purge ${lab.name}`);
    }, "down + delete files");
    const st = el("span", { class: "pill " + stateClass(lab.state) }, lab.busy ? "busy" : lab.state);
    const up = lab.containers.filter((c) => c.state === "running").length;
    const tr = el("tr", { class: lab.name === state.selected ? "sel" : "" },
      el("td", {}, lab.name), el("td", {}, lab.scenario.split("/").pop().replace(/\.toml$/, "")),
      el("td", {}, lab.profile), el("td", {}, lab.difficulty || "—"),
      el("td", {}, st), el("td", {}, `${up}/${lab.containers.length}`), el("td", {}, acts));
    tr.addEventListener("click", () => { state.selected = lab.name; renderLabs(); renderDetail(true); });
    tbody.append(tr);
  }
}

function selectedLab() { return state.labs.find((l) => l.name === state.selected); }

function scenarioFor(lab) { return state.topo[lab.name]; }

async function fetchTopology(name) {
  try {
    state.topo[name] = await api("GET", `/api/labs/${name}/topology`);
  } catch (_) {
    state.topo[name] = null;
  }
}

// ---- detail ------------------------------------------------------------------------
function renderDetail(changed = false) {
  const lab = selectedLab();
  $("#detail").classList.toggle("hidden", !lab);
  if (!lab) return;
  if (!(lab.name in state.topo)) { fetchTopology(lab.name).then(() => renderDetail()); }
  $("#d-title").textContent = `${lab.name} · ${lab.profile}` + (lab.difficulty ? ` · ${lab.difficulty}` : "");
  const topoOnly = lab.kind === "topology";
  for (const b of document.querySelectorAll(".tab")) {
    if (b.dataset.tab !== "topo") b.disabled = !topoOnly;
  }
  if (!topoOnly && state.tab !== "topo") showTab("topo");
  renderAccess(lab);
  renderTopology(lab);
  renderCheck(lab.name);
  if (changed && state.tab === "fw") loadFirewall();
}

function showTab(name) {
  state.tab = name;
  for (const b of document.querySelectorAll(".tab")) b.classList.toggle("active", b.dataset.tab === name);
  for (const p of ["topo", "check", "fw", "flags", "attacks", "detect"]) $(`#tab-${p}`).classList.toggle("hidden", p !== name);
  if (name === "fw") loadFirewall();
  if (name === "flags") loadFlags();
}

function renderAccess(lab) {
  const box = $("#access");
  box.replaceChildren();
  const sc = scenarioFor(lab);
  if (lab.kind === "web") {
    box.append(el("div", {}, `https://localhost:${lab.https_port}/   http://localhost:${lab.http_port}/`));
  } else if (sc) {
    for (const f of sc.forwards) {
      const port = f.host_port + (lab.port_offset || 0);
      const node = sc.nodes.find((n) => n.name === f.node);
      const how = node && node.role === "ssh"
        ? (lab.profile === "vulnerable" ? `ssh -p ${port} root@127.0.0.1   (toor)`
                                        : `ssh -i ${lab.dir}/ssh/id_ecdsa -p ${port} lab@127.0.0.1`)
        : f.port === 8443 ? `https://localhost:${port}/`
        : f.port === 8080 ? `http://localhost:${port}/` + (node && node.title ? `   (${node.title})` : "")
        : `127.0.0.1:${port}`;
      box.append(el("div", {}, `${f.node}:${f.port}  ←  ${how}`));
    }
  }
  if (lab.kind === "web" || sc) box.append(el("div", { class: "dim" }, `CA: ${lab.dir}/tls/ca.crt`));
}

function nodeVerdicts(labName) {
  const res = state.results[labName];
  const v = {};
  if (!res) return v;
  for (const r of res.results) {
    for (const n of [r.src, r.dst.split(":")[0]]) {
      if (!r.ok) v[n] = "bad";
      else if (!v[n]) v[n] = "ok";
    }
  }
  return v;
}

function renderTopology(lab) {
  const box = $("#topo");
  box.replaceChildren();
  const sc = scenarioFor(lab);
  if (!sc) { box.append(el("p", { class: "dim" }, "Loading topology…")); return; }
  const verdict = nodeVerdicts(lab.name);
  const segW = 240, gap = 24, nodeH = 46;
  const ry = 20, fwdLines = sc.forwards.length;
  const top = Math.max(130, ry + 60 + fwdLines * 14 + 24);
  const width = Math.max(760, sc.segments.length * (segW + gap) + gap);
  const maxNodes = Math.max(1, ...sc.segments.map((s) => sc.nodes.filter((n) => n.segment === s.name).length));
  const height = top + 50 + maxNodes * (nodeH + 10) + 20;
  const root = svg("svg", { width, height, viewBox: `0 0 ${width} ${height}`, role: "img",
                            "aria-label": `topology of ${lab.name}` });
  const rx = Math.max(width / 2 - 90, 260);
  const rlabel = lab.kind === "web" ? "docker bridges" : "router · nftables";
  // host + ingress (forward list under the host box, clear of the link)
  const host = svg("g", { class: "t-host" });
  host.append(svg("rect", { x: 16, y: ry, width: 150, height: 44, rx: 6 }),
              svg("text", { x: 28, y: ry + 27 }, "host 127.0.0.1"));
  root.append(svg("path", { d: `M166 ${ry + 22} L${rx} ${ry + 22}`, class: "t-link t-ingress" }));
  sc.forwards.forEach((f, i) => {
    root.append(svg("text", { x: 20, y: ry + 62 + i * 14, class: "t-small" },
      `:${f.host_port + (lab.port_offset || 0)} → ${f.node}:${f.port}`));
  });
  root.append(host);
  const router = svg("g", { class: "t-router" });
  router.append(svg("rect", { x: rx, y: ry, width: 180, height: 44, rx: 6 }),
                svg("text", { x: rx + 14, y: ry + 27 }, rlabel));
  // segments + nodes
  sc.segments.forEach((s, i) => {
    const x = gap + i * (segW + gap);
    const nodes = sc.nodes.filter((n) => n.segment === s.name);
    const h = 50 + nodes.length * (nodeH + 10);
    root.append(svg("path", { d: `M${rx + 90} ${ry + 44} C${rx + 90} ${top - 30}, ${x + segW / 2} ${top - 40}, ${x + segW / 2} ${top}`,
                              class: "t-link" }));
    root.append(svg("rect", { x, y: top, width: segW, height: h, rx: 8, class: "t-seg" }));
    root.append(svg("text", { x: x + 10, y: top + 20, class: "t-seg-label" }, `${s.name}  ${s.subnet}`));
    nodes.forEach((n, j) => {
      const g = svg("g", { class: "t-node " + (verdict[n.name] || "") });
      const ny = top + 32 + j * (nodeH + 10);
      g.append(svg("rect", { x: x + 10, y: ny, width: segW - 20, height: nodeH, rx: 5 }),
               svg("text", { x: x + 20, y: ny + 18 }, `${n.name}  `, ),
               svg("text", { x: x + 20, y: ny + 35, class: "sub" },
                   `${n.ip ? n.ip + " " : ""}:${n.ports.join(",")}`));
      g.children[1].append(svg("tspan", { class: "sub" }, n.role));
      g.append(svg("title", {}, `${n.name} (${n.role}) ${n.ip} ports ${n.ports.join(", ")}`));
      root.append(g);
    });
  });
  root.append(router);
  box.append(root);
  if (sc.allows.length) {
    box.append(el("div", { class: "dim small policy" },
      "target policy: " + sc.allows.map((a) => `${a.from}→${a.to}:${a.ports.join(",")}`).join("   ")));
  }
}

// ---- audit -------------------------------------------------------------------------
async function runCheck(name) {
  const j = await startJob("POST", `/api/labs/${name}/check`, {}, `audit ${name}`);
  if (j && j.state === "done") {
    state.results[name] = j.result;
    state.selected = name;
    if (state.tab !== "check") showTab("check");
    renderLabs();
    renderDetail();
  }
}

function renderCheck(name) {
  const tbody = $("#check tbody");
  tbody.replaceChildren();
  const res = state.results[name];
  const sum = $("#check-summary");
  if (!res) { sum.textContent = "no audit yet"; sum.className = "summary dim"; return; }
  const bad = res.total - res.passed;
  sum.textContent = `${res.passed}/${res.total} passed · ${bad} finding(s)`;
  sum.className = "summary " + (bad ? "pill bad" : "pill ok");
  const only = $("#only-fail").checked;
  const rows = [...res.results].sort((a, b) => (a.ok - b.ok) || a.kind.localeCompare(b.kind));
  for (const r of rows) {
    if (only && r.ok) continue;
    const word = (b) => (b ? "open" : "closed");
    tbody.append(el("tr", { class: r.ok ? "" : "fail" },
      el("td", {}, r.ok ? "PASS" : "FAIL"), el("td", {}, r.kind), el("td", {}, r.src), el("td", {}, r.dst),
      el("td", {}, String(r.port)), el("td", {}, word(r.expected)), el("td", {}, word(r.actual))));
  }
}

// ---- firewall ----------------------------------------------------------------------
async function loadFirewall() {
  const lab = selectedLab();
  if (!lab || lab.kind !== "topology") return;
  const msg = $("#fw-msg");
  try {
    const fw = await api("GET", `/api/labs/${lab.name}/fw`);
    $("#fw-edit").value = fw.file;
    $("#fw-live").textContent = fw.live;
    msg.textContent = ""; msg.className = "";
  } catch (e) {
    $("#fw-live").textContent = "";
    msg.textContent = e.message; msg.className = "bad";
  }
}

async function applyFirewall(body, label) {
  const lab = selectedLab();
  const msg = $("#fw-msg");
  msg.textContent = "validating…"; msg.className = "";
  try {
    await api("POST", `/api/labs/${lab.name}/fw`, body);
    msg.textContent = `${label}: applied`; msg.className = "ok";
    await loadFirewall();
    msg.textContent = `${label}: applied — run the audit to verify`; msg.className = "ok";
  } catch (e) {
    msg.textContent = e.message; msg.className = "bad";
  }
}

// ---- flags -------------------------------------------------------------------------
function renderScore(sc) {
  $("#flag-score").textContent = `${sc.solved.length}/${sc.total.length} flags captured`;
  $("#flag-score").className = "summary pill " + (sc.total.length && sc.solved.length === sc.total.length ? "ok" : "warn");
  const list = $("#flag-list");
  list.replaceChildren();
  for (const item of sc.total) {
    const done = sc.solved.includes(item);
    list.append(el("li", { class: done ? "done" : "" }, (done ? "✓ " : "· ") + item));
  }
  if (!sc.total.length) list.append(el("li", { class: "dim" }, "no vulnerable sites in this lab"));
}

async function loadFlags() {
  const lab = selectedLab();
  if (!lab || lab.kind !== "topology") return;
  try { renderScore(await api("GET", `/api/labs/${lab.name}/flags`)); } catch (e) { toast(e.message, "bad"); }
}

async function submitFlag() {
  const lab = selectedLab();
  const msg = $("#flag-msg");
  try {
    const r = await api("POST", `/api/labs/${lab.name}/flags`, { flag: $("#flag-in").value });
    msg.textContent = r.correct ? `correct: ${r.item}` : "wrong flag";
    msg.className = r.correct ? "ok" : "bad";
    if (r.correct) $("#flag-in").value = "";
    renderScore(r);
  } catch (e) { msg.textContent = e.message; msg.className = "bad"; }
}

// ---- generator ---------------------------------------------------------------------
function genParams(form) {
  const f = form.elements;
  const num = (k) => parseInt(f[k].value || "0", 10);
  return { name: f.name.value.trim() || "corp", departments: num("departments"), hosts_per_dept: num("hosts_per_dept"),
           sites: num("sites"), public_sites: num("public_sites"), seed: num("seed") || 1,
           database: f.database.checked, fileserver: f.fileserver.checked, mail: f.mail.checked,
           mgmt: f.mgmt.checked, guest: f.guest.checked };
}

let previewTimer = null;
function schedulePreview(form) {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(async () => {
    const est = $("#gen-est");
    try {
      const r = await api("POST", "/api/generate/preview", genParams(form));
      if (!r.valid) throw new Error(r.error);
      const e = r.estimate;
      est.textContent = `${e.segments} segments · ${e.containers} containers · RAM limit ${e.ram_limit_mb} MiB ` +
                        `(typical ~${e.ram_typical_mb} MiB) · ${r.topology.forwards.length} forwarded ports`;
      est.className = "est dim small";
      form.querySelector("button[type=submit]").disabled = false;
    } catch (err) {
      est.textContent = err.message;
      est.className = "est small bad";
      form.querySelector("button[type=submit]").disabled = true;
    }
  }, 250);
}

function initGenerator() {
  const form = $("#gen");
  for (const p of PROFILES) form.elements.profile.append(el("option", { value: p }, p));
  for (const d of DIFFS) form.elements.difficulty.append(el("option", { value: d }, d));
  form.elements.difficulty.value = "medium";
  form.addEventListener("input", () => schedulePreview(form));
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const gen = genParams(form);
    const body = { name: gen.name, profile: form.elements.profile.value, difficulty: form.elements.difficulty.value,
                   port_offset: parseInt(form.elements.port_offset.value || "0", 10), seed: gen.seed, generate: gen };
    const vulns = vulnSelection(form);
    if (vulns !== null) body.vulns = vulns; // omit when all enabled (server default)
    state.selected = gen.name;
    delete state.topo[gen.name];
    startJob("POST", "/api/labs", body, `up ${gen.name} (generated, ${body.profile}/${body.difficulty})`);
  });
  schedulePreview(form);
}

// enabled vuln classes from the gen form; null when every class is on (server treats absent = all)
function vulnSelection(form) {
  const on = VULN_CLASSES.filter((c) => form.elements["v_" + c] && form.elements["v_" + c].checked);
  return on.length === VULN_CLASSES.length ? null : on;
}

// ---- attacks -----------------------------------------------------------------------
function initAttacks() {
  const box = $("#attack-cats");
  for (const c of ATTACK_CATS) {
    const id = "ac-" + c;
    box.append(el("label", { class: "cat" },
      el("input", { type: "checkbox", id, checked: "checked", value: c }), " " + c));
  }
  $("#attack-run").addEventListener("click", runAttacks);
}

function selectedAttackCats() {
  const on = ATTACK_CATS.filter((c) => $("#ac-" + c).checked);
  return on.length === ATTACK_CATS.length ? null : on; // null = all
}

async function runAttacks() {
  const lab = selectedLab();
  if (!lab || lab.kind !== "topology") return;
  const only = selectedAttackCats();
  const j = await startJob("POST", `/api/labs/${lab.name}/attack`, only ? { only } : {}, `attack ${lab.name}`);
  if (j && j.state === "done") {
    renderAttackResults(j.result);
    loadFlags(); // scoreboard may have advanced
  }
}

function renderAttackResults(res) {
  const tbody = $("#attack-results tbody");
  tbody.replaceChildren();
  const rows = res.results || [];
  const hits = rows.filter((r) => r.captured).length;
  const msg = $("#attack-msg");
  msg.textContent = rows.length ? `${hits} captured / ${rows.length} tried` : "no reachable sites";
  msg.className = "summary " + (hits ? "pill ok" : "pill");
  for (const r of rows.sort((a, b) => (b.captured - a.captured) || a.node.localeCompare(b.node))) {
    tbody.append(el("tr", { class: r.captured ? "" : "fail" },
      el("td", {}, r.captured ? "HIT" : "—"), el("td", {}, r.node || ""), el("td", {}, r.category || ""),
      el("td", {}, r.technique || ""), el("td", {}, r.flag || ""), el("td", {}, r.detail || "")));
  }
}

// ---- detection (blue team) ---------------------------------------------------------
const SEV_CLASS = { critical: "bad", high: "bad", medium: "warn", low: "", info: "" };

async function runDetection() {
  const lab = selectedLab();
  if (!lab || lab.kind !== "topology") return;
  const sev = $("#detect-sev").value;
  const j = await startJob("POST", `/api/labs/${lab.name}/detect`, { min_severity: sev }, `detect ${lab.name}`);
  if (j && j.state === "done") renderDetection(j.result);
}

function renderDetection(res) {
  const tbody = $("#detect-results tbody");
  tbody.replaceChildren();
  const alerts = res.alerts || [];
  const kinds = Object.entries(res.by_kind || {}).map(([k, v]) => `${k}:${v}`).join(", ") || "none";
  const msg = $("#detect-msg");
  msg.textContent = `${res.events} events (${kinds}) · ${alerts.length} alert(s)`;
  msg.className = "summary " + (alerts.length ? "pill bad" : "pill");
  for (const a of alerts) {
    tbody.append(el("tr", {},
      el("td", {}, el("span", { class: "pill " + (SEV_CLASS[a.severity] || "") }, a.severity)),
      el("td", {}, a.rule), el("td", {}, a.technique), el("td", {}, a.source || ""),
      el("td", {}, "x" + a.count), el("td", {}, a.title),
      el("td", { class: "dim small" }, (a.evidence || []).join(" · "))));
  }
}

// ---- wiring ------------------------------------------------------------------------
function init() {
  if (!state.token) { $("#auth").classList.remove("hidden"); setConn(false, "no token"); return; }
  for (const b of document.querySelectorAll(".tab")) b.addEventListener("click", () => showTab(b.dataset.tab));
  $("#refresh").addEventListener("click", () => refreshLabs(true));
  $("#run-check").addEventListener("click", () => state.selected && runCheck(state.selected));
  $("#only-fail").addEventListener("change", () => state.selected && renderCheck(state.selected));
  $("#fw-apply").addEventListener("click", () => applyFirewall({ ruleset: $("#fw-edit").value }, "edited ruleset"));
  $("#fw-reload").addEventListener("click", loadFirewall);
  $("#flag-submit").addEventListener("click", submitFlag);
  $("#flag-in").addEventListener("keydown", (ev) => { if (ev.key === "Enter") submitFlag(); });
  initGenerator();
  initAttacks();
  $("#detect-run").addEventListener("click", runDetection);
  for (const p of PROFILES) {
    const b = el("button", { class: "ghost" }, p);
    b.addEventListener("click", () => {
      if (confirm(`Replace the router ruleset with the generated '${p}' level?`)) applyFirewall({ level: p }, p);
    });
    $("#fw-levels").append(b, " ");
  }
  loadScenarios().then(refreshLabs).catch((e) => toast(e.message, "bad"));
  setInterval(() => { if (!document.hidden) refreshLabs(); }, 4000);
}

document.addEventListener("DOMContentLoaded", init);
