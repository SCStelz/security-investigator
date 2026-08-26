// The canvas renderer: a single self-contained HTML document (inline CSS + JS).
// It fetches /api/data for skills/domains/tenant and POSTs /api/run when the
// analyst launches a skill. No build step, no external assets.

export function renderPage() {
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Mission Control — Security Investigator</title>
<style>
  :root {
    --bg: #0b0f17; --panel: #131a26; --panel2: #0f1521; --border: #223047;
    --text: #e6edf6; --muted: #8497b0; --accent: #4c9ffe; --accent2: #2b6fd6;
    --chip: #1b2739; --ok: #3fb950; --warn: #d29922; --hi: #f85149;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; }
  body {
    background: var(--bg); color: var(--text);
    font: 14px/1.45 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }
  a { color: var(--accent); }
  .app { display: grid; grid-template-rows: auto 1fr auto; height: 100vh; }

  header {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 16px; border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, #131c2c, #0d131e);
  }
  header h1 { font-size: 15px; margin: 0; font-weight: 650; letter-spacing: .2px; }
  header .sat { font-size: 18px; }
  .tenant {
    margin-left: auto; display: flex; align-items: center; gap: 8px;
    background: var(--chip); border: 1px solid var(--border);
    padding: 5px 10px; border-radius: 999px; font-size: 12px; color: var(--muted);
  }
  .tenant b { color: var(--text); }
  .refresh {
    background: var(--chip); border: 1px solid var(--border); color: var(--muted);
    border-radius: 8px; padding: 6px 9px; cursor: pointer; font-size: 13px;
  }
  .refresh:hover { color: var(--text); border-color: var(--accent2); }

  .body { display: grid; grid-template-columns: 240px 1fr; overflow: hidden; }
  .rail { border-right: 1px solid var(--border); padding: 14px; overflow-y: auto; background: var(--panel2); }
  .rail h2 { font-size: 11px; text-transform: uppercase; letter-spacing: .8px; color: var(--muted); margin: 4px 0 8px; }
  .search { width: 100%; padding: 8px 10px; border-radius: 8px; border: 1px solid var(--border);
    background: var(--panel); color: var(--text); margin-bottom: 16px; }
  .search::placeholder { color: #5c6b83; }

  .domain { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border-radius: 8px;
    cursor: pointer; user-select: none; font-size: 13px; }
  .domain:hover { background: var(--panel); }
  .domain.on { background: #17263c; outline: 1px solid var(--accent2); }
  .domain .ic { width: 20px; text-align: center; }
  .domain .nm { flex: 1; text-transform: capitalize; }
  .domain .ct { color: var(--muted); font-size: 11px; }

  .recent { margin-top: 18px; }
  .recent .item { font-size: 12px; color: var(--muted); padding: 5px 0; cursor: pointer; border-bottom: 1px dashed #1b2537; }
  .recent .item:hover { color: var(--text); }
  .recent .empty { font-size: 12px; color: #5c6b83; font-style: italic; }

  .main { overflow-y: auto; padding: 16px; }
  .feature {
    background: linear-gradient(135deg, #17263c, #101a2a); border: 1px solid var(--accent2);
    border-radius: 14px; padding: 16px 18px; margin-bottom: 18px; display: flex; align-items: center; gap: 16px;
  }
  .feature .big { font-size: 30px; }
  .feature .txt { flex: 1; }
  .feature .txt h3 { margin: 0 0 3px; font-size: 15px; }
  .feature .txt p { margin: 0; color: var(--muted); font-size: 12.5px; }
  .btn {
    background: var(--accent); color: #04121f; border: none; border-radius: 9px;
    padding: 9px 15px; font-weight: 650; font-size: 13px; cursor: pointer; white-space: nowrap;
  }
  .btn:hover { background: #6fb2ff; }
  .btn.ghost { background: transparent; color: var(--muted); border: 1px solid var(--border); font-weight: 500; }
  .btn.ghost:hover { color: var(--text); border-color: var(--accent2); }

  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 13px 14px; display: flex; flex-direction: column; gap: 8px; }
  .card .top { display: flex; align-items: flex-start; gap: 9px; }
  .card .ic { font-size: 18px; line-height: 1; margin-top: 1px; }
  .card .nm { font-weight: 620; font-size: 13.5px; word-break: break-word; }
  .card .desc { color: var(--muted); font-size: 12px; min-height: 32px; }
  .card .chips { display: flex; flex-wrap: wrap; gap: 5px; }
  .chip { background: var(--chip); border: 1px solid var(--border); border-radius: 6px; padding: 2px 7px; font-size: 10.5px; color: var(--muted); text-transform: capitalize; }
  .card .row { display: flex; gap: 7px; align-items: center; margin-top: 2px; }
  .card .status { margin-left: auto; font-size: 11px; color: var(--muted); }
  .entity { flex: 1; padding: 6px 8px; border-radius: 7px; border: 1px solid var(--border);
    background: var(--panel2); color: var(--text); font-size: 12px; display: none; }
  .entity.show { display: block; }
  .lookback { padding: 6px 6px; border-radius: 7px; border: 1px solid var(--border);
    background: var(--panel2); color: var(--text); font-size: 11.5px; cursor: pointer; max-width: 130px; }
  .lookback:hover { border-color: var(--accent, #388bfd); }

  footer { border-top: 1px solid var(--border); padding: 12px 16px; background: var(--panel2);
    display: flex; align-items: center; gap: 10px; }
  footer label { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); }
  footer input { flex: 1; padding: 8px 11px; border-radius: 8px; border: 1px solid var(--border);
    background: var(--panel); color: var(--text); }
  .toast { position: fixed; bottom: 70px; left: 50%; transform: translateX(-50%);
    background: #16324e; border: 1px solid var(--accent2); color: var(--text);
    padding: 9px 16px; border-radius: 10px; font-size: 13px; opacity: 0; transition: opacity .2s; pointer-events: none; }
  .toast.show { opacity: 1; }
  .banner { background: #3a1d1d; border: 1px solid var(--hi); color: #ffd7d5; padding: 10px 14px; border-radius: 10px; margin-bottom: 14px; font-size: 13px; }

  /* Tabs */
  .tabs { display: flex; gap: 4px; margin-bottom: 16px; border-bottom: 1px solid var(--border); }
  .tab { padding: 8px 14px; cursor: pointer; font-size: 13px; color: var(--muted); border-bottom: 2px solid transparent; user-select: none; }
  .tab:hover { color: var(--text); }
  .tab.on { color: var(--text); border-bottom-color: var(--accent); font-weight: 620; }
  .tab .badge { display: inline-block; margin-left: 6px; background: var(--hi); color: #fff; border-radius: 999px;
    font-size: 10.5px; padding: 0 6px; line-height: 16px; min-width: 16px; text-align: center; }
  .tab .badge.zero { background: var(--chip); color: var(--muted); }

  /* Findings */
  .findhead { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
  .findhead .roll { display: flex; gap: 6px; flex-wrap: wrap; }
  .sev-pill { font-size: 11px; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border); }
  .sev-critical { background: #3a1420; border-color: #f85149; color: #ffb3bd; }
  .sev-high { background: #3a2416; border-color: #f0883e; color: #ffcaa0; }
  .sev-medium { background: #3a3416; border-color: #d29922; color: #f2d98a; }
  .sev-low { background: #16303a; border-color: #388bfd; color: #a5d0ff; }
  .sev-info { background: #1b2739; border-color: #388bfd; color: #a5d0ff; }
  .sev-clean { background: #16321f; border-color: #3fb950; color: #9be6ac; }

  .finding { position: relative; background: var(--panel); border: 1px solid var(--border);
    border-left: 4px solid var(--border); border-radius: 12px; padding: 13px 15px; margin-bottom: 12px; }
  .finding.b-critical { border-left-color: #f85149; }
  .finding.b-high { border-left-color: #f0883e; }
  .finding.b-medium { border-left-color: #d29922; }
  .finding.b-low { border-left-color: #388bfd; }
  .finding.b-info { border-left-color: #388bfd; }
  .finding.b-clean { border-left-color: #3fb950; }
  .finding .fh { display: flex; align-items: baseline; gap: 9px; flex-wrap: wrap; }
  .finding .ftitle { font-weight: 640; font-size: 14px; }
  .finding .fmeta { color: var(--muted); font-size: 11.5px; margin-left: auto; }
  .finding .fskill { font-size: 11px; color: var(--accent); background: #14243a; border: 1px solid var(--accent2);
    border-radius: 6px; padding: 1px 7px; }
  .finding .fsum { color: #c9d6e8; font-size: 12.5px; margin: 8px 0; }
  .finding .fchips { display: flex; flex-wrap: wrap; gap: 6px; margin: 6px 0; }
  .metric { background: var(--chip); border: 1px solid var(--border); border-radius: 6px; padding: 2px 8px; font-size: 11px; }
  .metric b { color: var(--text); }
  .metric.m-critical b { color: #ff9aa6; } .metric.m-high b { color: #ffbf94; }
  .metric.m-medium b { color: #f2d98a; } .metric.m-clean b { color: #9be6ac; }
  .ent { background: #101d30; border: 1px solid var(--accent2); border-radius: 6px; padding: 2px 8px; font-size: 11px; color: #a5d0ff; }
  .freports { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
  .freports .lbl { font-size: 10.5px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); margin-right: 2px; }
  .rep { display: inline-flex; align-items: center; gap: 5px; background: #17251c; border: 1px solid #2ea04366;
    color: #9be6ac; border-radius: 8px; padding: 3px 9px; font-size: 12px; text-decoration: none; cursor: pointer;
    font-family: inherit; }
  .rep:hover { background: #1d3325; border-color: var(--ok); }

  /* Report preview modal */
  .modal { position: fixed; inset: 0; background: rgba(1, 4, 9, .72); display: none; z-index: 50;
    align-items: center; justify-content: center; padding: 24px; }
  .modal.on { display: flex; }
  .modal-box { background: #0d1117; border: 1px solid var(--border); border-radius: 14px; width: min(1000px, 96vw);
    height: min(88vh, 100%); display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 24px 70px rgba(0,0,0,.6); }
  .modal-head { display: flex; align-items: center; gap: 10px; padding: 11px 15px; border-bottom: 1px solid var(--border);
    background: var(--panel); }
  .modal-head .mt { font-weight: 620; font-size: 13.5px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .modal-head .mp { color: var(--muted); font-size: 11.5px; margin-left: 2px; }
  .modal-head .spacer { margin-left: auto; }
  .modal-head a.raw { color: var(--muted); font-size: 12px; text-decoration: none; border: 1px solid var(--border);
    border-radius: 7px; padding: 4px 9px; }
  .modal-head a.raw:hover { color: var(--text); border-color: var(--accent2); }
  .modal-head .x { cursor: pointer; color: #7d8aa0; font-size: 20px; line-height: 1; padding: 0 4px; }
  .modal-head .x:hover { color: var(--hi); }
  .modal iframe { border: 0; width: 100%; height: 100%; background: #0d1117; flex: 1; }
  /* Compose / tailor-before-send modal */
  .modal-box.compose { height: auto; max-height: 88vh; width: min(760px, 96vw); }
  .compose-body { padding: 14px 16px 16px; display: flex; flex-direction: column; gap: 12px; overflow: auto; }
  .compose-hint { color: var(--muted); font-size: 12px; margin: 0; }
  .compose-ta { width: 100%; box-sizing: border-box; min-height: 200px; resize: vertical; background: #0b0f16;
    color: var(--text); border: 1px solid var(--border); border-radius: 10px; padding: 12px 13px;
    font: 13px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; outline: none; }
  .compose-ta:focus { border-color: var(--accent2); }
  .compose-actions { display: flex; justify-content: flex-end; gap: 8px; align-items: center; }
  .compose-actions .grow { margin-right: auto; color: var(--muted); font-size: 11px; }
  .frecs { margin-top: 10px; border-top: 1px dashed #22304733; padding-top: 9px; }
  .frecs .lbl { font-size: 10.5px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); margin-bottom: 6px; }
  .rec { display: inline-flex; align-items: center; gap: 6px; margin: 0 6px 6px 0; }
  .rec button { background: #14243a; color: #cfe2ff; border: 1px solid var(--accent2); border-radius: 8px;
    padding: 5px 10px; font-size: 12px; cursor: pointer; }
  .rec button:hover { background: #1c3352; }
  .rec .why { color: var(--muted); font-size: 11px; }
  .rec .tuned { color: #7ee787; font-size: 11px; margin-left: 4px; cursor: help; }
  .finding .dismiss { position: absolute; top: 10px; right: 12px; color: #5c6b83; cursor: pointer; font-size: 15px; line-height: 1; }
  .finding .dismiss:hover { color: var(--hi); }
  .empty-find { color: var(--muted); text-align: center; padding: 40px 20px; }
  .empty-find .em { font-size: 34px; }
  .empty-find code { background: var(--chip); padding: 1px 6px; border-radius: 5px; color: #cfe2ff; }
</style>
</head>
<body>
<div class="app">
  <header>
    <span class="sat">🛰️</span>
    <h1>Security Investigator — Mission Control</h1>
    <span class="tenant">tenant <b id="tenant">…</b></span>
    <button class="refresh" id="refresh" title="Reload manifest">⟳</button>
  </header>

  <div class="body">
    <aside class="rail">
      <h2>Search</h2>
      <input class="search" id="search" placeholder="Filter skills…" />
      <h2>Filter by domain</h2>
      <div id="domains"></div>
      <div class="recent">
        <h2>Recently launched</h2>
        <div id="recent"><div class="empty">Nothing launched yet.</div></div>
      </div>
    </aside>

    <main class="main">
      <div id="errbanner"></div>
      <div class="tabs">
        <div class="tab on" id="tab-skills" data-view="skills">🚀 Skills</div>
        <div class="tab" id="tab-findings" data-view="findings">📌 Findings <span class="badge zero" id="findCount">0</span></div>
      </div>

      <div id="skillsView">
        <div class="feature" id="feature" style="display:none">
          <span class="big">🔴</span>
          <div class="txt">
            <h3>Threat Pulse</h3>
            <p>15-minute broad scan across 7 domains → prioritized dashboard. Recommended starting point.</p>
          </div>
          <select class="lookback" id="tpLookback" title="Lookback window"></select>
          <button class="btn" data-skill="threat-pulse">▶ Run Threat Pulse</button>
        </div>
        <div class="grid" id="grid"></div>
      </div>

      <div id="findingsView" style="display:none">
        <div class="findhead">
          <div class="roll" id="findRoll"></div>
          <button class="btn ghost" id="findClear" style="margin-left:auto">Clear all</button>
        </div>
        <div id="findings"></div>
      </div>
    </main>
  </div>

  <footer>
    <label>Entity quick-launch</label>
    <input id="quick" placeholder="Paste a UPN / IP / hash / device / incident #…" />
    <select class="lookback" id="quickLookback" title="Lookback window"></select>
    <button class="btn" id="quickgo">Go →</button>
  </footer>
</div>
<div class="toast" id="toast"></div>

<div class="modal" id="reportModal">
  <div class="modal-box">
    <div class="modal-head">
      <span class="mt" id="reportTitle">Report</span>
      <span class="mp" id="reportPath"></span>
      <span class="spacer"></span>
      <a class="raw" id="reportRaw" target="_blank" rel="noopener">Raw ↗</a>
      <span class="x" id="reportClose" title="Close">×</span>
    </div>
    <iframe id="reportFrame" title="Report preview"></iframe>
  </div>
</div>

<div class="modal" id="composeModal">
  <div class="modal-box compose">
    <div class="modal-head">
      <span class="mt">Review &amp; tailor prompt</span>
      <span class="mp" id="composeSkill"></span>
      <span class="spacer"></span>
      <span class="x" id="composeClose" title="Close">×</span>
    </div>
    <div class="compose-body">
      <p class="compose-hint">This is a starting point — edit it however you like, then send it to chat. Nothing is submitted until you click <b>Send</b>.</p>
      <textarea class="compose-ta" id="composeText" spellcheck="false"></textarea>
      <div class="compose-actions">
        <span class="grow" id="composeMeta"></span>
        <button class="btn ghost" id="composeCancel">Cancel</button>
        <button class="btn ghost" id="composeCopy">⧉ Copy</button>
        <button class="btn" id="composeSend">▶ Send to chat</button>
      </div>
    </div>
  </div>
</div>

<script>
const ICONS = ${JSON.stringify(domainIconsForClient())};
let DATA = { skills: [], domains: [], tenant: {} };
let activeDomains = new Set();
let searchTerm = "";

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 2600);
}

function skillIcon(s) { return ICONS[s.domains[0]] || "🧰"; }
function skillDesc(s) { return (s.prompt || "Utility skill — click to launch.").replace(/\\{entity\\}/g, "<target>"); }

// Lookback <option> markup from the single source of truth (DATA.lookbackOptions).
function lookbackOptionsHTML() {
  const opts = (DATA && DATA.lookbackOptions) || [{ value: "", label: "Default window" }];
  return opts.map(o => '<option value="' + o.value + '">' + o.label + '</option>').join("");
}
function fillLookback(el) { if (el) el.innerHTML = lookbackOptionsHTML(); }

async function load() {
  const res = await fetch("/api/data");
  DATA = await res.json();
  document.getElementById("tenant").textContent = DATA.tenant.name || "unknown";
  const err = document.getElementById("errbanner");
  err.innerHTML = DATA.error ? '<div class="banner">⚠️ ' + DATA.error + '</div>' : "";
  document.getElementById("feature").style.display = DATA.skills.some(s => s.name === "threat-pulse") ? "flex" : "none";
  fillLookback(document.getElementById("tpLookback"));
  fillLookback(document.getElementById("quickLookback"));
  renderDomains();
  renderRecent(DATA.recent || []);
  renderGrid();
}

function renderDomains() {
  const host = document.getElementById("domains");
  host.innerHTML = "";
  for (const d of DATA.domains) {
    const el = document.createElement("div");
    el.className = "domain" + (activeDomains.has(d.id) ? " on" : "");
    el.innerHTML = '<span class="ic">' + d.icon + '</span><span class="nm">' + d.id +
      '</span><span class="ct">' + d.skillCount + ' · ' + d.queryCount + 'q</span>';
    el.onclick = () => { activeDomains.has(d.id) ? activeDomains.delete(d.id) : activeDomains.add(d.id); renderDomains(); renderGrid(); };
    host.appendChild(el);
  }
}

function renderRecent(recent) {
  const host = document.getElementById("recent");
  if (!recent.length) { host.innerHTML = '<div class="empty">Nothing launched yet.</div>'; return; }
  host.innerHTML = "";
  for (const r of recent) {
    const el = document.createElement("div");
    el.className = "item";
    el.textContent = "• " + r.name + "  (" + r.ago + ")";
    el.title = "Re-launch " + r.name;
    el.onclick = () => run(r.name, r.entity || "");
    host.appendChild(el);
  }
}

function visibleSkills() {
  return DATA.skills.filter(s => {
    if (activeDomains.size && !s.domains.some(d => activeDomains.has(d))) return false;
    if (searchTerm && !(s.name + " " + (s.prompt || "")).toLowerCase().includes(searchTerm)) return false;
    return true;
  });
}

function renderGrid() {
  const grid = document.getElementById("grid");
  grid.innerHTML = "";
  const skills = visibleSkills().filter(s => s.name !== "threat-pulse");
  for (const s of skills) {
    const card = document.createElement("div");
    card.className = "card";
    const chips = s.domains.map(d => '<span class="chip">' + (ICONS[d] || "") + ' ' + d + '</span>').join("");
    card.innerHTML =
      '<div class="top"><span class="ic">' + skillIcon(s) + '</span><span class="nm">' + s.name + '</span></div>' +
      '<div class="desc">' + skillDesc(s) + '</div>' +
      '<div class="chips">' + chips + '</div>' +
      '<input class="entity" placeholder="' + (s.hasEntity ? "entity (UPN / IP / device / #)…" : "optional target…") + '" />' +
      '<div class="row"><select class="lookback" title="Lookback window">' + lookbackOptionsHTML() + '</select>' +
      '<button class="btn run">▶ Run</button>' +
      '<span class="status"></span></div>';
    const entity = card.querySelector(".entity");
    const lookback = card.querySelector(".lookback");
    const runBtn = card.querySelector(".run");
    if (s.hasEntity) entity.classList.add("show");
    runBtn.onclick = () => {
      if (s.hasEntity && !entity.value.trim()) { entity.classList.add("show"); entity.focus(); toast("Enter an entity to investigate"); return; }
      run(s.name, entity.value.trim(), "", lookback.value);
    };
    grid.appendChild(card);
  }
  if (!skills.length) grid.innerHTML = '<div style="color:var(--muted)">No skills match the current filter.</div>';
}

// Clicking Run no longer submits immediately — it composes the prompt and opens
// an editable preview so the analyst can tailor it first. The SDK has no way to
// write the host chat composer without submitting a turn, so the "tailor before
// send" step lives here in the canvas; Send is what actually injects the turn.
let PENDING = null;
async function run(name, entity, prompt, lookback) {
  try {
    const res = await fetch("/api/compose", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ skill: name || "", entity: entity || "", prompt: prompt || "", lookback: lookback || "" }),
    });
    const j = await res.json();
    if (j.ok) openCompose(j.skill, j.entity || "", j.prompt);
    else toast("⚠️ " + (j.error || "could not compose prompt"));
  } catch (e) { toast("⚠️ " + e.message); }
}

function openCompose(skill, entity, promptText) {
  PENDING = { skill, entity };
  document.getElementById("composeSkill").textContent = skill + (entity ? " · " + entity : "");
  const ta = document.getElementById("composeText");
  ta.value = promptText || "";
  document.getElementById("composeMeta").textContent = "";
  document.getElementById("composeModal").classList.add("on");
  setTimeout(() => { ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); }, 30);
}
function closeCompose() {
  document.getElementById("composeModal").classList.remove("on");
  PENDING = null;
}
async function sendCompose() {
  if (!PENDING) return;
  const text = document.getElementById("composeText").value.trim();
  if (!text) { toast("Prompt is empty"); return; }
  const { skill, entity } = PENDING;
  toast("Sending " + skill + "…");
  try {
    // Send the (possibly edited) text verbatim; lookback is already embedded.
    const res = await fetch("/api/run", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ skill, entity: entity || "", prompt: text, lookback: "" }),
    });
    const j = await res.json();
    if (j.ok) { toast("▶ " + skill + " sent to chat"); renderRecent(j.recent || []); closeCompose(); }
    else toast("⚠️ " + (j.error || "launch failed"));
  } catch (e) { toast("⚠️ " + e.message); }
}
document.getElementById("composeSend").onclick = sendCompose;
document.getElementById("composeCancel").onclick = closeCompose;
document.getElementById("composeClose").onclick = closeCompose;
document.getElementById("composeCopy").onclick = async () => {
  const text = document.getElementById("composeText").value;
  try { await navigator.clipboard.writeText(text); document.getElementById("composeMeta").textContent = "Copied to clipboard"; }
  catch { toast("⚠️ Copy failed"); }
};
document.getElementById("composeModal").addEventListener("click", (e) => { if (e.target.id === "composeModal") closeCompose(); });
document.getElementById("composeText").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); sendCompose(); }
});

document.getElementById("search").addEventListener("input", (e) => { searchTerm = e.target.value.toLowerCase(); renderGrid(); });
document.getElementById("refresh").onclick = () => { toast("Reloading manifest…"); load(); };
document.getElementById("feature").addEventListener("click", (e) => {
  if (e.target.dataset.skill) run("threat-pulse", "", "", (document.getElementById("tpLookback") || {}).value || "");
});
document.getElementById("quickgo").onclick = () => {
  const v = document.getElementById("quick").value.trim();
  if (!v) { toast("Paste an entity first"); return; }
  const lb = (document.getElementById("quickLookback") || {}).value || "";
  // Route the entity to a skill and open the editable preview (no auto-submit).
  run("", v, "", lb);
};
document.getElementById("quick").addEventListener("keydown", (e) => { if (e.key === "Enter") document.getElementById("quickgo").click(); });

// ---- Findings tab ----
let FINDINGS = { findings: [], summary: { total: 0, bySeverity: {} } };
let currentView = "skills";
const SEV_ORDER = ["critical", "high", "medium", "low", "info", "clean"];

function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

function switchView(view) {
  currentView = view;
  document.getElementById("skillsView").style.display = view === "skills" ? "" : "none";
  document.getElementById("findingsView").style.display = view === "findings" ? "" : "none";
  document.getElementById("tab-skills").classList.toggle("on", view === "skills");
  document.getElementById("tab-findings").classList.toggle("on", view === "findings");
  if (view === "findings") renderFindings();
}

async function loadFindings() {
  try {
    const res = await fetch("/api/findings");
    FINDINGS = await res.json();
  } catch (e) { return; }
  const n = FINDINGS.summary ? FINDINGS.summary.total : (FINDINGS.findings || []).length;
  const badge = document.getElementById("findCount");
  badge.textContent = n;
  badge.classList.toggle("zero", n === 0);
  if (currentView === "findings") renderFindings();
}

function renderRoll() {
  const host = document.getElementById("findRoll");
  const by = (FINDINGS.summary && FINDINGS.summary.counts) || {};
  const parts = SEV_ORDER.filter(s => by[s]).map(s =>
    '<span class="sev-pill sev-' + s + '">' + by[s] + ' ' + s + '</span>');
  host.innerHTML = parts.join("") || '';
}

function renderFindings() {
  renderRoll();
  const host = document.getElementById("findings");
  const list = FINDINGS.findings || [];
  if (!list.length) {
    host.innerHTML =
      '<div class="empty-find"><div class="em">🛰️</div>' +
      '<p>No findings recorded yet.</p>' +
      '<p style="font-size:12px">Run a skill, then the agent pushes its result here via the ' +
      '<code>record_finding</code> action — with one-click follow-up hunts.</p></div>';
    return;
  }
  host.innerHTML = "";
  for (const f of list) {
    const sev = (f.severity || "info").toLowerCase();
    const card = document.createElement("div");
    card.className = "finding b-" + sev;

    const metrics = (f.metrics || []).map(m =>
      '<span class="metric m-' + (m.severity || "") + '">' + esc(m.label) + ' <b>' + esc(m.value) + '</b></span>').join("");
    const ents = (f.entities || []).map(e =>
      '<span class="ent">' + esc(e.type) + ': ' + esc(e.value) + '</span>').join("");

    const reports = (f.reports || []).map(r => {
      const label = r.label || (r.path || "").split(/[\\/]/).pop();
      return '<button class="rep" data-path="' + esc(r.path) + '" data-label="' + esc(label) +
        '" title="' + esc(r.path) + '">📄 ' + esc(label) + '</button>';
    }).join("");

    const recs = (f.recommended || []).map((r, i) => {
      const label = r.skill + (r.entity ? ' → ' + r.entity : '');
      const why = r.reason ? '<span class="why">' + esc(r.reason) + '</span>' : '';
      const tailored = r.prompt && r.prompt.trim();
      // Hover title previews the exact prompt that will be sent to chat.
      const tip = tailored ? esc(r.prompt) : 'Generic prompt composed from the manifest';
      const tag = tailored ? '<span class="tuned" title="Tailored to this finding">✎</span>' : '';
      return '<span class="rec"><button data-ri="' + i + '" title="' + tip +
        '">▶ ' + esc(label) + tag + '</button>' + why + '</span>';
    }).join("");

    card.innerHTML =
      '<span class="dismiss" title="Dismiss">×</span>' +
      '<div class="fh"><span class="ftitle">' + esc(f.title) + '</span>' +
      '<span class="fskill">' + esc(f.skill) + '</span>' +
      '<span class="fmeta">' + esc(f.scope || "") + (f.ago ? ' · ' + esc(f.ago) : "") + '</span></div>' +
      (f.summary ? '<div class="fsum">' + esc(f.summary) + '</div>' : "") +
      (metrics ? '<div class="fchips">' + metrics + '</div>' : "") +
      (ents ? '<div class="fchips">' + ents + '</div>' : "") +
      (reports ? '<div class="freports"><span class="lbl">Reports</span>' + reports + '</div>' : "") +
      (recs ? '<div class="frecs"><div class="lbl">Recommended follow-ups</div>' + recs + '</div>' : "");

    card.querySelector(".dismiss").onclick = () => dismissFinding(f.id);
    card.querySelectorAll(".rec button").forEach(b => {
      b.onclick = () => {
        const r = (f.recommended || [])[Number(b.dataset.ri)] || {};
        run(r.skill, r.entity || "", r.prompt || "");
        switchView("skills");
      };
    });
    card.querySelectorAll(".rep").forEach(b => {
      b.onclick = () => openReport(b.dataset.path, b.dataset.label);
    });
    host.appendChild(card);
  }
}

async function dismissFinding(id) {
  try {
    const res = await fetch("/api/findings/dismiss", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id }),
    });
    FINDINGS = await res.json();
    document.getElementById("findCount").textContent = FINDINGS.summary ? FINDINGS.summary.total : 0;
    renderFindings();
  } catch (e) { toast("⚠️ " + e.message); }
}

document.getElementById("tab-skills").onclick = () => switchView("skills");
document.getElementById("tab-findings").onclick = () => switchView("findings");

// ---- Report preview modal ----
function openReport(pathRel, label) {
  const q = "/api/report?path=" + encodeURIComponent(pathRel);
  document.getElementById("reportTitle").textContent = label || (pathRel || "").split(/[\\/]/).pop();
  document.getElementById("reportPath").textContent = pathRel || "";
  document.getElementById("reportRaw").href = q + "&raw=1";
  document.getElementById("reportFrame").src = q;
  document.getElementById("reportModal").classList.add("on");
}
function closeReport() {
  document.getElementById("reportModal").classList.remove("on");
  document.getElementById("reportFrame").src = "about:blank";
}
document.getElementById("reportClose").onclick = closeReport;
document.getElementById("reportModal").addEventListener("click", (e) => {
  if (e.target.id === "reportModal") closeReport();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeReport(); closeCompose(); } });
document.getElementById("findClear").onclick = async () => {
  if (!(FINDINGS.findings || []).length) { toast("Nothing to clear"); return; }
  try {
    const res = await fetch("/api/findings/clear", { method: "POST" });
    FINDINGS = await res.json();
    document.getElementById("findCount").textContent = 0;
    document.getElementById("findCount").classList.add("zero");
    renderFindings();
    toast("Findings cleared");
  } catch (e) { toast("⚠️ " + e.message); }
};

loadFindings();
setInterval(loadFindings, 5000);

load();</script>
</body>
</html>`;
}

// Small helper so the client script has the same emoji map without importing.
function domainIconsForClient() {
    return {
        incidents: "🔴", identity: "🔐", spn: "🤖", endpoint: "🖥️",
        email: "📧", admin: "🔑", cloud: "☁️", exposure: "🛡️",
    };
}
