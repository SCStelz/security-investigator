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

  .body { display: grid; grid-template-columns: var(--rail-w, 200px) 1fr; overflow: hidden; position: relative; }
  .body.rail-collapsed { grid-template-columns: 34px 1fr; }
  .rail-resize { position: absolute; top: 0; bottom: 0; left: var(--rail-w, 200px); width: 7px; margin-left: -3px;
    cursor: col-resize; z-index: 8; }
  .rail-resize::after { content: ""; position: absolute; top: 0; bottom: 0; left: 3px; width: 1px; background: transparent; transition: background .12s; }
  .rail-resize:hover::after, .rail-resize.dragging::after { background: var(--accent2); }
  .body.rail-collapsed .rail-resize { display: none; }
  .rail-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .rail-head h2 { margin: 4px 0 8px; }
  .rail-toggle {
    background: var(--chip); border: 1px solid var(--border); color: var(--muted);
    border-radius: 6px; padding: 1px 7px; cursor: pointer; font-size: 13px; line-height: 1.4;
    flex: none;
  }
  .rail-toggle:hover { color: var(--text); border-color: var(--accent2); }
  .body.rail-collapsed .rail { padding: 12px 4px; overflow: hidden; }
  .body.rail-collapsed .rail > *:not(.rail-head) { display: none; }
  .body.rail-collapsed .rail-head { justify-content: center; }
  .body.rail-collapsed .rail-head h2 { display: none; }
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
  .fav-btn { margin-left: auto; background: none; border: none; cursor: pointer;
    font-size: 15px; line-height: 1; padding: 0 2px; filter: grayscale(1) opacity(.3);
    transition: filter .12s; align-self: flex-start; }
  .fav-btn:hover { filter: grayscale(.15) opacity(.9); }
  .fav-btn.on { filter: none; }
  .fav-btn.lst { font-size: 13px; margin: 0; padding: 0; }
  .domain.fav-row { margin-top: 8px; border-top: 1px solid var(--border); padding-top: 10px; }
  .domain.fav-row.on { background: #2a2410; outline: 1px solid #f5c518; }
  .card .desc { color: var(--muted); font-size: 12px; min-height: 32px; }
  .card .chips { display: flex; flex-wrap: wrap; gap: 5px; }
  .chip { background: var(--chip); border: 1px solid var(--border); border-radius: 6px; padding: 2px 7px; font-size: 10.5px; color: var(--muted); text-transform: capitalize; }
  .chip.alt { text-transform: none; color: #cfe2ff; }
  .qpath { font-size: 10.5px; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; text-align: right; opacity: .8; }
  .card .row { display: flex; gap: 7px; align-items: center; margin-top: 2px; flex-wrap: wrap; }
  .card .row.skrow { flex-wrap: nowrap; }
  .skrow .lookback, .skrow .output { flex: 1 1 0; min-width: 0; max-width: none; }
  .skrow .btn.open { padding: 8px 9px; flex: 0 0 auto; }
  .skrow .run { flex: 0 0 auto; }
  .skrow .status:empty { display: none; }
  .card .status { margin-left: auto; font-size: 11px; color: var(--muted); }
  .btn.qsel.on { background: var(--hi); color: #fff; border-color: var(--hi); }
  .qbar { position: sticky; bottom: 8px; margin-top: 12px; display: flex; align-items: center; gap: 10px;
    background: var(--panel2); border: 1px solid var(--hi); border-radius: 10px; padding: 9px 12px;
    box-shadow: 0 6px 20px rgba(0,0,0,.35); z-index: 5; }
  .qbar .qbar-n { font-weight: 640; font-size: 12.5px; color: var(--text); white-space: nowrap; }
  .qbar .qbar-paths { flex: 1; font-size: 10.5px; color: var(--muted);
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  /* ---- MITRE map view ---- */
  .mitre-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
  .mitre-bar .mlbl { font-size: 11.5px; color: var(--muted); }
  .mitre-bar label.mchk { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text); cursor: pointer; }
  .mitre-wrap { display: flex; gap: 8px; overflow-x: auto; padding-bottom: 10px; align-items: flex-start; }
  .mitre-col { flex: 0 0 156px; min-width: 156px; background: var(--panel2); border: 1px solid var(--border);
    border-radius: 8px; padding: 6px; display: flex; flex-direction: column; gap: 5px; }
  .mitre-col h4 { margin: 2px 2px 4px; font-size: 11px; line-height: 1.25; color: var(--text); font-weight: 640; }
  .mitre-col h4 .tc { display: block; font-size: 10px; color: var(--muted); font-weight: 500; margin-top: 1px; }
  .mtile { text-align: left; border: 1px solid var(--border); border-radius: 6px; padding: 5px 7px; font-size: 10.5px;
    line-height: 1.25; color: var(--text); background: var(--chip); cursor: pointer; display: flex; gap: 6px;
    align-items: flex-start; justify-content: space-between; }
  .mtile .tid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 9.5px; color: var(--muted); }
  .mtile .cnt { flex: 0 0 auto; min-width: 16px; text-align: center; border-radius: 999px; padding: 0 5px;
    font-size: 9.5px; font-weight: 700; color: #04121f; background: var(--accent); }
  .mtile.cov1 { border-color: rgba(88,166,255,.35); }
  .mtile.cov2 { border-color: rgba(88,166,255,.6); background: rgba(88,166,255,.10); }
  .mtile.cov3 { border-color: var(--accent); background: rgba(88,166,255,.18); }
  .mtile:not(.dim):hover { border-color: var(--accent); }
  .mtile.sel { outline: 2px solid var(--accent); outline-offset: -1px; }
  .mtile.dim { opacity: .4; cursor: default; }
  .mtile.dim .cnt { display: none; }
  .mitre-detail { border: 1px solid var(--hi); border-radius: 10px; background: var(--panel2);
    padding: 10px 12px; margin-bottom: 12px; }
  .mitre-detail .mdh { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
  .mitre-detail .mdh .mid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--accent); font-weight: 700; }
  .mitre-detail .mdh .mnm { font-weight: 640; font-size: 13px; }
  .mitre-detail .mdh .mtac { font-size: 11px; color: var(--muted); }
  .mitre-detail .mdh .mx { margin-left: auto; background: none; border: none; color: var(--muted); cursor: pointer; font-size: 14px; }
  .mitre-detail .mdrow { display: flex; align-items: center; gap: 8px; padding: 5px 0; border-top: 1px solid var(--border); flex-wrap: wrap; }
  .mitre-detail .mdrow .mdt { flex: 1; min-width: 140px; font-size: 12px; }
  .mitre-detail .mdrow .mdp { font-size: 10px; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .mitre-empty { color: var(--muted); font-size: 12.5px; padding: 20px 4px; }
  .entity { flex: 1; padding: 6px 8px; border-radius: 7px; border: 1px solid var(--border);
    background: var(--panel2); color: var(--text); font-size: 12px; display: none; }
  .entity.show { display: block; }
  .entity.dim { opacity: .45; }
  .fleetck { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--muted); cursor: pointer; margin-top: 4px; user-select: none; }
  .fleetck:hover { color: var(--text); }
  .fleetck input { accent-color: var(--accent, #388bfd); cursor: pointer; margin: 0; }
  .fleetck.on { color: var(--accent2, #6fb2ff); font-weight: 600; }
  .lookback { padding: 6px 6px; border-radius: 7px; border: 1px solid var(--border);
    background: var(--panel2); color: var(--text); font-size: 11.5px; cursor: pointer; max-width: 130px; }
  .lookback:hover { border-color: var(--accent, #388bfd); }
  .output { padding: 6px 6px; border-radius: 7px; border: 1px solid var(--border);
    background: var(--panel2); color: var(--text); font-size: 11.5px; cursor: pointer; max-width: 150px; }
  .output:hover { border-color: var(--accent, #388bfd); }

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
  .tabs { position: sticky; top: -16px; z-index: 20; background: var(--bg);
    display: flex; gap: 4px; padding: 16px 0 10px; margin: -16px 0 12px;
    border-bottom: 1px solid var(--border); }
  .tab { padding: 8px 14px; cursor: pointer; font-size: 13px; color: var(--muted); border-bottom: 2px solid transparent; user-select: none; }
  .tab:hover { color: var(--text); }
  .tab.on { color: var(--text); border-bottom-color: var(--accent); font-weight: 620; }
  .tab .badge { display: inline-block; margin-left: 6px; background: var(--hi); color: #fff; border-radius: 999px;
    font-size: 10.5px; padding: 0 6px; line-height: 16px; min-width: 16px; text-align: center; }
  .tab .badge.zero { background: var(--chip); color: var(--muted); }
  #queryCount { background: var(--chip); color: var(--muted); }

  /* Findings */
  .findhead { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
  .findhead .roll { display: flex; gap: 6px; flex-wrap: wrap; }
  .sev-pill { font-size: 11px; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border);
    cursor: pointer; user-select: none; transition: opacity .12s, box-shadow .12s, transform .06s; text-transform: capitalize; }
  .sev-pill:hover { transform: translateY(-1px); }
  .sev-pill.active { box-shadow: 0 0 0 2px var(--bg), 0 0 0 3px currentColor; }
  .sev-pill.dim { opacity: .4; }
  .sev-pill.dim:hover { opacity: .75; }
  .sev-all { font-size: 11px; padding: 2px 10px; border-radius: 999px; cursor: pointer; user-select: none;
    background: var(--chip); border: 1px solid var(--border); color: var(--muted); transition: opacity .12s; }
  .sev-all:hover { color: var(--text); border-color: var(--accent, #388bfd); }
  .sev-all.active { color: var(--text); border-color: var(--accent, #388bfd); box-shadow: 0 0 0 2px var(--bg), 0 0 0 3px var(--accent, #388bfd); }
  .sev-all.dim { opacity: .55; }
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

  /* Slim timeline gutter to the left of each finding card */
  .finding-row { display: flex; gap: 10px; align-items: stretch; }
  .ftime { flex: none; width: 58px; position: relative; text-align: right;
    padding: 13px 12px 0 0; color: var(--muted); font-size: 11px; line-height: 1.3; }
  .ftime .ft-day { display: block; color: var(--text); font-weight: 600; }
  .ftime .ft-time { display: block; font-size: 10.5px; opacity: .85; }
  .ftime::before { content: ""; position: absolute; top: 6px; bottom: 0; right: 0; width: 2px; background: var(--border); }
  .ftime::after { content: ""; position: absolute; top: 16px; right: -4px; width: 8px; height: 8px;
    border-radius: 50%; background: var(--panel2); border: 2px solid var(--accent2); }
  .finding-row:last-child .ftime::before { bottom: auto; height: 14px; }
  .ftime.b-critical::after { border-color: #f85149; }
  .ftime.b-high::after { border-color: #f0883e; }
  .ftime.b-medium::after { border-color: #d29922; }
  .ftime.b-low::after, .ftime.b-info::after { border-color: #388bfd; }
  .ftime.b-clean::after { border-color: #3fb950; }
  .finding .fh { display: flex; align-items: baseline; gap: 9px; flex-wrap: wrap; }
  .finding .ftitle { font-weight: 640; font-size: 14px; }
  .finding .fmeta { color: var(--muted); font-size: 11.5px; margin-left: auto; }
  .finding .frun { background: #14243a; color: #cfe2ff; border: 1px solid var(--accent2); border-radius: 7px;
    padding: 1px 8px; font-size: 11px; cursor: pointer; line-height: 1.55; }
  .finding .frun:hover { background: #1c3352; border-color: var(--accent); }
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
    height: min(88vh, 100%); display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 24px 70px rgba(0,0,0,.6);
    resize: both; min-width: 460px; min-height: 300px; max-width: 96vw; max-height: 96vh; }
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
  .modal-box.compose { height: auto; max-height: 92vh; width: min(760px, 96vw);
    resize: both; overflow: auto; min-width: 420px; min-height: 320px; max-width: 96vw; }
  .compose-body { padding: 14px 16px 16px; display: flex; flex-direction: column; gap: 12px; overflow: auto; flex: 1 1 auto; min-height: 0; }
  .compose-hint { color: var(--muted); font-size: 12px; margin: 0; }
  .compose-ta { width: 100%; box-sizing: border-box; min-height: 200px; flex: 1 1 auto; resize: vertical; background: #0b0f16;
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

  /* View toggle + list/grid tables */
  .viewbar { display: flex; align-items: center; gap: 9px; margin-bottom: 12px; }
  .viewbar .vlabel { font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); }
  .seg { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .seg button { background: var(--panel2); color: var(--muted); border: none; padding: 6px 12px; font-size: 12.5px; cursor: pointer; }
  .seg button + button { border-left: 1px solid var(--border); }
  .seg button.on { background: var(--accent); color: #04121f; font-weight: 640; }
  .seg button:not(.on):hover { color: var(--text); background: var(--panel); }

  table.lst { width: 100%; border-collapse: collapse; table-layout: fixed; }
  table.lst th, table.lst td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12.5px; }
  table.lst thead th { position: sticky; top: 0; background: var(--panel2); color: var(--muted);
    font-weight: 640; font-size: 10.5px; text-transform: uppercase; letter-spacing: .5px; user-select: none; z-index: 3; }
  table.lst th { position: relative; }
  table.lst th.sortable { cursor: pointer; }
  table.lst th.sortable:hover { color: var(--text); }
  table.lst th .sort-ind { opacity: .45; margin-left: 5px; font-size: 9px; }
  table.lst th.sorted { color: var(--text); }
  table.lst th.sorted .sort-ind { opacity: 1; color: var(--accent); }
  table.lst tbody tr:hover { background: var(--panel); }
  table.lst td.nm { font-weight: 620; color: var(--text); }
  table.lst td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; color: var(--muted); }
  table.lst .cellchips { display: flex; gap: 4px; flex-wrap: nowrap; overflow: hidden; }
  table.lst .rsz { position: absolute; top: 0; right: 0; width: 7px; height: 100%; cursor: col-resize; }
  table.lst .rsz:hover { background: var(--accent2); opacity: .55; }
  table.lst td.ic-cell { overflow: visible; text-overflow: clip; text-align: center; padding-left: 6px; padding-right: 4px; line-height: 1; }
  .lst-actions { display: flex; gap: 6px; align-items: center; }
  .lst-actions .btn { padding: 4px 8px; font-size: 11.5px; }
  .lst-sel { padding: 4px 5px; border-radius: 6px; border: 1px solid var(--border);
    background: var(--panel2); color: var(--text); font-size: 11px; cursor: pointer;
    width: auto; max-width: none; }
  .lst-sel:hover { border-color: var(--accent, #388bfd); }

  /* Memory checkbox + confirm dialog */
  .memck { display: inline-flex; align-items: center; gap: 6px; margin-right: auto; color: var(--muted);
    font-size: 12px; cursor: pointer; user-select: none; }
  .memck input { accent-color: var(--accent); cursor: pointer; }
  .memck.disabled { opacity: .4; cursor: not-allowed; }
  .memck.disabled input { cursor: not-allowed; }
  .btn.danger { background: #3a1620; color: #ffb3c1; border: 1px solid #7d2436; }
  .btn.danger:hover { background: #4d1a29; color: #ffd6de; border-color: #a5324a; }
  .modal-box.confirm { height: auto; max-height: 88vh; width: min(460px, 94vw); resize: none; min-width: 0; min-height: 0; }
  .confirm-body { padding: 16px 18px 18px; }
  .confirm-body p { margin: 0 0 16px; color: var(--text); font-size: 13px; line-height: 1.5; }
  .confirm-actions { display: flex; gap: 8px; align-items: center; }
  .confirm-actions .grow { margin-right: auto; }
  .confirm-body code { background: var(--panel2, rgba(127,127,127,.15)); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
  .memfile-input { width: 100%; box-sizing: border-box; margin: 0 0 14px; padding: 9px 11px; font-size: 13px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--text); background: var(--panel, #10151c);
    border: 1px solid var(--border, #2a3441); border-radius: 6px; outline: none; }
  .memfile-input:focus { border-color: var(--accent); }
  .confirm-actions .grow#memFileMeta { font-size: 12px; color: var(--muted); }
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
      <div class="rail-head">
        <h2>Search</h2>
        <button class="rail-toggle" id="railToggle" title="Collapse search panel">⟨</button>
      </div>
      <input class="search" id="search" placeholder="Filter skills &amp; queries…" />
      <h2>Filter by domain</h2>
      <div id="domains"></div>
      <div class="recent">
        <h2>Recently launched</h2>
        <div id="recent"><div class="empty">Nothing launched yet.</div></div>
      </div>
    </aside>
    <div class="rail-resize" id="railResize" title="Drag to resize"></div>

    <main class="main">
      <div id="errbanner"></div>
      <div class="tabs">
        <div class="tab on" id="tab-skills" data-view="skills">🚀 Skills</div>
        <div class="tab" id="tab-queries" data-view="queries">🔎 Queries <span class="badge" id="queryCount">0</span></div>
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
          <select class="output" id="tpOutput" title="Output format"></select>
          <button class="btn" data-skill="threat-pulse">▶ Run Threat Pulse</button>
        </div>
        <div class="viewbar">
          <span class="vlabel">View</span>
          <div class="seg" id="skillsViewToggle">
            <button data-mode="cards" class="on">⊞ Cards</button>
            <button data-mode="list">▤ List</button>
          </div>
        </div>
        <div class="grid" id="grid"></div>
        <div id="skillsTable" style="display:none"></div>
      </div>

      <div id="findingsView" style="display:none">
        <div class="findhead">
          <div class="roll" id="findRoll"></div>
          <button class="btn ghost" id="memSet" style="margin-left:auto" title="Set the tenant context-memory filename">⚙️</button>
          <button class="btn ghost" id="findCompact" title="Compact findings into your tenant context-memory file (propose-only review)">🧠 Compact to memory</button>
          <button class="btn ghost" id="findClear">Clear all</button>
        </div>
        <div id="findings"></div>
      </div>

      <div id="queriesView" style="display:none">
        <div class="viewbar">
          <span class="vlabel">View</span>
          <div class="seg" id="queriesViewToggle">
            <button data-mode="cards" class="on">⊞ Cards</button>
            <button data-mode="list">▤ List</button>
            <button data-mode="mitre">🗺️ MITRE</button>
          </div>
        </div>
        <div class="grid" id="queryGrid"></div>
        <div id="queriesTable" style="display:none"></div>
        <div id="queriesMitre" style="display:none"></div>
        <div class="qbar" id="qbar" style="display:none"></div>
      </div>
    </main>
  </div>

  <footer>
    <label>Entity quick-launch</label>
    <input id="quick" placeholder="Paste a UPN / IP / hash / device / incident #…" />
    <select class="lookback" id="quickLookback" title="Lookback window"></select>
    <select class="output" id="quickOutput" title="Output format"></select>
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
        <label class="memck" id="memWrap" title="Prepend a directive to review this tenant's context-memory file before investigating">
          <input type="checkbox" id="memChk" /> <span>🧠 Use memory</span>
        </label>
        <span class="grow" id="composeMeta"></span>
        <button class="btn ghost" id="composeCancel">Cancel</button>
        <button class="btn ghost" id="composeCopy">⧉ Copy</button>
        <button class="btn" id="composeSend">▶ Send to chat</button>
      </div>
    </div>
  </div>
</div>

<div class="modal" id="confirmModal">
  <div class="modal-box confirm">
    <div class="modal-head">
      <span class="mt" id="confirmTitle">Confirm</span>
      <span class="spacer"></span>
      <span class="x" id="confirmClose" title="Close">×</span>
    </div>
    <div class="confirm-body">
      <p id="confirmMsg"></p>
      <div class="confirm-actions">
        <span class="grow"></span>
        <button class="btn ghost" id="confirmCancel">Cancel</button>
        <button class="btn ghost" id="confirmAlt" style="display:none"></button>
        <button class="btn danger" id="confirmOk">Confirm</button>
      </div>
    </div>
  </div>
</div>

<div class="modal" id="memFileModal">
  <div class="modal-box confirm">
    <div class="modal-head">
      <span class="mt">Tenant memory file</span>
      <span class="spacer"></span>
      <span class="x" id="memFileClose" title="Close">×</span>
    </div>
    <div class="confirm-body">
      <p>Names the context-memory file under <code>.copilot/memories/repo/</code>. Saved to <code>config.json</code> — no manual editing needed.</p>
      <input type="text" id="memFileInput" class="memfile-input" spellcheck="false" autocomplete="off" placeholder="tenant-context.md" />
      <div class="confirm-actions">
        <span class="grow" id="memFileMeta"></span>
        <button class="btn ghost" id="memFileCancel">Cancel</button>
        <button class="btn" id="memFileSave">Save</button>
      </div>
    </div>
  </div>
</div>

<script>
const ICONS = ${JSON.stringify(domainIconsForClient())};
let DATA = { skills: [], domains: [], queries: [], tenant: {} };
let activeDomains = new Set();
let searchTerm = "";

// ---- Favorites (localStorage-backed) ----
// Skills keyed by name, queries by repo-relative path. favOnly is the sidebar
// filter toggle. Toggling re-renders the sidebar (fav counts) plus the affected
// grid so a de-favorited item drops out immediately when the filter is active.
let favSkills = new Set();
let favQueries = new Set();
let favOnly = false;
try { favSkills = new Set(JSON.parse(localStorage.getItem("mc.fav.skills") || "[]")); } catch (e) {}
try { favQueries = new Set(JSON.parse(localStorage.getItem("mc.fav.queries") || "[]")); } catch (e) {}
function saveFavs() {
  try {
    localStorage.setItem("mc.fav.skills", JSON.stringify([...favSkills]));
    localStorage.setItem("mc.fav.queries", JSON.stringify([...favQueries]));
  } catch (e) {}
}
function toggleFavSkill(name) {
  if (favSkills.has(name)) favSkills.delete(name); else favSkills.add(name);
  saveFavs(); renderDomains(); renderGrid();
}
function toggleFavQuery(path) {
  if (favQueries.has(path)) favQueries.delete(path); else favQueries.add(path);
  saveFavs(); renderDomains(); renderQueries();
}

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 2600);
}

function skillIcon(s) { return ICONS[s.domains[0]] || "🧰"; }
function skillDesc(s) { return (s.prompt || "Utility skill — click to launch.").replace(/\\{entity\\}/g, "<target>"); }

// Lookback <option> markup from the single source of truth (DATA.lookbackOptions).
function lookbackOptionsHTML() {
  const opts = (DATA && DATA.lookbackOptions) || [{ value: "", label: "Default" }];
  return opts.map(o => '<option value="' + o.value + '">' + o.label + '</option>').join("");
}
function fillLookback(el) { if (el) el.innerHTML = lookbackOptionsHTML(); }

// Output-mode <option> markup from the single source of truth (DATA.outputModes).
// Inline is the default (first entry); Markdown augments the prompt to also save a report file.
function outputOptionsHTML() {
  const opts = (DATA && DATA.outputModes) || [{ value: "inline", label: "💬 Inline" }];
  return opts.map(o => '<option value="' + o.value + '">' + o.label + '</option>').join("");
}
function fillOutput(el) { if (el) el.innerHTML = outputOptionsHTML(); }

async function load() {
  const res = await fetch("/api/data");
  DATA = await res.json();
  document.getElementById("tenant").textContent = DATA.tenant.name || "unknown";
  const err = document.getElementById("errbanner");
  err.innerHTML = DATA.error ? '<div class="banner">⚠️ ' + DATA.error + '</div>' : "";
  document.getElementById("feature").style.display = DATA.skills.some(s => s.name === "threat-pulse") ? "flex" : "none";
  fillLookback(document.getElementById("tpLookback"));
  fillLookback(document.getElementById("quickLookback"));
  fillOutput(document.getElementById("tpOutput"));
  fillOutput(document.getElementById("quickOutput"));
  renderDomains();
  renderRecent(DATA.recent || []);
  renderGrid();
  document.getElementById("queryCount").textContent = (DATA.queries || []).length;
  renderQueries();
}

function renderDomains() {
  const host = document.getElementById("domains");
  host.innerHTML = "";
  for (const d of DATA.domains) {
    const el = document.createElement("div");
    el.className = "domain" + (activeDomains.has(d.id) ? " on" : "");
    el.innerHTML = '<span class="ic">' + d.icon + '</span><span class="nm">' + d.id + '</span>';
    el.onclick = () => { activeDomains.has(d.id) ? activeDomains.delete(d.id) : activeDomains.add(d.id); renderDomains(); renderGrid(); renderQueries(); };
    host.appendChild(el);
  }
  // Favorites filter row — sits under the domain list, toggles favOnly.
  const fav = document.createElement("div");
  fav.className = "domain fav-row" + (favOnly ? " on" : "");
  fav.innerHTML = '<span class="ic">⭐</span><span class="nm">Favorites</span>';
  fav.title = "Show only favorited skills & queries";
  fav.onclick = () => { favOnly = !favOnly; renderDomains(); renderGrid(); renderQueries(); };
  host.appendChild(fav);
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
    if (favOnly && !favSkills.has(s.name)) return false;
    if (activeDomains.size && !s.domains.some(d => activeDomains.has(d))) return false;
    if (searchTerm && !(s.name + " " + (s.prompt || "")).toLowerCase().includes(searchTerm)) return false;
    return true;
  });
}

function renderSkillCards() {
  const grid = document.getElementById("grid");
  grid.innerHTML = "";
  const skills = visibleSkills().filter(s => s.name !== "threat-pulse");
  for (const s of skills) {
    const card = document.createElement("div");
    card.className = "card";
    const chips = s.domains.map(d => '<span class="chip">' + (ICONS[d] || "") + ' ' + d + '</span>').join("");
    const fleetHtml = s.fleet
      ? '<label class="fleetck"><input type="checkbox" class="fleetbox" /> 🌐 Fleet-wide (' + s.fleet.label + ')</label>'
      : '';
    card.innerHTML =
      '<div class="top"><span class="ic">' + skillIcon(s) + '</span><span class="nm">' + s.name + '</span>' +
      '<button class="fav-btn' + (favSkills.has(s.name) ? " on" : "") + '" title="Toggle favorite">⭐</button></div>' +
      '<div class="desc">' + skillDesc(s) + '</div>' +
      '<div class="chips">' + chips + '</div>' +
      fleetHtml +
      '<input class="entity" placeholder="' + (s.hasEntity ? "entity (UPN / IP / device / #)…" : "optional target…") + '" />' +
      '<div class="row skrow"><select class="lookback" title="Lookback window">' + lookbackOptionsHTML() + '</select>' +
      '<select class="output" title="Output format">' + outputOptionsHTML() + '</select>' +
      (s.path ? '<button class="btn ghost open" title="Open SKILL.md">📄</button>' : '') +
      '<button class="btn run">▶ Run</button>' +
      '<span class="status"></span></div>';
    const entity = card.querySelector(".entity");
    const lookback = card.querySelector(".lookback");
    const output = card.querySelector(".output");
    const runBtn = card.querySelector(".run");
    const openBtn = card.querySelector(".open");
    if (openBtn) openBtn.onclick = () => openReport(s.path, s.name);
    card.querySelector(".fav-btn").onclick = (e) => { e.stopPropagation(); toggleFavSkill(s.name); };
    const fleetBox = card.querySelector(".fleetbox");
    if (s.hasEntity) entity.classList.add("show");
    if (fleetBox) {
      // Fleet-wide overrides the per-entity target: disable + clear the entity
      // input so it's clear the sweep covers everything, and drop the "entity
      // required" gate on Run.
      fleetBox.onchange = () => {
        const on = fleetBox.checked;
        fleetBox.closest(".fleetck").classList.toggle("on", on);
        entity.disabled = on;
        entity.classList.toggle("dim", on);
        if (on) entity.value = "";
        entity.placeholder = on ? "Fleet-wide — " + s.fleet.label : "entity (UPN / IP / device / #)…";
      };
    }
    runBtn.onclick = () => {
      const fleet = !!(fleetBox && fleetBox.checked);
      if (s.hasEntity && !fleet && !entity.value.trim()) { entity.classList.add("show"); entity.focus(); toast("Enter an entity, or check Fleet-wide"); return; }
      run(s.name, entity.value.trim(), "", lookback.value, fleet, output.value);
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
async function run(name, entity, prompt, lookback, fleet, output) {
  try {
    const res = await fetch("/api/compose", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ skill: name || "", entity: entity || "", prompt: prompt || "", lookback: lookback || "", fleet: fleet === true, output: output || "" }),
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
  syncMemUI();
  applyMem();
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
// Close a modal on backdrop click only when the mousedown ALSO started on the
// backdrop — prevents a resize drag that starts inside the box and releases on
// the overlay from being treated as an outside click.
function bindBackdropClose(modalId, closeFn) {
  var el = document.getElementById(modalId);
  if (!el) return;
  var downOnSelf = false;
  el.addEventListener("mousedown", function (e) { downOnSelf = (e.target === el); });
  el.addEventListener("click", function (e) { var ok = (e.target === el && downOnSelf); downOnSelf = false; if (ok) closeFn(); });
}
bindBackdropClose("composeModal", closeCompose);
document.getElementById("composeText").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); sendCompose(); }
});

// --- Memory directive (Use memory checkbox) ---
function memFile() { return (DATA.tenant && DATA.tenant.memoryFile) ? DATA.tenant.memoryFile : ""; }
function memConfigured() { return !!(DATA.tenant && DATA.tenant.memoryFileConfigured); }
function memEnabled() { try { return localStorage.getItem("mc.useMemory") !== "0"; } catch (e) { return true; } }
function memBlock(file) {
  return "🧠 Before investigating and before rendering any verdict, consult your tenant context-memory file '" + file + "' (under ~/.copilot/memories/repo/). Don't read it in full — first skim its section headers, then search it for the specific entities in this task (IPs, UPNs, hostnames, domains, file hashes, app/SPN names) and read only the matching sections. Apply the documented ground truth you find — known-good IPs, automation/orchestration fingerprints, account classifications, and false-positive rules — and cite it explicitly when a signal matches a documented pattern.";
}
function applyMem() {
  var ta = document.getElementById("composeText");
  if (!ta) return;
  var stripped = ta.value
    .replace(/<!-- use-memory -->[\\s\\S]*?<!-- \\/use-memory -->\\n*/g, "")
    .replace(/^🧠 Before investigating[\\s\\S]*?documented pattern\\.\\n*/, "")
    .replace(/^\\s+/, "");
  var chk = document.getElementById("memChk");
  if (chk && chk.checked && memFile()) ta.value = memBlock(memFile()) + "\\n\\n" + stripped;
  else ta.value = stripped;
}
function syncMemUI() {
  var wrap = document.getElementById("memWrap");
  var chk = document.getElementById("memChk");
  if (!wrap || !chk) return;
  var has = !!memFile();
  wrap.classList.toggle("disabled", !has);
  chk.disabled = !has;
  chk.checked = has && memEnabled();
  wrap.title = has
    ? ("Prepend a directive to review " + memFile() + " before investigating" + (memConfigured() ? "" : " (default name — click ⚙ in Findings to set)"))
    : "Set a memory file (⚙ in Findings) to enable";
}
document.getElementById("memChk").addEventListener("change", function () {
  try { localStorage.setItem("mc.useMemory", this.checked ? "1" : "0"); } catch (e) {}
  applyMem();
  document.getElementById("composeText").focus();
});

// --- Confirm dialog (generic) ---
let CONFIRM_CB = null, CONFIRM_ALT_CB = null;
function openConfirm(opts) {
  document.getElementById("confirmTitle").textContent = opts.title || "Confirm";
  document.getElementById("confirmMsg").textContent = opts.message || "";
  var ok = document.getElementById("confirmOk");
  ok.textContent = opts.okLabel || "Confirm";
  ok.className = "btn " + (opts.okClass || "danger");
  CONFIRM_CB = opts.onOk || null;
  var alt = document.getElementById("confirmAlt");
  if (opts.altLabel) {
    alt.textContent = opts.altLabel;
    alt.style.display = "";
    CONFIRM_ALT_CB = opts.onAlt || null;
  } else { alt.style.display = "none"; CONFIRM_ALT_CB = null; }
  document.getElementById("confirmModal").classList.add("on");
}
function closeConfirm() { document.getElementById("confirmModal").classList.remove("on"); CONFIRM_CB = null; CONFIRM_ALT_CB = null; }
document.getElementById("confirmCancel").onclick = closeConfirm;
document.getElementById("confirmClose").onclick = closeConfirm;
document.getElementById("confirmOk").onclick = function () { var cb = CONFIRM_CB; closeConfirm(); if (cb) cb(); };
document.getElementById("confirmAlt").onclick = function () { var cb = CONFIRM_ALT_CB; closeConfirm(); if (cb) cb(); };
bindBackdropClose("confirmModal", closeConfirm);

// --- Compact findings to memory ---
function compactToMemory() {
  var file = memFile();
  if (!file) { toast("Set a memory file (⚙) to enable"); return; }
  var n = (FINDINGS.findings || []).length;
  if (n === 0) { toast("No findings to compact"); return; }
  var p = "";
  p += "Run the context-memory-review skill (.github/skills/context-memory-review/SKILL.md) to compact accumulated investigation evidence into the tenant context-memory file '" + file + "' (under ~/.copilot/memories/repo/).\\n\\n";
  p += "Evidence sources to review:\\n";
  p += "1. Current memory file '" + file + "' (if it exists).\\n";
  p += "2. Mission Control findings at .github/extensions/skills-canvas/state/findings.json (" + n + " recorded finding(s) — first-party, each from an actual skill drill-down).\\n";
  p += "3. Recent markdown reports under reports/.\\n\\n";
  p += "Produce a PROPOSE-ONLY review document for human approval: list candidate ADD / MODIFY / FLAG changes with the supporting evidence for each. Do NOT edit the memory file, and do NOT commit — applying approved changes is a separate manual step. Honor the feedback-loop guard and keep all tenant PII local (never in committed docs).";
  openCompose("context-memory-review", "", p);
}
function syncCompactBtn() {
  var b = document.getElementById("findCompact");
  if (!b) return;
  var has = !!memFile();
  var n = (FINDINGS.findings || []).length;
  b.disabled = !has || n === 0;
  b.title = !has ? "Set a memory file (⚙) to enable" : (n === 0 ? "No findings to compact" : "Compact findings + reports into " + memFile() + (memConfigured() ? "" : " (default name — click ⚙ to customize)"));
}
document.getElementById("findCompact").onclick = compactToMemory;

// --- Memory file setter (⚙) — writes config.json server-side, no manual JSON ---
function openMemFile() {
  var inp = document.getElementById("memFileInput");
  inp.value = memFile() || "";
  document.getElementById("memFileMeta").textContent = memConfigured() ? "Currently set in config.json" : "Currently using a default name";
  document.getElementById("memFileModal").classList.add("on");
  setTimeout(function () { inp.focus(); inp.select(); }, 30);
}
function closeMemFile() { document.getElementById("memFileModal").classList.remove("on"); }
async function saveMemFile() {
  var name = document.getElementById("memFileInput").value.trim();
  var meta = document.getElementById("memFileMeta");
  if (!name) { meta.textContent = "Enter a filename"; return; }
  try {
    var res = await fetch("/api/memory-file", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ file: name }),
    });
    var j = await res.json();
    if (!j.ok) { meta.textContent = "⚠️ " + (j.error || "save failed"); return; }
    DATA.tenant = DATA.tenant || {};
    DATA.tenant.memoryFile = j.memoryFile;
    DATA.tenant.memoryFileConfigured = true;
    closeMemFile();
    syncMemUI();
    syncCompactBtn();
    toast("Memory file set to " + j.memoryFile);
  } catch (e) { meta.textContent = "⚠️ " + e.message; }
}
document.getElementById("memSet").onclick = openMemFile;
document.getElementById("memFileSave").onclick = saveMemFile;
document.getElementById("memFileCancel").onclick = closeMemFile;
document.getElementById("memFileClose").onclick = closeMemFile;
bindBackdropClose("memFileModal", closeMemFile);
document.getElementById("memFileInput").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); saveMemFile(); } });

document.getElementById("search").addEventListener("input", (e) => { searchTerm = e.target.value.toLowerCase(); renderGrid(); renderQueries(); });
document.getElementById("refresh").onclick = () => { toast("Reloading manifest…"); load(); };

// --- Collapsible left rail (search / domain filter) ---
var railToggle = document.getElementById("railToggle");
function applyRailState(collapsed) {
  var body = document.querySelector(".body");
  if (!body) return;
  if (collapsed) body.classList.add("rail-collapsed"); else body.classList.remove("rail-collapsed");
  railToggle.textContent = collapsed ? "\u27E9" : "\u27E8";
  railToggle.title = collapsed ? "Show search panel" : "Collapse search panel";
}
var railCollapsed = false;
try { railCollapsed = localStorage.getItem("mc.railCollapsed") === "1"; } catch (e) {}
applyRailState(railCollapsed);
railToggle.addEventListener("click", function () {
  railCollapsed = !railCollapsed;
  try { localStorage.setItem("mc.railCollapsed", railCollapsed ? "1" : "0"); } catch (e) {}
  applyRailState(railCollapsed);
});

// --- Resizable left rail (drag the divider) ---
var RAIL_MIN = 150, RAIL_MAX = 460;
var railW = 200;
try { var _rw = parseInt(localStorage.getItem("mc.railWidth"), 10); if (_rw >= RAIL_MIN && _rw <= RAIL_MAX) railW = _rw; } catch (e) {}
function setRailWidth(px) {
  railW = Math.max(RAIL_MIN, Math.min(RAIL_MAX, Math.round(px)));
  var body = document.querySelector(".body");
  if (body) body.style.setProperty("--rail-w", railW + "px");
}
setRailWidth(railW);
(function () {
  var handle = document.getElementById("railResize");
  if (!handle) return;
  var dragging = false;
  handle.addEventListener("mousedown", function (e) {
    if (railCollapsed) return;
    dragging = true; handle.classList.add("dragging");
    document.body.style.userSelect = "none"; document.body.style.cursor = "col-resize";
    e.preventDefault();
  });
  window.addEventListener("mousemove", function (e) {
    if (!dragging) return;
    var body = document.querySelector(".body");
    var left = body ? body.getBoundingClientRect().left : 0;
    setRailWidth(e.clientX - left);
  });
  window.addEventListener("mouseup", function () {
    if (!dragging) return;
    dragging = false; handle.classList.remove("dragging");
    document.body.style.userSelect = ""; document.body.style.cursor = "";
    try { localStorage.setItem("mc.railWidth", String(railW)); } catch (e) {}
  });
})();
document.getElementById("feature").addEventListener("click", (e) => {
  if (e.target.dataset.skill) run("threat-pulse", "", "", (document.getElementById("tpLookback") || {}).value || "", false, (document.getElementById("tpOutput") || {}).value || "");
});
document.getElementById("quickgo").onclick = () => {
  const v = document.getElementById("quick").value.trim();
  if (!v) { toast("Paste an entity first"); return; }
  const lb = (document.getElementById("quickLookback") || {}).value || "";
  const out = (document.getElementById("quickOutput") || {}).value || "";
  // Route the entity to a skill and open the editable preview (no auto-submit).
  run("", v, "", lb, false, out);
};
document.getElementById("quick").addEventListener("keydown", (e) => { if (e.key === "Enter") document.getElementById("quickgo").click(); });

// ---- Findings tab ----
let FINDINGS = { findings: [], summary: { total: 0, bySeverity: {} } };
let currentView = "skills";
let sevFilter = null; // null = show all; otherwise a severity string
const SEV_ORDER = ["critical", "high", "medium", "low", "info", "clean"];

function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

function switchView(view) {
  currentView = view;
  document.getElementById("skillsView").style.display = view === "skills" ? "" : "none";
  document.getElementById("findingsView").style.display = view === "findings" ? "" : "none";
  document.getElementById("queriesView").style.display = view === "queries" ? "" : "none";
  document.getElementById("tab-skills").classList.toggle("on", view === "skills");
  document.getElementById("tab-findings").classList.toggle("on", view === "findings");
  document.getElementById("tab-queries").classList.toggle("on", view === "queries");
  if (view === "findings") renderFindings();
  if (view === "queries") renderQueries();
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
  syncCompactBtn();
  if (currentView === "findings") renderFindings();
}

function renderRoll() {
  const host = document.getElementById("findRoll");
  const by = (FINDINGS.summary && FINDINGS.summary.counts) || {};
  const active = sevFilter;
  const total = SEV_ORDER.reduce((n, s) => n + (by[s] || 0), 0);
  // "All" clears the filter; each severity pill toggles filtering to that severity.
  // When a filter is active, non-matching pills dim so the active one stands out.
  const all = '<span class="sev-all' + (active ? "" : " active") + '" data-sev="" title="Show all findings">All ' + total + '</span>';
  const parts = SEV_ORDER.filter(s => by[s]).map(s => {
    const cls = active ? (active === s ? " active" : " dim") : "";
    return '<span class="sev-pill sev-' + s + cls + '" data-sev="' + s + '" title="Filter to ' + s + ' findings">' + by[s] + ' ' + s + '</span>';
  });
  host.innerHTML = all + parts.join("");
  host.querySelectorAll("[data-sev]").forEach(el => {
    el.onclick = () => {
      const sev = el.getAttribute("data-sev");
      // Toggle off if the already-active severity is clicked again.
      sevFilter = (!sev || sev === sevFilter) ? null : sev;
      renderFindings();
    };
  });
}

function renderFindings() {
  syncCompactBtn();
  renderRoll();
  const host = document.getElementById("findings");
  const all = FINDINGS.findings || [];
  const list = sevFilter ? all.filter(f => (f.severity || "info").toLowerCase() === sevFilter) : all;
  if (!all.length) {
    host.innerHTML =
      '<div class="empty-find"><div class="em">🛰️</div>' +
      '<p>No findings recorded yet.</p>' +
      '<p style="font-size:12px">Run a skill, then the agent pushes its result here via the ' +
      '<code>record_finding</code> action — with one-click follow-up hunts.</p></div>';
    return;
  }
  if (!list.length) {
    host.innerHTML =
      '<div class="empty-find"><div class="em">🔍</div>' +
      '<p>No <b>' + esc(sevFilter) + '</b> findings.</p>' +
      '<p style="font-size:12px">Click <b>All</b> above to clear the filter.</p></div>';
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
      '<button class="frun" title="Compose an editable prompt seeded with this finding">▶ Investigate</button>' +
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
      };
    });
    card.querySelectorAll(".rep").forEach(b => {
      b.onclick = () => openReport(b.dataset.path, b.dataset.label);
    });
    card.querySelector(".frun").onclick = () => runFinding(f);

    const row = document.createElement("div");
    row.className = "finding-row";
    const tcol = document.createElement("div");
    tcol.className = "ftime b-" + sev;
    if (f.ts) {
      const st = fmtStamp(f.ts);
      tcol.innerHTML = '<span class="ft-day">' + esc(st.day) + '</span><span class="ft-time">' + esc(st.time) + '</span>';
      tcol.title = new Date(f.ts).toLocaleString() + (f.ago ? " · " + f.ago : "");
    } else {
      tcol.innerHTML = '<span class="ft-day">—</span>';
    }
    row.appendChild(tcol);
    row.appendChild(card);
    host.appendChild(row);
  }
}

// Short absolute stamp for the findings timeline gutter (e.g. "Aug 28" / "3:52 PM").
function fmtStamp(ts) {
  const d = new Date(ts);
  return {
    day: d.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    time: d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" }),
  };
}

// Compose an editable, freeform prompt seeded with a finding's context, then open
// the tailor-before-send modal — mirrors the Queries "Run with context" flow so an
// analyst can pick a finding and drive an ad-hoc follow-up investigation.
function runFinding(f) {
  const lines = [];
  lines.push("- Title: " + (f.title || ""));
  if (f.severity) lines.push("- Severity: " + f.severity);
  if (f.skill) lines.push("- Source skill: " + f.skill);
  if (f.scope) lines.push("- Scope: " + f.scope);
  if (f.ts) lines.push("- Recorded: " + new Date(f.ts).toLocaleString());
  if (f.summary) lines.push("- Summary: " + f.summary);
  const ents = (f.entities || []).map(e => e.type + ": " + e.value);
  if (ents.length) lines.push("- Entities: " + ents.join(", "));
  const reps = (f.reports || []).filter(r => r && r.path)
    .map(r => "- " + r.path + (r.label ? " \u2014 " + r.label : ""));
  let starter =
    '[Describe how you want to investigate or act on this finding \u2014 e.g. "Confirm remediation held and check for lateral movement"]\\n\\n' +
    "Context \u2014 investigation finding recorded in Mission Control:\\n" +
    lines.join("\\n");
  if (reps.length) starter += "\\n\\nReference report file(s) \u2014 read them for full detail:\\n" + reps.join("\\n");
  const t = f.title || "Finding";
  const label = "\uD83C\uDFAF " + (t.length > 42 ? t.slice(0, 42) + "\u2026" : t);
  composeStarter(label, starter);
}

// POST a freeform starter to /api/compose (applies memory directive etc.) and open
// the editable compose modal. Shared by runFinding and the Queries "Run with context".
async function composeStarter(label, starter) {
  try {
    const res = await fetch("/api/compose", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ skill: "", entity: "", prompt: starter }),
    });
    const j = await res.json();
    if (j.ok) openCompose(label, "", j.prompt);
    else toast("\u26A0\uFE0F " + (j.error || "could not compose prompt"));
  } catch (e) { toast("\u26A0\uFE0F " + e.message); }
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
document.getElementById("tab-queries").onclick = () => switchView("queries");

// ---- Queries tab ----
// Reuses the shared domain filter + search box, and the report modal for viewing.
function visibleQueries() {
  return (DATA.queries || []).filter(q => {
    if (favOnly && !favQueries.has(q.path)) return false;
    if (activeDomains.size && !q.domains.some(d => activeDomains.has(d))) return false;
    if (searchTerm) {
      const hay = (q.title + " " + (q.description || "") + " " + (q.domains || []).join(" ") +
        " " + (q.mitre || []).join(" ") + " " + (q.tables || []).join(" ")).toLowerCase();
      if (!hay.includes(searchTerm)) return false;
    }
    return true;
  });
}

// ---- Queries tab: multi-select + "run with query files as context" ----
// The canvas SDK has no file-attachment channel (sessionRef.send takes only a
// prompt string), so selected query files are handed off by embedding their
// repo-relative paths in the composed prompt and instructing the agent to read
// them. This mirrors how skills reference their own SKILL.md by path.
let querySel = new Map(); // path -> title
function toggleQuerySel(path, title) {
  if (querySel.has(path)) querySel.delete(path); else querySel.set(path, title);
  renderQueries();
}
function clearQuerySel() { querySel.clear(); renderQueries(); }
function updateQueryBar() {
  const bar = document.getElementById("qbar");
  if (!bar) return;
  if (!querySel.size) { bar.style.display = "none"; bar.innerHTML = ""; return; }
  bar.style.display = "";
  bar.innerHTML =
    '<span class="qbar-n">' + querySel.size + ' selected</span>' +
    '<span class="qbar-paths" title="' + esc([...querySel.keys()].join(", ")) + '">' +
      [...querySel.values()].map(esc).join(" · ") + '</span>' +
    '<button class="btn ghost" id="qbarClear">Clear</button>' +
    '<button class="btn" id="qbarRun">▶ Run with context</button>';
  bar.querySelector("#qbarClear").onclick = clearQuerySel;
  bar.querySelector("#qbarRun").onclick = runQueries;
}
async function runQueries() {
  if (!querySel.size) return;
  const list = [...querySel.entries()]
    .map(([p, t]) => "- " + p + (t ? " — " + t : "")).join("\\n");
  const starter =
    '[Describe what you want to hunt for or ask — e.g. "Hunt for OpenClaw shadow-AI usage in the last 30 days"]\\n\\n' +
    "Reference the following query file(s) for additional context — read them and adapt or run the relevant KQL as needed:\\n" +
    list;
  const label = "🔎 " + querySel.size + " quer" + (querySel.size === 1 ? "y" : "ies");
  try {
    const res = await fetch("/api/compose", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ skill: "", entity: "", prompt: starter }),
    });
    const j = await res.json();
    if (j.ok) openCompose(label, "", j.prompt);
    else toast("⚠️ " + (j.error || "could not compose prompt"));
  } catch (e) { toast("⚠️ " + e.message); }
}

function renderQueryCards() {
  const grid = document.getElementById("queryGrid");
  if (!grid) return;
  const qs = visibleQueries();
  if (!qs.length) {
    grid.innerHTML = '<div class="empty-find" style="grid-column:1/-1"><div class="em">🔎</div>' +
      '<p>No queries match this filter.</p>' +
      '<p style="font-size:12px">Clear the domain filter or search to see all ' +
      ((DATA.queries || []).length) + ' queries.</p></div>';
    updateQueryBar();
    return;
  }
  grid.innerHTML = "";
  for (const q of qs) {
    const card = document.createElement("div");
    card.className = "card";
    const icon = ICONS[(q.domains || [])[0]] || "🔎";
    const chips = (q.domains || []).map(d => '<span class="chip">' + (ICONS[d] || "") + ' ' + d + '</span>').join("");
    const meta = [];
    if ((q.mitre || []).length) meta.push('<span class="chip alt" title="' + esc((q.mitre || []).join(", ")) + '">🎯 ' + q.mitre.length + ' MITRE</span>');
    if ((q.tables || []).length) meta.push('<span class="chip alt" title="' + esc((q.tables || []).join(", ")) + '">🗂 ' + q.tables.length + ' tables</span>');
    const desc = q.description ? esc(q.description) : '<span style="opacity:.6">No summary available.</span>';
    const sel = querySel.has(q.path);
    card.innerHTML =
      '<div class="top"><span class="ic">' + icon + '</span><span class="nm">' + esc(q.title) + '</span>' +
      '<button class="fav-btn' + (favQueries.has(q.path) ? " on" : "") + '" title="Toggle favorite">⭐</button></div>' +
      '<div class="desc">' + desc + '</div>' +
      '<div class="chips">' + chips + meta.join("") + '</div>' +
      '<div class="row"><button class="btn open">📄 Open</button>' +
      '<button class="btn ghost qsel' + (sel ? " on" : "") + '">' + (sel ? "✓ Added" : "＋ Select") + '</button>' +
      '<span class="qpath" title="' + esc(q.path) + '">' + esc(q.path) + '</span></div>';
    card.querySelector(".open").onclick = () => openReport(q.path, q.title);
    card.querySelector(".qsel").onclick = () => toggleQuerySel(q.path, q.title);
    card.querySelector(".fav-btn").onclick = (e) => { e.stopPropagation(); toggleFavQuery(q.path); };
    grid.appendChild(card);
  }
  updateQueryBar();
}

// ---- Queries tab: MITRE ATT&CK coverage map ----
// Tactics (from the vendored ATT&CK reference in DATA.mitre) become columns;
// technique tiles are lit by how many *currently visible* query files cover them
// (sub-techniques roll up to their base technique). Clicking a covered tile opens
// an inline detail panel listing the matching query files with Open/Select, reusing
// the same actions as the card view so the "Run with context" bar keeps working.
let mitreShowAll = false;
try { mitreShowAll = localStorage.getItem("mc.mitreShowAll") === "1"; } catch (e) {}
let mitreSel = null; // selected base technique id

function mitreCoverage() {
  const map = new Map(); // baseId -> [query,...]
  const re = /^T\\d{4}(\\.\\d{3})?$/;
  for (const q of visibleQueries()) {
    const seen = new Set();
    for (const m of (q.mitre || [])) {
      if (!re.test(m)) continue; // skip TAxxxx tactic ids
      const base = m.split(".")[0];
      if (seen.has(base)) continue;
      seen.add(base);
      if (!map.has(base)) map.set(base, []);
      map.get(base).push(q);
    }
  }
  return map;
}

function mtile(id, name, count) {
  const cls = count >= 3 ? "cov3" : count === 2 ? "cov2" : count === 1 ? "cov1" : "dim";
  const sel = mitreSel === id ? " sel" : "";
  const badge = count ? '<span class="cnt">' + count + '</span>' : "";
  return '<div class="mtile ' + cls + sel + '" data-id="' + esc(id) + '" title="' + esc(id + " \\u00b7 " + name) + '">' +
    '<span><span class="tid">' + esc(id) + '</span> ' + esc(name) + '</span>' + badge + '</div>';
}

function renderQueryMitre() {
  const host = document.getElementById("queriesMitre");
  if (!host) return;
  const ref = DATA.mitre;
  if (!ref || !(ref.tactics || []).length) {
    host.innerHTML = '<div class="mitre-empty">MITRE ATT&CK reference unavailable in this build.</div>';
    updateQueryBar();
    return;
  }
  const cov = mitreCoverage();
  const nq = visibleQueries().length;
  const known = new Set();
  host.innerHTML = "";

  const bar = document.createElement("div");
  bar.className = "mitre-bar";
  bar.innerHTML =
    '<span class="mlbl">' + cov.size + ' techniques covered by ' + nq + ' quer' + (nq === 1 ? "y" : "ies") + '</span>' +
    '<label class="mchk"><input type="checkbox" id="mitreAll"' + (mitreShowAll ? " checked" : "") + '> Show all techniques</label>' +
    '<span class="mlbl" style="margin-left:auto">ATT&CK v' + esc(ref.version || "") + '</span>';
  host.appendChild(bar);

  const detail = document.createElement("div");
  detail.id = "mitreDetail";
  host.appendChild(detail);

  const wrap = document.createElement("div");
  wrap.className = "mitre-wrap";
  for (const t of ref.tactics) {
    const col = document.createElement("div");
    col.className = "mitre-col";
    let colCovered = 0;
    const tiles = [];
    for (const tech of (t.techniques || [])) {
      known.add(tech.id);
      const n = (cov.get(tech.id) || []).length;
      if (n) colCovered++;
      if (!n && !mitreShowAll) continue;
      tiles.push(mtile(tech.id, tech.name, n));
    }
    col.innerHTML = '<h4>' + esc(t.name) + '<span class="tc">' + colCovered + ' covered</span></h4>' + tiles.join("");
    wrap.appendChild(col);
  }
  const unmapped = [...cov.keys()].filter(id => !known.has(id)).sort();
  if (unmapped.length) {
    const col = document.createElement("div");
    col.className = "mitre-col";
    const tiles = unmapped.map(id => mtile(id, "(unmapped technique)", (cov.get(id) || []).length));
    col.innerHTML = '<h4>Other / Unmapped<span class="tc">' + unmapped.length + ' covered</span></h4>' + tiles.join("");
    wrap.appendChild(col);
  }
  host.appendChild(wrap);

  bar.querySelector("#mitreAll").onchange = (e) => {
    mitreShowAll = e.target.checked;
    try { localStorage.setItem("mc.mitreShowAll", mitreShowAll ? "1" : "0"); } catch (e2) {}
    renderQueryMitre();
  };
  wrap.querySelectorAll(".mtile").forEach(el => {
    if (el.classList.contains("dim")) return;
    el.onclick = () => showMitreTechnique(el.dataset.id);
  });
  if (mitreSel) renderMitreDetail(mitreSel);
  updateQueryBar();
}

function showMitreTechnique(id) {
  mitreSel = id;
  document.querySelectorAll("#queriesMitre .mtile").forEach(el => el.classList.toggle("sel", el.dataset.id === id));
  renderMitreDetail(id);
}

function renderMitreDetail(id) {
  const box = document.getElementById("mitreDetail");
  if (!box) return;
  const qs = mitreCoverage().get(id) || [];
  let name = "";
  const tacs = [];
  for (const t of ((DATA.mitre || {}).tactics || [])) {
    for (const tech of (t.techniques || [])) {
      if (tech.id === id) { name = tech.name; if (tacs.indexOf(t.name) < 0) tacs.push(t.name); }
    }
  }
  const head =
    '<div class="mdh"><span class="mid">' + esc(id) + '</span>' +
    '<span class="mnm">' + esc(name || "(unmapped technique)") + '</span>' +
    (tacs.length ? '<span class="mtac">' + esc(tacs.join(" \\u00b7 ")) + '</span>' : "") +
    '<button class="mx" id="mitreClose" title="Close">\\u2715</button></div>';
  box.className = "mitre-detail";
  if (!qs.length) {
    box.innerHTML = head + '<div class="mdrow" style="border:none"><span class="mdt">No query files cover this technique.</span></div>';
    box.querySelector("#mitreClose").onclick = clearMitreSel;
    return;
  }
  box.innerHTML = head + qs.map((q, i) =>
    '<div class="mdrow"><span class="mdt">' + esc(q.title) + '<div class="mdp">' + esc(q.path) + '</div></span>' +
    '<button class="btn open" data-i="' + i + '">📄 Open</button>' +
    '<button class="btn ghost qsel' + (querySel.has(q.path) ? " on" : "") + '" data-i="' + i + '">' +
      (querySel.has(q.path) ? "✓ Added" : "＋ Select") + '</button></div>'
  ).join("");
  box.querySelector("#mitreClose").onclick = clearMitreSel;
  box.querySelectorAll(".open").forEach(b => { const q = qs[+b.dataset.i]; b.onclick = () => openReport(q.path, q.title); });
  box.querySelectorAll(".qsel").forEach(b => { const q = qs[+b.dataset.i]; b.onclick = () => toggleQuerySel(q.path, q.title); });
}

function clearMitreSel() {
  mitreSel = null;
  const box = document.getElementById("mitreDetail");
  if (box) { box.innerHTML = ""; box.className = ""; }
  document.querySelectorAll("#queriesMitre .mtile").forEach(el => el.classList.remove("sel"));
}

// ---- List/grid view: sortable + resizable tables ----
// Both tabs can switch between the existing card grid and a dense table with
// per-column sorting + drag-to-resize columns. Tables are built with DOM APIs
// (not innerHTML template strings) to avoid the outer-template-literal newline
// trap and to keep event wiring simple. View mode, sort, and column widths
// persist in localStorage so the analyst's layout survives reloads.
let skillsMode = "cards";
let queriesMode = "cards";
try { skillsMode = localStorage.getItem("mc.view.skills") || "cards"; } catch (e) {}
try { queriesMode = localStorage.getItem("mc.view.queries") || "cards"; } catch (e) {}
let skillSort = { key: "name", dir: 1 };
let querySort = { key: "title", dir: 1 };

function loadColW(k) { try { return JSON.parse(localStorage.getItem("mc.colw." + k) || "{}"); } catch (e) { return {}; } }
function saveColW(k, m) { try { localStorage.setItem("mc.colw." + k, JSON.stringify(m)); } catch (e) {} }

function chipCell(domains) {
  const inner = (domains || []).map(d => '<span class="chip">' + (ICONS[d] || "") + " " + esc(d) + "</span>").join("");
  return '<div class="cellchips">' + inner + "</div>";
}

function startColResize(e, colgroup, ci, storeKey, colKey) {
  e.preventDefault(); e.stopPropagation();
  const col = colgroup.children[ci];
  const startX = e.clientX;
  const startW = col.getBoundingClientRect().width;
  function move(ev) { col.style.width = Math.max(56, startW + (ev.clientX - startX)) + "px"; }
  function up() {
    document.removeEventListener("mousemove", move);
    document.removeEventListener("mouseup", up);
    const m = loadColW(storeKey); m[colKey] = Math.round(col.getBoundingClientRect().width); saveColW(storeKey, m);
  }
  document.addEventListener("mousemove", move);
  document.addEventListener("mouseup", up);
}

function buildTable(host, cfg) {
  host.innerHTML = "";
  const saved = loadColW(cfg.storeKey);
  const table = document.createElement("table");
  table.className = "lst";
  const colgroup = document.createElement("colgroup");
  cfg.cols.forEach(c => {
    const col = document.createElement("col");
    const w = saved[c.key] != null ? saved[c.key] : c.w;
    if (w != null) col.style.width = (typeof w === "number" ? w + "px" : w);
    colgroup.appendChild(col);
  });
  table.appendChild(colgroup);

  const thead = document.createElement("thead");
  const htr = document.createElement("tr");
  cfg.cols.forEach((c, ci) => {
    const th = document.createElement("th");
    if (c.align) th.style.textAlign = c.align;
    const lbl = document.createElement("span"); lbl.textContent = c.label; th.appendChild(lbl);
    if (c.sortable) {
      th.className = "sortable" + (cfg.sort.key === c.key ? " sorted" : "");
      const ind = document.createElement("span"); ind.className = "sort-ind";
      ind.textContent = cfg.sort.key === c.key ? (cfg.sort.dir > 0 ? "▲" : "▼") : "↕";
      th.appendChild(ind);
      th.addEventListener("click", (e) => {
        if (e.target.classList.contains("rsz")) return;
        if (cfg.sort.key === c.key) cfg.sort.dir = -cfg.sort.dir; else { cfg.sort.key = c.key; cfg.sort.dir = 1; }
        cfg.onsort();
      });
    }
    if (ci < cfg.cols.length - 1) {
      const rsz = document.createElement("span"); rsz.className = "rsz";
      rsz.addEventListener("mousedown", (e) => startColResize(e, colgroup, ci, cfg.storeKey, c.key));
      th.appendChild(rsz);
    }
    htr.appendChild(th);
  });
  thead.appendChild(htr); table.appendChild(thead);

  const tbody = document.createElement("tbody");
  const rows = (cfg.rows || []).slice();
  const sc = cfg.cols.find(c => c.key === cfg.sort.key);
  if (sc && sc.sortVal) {
    rows.sort((a, b) => {
      const va = sc.sortVal(a), vb = sc.sortVal(b);
      if (typeof va === "number" && typeof vb === "number") return (va - vb) * cfg.sort.dir;
      return String(va).localeCompare(String(vb), undefined, { numeric: true }) * cfg.sort.dir;
    });
  }
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td"); td.colSpan = cfg.cols.length;
    td.style.color = "var(--muted)"; td.style.padding = "18px"; td.textContent = cfg.empty || "Nothing to show.";
    tr.appendChild(td); tbody.appendChild(tr);
  }
  rows.forEach(r => {
    const tr = document.createElement("tr");
    cfg.cols.forEach(c => {
      const td = document.createElement("td");
      if (c.align) td.style.textAlign = c.align;
      if (c.cls) td.className = c.cls;
      if (c.title) td.title = c.title(r);
      if (c.build) c.build(td, r);
      else td.innerHTML = c.html ? c.html(r) : "";
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  host.appendChild(table);
}

function actionBtn(label, cls, on) {
  const b = document.createElement("button");
  b.className = "btn " + (cls || "");
  b.textContent = label;
  b.addEventListener("click", on);
  return b;
}

function renderSkillsTable() {
  const host = document.getElementById("skillsTable");
  if (!host) return;
  const rows = visibleSkills().filter(s => s.name !== "threat-pulse");
  buildTable(host, {
    storeKey: "skills", sort: skillSort, onsort: renderGrid, rows,
    empty: "No skills match the current filter.",
    cols: [
      { key: "icon", label: "", w: 34, cls: "ic-cell", html: s => '<span style="font-size:16px">' + skillIcon(s) + "</span>" },
      { key: "fav", label: "", w: 36, align: "center", cls: "ic-cell", sortable: true, sortVal: s => favSkills.has(s.name) ? 0 : 1, build: (td, s) => {
          const b = document.createElement("button");
          b.className = "fav-btn lst" + (favSkills.has(s.name) ? " on" : "");
          b.textContent = "⭐"; b.title = "Toggle favorite";
          b.onclick = () => toggleFavSkill(s.name);
          td.appendChild(b);
        } },
      { key: "name", label: "Skill", w: 210, sortable: true, cls: "nm", sortVal: s => (s.name || "").toLowerCase(), html: s => esc(s.name) },
      { key: "desc", label: "Description", w: 460, sortable: true, sortVal: s => skillDesc(s).replace(/<[^>]*>/g, "").toLowerCase(), html: s => '<span style="color:var(--muted)">' + esc(skillDesc(s).replace(/<[^>]*>/g, "")) + "</span>", title: s => skillDesc(s).replace(/<[^>]*>/g, "") },
      { key: "domains", label: "Domains", w: 170, sortable: true, sortVal: s => (s.domains || []).join(","), html: s => chipCell(s.domains), title: s => (s.domains || []).join(", ") },
      { key: "actions", label: "", w: 250, build: (td, s) => {
          const wrap = document.createElement("div"); wrap.className = "lst-actions";
          const lb = document.createElement("select"); lb.className = "lst-sel"; lb.title = "Lookback window"; lb.innerHTML = lookbackOptionsHTML();
          const out = document.createElement("select"); out.className = "lst-sel"; out.title = "Output format"; out.innerHTML = outputOptionsHTML();
          wrap.appendChild(lb); wrap.appendChild(out);
          if (s.path) wrap.appendChild(actionBtn("📄", "ghost", () => openReport(s.path, s.name)));
          wrap.appendChild(actionBtn("▶ Run", "", () => run(s.name, "", "", lb.value, false, out.value)));
          td.appendChild(wrap);
        } },
    ],
  });
}

function renderQueriesTable() {
  const host = document.getElementById("queriesTable");
  if (!host) return;
  const rows = visibleQueries();
  buildTable(host, {
    storeKey: "queries", sort: querySort, onsort: renderQueries, rows,
    empty: "No queries match this filter.",
    cols: [
      { key: "icon", label: "", w: 34, cls: "ic-cell", html: q => '<span style="font-size:15px">' + (ICONS[(q.domains || [])[0]] || "🔎") + "</span>" },
      { key: "fav", label: "", w: 36, align: "center", cls: "ic-cell", sortable: true, sortVal: q => favQueries.has(q.path) ? 0 : 1, build: (td, q) => {
          const b = document.createElement("button");
          b.className = "fav-btn lst" + (favQueries.has(q.path) ? " on" : "");
          b.textContent = "⭐"; b.title = "Toggle favorite";
          b.onclick = () => toggleFavQuery(q.path);
          td.appendChild(b);
        } },
      { key: "title", label: "Query", w: 250, sortable: true, cls: "nm", sortVal: q => (q.title || "").toLowerCase(), html: q => esc(q.title) },
      { key: "domains", label: "Domains", w: 150, sortable: true, sortVal: q => (q.domains || []).join(","), html: q => chipCell(q.domains), title: q => (q.domains || []).join(", ") },
      { key: "mitre", label: "MITRE", w: 82, align: "center", sortable: true, sortVal: q => (q.mitre || []).length, html: q => (q.mitre || []).length ? '<span class="chip alt">' + (q.mitre || []).length + "</span>" : '<span style="opacity:.4">—</span>', title: q => (q.mitre || []).join(", ") },
      { key: "tables", label: "Tables", w: 82, align: "center", sortable: true, sortVal: q => (q.tables || []).length, html: q => (q.tables || []).length ? '<span class="chip alt">' + (q.tables || []).length + "</span>" : '<span style="opacity:.4">—</span>', title: q => (q.tables || []).join(", ") },
      { key: "path", label: "Path", w: 260, sortable: true, cls: "mono", sortVal: q => (q.path || "").toLowerCase(), html: q => esc(q.path), title: q => q.path },
      { key: "actions", label: "", w: 160, build: (td, q) => {
          const wrap = document.createElement("div"); wrap.className = "lst-actions";
          wrap.appendChild(actionBtn("📄 Open", "", () => openReport(q.path, q.title)));
          const sel = querySel.has(q.path);
          wrap.appendChild(actionBtn(sel ? "✓ Added" : "＋ Select", "ghost qsel" + (sel ? " on" : ""), () => toggleQuerySel(q.path, q.title)));
          td.appendChild(wrap);
        } },
    ],
  });
  updateQueryBar();
}

// Dispatchers keep the original names used across load()/search/domain filters,
// so switching between card and list view is transparent to every caller.
function renderGrid() {
  const cards = document.getElementById("grid");
  const tbl = document.getElementById("skillsTable");
  const list = skillsMode === "list";
  if (cards) cards.style.display = list ? "none" : "";
  if (tbl) tbl.style.display = list ? "" : "none";
  syncViewToggle("skills");
  if (list) renderSkillsTable(); else renderSkillCards();
}
function renderQueries() {
  const cards = document.getElementById("queryGrid");
  const tbl = document.getElementById("queriesTable");
  const mitre = document.getElementById("queriesMitre");
  const mode = queriesMode === "list" || queriesMode === "mitre" ? queriesMode : "cards";
  if (cards) cards.style.display = mode === "cards" ? "" : "none";
  if (tbl) tbl.style.display = mode === "list" ? "" : "none";
  if (mitre) mitre.style.display = mode === "mitre" ? "" : "none";
  syncViewToggle("queries");
  if (mode === "list") renderQueriesTable();
  else if (mode === "mitre") renderQueryMitre();
  else renderQueryCards();
}
function syncViewToggle(which) {
  const id = which === "skills" ? "skillsViewToggle" : "queriesViewToggle";
  const mode = which === "skills" ? skillsMode : queriesMode;
  document.querySelectorAll("#" + id + " button").forEach(b => b.classList.toggle("on", b.dataset.mode === mode));
}
function setSkillsMode(m) { skillsMode = m; try { localStorage.setItem("mc.view.skills", m); } catch (e) {} renderGrid(); }
function setQueriesMode(m) { queriesMode = m; try { localStorage.setItem("mc.view.queries", m); } catch (e) {} renderQueries(); }
document.querySelectorAll("#skillsViewToggle button").forEach(b => b.addEventListener("click", () => setSkillsMode(b.dataset.mode)));
document.querySelectorAll("#queriesViewToggle button").forEach(b => b.addEventListener("click", () => setQueriesMode(b.dataset.mode)));

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
bindBackdropClose("reportModal", closeReport);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeReport(); closeCompose(); closeConfirm(); closeMemFile(); } });
async function doClearFindings() {
  try {
    const res = await fetch("/api/findings/clear", { method: "POST" });
    FINDINGS = await res.json();
    sevFilter = null;
    document.getElementById("findCount").textContent = 0;
    document.getElementById("findCount").classList.add("zero");
    syncCompactBtn();
    renderFindings();
    toast("Findings cleared");
  } catch (e) { toast("⚠️ " + e.message); }
}
document.getElementById("findClear").onclick = () => {
  const n = (FINDINGS.findings || []).length;
  if (!n) { toast("Nothing to clear"); return; }
  const hasMem = !!memFile();
  openConfirm({
    title: "Clear all findings?",
    message: "This permanently removes all " + n + " recorded finding(s) and can't be undone." + (hasMem ? " Consider compacting them into memory first." : ""),
    okLabel: "Clear anyway",
    okClass: "danger",
    onOk: doClearFindings,
    altLabel: hasMem ? "🧠 Compact to memory first" : "",
    onAlt: hasMem ? compactToMemory : null,
  });
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
