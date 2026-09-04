// Extension: skills-canvas — "Mission Control"
// A canvas that renders the project's investigation skills as a launchable
// dashboard. Clicking a skill composes its canned prompt (from the discovery
// manifest) and injects it into the current chat session via session.send(),
// so every existing global rule / skill workflow applies unchanged. The canvas
// is a launcher + visual layer, not a new execution path.

import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { readFile, writeFile, readdir } from "node:fs/promises";
import path from "node:path";
import { homedir } from "node:os";
import { joinSession, createCanvas } from "@github/copilot-sdk/extension";
import { renderPage } from "./ui.mjs";
import { loadCanvasData, composePrompt, lookbackPhrase, outputPhrase } from "./manifest.mjs";
import { loadPrefs, savePrefs, memoryPromptTemplate, memoryEnabled, recordPromptTemplate, DEFAULT_MEMORY_PROMPT, DEFAULT_RECORD_PROMPT, autopilotLimits, AUTOPILOT_DEFAULTS, AUTOPILOT_CEILINGS, AUTOPILOT_KEYS } from "./prefs.mjs";
import { renderMarkdown, htmlReportPage } from "./md.mjs";
import {
    loadFindings,
    addFinding,
    dismissFinding,
    clearFindings,
    pruneFindings,
    archiveFindings,
    archiveOneFinding,
    listArchives,
    readArchive,
    loadAllFindingsAggregated,
    getFinding,
    setVerdict,
    chainFor,
    summarize,
} from "./findings.mjs";
import {
    loadCosting,
    addCosting,
    seedCostingFromFindings,
    summarizeCosting,
} from "./costing.mjs";
import {
    initActivity,
    activitySessionId,
    activeRun,
    hasActiveRun,
    beginRun,
    enqueueRun,
    takeNextQueued,
    dropQueued,
    dropAutopilotQueued,
    flushActivity,
    syncHeartbeat,
    updateRun,
    bumpTool,
    bumpSubagent,
    markRecorded,
    endRun,
    clearSession,
    setSessionTitle,
    readActivity,
} from "./activity.mjs";
import {
    initAutopilot,
    applyAutopilotLimits,
    autopilotSnapshot,
    enableAutopilot,
    stopAutopilot,
    resumeAutopilot,
    autopilotOnFinding,
    autopilotOnRunClosed,
    autopilotAllowsPromotion,
    autopilotBoardPreview,
} from "./autopilot.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// .github/extensions/skills-canvas -> repo root is three levels up.
const REPO_ROOT = path.resolve(HERE, "..", "..", "..");

// Set after joinSession resolves; HTTP handlers read it at request time.
let sessionRef = null;
// Cache of parsed manifest data, refreshed on /api/data.
let cache = null;
// In-memory "recently launched" ring (most-recent first).
const recent = [];
const servers = new Map();

// Auto-open the Mission Control canvas at the start of each session. An
// extension can't push a canvas open itself, so on the first user prompt of a
// session we silently inject guidance telling the agent to call open_canvas
// (only when the canvas isn't already open). Disable with MC_AUTO_OPEN=0.
const AUTO_OPEN = !/^(0|false|off|no)$/i.test(String(process.env.MC_AUTO_OPEN ?? ""));
const autoOpened = new Set();

// Running total of AI usage (nano-AI units) reported via `assistant.usage`
// session events. We snapshot the delta at each record_finding call so every
// finding is attributed the credits consumed since the previous one.
let cumulativeNaiu = 0;
let lastFindingNaiu = 0;
// Per-model cumulative nano-AIU so each finding can be attributed the model that
// consumed the most credits since the previous finding (best-effort; sub-agents
// may mix models within a run).
const cumulativeByModel = new Map();
const lastByModel = new Map();

// Per-run cost baseline: cumulativeNaiu at the moment a run opened, so the live
// strip can show credits consumed by THIS investigation rather than the session
// total. Report paths written during a run are harvested from tool arguments so
// `record_finding` can auto-fill `reports` without the agent being told to.
let runBaselineNaiu = 0;
// Credits attributable to autopilot. The budget governor must measure what
// AUTOPILOT spent, not what the session spent: the documented flow is to arm
// first and then launch a seed hunt by hand, so a session-wide delta silently
// charges the analyst's own run to autopilot's allowance. Closed autopilot runs
// accumulate here; the in-flight one is added live from its own baseline.
let autopilotNaiu = 0;
let activeRunIsAutopilot = false;

/** Credits autopilot itself is responsible for, including the run in flight. */
function autopilotSpentNaiu() {
    const live = activeRunIsAutopilot ? Math.max(0, cumulativeNaiu - runBaselineNaiu) : 0;
    return autopilotNaiu + live;
}
let runReportPaths = [];

// Pull a model identifier out of an assistant.usage event, tolerating a few
// shapes across runtime versions. Returns "unknown" when none is present.
function usageModel(event) {
  const d = event?.data || {};
  const u = d.copilotUsage || {};
  const raw = d.model || d.modelId || d.modelSlug || u.model || u.modelId || u.modelSlug || u.modelFamily || "";
  return String(raw || "unknown").slice(0, 60);
}

function relAgo(ts) {
    const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 60) return s + "s ago";
    const m = Math.round(s / 60);
    if (m < 60) return m + "m ago";
    const h = Math.round(m / 60);
    return h + "h ago";
}

function recentPayload() {
    return recent.slice(0, 8).map((r) => ({ name: r.name, entity: r.entity, ago: relAgo(r.at) }));
}

function recordRun(name, entity) {
    recent.unshift({ name, entity: entity || "", at: Date.now() });
    if (recent.length > 20) recent.length = 20;
}

/** Heuristic entity -> skill routing for the footer quick-launch box. */
function routeEntity(entity) {
    const e = entity.trim();
    if (/^#?\d{1,7}$/.test(e)) return "incident-investigation";
    if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(e)) return "ioc-investigation";
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(e) || /:[0-9a-f]{0,4}:/i.test(e)) return "ioc-investigation";
    if (e.includes("@")) return "user-investigation";
    if (/^https?:\/\//i.test(e)) return "ioc-investigation";
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(e)) return "ioc-investigation"; // bare domain
    return "computer-investigation"; // fall back to device/hostname
}

// Placeholder skill for a free-form question, where the routing decision belongs
// to the model rather than a regex. Upgraded in place by the `skill.invoked`
// handler the moment the agent actually loads a SKILL.md, so the strip and the
// cost ledger end up attributed to the real skill.
const ADHOC_SKILL = "ad-hoc";

// Does this look like a question/instruction rather than an entity to route?
// routeEntity() is deliberately total — every input falls through to
// computer-investigation — so without this check a typed question would be
// launched as a device investigation against the question text itself.
function looksFreeForm(text) {
    const t = String(text || "").trim();
    if (!t) return false;
    // Anything shaped like an entity is routed by regex, never treated as prose.
    if (!/\s/.test(t)) return false;             // single token => entity
    if (/^https?:\/\//i.test(t)) return false;   // URLs may contain spaces when pasted
    return /\?$/.test(t) || t.split(/\s+/).length >= 3;
}

// A free-form ask: the analyst's words come first and verbatim, then a short
// directive telling the agent to route it itself. Skill selection is exactly the
// job the CLI's own instructions already describe, so this stays deliberately
// thin — it only pins down the two things the canvas cares about (pick from the
// project catalog, and still record a finding). Lookback/output are attached to
// the question here rather than left to composeFor, which would otherwise staple
// them onto the end of the routing directive where they read as nonsense.
function composeAdHoc(question, lookback, output) {
    let q = question.trim();
    const phrase = lookbackPhrase(lookback);
    if (phrase) q += ` — use a lookback window of ${phrase}`;
    const outPhrase = outputPhrase(output);
    if (outPhrase) q += ` — ${outPhrase}`;
    return [
        q,
        "",
        "---",
        "Route this yourself: if one of this project's skills in `.github/skills/` fits, load its SKILL.md and follow it. Otherwise answer directly using the repo's query library and the KQL pre-flight rules.",
    ].join("\n");
}

async function readBody(req) {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    if (!chunks.length) return {};
    try {
        return JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
        return {};
    }
}

function json(res, code, obj) {
    res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(obj));
}

// Persist a tenant memory filename into config.json (and the matched
// config.json.<tenant> variant, so it survives the copy-based tenant switch).
// Enables first-run setup from the canvas without hand-editing JSON. config.json
// is gitignored + local, so this is not a tenant/resource state change.
async function setMemoryFile(rawFile) {
    let name = String(rawFile || "").trim();
    if (!name) return { ok: false, error: "Filename is empty" };
    name = name.split(/[\\/]/).pop(); // basename only — no path traversal
    if (!/^[A-Za-z0-9._-]+$/.test(name)) {
        return { ok: false, error: "Use letters, numbers, dot, dash, underscore only" };
    }
    if (!/\.md$/i.test(name)) name += ".md";

    const cfgPath = path.join(REPO_ROOT, "config.json");
    let cfg;
    try {
        cfg = JSON.parse(await readFile(cfgPath, "utf8"));
    } catch {
        return { ok: false, error: "config.json not found — copy config.json.template to config.json first" };
    }
    cfg.memory_file = name;
    await writeFile(cfgPath, JSON.stringify(cfg, null, 2) + "\n", "utf8");

    const written = ["config.json"];
    try {
        const tenantId = cfg.tenant_id || null;
        if (tenantId && !/^YOUR_/.test(tenantId)) {
            for (const f of await readdir(REPO_ROOT)) {
                const m = /^config\.json\.([A-Za-z0-9_-]+)$/.exec(f);
                if (!m || m[1] === "template") continue;
                const vp = path.join(REPO_ROOT, f);
                try {
                    const variant = JSON.parse(await readFile(vp, "utf8"));
                    if (variant.tenant_id === tenantId) {
                        variant.memory_file = name;
                        await writeFile(vp, JSON.stringify(variant, null, 2) + "\n", "utf8");
                        written.push(f);
                    }
                } catch {
                    /* ignore unreadable variant */
                }
            }
        }
    } catch {
        /* ignore */
    }
    cache = null; // force /api/data to re-read config on next load
    return { ok: true, memoryFile: name, written };
}

// Closing directive appended to every Mission Control launch so the agent posts
// its results back to the Findings tab when done. This lives in the launched
// prompt (NOT in copilot-instructions.md) so the behavior is scoped strictly to
// canvas-initiated runs — a hand-typed chat investigation is unaffected.
//
// The wording is editable from Settings → Record findings; the default lives in
// prefs.mjs. An empty override disables the directive entirely.

// Append the record-finding directive exactly once. Idempotent: the compose
// modal path runs composeFor twice (preview via /api/compose, then send via
// /api/run with the edited text as an override), so we skip when the directive
// is already present to avoid a duplicated tail. The `record_finding` token is
// checked as well, so a directive the analyst edited inside the compose box
// still counts as present.
function withRecordDirective(prompt, prefs) {
    if (!prompt) return prompt;
    const text = recordPromptTemplate(prefs).trim();
    if (!text) return prompt; // deliberately disabled
    if (prompt.includes(text) || prompt.includes("record_finding")) return prompt;
    return `${prompt}\n\n---\n${text}`;
}

/**
 * Prepend the tenant memory preamble exactly once.
 *
 * The client prepends this in the compose bar so the analyst can see and edit
 * it, which is why this must be idempotent — a composed prompt arriving back
 * through /api/run already carries it. But autopilot never touches the compose
 * bar, so without applying it here an autonomous chain would investigate with
 * no tenant ground truth at all: exactly the runs where a documented
 * false-positive rule matters most, because nobody is reading the output live.
 *
 * Honours the same `mc.useMemory` checkbox rather than adding a second switch —
 * one decision, one place, whoever pulls the trigger.
 */
function withMemoryPreamble(prompt, prefs) {
    if (!prompt) return prompt;
    if (!memoryEnabled(prefs)) return prompt;
    const file = String(cache?.tenant?.memoryFile || "").trim();
    if (!file) return prompt;
    const text = memoryPromptTemplate(prefs).split("{file}").join(file).trim();
    if (!text) return prompt; // template cleared in Settings = disabled
    if (prompt.includes(text) || prompt.includes(file)) return prompt;
    return `${text}\n\n---\n${prompt}`;
}

async function launchSkill(name, entity, promptOverride, lookback, meta) {
    // fleet/output must reach composeFor or the directive never makes it into
    // the prompt — the ledger would badge a run "Markdown" while the agent was
    // only ever asked for an inline answer.
    const composed = await composeFor(
        name,
        entity,
        promptOverride,
        lookback,
        meta?.fleet === true,
        meta?.output || "",
    );
    if (composed.error) return { ok: false, error: composed.error };
    if (!sessionRef) return { ok: false, error: "Session not connected yet" };
    // Applied here rather than in composeFor: composeFor also serves the compose
    // modal's preview, where the client owns the preamble so the analyst can
    // edit it. This is the send path — the last point every launch passes
    // through, whether it came from a click, a quick-launch or autopilot.
    const prompt = withMemoryPreamble(composed.prompt, await loadPrefs(REPO_ROOT));
    const spec = {
        skill: name,
        entity,
        lookback,
        output: meta?.output || "",
        fleet: meta?.fleet === true,
        prompt,
        // { depth, parentFindingId } when autopilot chased this. Rides through the
        // queue and the ledger so the finding it eventually produces knows its parent.
        autopilot: meta?.autopilot || null,
    };
    // One agent, one investigation at a time. Sending now would let the CLI queue
    // the prompt internally, but it gives us no event when it later dequeues, so
    // the ledger could not tell run A's work from run B's — the previous
    // behaviour closed run A early, stamped it "not recorded", and misattributed
    // everything after. Hold it instead and dispatch on run end.
    if (hasActiveRun()) {
        const position = enqueueRun(spec);
        if (!position) return { ok: false, error: "Queue is full — wait for the running investigation to finish" };
        try {
            await sessionRef.log(`🕒 Mission Control queued: ${name}${entity ? ` (${entity})` : ""} (#${position})`, { ephemeral: true });
        } catch { /* logging is best-effort */ }
        if ((await knownSkillNames()).has(name)) recordRun(name, entity);
        return { ok: true, queued: true, position, recent: recentPayload() };
    }
    const sent = await dispatchRun(spec);
    if (!sent.ok) return sent;
    if ((await knownSkillNames()).has(name)) recordRun(name, entity);
    return { ok: true, recent: recentPayload() };
}

/**
 * Send a composed launch and open its ledger run. The send and the run must
 * start together so per-run cost is a true delta — which is exactly why queued
 * launches are dispatched here at promotion time rather than at request time.
 */
async function dispatchRun(spec) {
    if (!sessionRef) return { ok: false, error: "Session not connected yet" };
    try {
        await sessionRef.send({ prompt: spec.prompt });
        await sessionRef.log(`🛰️ Mission Control launched: ${spec.skill}${spec.entity ? ` (${spec.entity})` : ""}`, { ephemeral: true });
        // Open a live run in the cross-session activity ledger. This is the
        // 100%-reliable start signal: at send time we already know the skill,
        // entity and scope, and it needs no cooperation from the agent. The
        // `skill.invoked` event is only a secondary signal (this project's
        // instructions tell the agent to `view` a SKILL.md, which doesn't emit
        // it). Baseline the credit counter so per-run cost is a delta.
        try {
            cancelEnd(); // a close scheduled by the previous run must not hit this one
            runBaselineNaiu = cumulativeNaiu;
            activeRunIsAutopilot = !!spec.autopilot;
            runReportPaths = [];
            beginRun({
                skill: spec.skill,
                entity: spec.entity,
                lookback: spec.lookback,
                output: spec.output || "",
                fleet: spec.fleet === true,
                source: "canvas",
                autopilot: spec.autopilot || null,
            });
        } catch { /* ledger is best-effort */ }
        return { ok: true };
    } catch (err) {
        return { ok: false, error: err.message };
    }
}

/**
 * Start the next queued launch once nothing is running. Called after every run
 * close. Failures drop the entry rather than stalling the queue behind it.
 */
async function promoteQueued() {
    if (hasActiveRun()) return;
    const next = takeNextQueued();
    if (!next) return;
    // Governors are checked again here, not just at enqueue: the originating
    // run's final credits land in between, so a chain can cross the budget while
    // its next hop is already sitting in the queue. Human-queued work always passes.
    const gate = await autopilotAllowsPromotion(next);
    if (!gate.ok) {
        try { await sessionRef?.log(`🛰️ Autopilot skipped queued ${next.skill} — ${gate.reason}.`, { ephemeral: true }); } catch { /* best-effort */ }
        void promoteQueued();
        return;
    }
    const sent = await dispatchRun({
        skill: next.skill,
        entity: next.entity,
        lookback: next.scope?.lookback || "",
        output: next.scope?.output || "",
        fleet: next.scope?.fleet === true,
        prompt: next.prompt,
        autopilot: next.autopilot || null,
    });
    if (!sent.ok) {
        try { await sessionRef?.log(`⚠️ Mission Control could not start queued ${next.skill}: ${sent.error}`, { ephemeral: true }); } catch { /* best-effort */ }
        void promoteQueued(); // don't let one bad entry block the rest
    }
}

// Compose the final prompt for a skill launch WITHOUT sending it. Shared by
// launchSkill (which then sends) and the /api/compose endpoint (which returns
// the text so the canvas can show an editable preview the analyst tailors
// before submitting). Keeping the lookback-injection logic here means the
// preview and the eventual send stay identical.
async function composeFor(name, entity, promptOverride, lookback, fleet, output) {
    if (!cache) cache = await loadCanvasData(REPO_ROOT);
    const skill = (cache.skills || []).find((s) => s.name === name);
    // A tailored, agent-authored prompt (or an auto-derived context prompt) is
    // used verbatim. Only fall back to the skill's generic manifest prompt when
    // no override is supplied. This lets follow-ups launched from the Findings
    // tab carry the originating finding's evidence into chat — and also lets
    // sub-skills (e.g. scope-drift-detection/spn) launch by prompt even when
    // they aren't surfaced as a standalone card.
    const override = (promptOverride || "").trim();
    let prompt = override || (skill ? composePrompt(skill, entity, lookback, fleet, output) : "");
    // composePrompt already injects the lookback + output mode for card launches.
    // For a verbatim override (Findings follow-up) that carries its own framing,
    // only append the window / output directive when explicitly chosen alongside it.
    if (override) {
        // Idempotent: the compose modal previews through composeFor and then
        // sends the result back as an override, so both directives can already
        // be present. Appending blind would duplicate them.
        const phrase = lookbackPhrase(lookback);
        if (phrase && !prompt.includes(phrase)) prompt = `${prompt} — use a lookback window of ${phrase}`;
        const outPhrase = outputPhrase(output);
        if (outPhrase && !prompt.includes(outPhrase)) prompt = `${prompt} — ${outPhrase}`;
    }
    if (!prompt) return { error: `Unknown skill: ${name}` };
    return { skill: name, prompt: withRecordDirective(prompt, await loadPrefs(REPO_ROOT)) };
}

/** Names of launchable skills — used to validate auto-recommended follow-ups. */
async function knownSkillNames() {
    if (!cache) cache = await loadCanvasData(REPO_ROOT);
    return new Set((cache.skills || []).map((s) => s.name));
}

async function findingsPayload() {
    const findings = (await loadFindings(REPO_ROOT)).map((f) => ({ ...f, ago: relAgo(f.ts) }));
    return { findings, summary: summarize(findings) };
}

// Persistent cost ledger payload. Auto-seeds from the current findings on first
// fetch (when the ledger is empty) so historical spend is carried over once.
async function costingPayload() {
    let rows = await loadCosting(REPO_ROOT);
    if (!rows.length) {
        try {
            rows = await seedCostingFromFindings(REPO_ROOT, await loadFindings(REPO_ROOT));
        } catch {
            rows = [];
        }
    }
    return { costing: rows, summary: summarizeCosting(rows) };
}

// Serve a report file referenced by a finding. Only files inside REPO_ROOT are
// allowed (path-traversal guarded). Markdown/text render inline in the browser;
// HTML is served as-is. Everything else downloads.
async function serveReport(rel, raw, res) {
    if (!rel) {
        res.writeHead(400);
        res.end("missing path");
        return;
    }
    const clean = rel.replace(/^[\\/]+/, "");
    const abs = path.resolve(REPO_ROOT, clean);
    const rootPrefix = REPO_ROOT.endsWith(path.sep) ? REPO_ROOT : REPO_ROOT + path.sep;
    if (abs !== REPO_ROOT && !abs.startsWith(rootPrefix)) {
        res.writeHead(403);
        res.end("forbidden");
        return;
    }
    let data;
    try {
        data = await readFile(abs);
    } catch {
        res.writeHead(404);
        res.end("report not found");
        return;
    }
    const ext = path.extname(abs).toLowerCase();

    // Markdown -> rendered HTML page (unless ?raw=1 for the source).
    if ((ext === ".md" || ext === ".markdown") && !raw) {
        const title = path.basename(abs);
        const html = htmlReportPage(title, renderMarkdown(data.toString("utf8"), clean.replace(/\\/g, "/")));
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(html);
        return;
    }

    const type =
        ext === ".html" || ext === ".htm"
            ? "text/html; charset=utf-8"
            : ext === ".json"
            ? "application/json; charset=utf-8"
            : ext === ".csv"
            ? "text/csv; charset=utf-8"
            : ext === ".svg"
            ? "image/svg+xml"
            : ext === ".md" || ext === ".markdown" || ext === ".txt" || ext === ".log"
            ? "text/plain; charset=utf-8"
            : "application/octet-stream";
    res.writeHead(200, { "Content-Type": type });
    res.end(data);
}

// Serve the tenant context-memory file for read-only markdown preview. The file
// lives OUTSIDE the repo, under ~/.copilot/memories/repo/, so it can't go through
// serveReport (which is repo-root scoped). The effective filename comes from the
// manifest (config.json memory_file, or a derived default) — never from the client
// — and is reduced to a basename, so there's no path-traversal surface.
async function serveMemFile(raw, res) {
    if (!cache) cache = await loadCanvasData(REPO_ROOT);
    const file = String((cache && cache.tenant && cache.tenant.memoryFile) || "").split(/[\\/]/).pop();
    if (!file) {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("No memory file configured — click ⚙ in the Findings tab to set one.");
        return;
    }
    const abs = path.join(homedir(), ".copilot", "memories", "repo", file);
    let text;
    try {
        text = (await readFile(abs)).toString("utf8");
    } catch {
        // File named but not created yet — render a friendly placeholder rather than a 404.
        const note =
            "# " + file + "\n\n" +
            "_This context-memory file does not exist yet at_ `~/.copilot/memories/repo/" + file + "`.\n\n" +
            "It will be created when you approve a **Compact** review, or you can create it manually.";
        if (raw) {
            res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
            res.end(note);
            return;
        }
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(htmlReportPage(file, renderMarkdown(note, file)));
        return;
    }
    if (raw) {
        res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
        res.end(text);
        return;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(htmlReportPage(file, renderMarkdown(text, file)));
}

async function handle(req, res) {
    const url = new URL(req.url, "http://127.0.0.1");
    try {
        if (req.method === "GET" && url.pathname === "/") {
            // Prefs are inlined into the document rather than fetched, so they
            // are already present when the client's module-level init reads
            // localStorage — no first-paint flash of default settings.
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
            res.end(renderPage(await loadPrefs(REPO_ROOT)));
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/prefs") {
            // Durable UI settings. The canvas server binds to port 0, so its
            // origin changes on every load and localStorage alone would reset
            // every time.
            const body = await readBody(req);
            json(res, 200, { ok: true, prefs: await savePrefs(REPO_ROOT, body?.patch) });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/autopilot") {
            // Autopilot control surface. Only the owning session can act, so this
            // route is a no-op in any other session's canvas by construction —
            // the state machine lives in this process.
            const body = await readBody(req);
            const action = String(body?.action || "");
            let snap = autopilotSnapshot();
            if (action === "enable") {
                snap = await enableAutopilot({ coldStart: body?.coldStart === true });
            } else if (action === "stop") {
                // The analyst's reason is a judgement signal worth keeping, not
                // just a UI transition — write it back onto the finding it was
                // made about before tearing the chain down.
                const fid = snap.findingId;
                if (fid) { try { await setVerdict(REPO_ROOT, fid, "stopped", body?.reason); } catch {} }
                // Pausing must never touch analyst-queued work; stopping drops
                // only the launches autopilot itself added.
                let dropped = 0;
                try { dropped = dropAutopilotQueued(); } catch {}
                snap = await stopAutopilot(body?.reason);
                snap.dropped = dropped;
            } else if (action === "resume") {
                const fid = snap.findingId;
                if (fid && snap.reason === "critical") {
                    try { await setVerdict(REPO_ROOT, fid, "approved", body?.reason); } catch {}
                }
                snap = await resumeAutopilot();
            } else if (action === "settings") {
                const patch = {};
                const p = body?.limits || {};
                for (const k of ["maxRuns", "maxAic", "maxDepth"]) {
                    if (p[k] !== undefined && p[k] !== null && p[k] !== "") patch[AUTOPILOT_KEYS[k]] = String(p[k]);
                }
                if (p.minSeverity) patch[AUTOPILOT_KEYS.minSeverity] = String(p.minSeverity);
                if (p.output) patch[AUTOPILOT_KEYS.output] = String(p.output);
                const prefs = await savePrefs(REPO_ROOT, patch);
                const limits = autopilotLimits(prefs);
                json(res, 200, { ok: true, autopilot: applyAutopilotLimits(limits), limits, prefs });
                return;
            }
            json(res, 200, { ok: true, autopilot: snap, limits: autopilotLimits(await loadPrefs(REPO_ROOT)) });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/autopilot") {
            const prefs = await loadPrefs(REPO_ROOT);
            json(res, 200, {
                autopilot: autopilotSnapshot(),
                limits: autopilotLimits(prefs),
                defaults: AUTOPILOT_DEFAULTS,
                ceilings: AUTOPILOT_CEILINGS,
                // What a cold start would pick up right now, so the enable
                // prompt can name the work instead of asking blind.
                board: await autopilotBoardPreview(),
            });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/chain") {
            json(res, 200, { chain: await chainFor(REPO_ROOT, String(url.searchParams.get("id") || "")) });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/data") {
            cache = await loadCanvasData(REPO_ROOT);
            json(res, 200, { ...cache, recent: recentPayload() });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/activity") {
            // Live cross-session investigation status. Merges every session's
            // ledger file, so this canvas shows runs happening in OTHER sessions
            // too — including sessions that never opened Mission Control.
            json(res, 200, await readActivity(REPO_ROOT, activitySessionId()));
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/queue/cancel") {
            // Drop a launch the analyst queued but no longer wants. Only this
            // session's own queue is cancellable — another session's ledger file
            // is written solely by that session's process.
            const body = await readBody(req);
            json(res, 200, { ok: dropQueued(String(body?.queueId || "")) });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/compose") {
            // Compose-only: returns the prompt text (no send) so the canvas can
            // show an editable preview. If no explicit skill is given but an
            // entity is, route the entity to the right skill (quick-launch path).
            const body = await readBody(req);
            let skill = body.skill || "";
            const entity = (body.entity || "").trim();
            let override = body.prompt || "";
            let free = false;
            if (!skill && !override) {
                if (!entity) { json(res, 200, { ok: false, error: "ask a question or paste an entity" }); return; }
                if (looksFreeForm(entity)) {
                    // Free-form ask: hand the routing decision to the model. The
                    // question becomes the prompt override so composeFor uses it
                    // verbatim, and the run is tagged `ad-hoc` until the agent
                    // loads a real skill. Scope directives are already baked in
                    // by composeAdHoc, so they are not passed on again below.
                    skill = ADHOC_SKILL;
                    override = composeAdHoc(entity, body.lookback || "", body.output || "");
                    free = true;
                } else {
                    skill = routeEntity(entity);
                }
            }
            const composed = await composeFor(
                skill,
                free ? "" : entity,
                override,
                free ? "" : (body.lookback || ""),
                body.fleet === true,
                free ? "" : (body.output || ""),
            );
            if (composed.error) { json(res, 200, { ok: false, error: composed.error }); return; }
            json(res, 200, { ok: true, skill: composed.skill || skill, entity: free ? "" : entity, prompt: composed.prompt });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/run") {
            const body = await readBody(req);
            const { skill, entity, prompt, lookback } = body;
            json(res, 200, await launchSkill(skill, entity || "", prompt || "", lookback || "", { fleet: body.fleet === true, output: body.output || "" }));
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/quicklaunch") {
            const { entity, lookback } = await readBody(req);
            if (!entity || !entity.trim()) {
                json(res, 200, { ok: false, error: "ask a question or paste an entity" });
                return;
            }
            const free = looksFreeForm(entity);
            const skill = free ? ADHOC_SKILL : routeEntity(entity);
            const result = await launchSkill(
                skill,
                free ? "" : entity.trim(),
                free ? composeAdHoc(entity, lookback || "", "") : "",
                free ? "" : (lookback || ""),
            );
            json(res, 200, { ...result, skill });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/findings") {
            json(res, 200, await findingsPayload());
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/costing") {
            json(res, 200, await costingPayload());
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/findings/dismiss") {
            const { id } = await readBody(req);
            await dismissFinding(REPO_ROOT, id);
            json(res, 200, { ok: true, ...(await findingsPayload()) });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/findings/clear") {
            await clearFindings(REPO_ROOT);
            json(res, 200, { ok: true, ...(await findingsPayload()) });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/findings/prune") {
            const body = await readBody(req);
            await pruneFindings(REPO_ROOT, {
                olderThanDays: body.olderThanDays,
                severities: body.severities,
            });
            json(res, 200, { ok: true, ...(await findingsPayload()) });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/findings/archive") {
            const body = await readBody(req);
            const r = await archiveFindings(REPO_ROOT, {
                olderThanDays: body.olderThanDays,
                severities: body.severities,
            });
            json(res, 200, {
                ok: true,
                archived: r.archived,
                file: r.file,
                archives: await listArchives(REPO_ROOT),
                ...(await findingsPayload()),
            });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/findings/archive-one") {
            const { id } = await readBody(req);
            const r = await archiveOneFinding(REPO_ROOT, id);
            json(res, 200, {
                ok: true,
                archived: r.archived,
                file: r.file,
                archives: await listArchives(REPO_ROOT),
                ...(await findingsPayload()),
            });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/findings/all") {
            const items = (await loadAllFindingsAggregated(REPO_ROOT)).map((f) => ({ ...f, ago: relAgo(f.ts) }));
            json(res, 200, {
                ok: true,
                items,
                archives: await listArchives(REPO_ROOT),
                summary: summarize(items),
            });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/findings/archives") {
            json(res, 200, { archives: await listArchives(REPO_ROOT) });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/findings/archive") {
            const a = await readArchive(REPO_ROOT, url.searchParams.get("file") || "");
            if (!a) {
                json(res, 404, { ok: false, error: "archive not found" });
                return;
            }
            const findings = a.findings.map((f) => ({ ...f, ago: relAgo(f.ts) }));
            json(res, 200, {
                ok: true,
                file: a.file,
                archivedAt: a.archivedAt,
                stamp: a.stamp,
                count: a.count,
                findings,
                summary: summarize(findings),
            });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/memory-file") {
            json(res, 200, await setMemoryFile((await readBody(req)).file));
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/report") {
            await serveReport(url.searchParams.get("path"), url.searchParams.get("raw"), res);
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/memfile") {
            await serveMemFile(url.searchParams.get("raw"), res);
            return;
        }
        res.writeHead(404);
        res.end("not found");
    } catch (err) {
        json(res, 500, { ok: false, error: err.message });
    }
}

async function startServer() {
    const server = createServer(handle);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    return { server, url: `http://127.0.0.1:${port}/` };
}

sessionRef = await joinSession({
    canvases: [
        createCanvas({
            id: "skills-canvas",
            displayName: "Mission Control",
            description: "Launchable dashboard of this project's investigation skills — filter by domain, search, and one-click launch skills or route an entity to the right investigation.",
            actions: [
                {
                    // Agent-invokable: lets the agent open + launch a skill on the
                    // user's behalf, e.g. after a Threat Pulse recommends a drill-down.
                    name: "launch_skill",
                    description: "Launch one of the project's investigation skills by name, optionally with a target entity (UPN/IP/hash/device/incident number).",
                    inputSchema: {
                        type: "object",
                        properties: {
                            skill: { type: "string", description: "Skill name, e.g. user-investigation" },
                            entity: { type: "string", description: "Optional target entity" },
                        },
                        required: ["skill"],
                    },
                    handler: async (ctx) => {
                        const args = ctx.input || {};
                        return await launchSkill(args.skill, args.entity || "");
                    },
                },
                {
                    // Agent-invokable: after finishing a skill/investigation, the
                    // agent pushes a structured result back so it appears in the
                    // canvas "Findings" tab with one-click follow-up skills. This
                    // closes the hunt -> findings -> next-hunt loop.
                    name: "record_finding",
                    description:
                        "Record a completed investigation result to the Mission Control Findings tab. Call after a skill run. Always include a 1-3 sentence `summary` alongside `title`/`severity` — never title-only. `skill` and `reports` are auto-filled from the active run when omitted. Add `metrics`, notable `entities`, and `recommended` follow-ups; give each follow-up a one-line `reason` and a tailored `prompt` carrying this finding's evidence, not a bare skill name.",
                    inputSchema: {
                        type: "object",
                        properties: {
                            skill: { type: "string", description: "Skill that produced this finding, e.g. exposure-investigation. Optional — auto-filled from the active Mission Control run." },
                            title: { type: "string", description: "Short headline for the finding" },
                            severity: {
                                type: "string",
                                enum: ["critical", "high", "medium", "low", "info", "clean"],
                                description: "Overall severity/risk of the finding",
                            },
                            scope: { type: "string", description: "What it covers, e.g. 'org-wide' or a specific entity" },
                            summary: { type: "string", description: "1-3 sentence human summary of what was found" },
                            metrics: {
                                type: "array",
                                description: "Key numbers to surface as chips",
                                items: {
                                    type: "object",
                                    properties: {
                                        label: { type: "string" },
                                        value: { type: "string" },
                                        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info", "clean"] },
                                    },
                                    required: ["label", "value"],
                                },
                            },
                            entities: {
                                type: "array",
                                description: "Discovered entities worth investigating further",
                                items: {
                                    type: "object",
                                    properties: {
                                        type: { type: "string", description: "user|ip|domain|url|hash|device|incident|spn|app" },
                                        value: { type: "string" },
                                    },
                                    required: ["type", "value"],
                                },
                            },
                            domains: {
                                type: "array",
                                description: "Threat-pulse domain tags this finding touches",
                                items: { type: "string" },
                            },
                            reports: {
                                type: "array",
                                description: "Generated report/artifact files for this finding (e.g. reports/exposure/xyz.md). Repo-relative paths, optionally with a label. Rendered as clickable links in the Findings tab.",
                                items: {
                                    type: "object",
                                    properties: {
                                        path: { type: "string", description: "Repo-relative path to the report/artifact file" },
                                        label: { type: "string", description: "Optional display label; defaults to the file name" },
                                    },
                                    required: ["path"],
                                },
                            },
                            recommended: {
                                type: "array",
                                description:
                                    "Recommended follow-up skills (agent-authored). If omitted, they are auto-derived from entities/domains with a context-enriched prompt. Prefer authoring these yourself so each carries a tailored drill-down prompt.",
                                items: {
                                    type: "object",
                                    properties: {
                                        skill: { type: "string", description: "Follow-up skill name, e.g. authentication-tracing or scope-drift-detection/user" },
                                        entity: { type: "string", description: "Target entity for the follow-up, e.g. a UPN/IP/device/CVE" },
                                        reason: { type: "string", description: "Short one-line rationale shown under the button" },
                                        prompt: {
                                            type: "string",
                                            description:
                                                "The exact chat prompt to fire when the analyst clicks this follow-up. Author it tailored to THIS finding — like a threat-pulse drill-down: start with the skill's natural trigger phrasing (so keyword detection loads the right skill, e.g. 'Trace authentication chain for user@corp.com'), then embed the specific evidence, correlations, and why this matters. Sent verbatim; if omitted, a generic prompt is composed from the manifest.",
                                        },
                                    },
                                    required: ["skill"],
                                },
                            },
                        },
                        required: ["title", "severity"],
                    },
                    handler: async (ctx) => {
                        const args = ctx.input || {};
                        // Auto-fill the mechanical fields from the active run so the
                        // launch directive doesn't have to ask for them. `skill` comes
                        // from whatever Mission Control (or the Skill tool) opened;
                        // `reports` from markdown files observed being written during
                        // the run. Anything the agent supplied explicitly wins.
                        const run = activeRun();
                        if (!args.skill) args.skill = run?.skill || "ad-hoc";
                        if (!Array.isArray(args.reports) || args.reports.length === 0) {
                            if (runReportPaths.length) args.reports = runReportPaths.map((p) => ({ path: p }));
                        }
                        // Attribute AI usage since the previous finding to this one.
                        const deltaNaiu = Math.max(0, cumulativeNaiu - lastFindingNaiu);
                        lastFindingNaiu = cumulativeNaiu;
                        args.creditsNaiu = deltaNaiu;
                        // Dominant model since the previous finding (most credits consumed).
                        let bestModel = "", bestDelta = 0;
                        for (const [m, cum] of cumulativeByModel) {
                            const d = cum - (lastByModel.get(m) || 0);
                            if (d > bestDelta) { bestDelta = d; bestModel = m; }
                        }
                        for (const [m, cum] of cumulativeByModel) lastByModel.set(m, cum);
                        if (bestModel) args.model = bestModel;
                        // Lineage. The run knows whether autopilot launched it and
                        // from which parent finding, so the chain records itself with
                        // no cooperation from the agent and no extra prompt text.
                        if (run?.autopilot) {
                            args.origin = {
                                autopilot: true,
                                parentFindingId: run.autopilot.parentFindingId || "",
                                depth: Number(run.autopilot.depth) || 0,
                            };
                        }
                        try {
                            const finding = await addFinding(REPO_ROOT, args, await knownSkillNames());
                            try { await addCosting(REPO_ROOT, { ...finding, model: args.model }); } catch {}
                            // Link the finding to the run so the live strip can show it
                            // resolved and the recent-runs line doesn't flag it unrecorded.
                            try { markRecorded(finding.id); } catch {}
                            await sessionRef?.log(`📌 Finding recorded: ${finding.title} (${finding.severity})`, { ephemeral: true });
                            // The decision point. Fires while this run is still open, so
                            // any follow-up lands in the queue and is dispatched on close
                            // — exactly what a click would have done.
                            try { await autopilotOnFinding(finding, run); } catch {}
                            return { ok: true, id: finding.id, recommended: finding.recommended };
                        } catch (err) {
                            return { ok: false, error: err.message };
                        }
                    },
                },
            ],
            open: async (ctx) => {
                let entry = servers.get(ctx.instanceId);
                if (!entry) {
                    entry = await startServer();
                    servers.set(ctx.instanceId, entry);
                }
                return { title: "Mission Control", url: entry.url, status: "ready" };
            },
            onClose: async (ctx) => {
                const entry = servers.get(ctx.instanceId);
                if (entry) {
                    servers.delete(ctx.instanceId);
                    await new Promise((resolve) => entry.server.close(() => resolve()));
                }
            },
        }),
    ],
    hooks: {
        // On the first prompt of each session, nudge the agent to open Mission
        // Control (once, and only if it isn't already open). This is the only
        // way to auto-open, since an extension can't open its own canvas.
        onUserPromptSubmitted: async (_input, invocation) => {
            if (!AUTO_OPEN) return;
            const sessionId = invocation?.sessionId || "";
            if (autoOpened.has(sessionId)) return;
            autoOpened.add(sessionId);
            try {
                const open = (sessionRef?.openCanvases || []).some((c) => c.canvasId === "skills-canvas");
                if (open) return;
            } catch { /* openCanvases may be unavailable early; fall through */ }
            return {
                additionalContext:
                    'Session setup: if the "skills-canvas" (Mission Control) canvas is not already open, silently open it now by calling the open_canvas tool with canvasId "skills-canvas" and instanceId "mission-control". Do this once at the start of the session without commentary, then handle the user\'s request normally.',
            };
        },
    },
});

await sessionRef.log("🛰️ Mission Control canvas ready — open it to launch skills.", { ephemeral: true });

// Accumulate AI usage telemetry so findings can report credits consumed. Each
// assistant.usage event carries copilotUsage.totalNanoAiu (nano-AI units) for
// one model call; multiple fire per turn (incl. sub-agents), so we sum them.
try {
    sessionRef.on("assistant.usage", (event) => {
        const n = event?.data?.copilotUsage?.totalNanoAiu;
        if (typeof n === "number" && n > 0) {
            cumulativeNaiu += n;
            const model = usageModel(event);
            cumulativeByModel.set(model, (cumulativeByModel.get(model) || 0) + n);
            // Live per-run cost for the Findings strip (delta since run start).
            // A usage event also means a model call just completed, so the run
            // is demonstrably still alive — hold off any pending close.
            try { cancelEnd(); updateRun({ creditsNaiu: Math.max(0, cumulativeNaiu - runBaselineNaiu) }); } catch {}
        }
    });
} catch { /* usage telemetry optional; findings simply omit the chip */ }

// ---------------------------------------------------------------------------
// Live investigation status (cross-session).
//
// These subscriptions are registered at module load, NOT on canvas open — so a
// session reports its progress even when Mission Control is never opened in it,
// and any other session's Findings tab can watch it. Nothing here requires the
// agent to be prompted: the run is observed, not self-reported.
//
// Every subscription is wrapped individually so an event name renamed by a
// future SDK can degrade one signal without breaking extension load.
// ---------------------------------------------------------------------------

initActivity(REPO_ROOT, sessionRef?.sessionId || process.env.SESSION_ID || "");

// Autopilot's dependencies, injected rather than imported, so the state machine
// stays testable and can't reach into the session on its own.
initAutopilot({
    log: (message, opts) => sessionRef?.log(message, { ephemeral: !opts?.sticky }),
    // Deliberately the same entry point a click uses — autopilot gets no
    // privileged execution path, just the queue everything else goes through.
    launch: (lead) => launchSkill(lead.skill, lead.entity, lead.prompt, "", { autopilot: lead.autopilot, output: lead.output || "" }),
    limits: async () => autopilotLimits(await loadPrefs(REPO_ROOT)),
    credits: () => autopilotSpentNaiu(),
    knownSkills: () => knownSkillNames(),
    getFinding: (id) => getFinding(REPO_ROOT, id),
    listFindings: () => loadFindings(REPO_ROOT),
    // Every run that actually executed, recorded or not — the only source that
    // knows about runs which finished without producing a finding.
    recentRuns: async () => (await readActivity(REPO_ROOT, activitySessionId())).recent || [],
    flush: () => { try { flushActivity(); syncHeartbeat(); } catch { } },
});

function on(eventName, fn) {
    try {
        sessionRef.on(eventName, (event) => {
            try { fn(event); } catch { /* one bad payload must not kill the stream */ }
        });
    } catch { /* event unavailable in this SDK build — signal simply goes dark */ }
}

// Secondary start signal: a skill loaded via the Skill tool rather than a canvas
// click (hand-typed "run threat pulse"). Only project skills count — this keeps
// ordinary coding/chat turns out of the strip entirely.
on("skill.invoked", (event) => {
    const d = event?.data || {};
    const p = String(d.path || "").replace(/\\/g, "/");
    if (!p.includes(".github/skills/")) return;
    const open = activeRun();
    if (open) {
        // A free-form quick-launch opens as `ad-hoc` because the routing decision
        // was the model's to make. Now that it has made it, re-attribute the run
        // so the live strip, findings and cost ledger show the real skill.
        if (open.skill === ADHOC_SKILL) updateRun({ skill: String(d.name || ADHOC_SKILL) });
        return; // canvas launch already opened this run
    }
    cancelEnd(); // a stale close scheduled by the previous run must not hit this one
    runBaselineNaiu = cumulativeNaiu;
    // A run the agent started itself (skill tool) is the analyst's, not autopilot's.
    activeRunIsAutopilot = false;
    runReportPaths = [];
    beginRun({ skill: String(d.name || "investigation"), source: "skill-tool" });
});

// The live one-liner shown in the strip. `assistant.intent` is the documented
// source but is `ephemeral` and — verified empirically against SDK 1.0.61 — is
// never delivered to extensions, so it alone left the phase stuck at "Starting…".
// The reliable source is `assistant.message.content`: the agent's own progress
// narration, which the system prompt already requires. No extra prompting needed.
// Both are wired; whichever arrives wins. Each is also proof of life.
on("assistant.intent", (event) => {
    const intent = cleanText(event?.data?.intent);
    if (!intent) return;
    cancelEnd();
    updateRun({ phase: shortPhase(intent), phaseFull: intent });
});

on("assistant.message", (event) => {
    // Tool-only messages carry empty content — ignore those so the last real
    // narration stays on screen instead of blanking between steps.
    const full = cleanText(event?.data?.content);
    if (!full) return;
    cancelEnd();
    // `phase` is the one-line display value; `phaseFull` backs the hover tooltip
    // so the analyst can read the whole update without it being cut off.
    updateRun({ phase: shortPhase(full), phaseFull: full });
});

// Flatten a markdown progress update into plain prose, keeping the whole thing.
function cleanText(text) {
    if (typeof text !== "string") return "";
    const t = text
        .replace(/```[\s\S]*?```/g, " ")   // drop fenced code
        .replace(/`([^`]*)`/g, "$1")       // unwrap inline code
        .replace(/[*_#>|]/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    return t.length > 600 ? t.slice(0, 597).trimEnd() + "\u2026" : t;
}

// Condense to a single status line for the collapsed row.
function shortPhase(t) {
    if (!t) return "";
    const stop = t.match(/^.{20,}?[.!?](\s|$)/);   // first sentence, if long enough to stand alone
    let s = stop ? stop[0].trim() : t;
    if (s.length > 120) s = s.slice(0, 117).trimEnd() + "\u2026";
    return s;
}

// Tool activity: drives the tool counter/chip, and doubles as the source for
// auto-filled `reports` (markdown paths written during the run).
on("tool.execution_start", (event) => {
    const d = event?.data || {};
    const label = d.mcpToolName || d.toolName || "";
    cancelEnd();
    bumpTool(String(label));
    harvestReportPath(d);
});

on("subagent.started", () => { cancelEnd(); bumpSubagent(1); });
on("subagent.completed", () => bumpSubagent(-1));

on("session.title_changed", (event) => setSessionTitle(event?.data?.title || ""));

// Signal-only event — the todo table changed. Reading it is an extra call, so
// debounce and treat any failure as "no progress info available".
let todoTimer = null;
on("session.todos_changed", () => {
    if (!activeRun() || todoTimer) return;
    todoTimer = setTimeout(async () => {
        todoTimer = null;
        try {
            const rows = await sessionRef?.plan?.readSqlTodosWithDependencies?.();
            const list = Array.isArray(rows) ? rows : (rows?.todos || []);
            if (!Array.isArray(list) || !list.length) return;
            const done = list.filter((t) => String(t?.status || "") === "done").length;
            updateRun({ todos: { done, total: list.length } });
        } catch { /* progress detail is optional */ }
    }, 2000);
    if (todoTimer.unref) todoTimer.unref();
});

// Closing the run.
//
// `assistant.turn_end` fires per model round-trip, NOT once per investigation —
// a multi-step skill emits many of them, so ending on the first one closed runs
// seconds after they started while the agent was still working. `session.idle`
// can likewise arrive before the first model call has produced anything.
//
// So an end signal never ends the run directly: it opens a quiet window. Any
// proof of life (new turn, tool call, intent, sub-agent) cancels it, and a run
// younger than MIN_RUN_MS is deferred rather than closed. The run ends only
// after the session has genuinely stopped doing anything.
const END_QUIET_MS = 12000;   // silence after turn_end before a run is done
const IDLE_QUIET_MS = 5000;   // idle is a stronger signal, so a shorter window
const MIN_RUN_MS = 20000;     // never close a run that only just opened
let endTimer = null;

/**
 * Fold the finished run's credits into autopilot's total. Must run before
 * endRun clears the run, and before the next run rebaselines the counter —
 * otherwise the spend is lost and the budget governor under-counts.
 */
function settleAutopilotCredits() {
    if (activeRunIsAutopilot) {
        autopilotNaiu += Math.max(0, cumulativeNaiu - runBaselineNaiu);
        activeRunIsAutopilot = false;
    }
}

function cancelEnd() {
    if (endTimer) { clearTimeout(endTimer); endTimer = null; }
}

function scheduleEnd(ms, opts) {
    if (!activeRun()) return;
    cancelEnd();
    endTimer = setTimeout(() => {
        endTimer = null;
        const run = activeRun();
        if (!run) return;
        // Too young to be finished — wait out the remainder instead of closing.
        const age = Date.now() - (Number(run.startedAt) || 0);
        if (age < MIN_RUN_MS) { scheduleEnd(MIN_RUN_MS - age, opts); return; }
        settleAutopilotCredits();
        endRun(opts || {});
        // Watchdog: an autopilot run that closed without recording a finding has
        // broken the chain. Without this the loop stalls while looking healthy.
        void autopilotOnRunClosed(run);
        void promoteQueued();
    }, Math.max(0, ms));
    if (endTimer.unref) endTimer.unref();
}

on("assistant.turn_start", () => cancelEnd());
on("assistant.turn_end", () => scheduleEnd(END_QUIET_MS, {}));
on("session.idle", () => scheduleEnd(IDLE_QUIET_MS, {}));

// A hard error is unambiguous — close immediately so the failure is visible.
on("session.error", (event) => {
    cancelEnd();
    settleAutopilotCredits();
    endRun({ error: event?.data?.message || "Session error" });
    void promoteQueued();
});
on("session.shutdown", () => { cancelEnd(); void clearSession(); });

// Harvest repo-relative markdown paths from file-writing tool calls so a report
// authored during the run is linked to the finding without the agent being asked
// to include it. Only .md under the repo, capped so a runaway run can't grow the
// ledger without bound.
function harvestReportPath(d) {
    const name = String(d?.toolName || "").toLowerCase();
    if (name !== "create" && name !== "edit" && name !== "write" && name !== "str_replace_editor") return;
    const a = d?.arguments || {};
    const raw = a.path || a.file_path || a.filePath || a.filename || "";
    if (typeof raw !== "string" || !raw.toLowerCase().endsWith(".md")) return;
    let rel = raw.replace(/\\/g, "/");
    const root = REPO_ROOT.replace(/\\/g, "/");
    if (rel.toLowerCase().startsWith(root.toLowerCase())) rel = rel.slice(root.length).replace(/^\/+/, "");
    if (!rel || rel.startsWith("..") || /^[a-zA-Z]:/.test(rel)) return; // outside the repo
    if (rel.includes(".github/extensions/")) return; // extension state, not a report
    if (runReportPaths.includes(rel) || runReportPaths.length >= 5) return;
    runReportPaths.push(rel);
}
