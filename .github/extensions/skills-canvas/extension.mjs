// Extension: skills-canvas — "Mission Control"
// A canvas that renders the project's investigation skills as a launchable
// dashboard. Clicking a skill composes its canned prompt (from the discovery
// manifest) and injects it into the current chat session via session.send(),
// so every existing global rule / skill workflow applies unchanged. The canvas
// is a launcher + visual layer, not a new execution path.

import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { joinSession, createCanvas } from "@github/copilot-sdk/extension";
import { renderPage } from "./ui.mjs";
import { loadCanvasData, composePrompt, lookbackPhrase, outputPhrase } from "./manifest.mjs";
import { renderMarkdown, htmlReportPage } from "./md.mjs";
import {
    loadFindings,
    addFinding,
    dismissFinding,
    clearFindings,
    summarize,
} from "./findings.mjs";

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

// Closing directive appended to every Mission Control launch so the agent posts
// its results back to the Findings tab when done. This lives in the launched
// prompt (NOT in copilot-instructions.md) so the behavior is scoped strictly to
// canvas-initiated runs — a hand-typed chat investigation is unaffected. It also
// nudges the agent to author fully tailored, threat-pulse-style follow-up prompts.
const RECORD_FINDING_DIRECTIVE = [
    "",
    "---",
    "When the investigation is done, post it to Mission Control's Findings tab via the `record_finding` canvas action, following its input schema. Required: `skill`, `title`, `severity` (enum uses `info`/`clean`, never `informational`). Also ALWAYS include a `summary` — 1-3 sentences describing what was found — so the finding is never title-only. Prefer adding `metrics` chips and any `entities` worth chasing. For every `recommended` follow-up, provide the full object: `skill`, and both a one-line `reason` (shown under the button) and a tailored, ready-to-run `prompt` that embeds THIS finding's specific evidence — never a bare skill name or generic template. Always record, even a clean or informational result.",
].join("\n");

// Append the record-finding directive exactly once. Idempotent: the compose
// modal path runs composeFor twice (preview via /api/compose, then send via
// /api/run with the edited text as an override), so we skip when the token is
// already present to avoid a duplicated directive.
function withRecordDirective(prompt) {
    if (!prompt || prompt.includes("record_finding")) return prompt;
    return prompt + "\n" + RECORD_FINDING_DIRECTIVE;
}

async function launchSkill(name, entity, promptOverride, lookback) {
    const composed = await composeFor(name, entity, promptOverride, lookback);
    if (composed.error) return { ok: false, error: composed.error };
    if (!sessionRef) return { ok: false, error: "Session not connected yet" };
    try {
        await sessionRef.send({ prompt: composed.prompt });
        await sessionRef.log(`🛰️ Mission Control launched: ${name}${entity ? ` (${entity})` : ""}`, { ephemeral: true });
        // Only record entries that are safely re-launchable from the "Recently
        // launched" list. Clicking a recent item calls run(name) with no prompt,
        // which resolves only for real skill cards. Ad-hoc query-context launches
        // (labels like "🔎 2 queries") would compose to "Unknown skill", so skip them.
        if ((await knownSkillNames()).has(name)) recordRun(name, entity);
        return { ok: true, recent: recentPayload() };
    } catch (err) {
        return { ok: false, error: err.message };
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
        const phrase = lookbackPhrase(lookback);
        if (phrase) prompt = `${prompt} — use a lookback window of ${phrase}`;
        const outPhrase = outputPhrase(output);
        if (outPhrase) prompt = `${prompt} — ${outPhrase}`;
    }
    if (!prompt) return { error: `Unknown skill: ${name}` };
    return { skill: name, prompt: withRecordDirective(prompt) };
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
        const html = htmlReportPage(title, renderMarkdown(data.toString("utf8")));
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

async function handle(req, res) {
    const url = new URL(req.url, "http://127.0.0.1");
    try {
        if (req.method === "GET" && url.pathname === "/") {
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
            res.end(renderPage());
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/data") {
            cache = await loadCanvasData(REPO_ROOT);
            json(res, 200, { ...cache, recent: recentPayload() });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/compose") {
            // Compose-only: returns the prompt text (no send) so the canvas can
            // show an editable preview. If no explicit skill is given but an
            // entity is, route the entity to the right skill (quick-launch path).
            const body = await readBody(req);
            let skill = body.skill || "";
            const entity = (body.entity || "").trim();
            const override = body.prompt || "";
            if (!skill && !override) {
                if (!entity) { json(res, 200, { ok: false, error: "empty entity" }); return; }
                skill = routeEntity(entity);
            }
            const composed = await composeFor(skill, entity, override, body.lookback || "", body.fleet === true, body.output || "");
            if (composed.error) { json(res, 200, { ok: false, error: composed.error }); return; }
            json(res, 200, { ok: true, skill: composed.skill || skill, entity, prompt: composed.prompt });
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/run") {
            const { skill, entity, prompt, lookback } = await readBody(req);
            json(res, 200, await launchSkill(skill, entity || "", prompt || "", lookback || ""));
            return;
        }
        if (req.method === "POST" && url.pathname === "/api/quicklaunch") {
            const { entity, lookback } = await readBody(req);
            if (!entity || !entity.trim()) {
                json(res, 200, { ok: false, error: "empty entity" });
                return;
            }
            const skill = routeEntity(entity);
            const result = await launchSkill(skill, entity.trim(), "", lookback || "");
            json(res, 200, { ...result, skill });
            return;
        }
        if (req.method === "GET" && url.pathname === "/api/findings") {
            json(res, 200, await findingsPayload());
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
        if (req.method === "GET" && url.pathname === "/api/report") {
            await serveReport(url.searchParams.get("path"), url.searchParams.get("raw"), res);
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
                        "Record a finding/result from a completed investigation so it appears in the Mission Control Findings tab. Call this after finishing a skill run. ALWAYS supply a `summary` (1-3 sentence description of what was found) in addition to the required `skill`/`title`/`severity` — never record a title-only finding. Also supply key `metrics`, any discovered `entities` worth chasing, and `recommended` follow-ups. For each follow-up, provide both a one-line `reason` (shown under the button) and a fully tailored, ready-to-run `prompt` (threat-pulse drill-down style) that embeds the specific evidence, entity, and correlation from THIS finding — do not leave it to a generic template or a bare skill name.",
                    inputSchema: {
                        type: "object",
                        properties: {
                            skill: { type: "string", description: "Skill that produced this finding, e.g. exposure-investigation" },
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
                        required: ["skill", "title", "severity"],
                    },
                    handler: async (ctx) => {
                        const args = ctx.input || {};
                        try {
                            const finding = await addFinding(REPO_ROOT, args, await knownSkillNames());
                            await sessionRef?.log(`📌 Finding recorded: ${finding.title} (${finding.severity})`, { ephemeral: true });
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
});

await sessionRef.log("🛰️ Mission Control canvas ready — open it to launch skills.", { ephemeral: true });
