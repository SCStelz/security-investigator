// Server-side UI preferences for Mission Control.
//
// The canvas HTTP server binds to port 0, so it gets a fresh port on every
// extension load. Browsers scope localStorage by ORIGIN, and the port is part
// of the origin — so http://127.0.0.1:59140 and http://127.0.0.1:63578 have
// completely separate stores. Every relaunch therefore looked like a factory
// reset: currency, favorites, rail width, view modes and column widths all
// reverted to defaults.
//
// Persisting here instead makes preferences survive relaunches, and shares them
// across sessions (all sessions resolve the same repo root, same as findings /
// costing / activity). The client keeps using localStorage as its synchronous
// cache; this file is the durable copy that seeds it on load.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

// Guard rails: prefs are small scalars (a currency code, a width, a JSON array
// of favorites). Anything larger is a bug or an abuse of the endpoint.
const MAX_KEYS = 200;
const MAX_VALUE_LEN = 20000;

function storePath(repoRoot) {
    return path.join(repoRoot, ".github", "extensions", "skills-canvas", "state", "prefs.json");
}

// ---- Customisable launch prompts ----
//
// Mission Control wraps every launched prompt: a memory preamble in front and a
// record-finding directive behind. Both are editable from Settings, so these are
// the fallbacks used when the analyst hasn't overridden them. Defined here (not
// in ui.mjs / extension.mjs) so the editor, the client-side compose preview and
// the server-side send all read one source of truth.

/** Prefix. `{file}` is substituted with the configured tenant memory filename. */
export const DEFAULT_MEMORY_PROMPT =
    "🧠 Before investigating and before rendering any verdict, consult your tenant context-memory file '{file}' " +
    "(under ~/.copilot/memories/repo/). Don't read it in full — first skim its section headers, then search it for " +
    "the specific entities in this task (IPs, UPNs, hostnames, domains, file hashes, app/SPN names) and read only " +
    "the matching sections. Apply the documented ground truth you find — known-good IPs, automation/orchestration " +
    "fingerprints, account classifications, and false-positive rules — and cite it explicitly when a signal matches " +
    "a documented pattern.";

// Deliberately minimal: it asks only for the things the model must *judge*. The
// mechanical fields are filled in by the extension itself — `skill` comes from
// the active run, `reports` from markdown paths observed during the run, and
// severity is normalised server-side (findings.mjs coerces any unknown value to
// `info`). Every word removed here is a word the model doesn't have to carry.
//
// Naming `invoke_canvas_action` is what earns its place: `record_finding` is a
// canvas action, so "call record_finding" sent the agent hunting for a tool
// that isn't in its list. Pointing at the right verb is enough — it can work
// out the rest.
export const DEFAULT_RECORD_PROMPT =
    "When done, record the result: `invoke_canvas_action` on the Mission Control panel with `actionName` " +
    "`record_finding`. Pass a `title`, `severity`, and a 1-3 sentence `summary`; add `metrics`/`entities` where " +
    "relevant, and give each `recommended` follow-up a `reason` and a tailored `prompt` carrying this finding's " +
    "evidence. Always record, even clean results.";

export const MEMORY_PROMPT_KEY = "mc.prompt.memory";
export const RECORD_PROMPT_KEY = "mc.prompt.record";
// The compose-bar "use memory" checkbox. Written by the client through the
// localStorage mirror, but read on the server too — autopilot launches never
// pass through the compose bar, so the server has to apply the preamble itself.
export const MEMORY_ENABLED_KEY = "mc.useMemory";

// ---- Autopilot governors ----
//
// Config lives here because it's durable and shared; the *runtime* state
// (counters, pause reason, chain trail) belongs to the per-session activity
// ledger instead, since only the owning session can act on it.

export const AUTOPILOT_DEFAULTS = Object.freeze({
    maxRuns: 8,
    maxAic: 2000, // 1 AIC = $0.01, so ~$20 per autopilot session
    maxDepth: 3,
    minSeverity: "medium",
    // Inline: markdown reports cost materially more per run, and autopilot is
    // the one place where that compounds — every extra AIC a report costs is an
    // investigation the budget no longer buys. Switch it per-chain when the
    // output is worth keeping.
    output: "inline",
});

// Absolute ceilings, applied on top of whatever is stored. Autopilot spends real
// credits without asking, so a mistyped preference must not be able to run away.
export const AUTOPILOT_CEILINGS = Object.freeze({ maxRuns: 25, maxAic: 20000, maxDepth: 6 });

export const AUTOPILOT_KEYS = Object.freeze({
    maxRuns: "mc.autopilot.maxRuns",
    maxAic: "mc.autopilot.maxAic",
    maxDepth: "mc.autopilot.maxDepth",
    minSeverity: "mc.autopilot.minSeverity",
    output: "mc.autopilot.output",
});

// Mirrors manifest.mjs OUTPUT_MODES. Kept as a plain set so prefs.mjs stays
// dependency-free; an unknown value falls back to the default.
const OUTPUT_VALUES = new Set(["inline", "markdown"]);

// `clean` is deliberately absent: a floor of "chase everything including clean
// results" is never what someone means, and would burn the budget on dead ends.
const SEVERITY_FLOORS = new Set(["critical", "high", "medium", "low", "info"]);

function clampInt(raw, fallback, min, max) {
    const n = Math.round(Number(raw));
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}

/** The autopilot governors in force, clamped to the hard ceilings. */
export function autopilotLimits(prefs) {
    const p = prefs || {};
    const sev = String(p[AUTOPILOT_KEYS.minSeverity] || "").toLowerCase().trim();
    const out = String(p[AUTOPILOT_KEYS.output] || "").toLowerCase().trim();
    return {
        maxRuns: clampInt(p[AUTOPILOT_KEYS.maxRuns], AUTOPILOT_DEFAULTS.maxRuns, 1, AUTOPILOT_CEILINGS.maxRuns),
        maxAic: clampInt(p[AUTOPILOT_KEYS.maxAic], AUTOPILOT_DEFAULTS.maxAic, 50, AUTOPILOT_CEILINGS.maxAic),
        maxDepth: clampInt(p[AUTOPILOT_KEYS.maxDepth], AUTOPILOT_DEFAULTS.maxDepth, 1, AUTOPILOT_CEILINGS.maxDepth),
        minSeverity: SEVERITY_FLOORS.has(sev) ? sev : AUTOPILOT_DEFAULTS.minSeverity,
        output: OUTPUT_VALUES.has(out) ? out : AUTOPILOT_DEFAULTS.output,
    };
}

// A stored empty string is meaningful — it means "disabled" — so only fall back
// to the default when the key is absent entirely.
function resolve(prefs, key, fallback) {
    const v = prefs ? prefs[key] : undefined;
    return typeof v === "string" ? v : fallback;
}

/** The memory preamble template in force (may contain `{file}`). */
export function memoryPromptTemplate(prefs) {
    return resolve(prefs, MEMORY_PROMPT_KEY, DEFAULT_MEMORY_PROMPT);
}

/** Whether the memory preamble is switched on. Absent key = on. */
export function memoryEnabled(prefs) {
    return (prefs || {})[MEMORY_ENABLED_KEY] !== "0";
}

/** The record-finding directive in force. */
export function recordPromptTemplate(prefs) {
    return resolve(prefs, RECORD_PROMPT_KEY, DEFAULT_RECORD_PROMPT);
}

// Only the client's own namespaced keys are accepted, so a stray setItem from
// anything else on the page can never reach disk.
function validKey(k) {
    return typeof k === "string" && k.startsWith("mc.") && k.length <= 120;
}

/** Load persisted UI prefs as a flat string map. Never throws. */
export async function loadPrefs(repoRoot) {
    try {
        const raw = await readFile(storePath(repoRoot), "utf8");
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
        const out = {};
        for (const [k, v] of Object.entries(parsed)) {
            if (validKey(k) && typeof v === "string") out[k] = v;
        }
        return out;
    } catch {
        return {};
    }
}

/**
 * Merge a patch into the stored prefs and persist. A null/undefined value
 * deletes the key, mirroring localStorage.removeItem. Returns the merged map.
 */
export async function savePrefs(repoRoot, patch) {
    const current = await loadPrefs(repoRoot);
    if (patch && typeof patch === "object" && !Array.isArray(patch)) {
        for (const [k, v] of Object.entries(patch)) {
            if (!validKey(k)) continue;
            if (v === null || v === undefined) {
                delete current[k];
                continue;
            }
            const s = String(v);
            if (s.length > MAX_VALUE_LEN) continue; // silently ignore oversized values
            current[k] = s;
        }
    }
    // Trim oldest-inserted keys if a client ever goes haywire; insertion order
    // is preserved by Object.entries, so this keeps the most recent writes.
    let entries = Object.entries(current);
    if (entries.length > MAX_KEYS) entries = entries.slice(entries.length - MAX_KEYS);
    const merged = Object.fromEntries(entries);

    const p = storePath(repoRoot);
    await mkdir(path.dirname(p), { recursive: true });
    await writeFile(p, JSON.stringify(merged, null, 2), "utf8");
    return merged;
}
