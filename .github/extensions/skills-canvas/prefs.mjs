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
export const DEFAULT_RECORD_PROMPT =
    "When done, call `record_finding` with a `title`, `severity`, and a 1-3 sentence `summary`; add " +
    "`metrics`/`entities` where relevant, and give each `recommended` follow-up a `reason` and a tailored `prompt` " +
    "carrying this finding's evidence. Always record, even clean results.";

export const MEMORY_PROMPT_KEY = "mc.prompt.memory";
export const RECORD_PROMPT_KEY = "mc.prompt.record";

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
