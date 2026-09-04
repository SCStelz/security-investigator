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
