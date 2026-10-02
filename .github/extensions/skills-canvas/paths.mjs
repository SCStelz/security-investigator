// Runtime state location for Mission Control.
//
// State lives OUTSIDE `.github/extensions/` on purpose: the Copilot App's
// repository-trust hash covers every file under `.github/extensions/**`
// (gitignore does not exclude files from it), so writing runtime data there
// invalidates trust and disables project extensions on every write.

import { existsSync, mkdirSync, cpSync } from "node:fs";
import path from "node:path";

export const STATE_DIRNAME = ".mission-control";

/** Root of all Mission Control runtime state: `<repo>/.mission-control`. */
export function stateRoot(repoRoot) {
    return path.join(repoRoot, STATE_DIRNAME);
}

/** Pre-relocation state dir, read only by the one-time migration. */
export function legacyStateRoot(repoRoot) {
    return path.join(repoRoot, ".github", "extensions", "skills-canvas", "state");
}

const MIGRATE_ITEMS = ["findings.json", "costing.json", "prefs.json", "archive", "activity"];

/**
 * One-time copy of live data from the legacy state dir. Runs only when none of
 * the target items exist yet in the new location; never deletes the legacy dir
 * (removing it changes the trust hash, so that's a deliberate manual step).
 * Synchronous so it completes before any module reads state. Never throws.
 */
export function migrateLegacyState(repoRoot) {
    try {
        const legacy = legacyStateRoot(repoRoot);
        if (!existsSync(legacy)) return [];
        const root = stateRoot(repoRoot);
        if (MIGRATE_ITEMS.some((n) => existsSync(path.join(root, n)))) return [];
        mkdirSync(root, { recursive: true });
        const copied = [];
        for (const name of MIGRATE_ITEMS) {
            const src = path.join(legacy, name);
            if (!existsSync(src)) continue;
            try {
                cpSync(src, path.join(root, name), { recursive: true, errorOnExist: false, force: false });
                copied.push(name);
            } catch {
                // Best-effort per item.
            }
        }
        return copied;
    } catch {
        return [];
    }
}
