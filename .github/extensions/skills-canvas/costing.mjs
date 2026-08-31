// Persistent AI-credit cost ledger for Mission Control. The Findings tab can be
// pruned or cleared, but cost history should survive so the Costing tab keeps an
// accurate long-term picture of AI-credit spend. Every credited finding is
// mirrored here as a compact, append-only record keyed by the finding id. The
// record keeps skill-linked metadata (skill, domains, severity, scope) so the
// by-skill breakdown still works after the originating findings are gone.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

function storePath(repoRoot) {
    return path.join(repoRoot, ".github", "extensions", "skills-canvas", "state", "costing.json");
}

/** Load the persisted cost ledger array (chronological, oldest first). Never throws. */
export async function loadCosting(repoRoot) {
    try {
        const raw = await readFile(storePath(repoRoot), "utf8");
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

async function saveCosting(repoRoot, rows) {
    const p = storePath(repoRoot);
    await mkdir(path.dirname(p), { recursive: true });
    await writeFile(p, JSON.stringify(rows, null, 2), "utf8");
}

// Reduce a finding (or a finding-shaped seed record) to the compact cost row we
// persist. Returns null when the finding carries no positive AI-credit cost.
function toCostRecord(finding) {
    const naiu = Number(finding.creditsNaiu);
    if (!Number.isFinite(naiu) || naiu <= 0) return null;
    return {
        id: String(finding.id || ""),
        ts: Number(finding.ts) || Date.now(),
        skill: String(finding.skill || "unknown").slice(0, 80),
        title: String(finding.title || "").slice(0, 200),
        severity: String(finding.severity || "info").slice(0, 16),
        scope: finding.scope ? String(finding.scope).slice(0, 120) : "",
        domains: Array.isArray(finding.domains) ? finding.domains.slice(0, 8).map(String) : [],
        model: String(finding.model || "unknown").slice(0, 60),
        creditsNaiu: Math.round(naiu),
    };
}

/**
 * Append one finding's cost to the ledger. No-op when the finding has no cost.
 * Deduplicates by finding id and keeps the ledger sorted chronologically
 * (oldest first) so trend buckets read cleanly. Returns the stored record (or
 * null when nothing was recorded).
 */
export async function addCosting(repoRoot, finding) {
    const rec = toCostRecord(finding);
    if (!rec) return null;
    const rows = await loadCosting(repoRoot);
    if (rec.id && rows.some((r) => r.id === rec.id)) return null;
    rows.push(rec);
    rows.sort((a, b) => (Number(a.ts) || 0) - (Number(b.ts) || 0));
    await saveCosting(repoRoot, rows);
    return rec;
}

/**
 * Seed the ledger from the existing findings array — one-time migration so cost
 * history that predates this store isn't lost. Only runs when the ledger is
 * empty; otherwise it's a no-op. Returns the resulting ledger.
 */
export async function seedCostingFromFindings(repoRoot, findings) {
    const existing = await loadCosting(repoRoot);
    if (existing.length) return existing;
    const seen = new Set();
    const rows = [];
    for (const f of Array.isArray(findings) ? findings : []) {
        const rec = toCostRecord(f);
        if (!rec) continue;
        if (rec.id && seen.has(rec.id)) continue;
        if (rec.id) seen.add(rec.id);
        rows.push(rec);
    }
    rows.sort((a, b) => (Number(a.ts) || 0) - (Number(b.ts) || 0));
    if (rows.length) await saveCosting(repoRoot, rows);
    return rows;
}

/** Small rollup for the API payload: record count + total nano-AI units. */
export function summarizeCosting(rows) {
    let totalNaiu = 0;
    for (const r of rows) totalNaiu += Number(r.creditsNaiu) || 0;
    return { count: rows.length, totalNaiu };
}
