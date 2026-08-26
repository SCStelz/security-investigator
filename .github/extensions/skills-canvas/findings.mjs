// Persistent "Findings" ledger for Mission Control. Skill runs happen in the
// agent turn (not in this process), so the agent pushes structured results back
// via the canvas `record_finding` action. Those are persisted here as a small
// JSON file so they survive extension reloads, and the Findings tab renders them
// with agent-authored (or auto-derived) follow-up skill recommendations.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, clean: 5 };
const VALID_SEVERITY = new Set(Object.keys(SEVERITY_ORDER));

// Entity type -> the skill that best investigates it. Mirrors routeEntity() in
// extension.mjs but keyed by declared type so agent-supplied entities route well.
const ENTITY_SKILL = {
    user: "user-investigation",
    upn: "user-investigation",
    account: "user-investigation",
    ip: "ioc-investigation",
    domain: "ioc-investigation",
    url: "ioc-investigation",
    hash: "ioc-investigation",
    file: "ioc-investigation",
    device: "computer-investigation",
    host: "computer-investigation",
    hostname: "computer-investigation",
    computer: "computer-investigation",
    incident: "incident-investigation",
    spn: "scope-drift-detection/spn",
    app: "app-registration-posture",
};

// Domain tag -> a sensible deeper skill, for findings that carry no entities.
const DOMAIN_SKILL = {
    exposure: "exposure-investigation",
    identity: "identity-posture",
    endpoint: "computer-investigation",
    email: "email-threat-posture",
    cloud: "app-registration-posture",
    incidents: "incident-investigation",
    admin: "app-registration-posture",
    spn: "scope-drift-detection/spn",
};

function storePath(repoRoot) {
    return path.join(repoRoot, ".github", "extensions", "skills-canvas", "state", "findings.json");
}

export function normalizeSeverity(s) {
    const v = String(s || "").toLowerCase().trim();
    return VALID_SEVERITY.has(v) ? v : "info";
}

/** Load the persisted findings array (newest first). Never throws. */
export async function loadFindings(repoRoot) {
    try {
        const raw = await readFile(storePath(repoRoot), "utf8");
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

async function saveFindings(repoRoot, findings) {
    const p = storePath(repoRoot);
    await mkdir(path.dirname(p), { recursive: true });
    await writeFile(p, JSON.stringify(findings, null, 2), "utf8");
}

/**
 * Compact one-line evidence string from a finding: its headline plus the top
 * few metric chips. Used to give auto-derived follow-up prompts real context
 * instead of a generic "use this skill" instruction.
 */
function findingContext(finding) {
    const bits = [];
    if (finding.title) bits.push(`"${finding.title}"`);
    const topMetrics = (finding.metrics || [])
        .slice(0, 4)
        .map((m) => `${m.label}: ${m.value}`)
        .filter(Boolean);
    if (topMetrics.length) bits.push(topMetrics.join(", "));
    return bits.join(" — ");
}

/**
 * Build a context-carrying follow-up prompt when the agent didn't author one.
 * Mirrors the threat-pulse drill-down style: lead with the skill's natural
 * trigger phrasing (so keyword detection loads the right skill), then embed the
 * originating finding's severity, evidence, and summary so the launched skill
 * inherits the context rather than starting cold.
 */
function buildFollowupPrompt({ skill, entity, type, lead, finding }) {
    const ctx = findingContext(finding);
    const parts = [];
    parts.push(lead);
    let provenance = `This follow-up is scoped from a ${finding.severity} finding recorded by ${finding.skill}`;
    if (ctx) provenance += `: ${ctx}`;
    parts.push(provenance + ".");
    if (finding.summary) parts.push(`Prior context: ${finding.summary}`);
    const focus = entity || (type ? `this ${type}` : `the ${(finding.domains || [])[0] || "affected"} area`);
    parts.push(`Focus on ${focus} and correlate your results with the finding above.`);
    return parts.join(" ").slice(0, 1000);
}

/**
 * Derive follow-up recommendations when the agent didn't supply any: route each
 * discovered entity to its investigation skill, then fall back to a domain skill.
 * Each recommendation carries a tailored `prompt` built from the finding's own
 * evidence so a one-click launch runs a context-aware drill-down.
 * Returns [{ skill, entity?, reason, prompt }].
 */
export function autoRecommend(finding, knownSkillNames) {
    const known = knownSkillNames instanceof Set ? knownSkillNames : new Set(knownSkillNames || []);
    const out = [];
    const seen = new Set();
    for (const ent of finding.entities || []) {
        const type = String(ent.type || "").toLowerCase();
        const skill = ENTITY_SKILL[type];
        if (skill && known.has(skill) && !seen.has(skill + "|" + ent.value)) {
            seen.add(skill + "|" + ent.value);
            const lead = `Investigate ${type} ${ent.value}.`;
            out.push({
                skill,
                entity: ent.value,
                reason: `Investigate ${type} ${ent.value}`,
                prompt: buildFollowupPrompt({ skill, entity: ent.value, type, lead, finding }),
            });
        }
    }
    if (!out.length) {
        for (const d of finding.domains || []) {
            const skill = DOMAIN_SKILL[d];
            if (skill && known.has(skill) && !seen.has(skill)) {
                seen.add(skill);
                const lead = `Go deeper on the ${d} domain using the ${skill} skill.`;
                out.push({
                    skill,
                    reason: `Go deeper on ${d}`,
                    prompt: buildFollowupPrompt({ skill, entity: "", type: "", lead, finding }),
                });
            }
        }
    }
    return out.slice(0, 4);
}

/**
 * Append a finding. Sanitizes/normalizes fields, fills auto-recommendations when
 * absent, assigns an id + timestamp, and persists. Returns the stored finding.
 */
export async function addFinding(repoRoot, input, knownSkillNames) {
    const findings = await loadFindings(repoRoot);
    const finding = {
        id: "f_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
        ts: Date.now(),
        skill: String(input.skill || "unknown").slice(0, 80),
        title: String(input.title || "Untitled finding").slice(0, 200),
        severity: normalizeSeverity(input.severity),
        scope: input.scope ? String(input.scope).slice(0, 120) : "",
        summary: String(input.summary || "").slice(0, 1200),
        metrics: Array.isArray(input.metrics)
            ? input.metrics.slice(0, 12).map((m) => ({
                  label: String(m.label || "").slice(0, 60),
                  value: String(m.value ?? "").slice(0, 60),
                  severity: m.severity ? normalizeSeverity(m.severity) : null,
              }))
            : [],
        entities: Array.isArray(input.entities)
            ? input.entities.slice(0, 20).map((e) => ({
                  type: String(e.type || "").slice(0, 24),
                  value: String(e.value || "").slice(0, 200),
              }))
            : [],
        domains: Array.isArray(input.domains) ? input.domains.slice(0, 8).map(String) : [],
        reports: Array.isArray(input.reports)
            ? input.reports
                  .slice(0, 8)
                  .map((r) => {
                      if (typeof r === "string") return { path: r.slice(0, 300), label: "" };
                      return {
                          path: String(r.path || r.url || "").slice(0, 300),
                          label: String(r.label || "").slice(0, 120),
                      };
                  })
                  .filter((r) => r.path)
            : [],
        recommended: [],
    };
    const supplied = Array.isArray(input.recommended) ? input.recommended : [];
    finding.recommended = supplied.length
        ? supplied.slice(0, 6).map((r) => ({
              skill: String(r.skill || "").slice(0, 80),
              entity: r.entity ? String(r.entity).slice(0, 200) : "",
              reason: String(r.reason || "").slice(0, 160),
              // Agent-authored tailored drill-down prompt (threat-pulse style).
              // Sent verbatim when the analyst clicks the follow-up; falls back
              // to the skill's generic manifest prompt only when absent.
              prompt: r.prompt ? String(r.prompt).slice(0, 1000) : "",
          }))
        : autoRecommend(finding, knownSkillNames);

    findings.unshift(finding);
    if (findings.length > 100) findings.length = 100;
    await saveFindings(repoRoot, findings);
    return finding;
}

/** Remove one finding by id. Returns the remaining array. */
export async function dismissFinding(repoRoot, id) {
    const findings = (await loadFindings(repoRoot)).filter((f) => f.id !== id);
    await saveFindings(repoRoot, findings);
    return findings;
}

/** Clear the whole ledger. */
export async function clearFindings(repoRoot) {
    await saveFindings(repoRoot, []);
    return [];
}

/** Small severity rollup for the tab badge / header. */
export function summarize(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, clean: 0 };
    for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
    return { total: findings.length, counts };
}
