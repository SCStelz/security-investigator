// Autopilot — autonomous follow-up chasing for Mission Control.
//
// The hunt loop is fully automated except one step: an analyst clicking a
// follow-up on a recorded finding. The judgement already happened when the agent
// authored that recommendation — it carries a skill, an entity, a reason and a
// prompt built from the finding's own evidence — so the click itself is
// mechanical. Autopilot performs it, under governors, with a hard stop for
// findings that deserve human eyes.
//
// Deliberately adds NO new execution machinery. It calls the same launch path a
// click does, so the launch lands in the existing one-at-a-time queue and is
// dispatched by promoteQueued() on run close. That sequencing is automatic:
// record_finding fires while the originating run is still open, so the follow-up
// is always queued rather than racing the run it came from.
//
// Scope is the owning session only. Autopilot lives in the extension process
// that runs the agent, so it can only ever chase findings its own session
// produced. Other sessions observe the state through the shared ledger but never
// act on it — anything else would mean session B silently spending credits
// because of something session A found.

import { autopilotLimits } from "./prefs.mjs";

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, clean: 5 };
const MAX_TRAIL = 24;

// Injected by extension.mjs at load: { log, launch, limits, credits, knownSkills, getFinding }.
let hooks = null;
let state = null;

export function initAutopilot(deps) {
    hooks = deps || null;
}

function rank(sev) {
    const r = SEVERITY_RANK[String(sev || "").toLowerCase()];
    return Number.isFinite(r) ? r : SEVERITY_RANK.info;
}

function dedupeKey(skill, entity) {
    return String(skill || "").toLowerCase() + "|" + String(entity || "").toLowerCase();
}

/** Credits autopilot has spent since it was armed (or since the last fresh allowance). */
function spentAic() {
    if (!state || !hooks?.credits) return 0;
    const now = Number(hooks.credits()) || 0;
    return Math.max(0, (now - state.baselineNaiu) / 1e9);
}

async function log(message, sticky) {
    if (!hooks?.log) return;
    try {
        await hooks.log(message, { sticky: sticky === true });
    } catch {
        /* logging is best-effort */
    }
}

function push(kind, info) {
    if (!state) return;
    state.trail.unshift({
        ts: Date.now(),
        kind,
        skill: String(info?.skill || ""),
        entity: String(info?.entity || ""),
        depth: Number.isFinite(info?.depth) ? info.depth : null,
        note: String(info?.note || "").slice(0, 240),
    });
    if (state.trail.length > MAX_TRAIL) state.trail.length = MAX_TRAIL;
    // Every transition passes through here, so this is the one place that has to
    // flush the ledger. Without it, enabling autopilot outside a run leaves the
    // shared activity file stale and no canvas — including this session's — sees
    // the state change until the next run happens to write.
    hooks?.flush?.();
}

/**
 * Re-read the governors mid-flight. Saving new limits while a chain is running
 * should take effect now, not on the next enable — otherwise the settings pane
 * lies about what is actually constraining the loop.
 */
export function applyAutopilotLimits(limits) {
    if (!state || !limits) return autopilotSnapshot();
    state.limits = limits;
    hooks?.flush?.();
    return autopilotSnapshot();
}

/** Serialisable view for the ledger and the canvas. */
export function autopilotSnapshot() {
    if (!state) return { status: "off", trail: [] };
    return {
        status: state.status,
        reason: state.reason,
        findingId: state.findingId,
        findingTitle: state.findingTitle,
        startedAt: state.startedAt,
        runsUsed: state.runsUsed,
        spentAic: Math.round(spentAic()),
        depth: state.depth,
        limits: { ...state.limits },
        trail: state.trail.slice(0, MAX_TRAIL),
    };
}

export function autopilotActive() {
    return !!state && (state.status === "armed" || state.status === "running");
}

/**
 * Arm autopilot. Re-enabling resets counters and starts a fresh credit baseline.
 *
 * With { coldStart: true } it also works the existing board immediately instead
 * of idling until the next finding lands — the same sweep a dried-up branch
 * uses, so a cold start and a mid-chain hop behave identically.
 */
export async function enableAutopilot(opts) {
    const limits = await hooks.limits();
    state = {
        status: "armed",
        reason: "",
        findingId: "",
        findingTitle: "",
        startedAt: Date.now(),
        baselineNaiu: Number(hooks.credits?.()) || 0,
        runsUsed: 0,
        depth: 0,
        limits,
        // "skill|entity" pairs already chased, so a repeated recommendation
        // doesn't send the loop round in a circle. Seeded from work that
        // already happened — arming is not a reason to redo it.
        seen: await alreadyChased(),
        trail: [],
        // Guards against a chatty agent calling record_finding twice in one turn
        // and multiplying the chain regardless of the branching factor.
        lastChasedRunId: "",
    };
    push("enabled", {
        note: `${limits.maxRuns} runs · ${limits.maxAic} AIC · depth ${limits.maxDepth} · ≥${limits.minSeverity}`,
    });
    await log(
        `🛰️ Autopilot armed — up to ${limits.maxRuns} runs, ${limits.maxAic} AIC, depth ${limits.maxDepth}, findings ≥ ${limits.minSeverity}. Critical findings pause for approval.`,
        true,
    );

    if (opts?.coldStart) {
        const hit = await sweepBoard();
        if (!hit) {
            await log("🛰️ Autopilot: nothing on the board to chase yet — waiting for the next finding.");
        } else if (
            String(hit.finding.severity).toLowerCase() === "critical" &&
            hit.finding.autopilotVerdict?.decision !== "approved"
        ) {
            await pause("critical", hit.finding);
        } else {
            await log(`🛰️ Autopilot: starting from the board — ${hit.count} open finding${hit.count === 1 ? "" : "s"} still have untried follow-ups.`);
            await advance(hit.finding);
        }
    }

    return autopilotSnapshot();
}

/** Turn autopilot off. The trail is retained so the chain stays reviewable. */
export async function stopAutopilot(note) {
    if (!state) return autopilotSnapshot();
    const wasPaused = state.status === "paused";
    state.status = "off";
    state.reason = "";
    push("stopped", { note: note || "" });
    await log(`🛰️ Autopilot stopped after ${state.runsUsed} run${state.runsUsed === 1 ? "" : "s"} (${Math.round(spentAic())} AIC).${wasPaused ? " Paused chain abandoned." : ""}`, true);
    return autopilotSnapshot();
}

/**
 * Release a pause.
 *
 * From a `critical` pause this means "approved" — chase that finding's top lead,
 * skipping the critical gate once. From a governor pause it starts a FRESH
 * allowance (new baseline, counters reset), because resuming into a limit that
 * immediately re-trips would be worse than useless.
 */
export async function resumeAutopilot() {
    if (!state || state.status !== "paused") return autopilotSnapshot();
    const reason = state.reason;
    const findingId = state.findingId;
    state.status = "armed";
    state.reason = "";

    if (reason === "runs" || reason === "budget") {
        state.limits = await hooks.limits();
        state.baselineNaiu = Number(hooks.credits?.()) || 0;
        state.runsUsed = 0;
        state.findingId = "";
        state.findingTitle = "";
        push("resumed", { note: "fresh allowance" });
        await log(`🛰️ Autopilot resumed with a fresh allowance — ${state.limits.maxRuns} runs, ${state.limits.maxAic} AIC.`, true);
        return autopilotSnapshot();
    }

    push("resumed", { note: "critical finding approved" });
    await log("🛰️ Autopilot resumed — critical finding approved, continuing the chain.", true);
    const finding = findingId && hooks.getFinding ? await hooks.getFinding(findingId) : null;
    state.findingId = "";
    state.findingTitle = "";
    if (!finding) {
        await endChain("the approved finding is no longer in the ledger");
        return autopilotSnapshot();
    }
    // The originating run is long closed; clear the guard so the approved
    // finding can be chased even though its run already had its turn.
    state.lastChasedRunId = "";
    await advance(finding);
    return autopilotSnapshot();
}

/**
 * The decision point. Called right after a finding is persisted, while its run
 * is still open — so anything launched here queues behind that run.
 */
export async function autopilotOnFinding(finding, run) {
    if (!state || (state.status !== "armed" && state.status !== "running")) return;
    if (!finding) return;

    const runId = String(run?.runId || "");
    if (runId) {
        if (state.lastChasedRunId === runId) return;
        state.lastChasedRunId = runId;
    }

    // Human-in-the-loop. At critical, an analyst's judgement is worth more than
    // another automated hop, so the loop stops dead and waits.
    if (String(finding.severity).toLowerCase() === "critical") {
        await pause("critical", finding);
        return;
    }
    await advance(finding);
}

/** Governors + lead selection. Shared by the finding hook and by approve-resume. */
async function advance(finding) {
    const depth = Number(finding.origin?.depth) || 0;
    state.depth = depth;

    if (rank(finding.severity) > rank(state.limits.minSeverity)) {
        await endChain(`the ${finding.severity} finding is below the ${state.limits.minSeverity} floor`);
        return;
    }
    if (state.runsUsed >= state.limits.maxRuns) {
        await pause("runs", finding);
        return;
    }
    if (spentAic() >= state.limits.maxAic) {
        await pause("budget", finding);
        return;
    }
    if (depth + 1 > state.limits.maxDepth) {
        await endChain(`the chain reached the depth-${state.limits.maxDepth} limit`);
        return;
    }

    const lead = await pickLead(finding);
    if (!lead) {
        await endChain("no eligible follow-up remains on this finding");
        return;
    }
    await chase(lead, finding, depth + 1);
}

/**
 * Top *eligible* recommendation, in the order the agent ranked them. Falling
 * through duplicates matters: a repeated recommendation should narrow the chain,
 * not silently kill it.
 */
async function pickLead(finding, seen) {
    const chased = seen || state?.seen || new Set();
    let known = null;
    try {
        known = hooks.knownSkills ? await hooks.knownSkills() : null;
    } catch {
        known = null;
    }
    for (const r of finding.recommended || []) {
        const skill = String(r?.skill || "").trim();
        if (!skill) continue;
        if (known && known.size && !known.has(skill)) continue;
        const entity = String(r?.entity || "");
        const key = dedupeKey(skill, entity);
        if (chased.has(key)) continue;
        return { skill, entity, key, reason: String(r?.reason || ""), prompt: String(r?.prompt || "") };
    }
    return null;
}

async function chase(lead, parent, depth) {
    state.seen.add(lead.key);
    state.status = "running";
    state.depth = depth;
    state.runsUsed += 1;
    const label = lead.skill + (lead.entity ? ` (${lead.entity})` : "");

    push("launched", { skill: lead.skill, entity: lead.entity, depth, note: lead.reason });
    let res = null;
    try {
        res = await hooks.launch({
            skill: lead.skill,
            entity: lead.entity,
            prompt: lead.prompt,
            output: state.limits.output || "",
            autopilot: { depth, parentFindingId: parent.id },
        });
    } catch (err) {
        res = { ok: false, error: err.message };
    }
    if (!res || res.ok === false) {
        state.runsUsed = Math.max(0, state.runsUsed - 1);
        await endChain(`${label} could not be launched — ${res?.error || "unknown error"}`);
        return;
    }
    await log(`🛰️ Autopilot → ${label} · depth ${depth} · run ${state.runsUsed}/${state.limits.maxRuns} · ${Math.round(spentAic())}/${state.limits.maxAic} AIC`);
}

const PAUSE_TEXT = {
    critical: (s, f) => `⛔ Autopilot paused — critical finding needs a human: "${f?.title || "untitled"}". Approve in Mission Control to continue the chain, or stop.`,
    runs: (s) => `⛔ Autopilot paused — run limit reached (${s.runsUsed}/${s.limits.maxRuns}). Resuming starts a fresh allowance.`,
    budget: (s) => `⛔ Autopilot paused — AIC budget spent (${Math.round(spentAic())}/${s.limits.maxAic}). Resuming starts a fresh allowance.`,
};

async function pause(reason, finding) {
    state.status = "paused";
    state.reason = reason;
    state.findingId = String(finding?.id || "");
    state.findingTitle = String(finding?.title || "");
    push("paused", { note: reason, skill: String(finding?.skill || "") });
    const text = PAUSE_TEXT[reason];
    await log(text ? text(state, finding) : `⛔ Autopilot paused (${reason}).`, true);
}

/**
 * The board sweep. A single finding's recommendations running dry says nothing
 * about the rest of the board — the seeding hunt usually records several
 * findings, and every chased finding contributes its own untried leads. Since
 * autopilot is the only thing launching runs once it's armed, going idle here
 * would strand all of that work.
 *
 * Returns the best open finding that still has an eligible, unseen lead:
 * highest severity first, most recent as the tiebreak. Findings already
 * stopped by an analyst are respected; ones already approved are not re-held.
 */
/**
 * Reconstruct which leads have already been followed.
 *
 * Two independent sources, because neither is sufficient alone:
 *
 *  - Finding lineage. A finding carrying origin.autopilot proves its parent's
 *    recommendation for that skill was chased.
 *  - The run ledger. A run that finished WITHOUT recording a finding leaves no
 *    lineage at all, so lineage alone would re-chase it forever. The ledger
 *    records every run that actually executed, recorded or not.
 *
 * The ledger is also the more honest source for a different reason: a lead that
 * was launched but then dropped by a pause never ran, so it correctly stays
 * unseen and gets picked up again.
 *
 * Hand-launched runs count too. If the analyst just investigated a host, that
 * work is done — autopilot spending credits to redo it is the same waste
 * whoever started it.
 */
function seedSeen(all, recent) {
    const seen = new Set();

    const byId = new Map((all || []).map((f) => [f.id, f]));
    for (const f of all || []) {
        const parent = f.origin?.autopilot ? byId.get(f.origin.parentFindingId) : null;
        if (!parent) continue;
        const rec = (parent.recommended || []).find((r) => r?.skill === f.skill);
        if (rec) seen.add(dedupeKey(rec.skill, rec.entity || ""));
    }

    for (const r of recent || []) {
        if (r?.skill) seen.add(dedupeKey(r.skill, r.entity || ""));
    }

    return seen;
}

/** Everything already investigated, from both sources. Never throws. */
async function alreadyChased() {
    let all = [];
    let recent = [];
    try {
        all = (await hooks.listFindings?.()) || [];
    } catch {
        all = [];
    }
    try {
        recent = (await hooks.recentRuns?.()) || [];
    } catch {
        recent = [];
    }
    return seedSeen(all, recent);
}

async function sweepBoard(limits, seen) {
    if (!hooks.listFindings) return null;
    const lim = limits || state?.limits;
    const chased = seen || state?.seen || new Set();
    if (!lim) return null;
    let all = [];
    try {
        all = (await hooks.listFindings()) || [];
    } catch {
        return null;
    }

    const eligible = all.filter((f) => {
        if (!f || !f.id) return false;
        if (f.autopilotVerdict?.decision === "stopped") return false;
        if (rank(f.severity) > rank(lim.minSeverity)) return false;
        // Depth is measured from the finding we'd be branching off, so a lead
        // hanging off a deep finding is still correctly capped.
        const d = Number(f.origin?.depth) || 0;
        return d + 1 <= lim.maxDepth;
    });

    eligible.sort(
        (a, b) => rank(a.severity) - rank(b.severity) || Number(b.ts || 0) - Number(a.ts || 0),
    );

    const hits = [];
    for (const f of eligible) {
        const lead = await pickLead(f, chased);
        if (lead) hits.push({ finding: f, lead });
    }
    return hits.length ? { ...hits[0], count: hits.length } : null;
}

/**
 * What a cold start would do right now, without arming anything. Lets the UI
 * offer "start from the board" only when the board actually has work — an
 * offer that turns out to be empty is worse than no offer.
 */
export async function autopilotBoardPreview() {
    if (!hooks?.limits || !hooks?.listFindings) return { count: 0 };
    let lim = null;
    try {
        lim = await hooks.limits();
    } catch {
        return { count: 0 };
    }
    const hit = await sweepBoard(lim, await alreadyChased());
    if (!hit) return { count: 0 };
    return {
        count: hit.count,
        severity: String(hit.finding.severity || ""),
        title: String(hit.finding.title || ""),
        skill: hit.lead.skill,
        entity: hit.lead.entity || "",
    };
}

/**
 * A branch ran out of leads. Sweep the rest of the board first; only when
 * nothing is left anywhere does the run end.
 *
 * What happens then depends on whether autopilot actually did anything. Having
 * worked the board to exhaustion is a finished job, so it stands down and the
 * chip clears — leaving it armed would show a live counter for something that
 * will never move again. But an autopilot armed moments ago that hasn't chased
 * anything yet is waiting for the seed hunt by design, so it stays armed.
 */
async function endChain(note) {
    if (!state) return;

    const next = await sweepBoard();
    if (next) {
        push("chain-end", { note: `${note} — moving to the next open finding` });
        await log(`🛰️ Autopilot: branch ended — ${note}. Picking up the next open finding.`);
        // A critical finding still buys a human's attention, wherever it was
        // found — unless an analyst already approved this one.
        if (
            String(next.finding.severity).toLowerCase() === "critical" &&
            next.finding.autopilotVerdict?.decision !== "approved"
        ) {
            await pause("critical", next.finding);
            return;
        }
        await advance(next.finding);
        return;
    }

    state.reason = "";
    state.findingId = "";
    state.findingTitle = "";

    if (state.runsUsed > 0) {
        const runs = state.runsUsed;
        const spent = Math.round(spentAic());
        // Status first: push() flushes the ledger, and that flush has to carry
        // the terminal state or the canvas keeps rendering a live chip.
        state.status = "off";
        state.depth = 0;
        push("complete", { note: `${note} — board exhausted after ${runs} run${runs === 1 ? "" : "s"}` });
        await log(
            `🛰️ Autopilot complete — ${runs} run${runs === 1 ? "" : "s"}, ${spent} AIC. Nothing left to chase (${note}). Click Autopilot to arm it again.`,
            true,
        );
        return;
    }

    state.status = "armed";
    push("chain-end", { note });
    await log(`🛰️ Autopilot: chain ended — ${note}. Still armed for the next finding.`);
}

/**
 * Watchdog. An autopilot run that closes without recording a finding has broken
 * the chain; without this the loop stalls while still looking healthy.
 */
export async function autopilotOnRunClosed(run) {
    if (!state || state.status !== "running") return;
    if (!run?.autopilot) return; // a hand-launched run isn't ours to reason about
    if (run.findingId) return; // the finding hook already decided what happens next
    await endChain("the run finished without recording a finding");
}

/**
 * Gate a queued launch at promotion time. Autopilot-tagged entries are dropped
 * when autopilot has since been stopped or paused, and the budget is re-checked
 * because the originating run's final credits land between enqueue and promote.
 *
 * Returns { ok } — human-queued entries always pass.
 */
export async function autopilotAllowsPromotion(entry) {
    if (!entry?.autopilot) return { ok: true };
    if (!state || state.status === "off") return { ok: false, reason: "autopilot stopped" };
    if (state.status === "paused") return { ok: false, reason: "autopilot paused" };
    if (spentAic() >= state.limits.maxAic) {
        await pause("budget", null);
        return { ok: false, reason: "AIC budget spent" };
    }
    return { ok: true };
}
