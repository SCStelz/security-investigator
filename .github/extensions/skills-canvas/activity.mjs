// Cross-session activity ledger for Mission Control.
//
// Every Copilot session forks its own extension process (SESSION_ID in env) and
// all of them resolve the same repo root — so the shared `state/` directory is a
// zero-infrastructure bus between sessions. Each process writes ONLY its own
// `state/activity/<sessionId>.json`, so there is a single writer per file: no
// locking, no races. Readers merge the whole directory, which is how the
// Findings tab in any one session can show investigations running in all the
// others (even sessions that never opened the canvas — event subscriptions are
// registered at module load, independent of the canvas HTTP server).
//
// This is ephemeral runtime state and lives under the already-gitignored
// `state/` dir, mirroring findings.mjs / costing.mjs conventions.

import { readFile, writeFile, mkdir, readdir, unlink, rename } from "node:fs/promises";
import path from "node:path";

// Coalesce disk writes: tool.execution_start / assistant.usage fire in bursts.
const WRITE_THROTTLE_MS = 1500;
// Refresh updatedAt while a run is active so readers can tell "working" from
// "process died mid-run".
const HEARTBEAT_MS = 20000;
// A run whose heartbeat is older than this is presumed crashed, not working.
const STALE_MS = 90000;
// Session files untouched for this long are deleted on read.
const PRUNE_MS = 12 * 60 * 60 * 1000;
// Completed runs retained per session for the "recent runs" line.
const MAX_RECENT = 8;

function activityDir(repoRoot) {
    return path.join(repoRoot, ".github", "extensions", "skills-canvas", "state", "activity");
}

function safeId(id) {
    return String(id || "unknown").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 120) || "unknown";
}

function activityPath(repoRoot, sessionId) {
    return path.join(activityDir(repoRoot), safeId(sessionId) + ".json");
}

// ---------------------------------------------------------------------------
// Writer side — one session per process.
// ---------------------------------------------------------------------------

let state = null;
let writeTimer = null;
let pendingWrite = false;
let lastWriteAt = 0;
let writing = false;
let heartbeatTimer = null;

/** Initialise the ledger for this process. Safe to call more than once. */
export function initActivity(repoRoot, sessionId) {
    const id = String(sessionId || process.env.SESSION_ID || "unknown");
    if (state && state.sessionId === id) return id;
    state = {
        repoRoot,
        sessionId: id,
        pid: process.pid,
        title: "",
        startedAt: Date.now(),
        updatedAt: Date.now(),
        run: null,
        recent: [],
    };
    return id;
}

export function activitySessionId() {
    return state ? state.sessionId : "";
}

export function hasActiveRun() {
    return !!(state && state.run);
}

export function activeRun() {
    return state ? state.run : null;
}

function snapshot() {
    return {
        sessionId: state.sessionId,
        pid: state.pid,
        title: state.title,
        startedAt: state.startedAt,
        updatedAt: state.updatedAt,
        run: state.run ? { ...state.run } : null,
        recent: state.recent.slice(0, MAX_RECENT),
    };
}

async function flush() {
    if (!state) return;
    // Serialize: two flushes racing on the same path can land out of order and
    // persist a stale snapshot (or let a reader see a half-written file). Any
    // flush requested while one is in flight is collapsed into a single
    // follow-up write that re-snapshots the newest state.
    if (writing) { pendingWrite = true; return; }
    writing = true;
    lastWriteAt = Date.now();
    pendingWrite = false;
    const file = activityPath(state.repoRoot, state.sessionId);
    try {
        await mkdir(activityDir(state.repoRoot), { recursive: true });
        // Write-then-rename so readers never observe a partial JSON document.
        const tmp = file + ".tmp";
        await writeFile(tmp, JSON.stringify(snapshot(), null, 2), "utf8");
        await rename(tmp, file);
    } catch { /* ledger is best-effort; never break the session */ }
    writing = false;
    if (pendingWrite) { pendingWrite = false; void flush(); }
}

// Write now if the throttle window has elapsed, otherwise arm a trailing flush.
// `force` (run start/end) bypasses the throttle so state transitions are never
// delayed behind a burst of progress updates.
function schedule(force) {
    if (!state) return;
    state.updatedAt = Date.now();
    if (force) {
        if (writeTimer) { clearTimeout(writeTimer); writeTimer = null; }
        void flush();
        return;
    }
    if (writeTimer) { pendingWrite = true; return; }
    const since = Date.now() - lastWriteAt;
    if (since >= WRITE_THROTTLE_MS) { void flush(); return; }
    pendingWrite = true;
    writeTimer = setTimeout(() => {
        writeTimer = null;
        if (pendingWrite) void flush();
    }, WRITE_THROTTLE_MS - since);
    if (writeTimer.unref) writeTimer.unref();
}

function startHeartbeat() {
    stopHeartbeat();
    heartbeatTimer = setInterval(() => schedule(true), HEARTBEAT_MS);
    if (heartbeatTimer.unref) heartbeatTimer.unref();
}

function stopHeartbeat() {
    if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = null; }
}

/** Session title (from session.title_changed) — shown as the strip row label. */
export function setSessionTitle(title) {
    if (!state) return;
    const t = String(title || "").slice(0, 120);
    if (!t || t === state.title) return;
    state.title = t;
    schedule(false);
}

/**
 * Open a run. Called from launchSkill() (primary, source "canvas") and from the
 * skill.invoked event (secondary, source "skill-tool"). A second beginRun while
 * one is already open closes the previous one first, so a run can never leak.
 */
export function beginRun(info) {
    if (!state) return null;
    if (state.run) endRun({ reason: "superseded" });
    const now = Date.now();
    state.run = {
        runId: state.sessionId.slice(0, 8) + "-" + now.toString(36),
        skill: String(info?.skill || "investigation").slice(0, 120),
        entity: String(info?.entity || "").slice(0, 160),
        scope: {
            lookback: String(info?.lookback || ""),
            output: String(info?.output || ""),
            fleet: info?.fleet === true,
        },
        source: info?.source === "skill-tool" ? "skill-tool" : "canvas",
        startedAt: now,
        phase: "Starting…",
        tool: "",
        toolCount: 0,
        subagents: 0,
        todos: null,
        creditsNaiu: 0,
        findingId: "",
        error: "",
    };
    startHeartbeat();
    schedule(true);
    return state.run;
}

/** Shallow-merge a patch into the active run. No-op when nothing is running. */
export function updateRun(patch) {
    if (!state || !state.run || !patch) return;
    let changed = false;
    for (const [k, v] of Object.entries(patch)) {
        if (v === undefined) continue;
        if (state.run[k] === v) continue;
        state.run[k] = v;
        changed = true;
    }
    if (changed) schedule(false);
}

/** Record a tool invocation: bumps the counter and updates the live tool chip. */
export function bumpTool(label) {
    if (!state || !state.run) return;
    state.run.toolCount += 1;
    const l = String(label || "").slice(0, 60);
    if (l) state.run.tool = l;
    schedule(false);
}

export function bumpSubagent(delta) {
    if (!state || !state.run) return;
    state.run.subagents = Math.max(0, (state.run.subagents || 0) + (Number(delta) || 0));
    schedule(false);
}

/** Link a recorded finding back to the run so the strip can show it resolved. */
export function markRecorded(findingId) {
    if (!state) return;
    const id = String(findingId || "");
    if (!id) return;
    if (state.run) {
        state.run.findingId = id;
        schedule(true);
        return;
    }
    // record_finding can land just after the turn ended — attach to the newest
    // completed run instead so it isn't flagged as unrecorded.
    const last = state.recent[0];
    if (last && !last.findingId && Date.now() - (last.endedAt || 0) < 120000) {
        last.findingId = id;
        last.recorded = true;
        schedule(true);
    }
}

/** Close the active run and push a compact summary onto the recent list. */
export function endRun(opts) {
    if (!state || !state.run) return;
    const r = state.run;
    const err = String(opts?.error || "");
    if (err) r.error = err.slice(0, 300);
    state.recent.unshift({
        runId: r.runId,
        skill: r.skill,
        entity: r.entity,
        startedAt: r.startedAt,
        endedAt: Date.now(),
        toolCount: r.toolCount,
        creditsNaiu: r.creditsNaiu,
        findingId: r.findingId,
        recorded: !!r.findingId,
        error: r.error,
    });
    state.recent = state.recent.slice(0, MAX_RECENT);
    state.run = null;
    stopHeartbeat();
    schedule(true);
}

/** Remove this session's ledger file (session shutdown). */
export async function clearSession() {
    if (!state) return;
    stopHeartbeat();
    if (writeTimer) { clearTimeout(writeTimer); writeTimer = null; }
    try { await unlink(activityPath(state.repoRoot, state.sessionId)); } catch { /* already gone */ }
}

// ---------------------------------------------------------------------------
// Reader side — merges every session's file.
// ---------------------------------------------------------------------------

/**
 * Merge all session ledgers into a single view. Marks runs whose heartbeat has
 * lapsed as stale (crashed process) rather than leaving a zombie "running" row,
 * and prunes long-dead session files as a side effect.
 */
export async function readActivity(repoRoot, selfSessionId) {
    const dir = activityDir(repoRoot);
    const now = Date.now();
    let names = [];
    try {
        names = await readdir(dir);
    } catch {
        return { active: [], recent: [], sessions: 0, self: selfSessionId || "", now };
    }
    const active = [];
    const recent = [];
    let sessions = 0;
    for (const name of names) {
        if (!name.endsWith(".json")) continue;
        const p = path.join(dir, name);
        let rec = null;
        try { rec = JSON.parse(await readFile(p, "utf8")); } catch { continue; }
        if (!rec || typeof rec !== "object") continue;
        const updatedAt = Number(rec.updatedAt) || 0;
        if (now - updatedAt > PRUNE_MS) { try { await unlink(p); } catch { /* raced */ } continue; }
        sessions += 1;
        const sid = String(rec.sessionId || "");
        const label = String(rec.title || "");
        const self = !!selfSessionId && sid === selfSessionId;
        if (rec.run && typeof rec.run === "object") {
            active.push({
                ...rec.run,
                sessionId: sid,
                sessionTitle: label,
                self,
                stale: now - updatedAt > STALE_MS,
                heartbeatAgo: Math.max(0, Math.round((now - updatedAt) / 1000)),
            });
        }
        for (const r of Array.isArray(rec.recent) ? rec.recent : []) {
            recent.push({ ...r, sessionId: sid, sessionTitle: label, self });
        }
    }
    active.sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0));
    recent.sort((a, b) => (b.endedAt || 0) - (a.endedAt || 0));
    return { active, recent: recent.slice(0, 12), sessions, self: selfSessionId || "", now };
}
