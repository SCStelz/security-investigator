// sequenceDiagram -> SVG. Covers the subset used by the investigation reports
// in this repo: participants/actors, solid and dashed messages, self-calls,
// autonumbering, notes, and coloured `rect` bands.
//
//   sequenceDiagram
//     autonumber
//     actor U as user@example.com
//     participant A as Agent
//     U->>A: request
//     A-->>U: reply
//     Note over U,A: something worth calling out
//     rect rgb(30,58,95)
//       A->>A: retry
//     end
//
// Layout is a fixed set of columns and a sequential stack of rows, so unlike
// the flowchart renderer there is no graph layout step — only width fitting.

import { esc, textWidth, textLines, svgText, FONT_STACK } from "./svgutil.mjs";

const THEME = {
    text: "#c9d1d9",
    muted: "#adbac7",
    line: "#8b949e",
    lifeline: "#3d4753",
    boxFill: "#21262d",
    boxStroke: "#444c56",
    noteFill: "#1c2128",
    noteStroke: "#4a5568",
    bg: "#0f141a",
};

const FONT = 12.5;
const LINE_H = 17;
const HEAD_PAD_X = 14;
const HEAD_MIN_W = 96;
const HEAD_PAD_Y = 9;
const COL_GAP = 40;
const MARGIN = 18;
const MSG_PAD = 12;
const NOTE_PAD_X = 12;
const NOTE_PAD_Y = 8;
const SELF_W = 46;
const TITLE_SIZE = 14;

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

// Message operators, longest first so "-->>" wins over "-->".
const ARROWS = [
    { op: "-->>", dashed: true, head: "solid" },
    { op: "->>", dashed: false, head: "solid" },
    { op: "--x", dashed: true, head: "cross" },
    { op: "-x", dashed: false, head: "cross" },
    { op: "--)", dashed: true, head: "open" },
    { op: "-)", dashed: false, head: "open" },
    { op: "-->", dashed: true, head: "line" },
    { op: "->", dashed: false, head: "line" },
];

export function parseSequence(src) {
    const lines = String(src).replace(/\r\n/g, "\n").split("\n");
    const order = [];
    const byId = new Map();
    const events = [];
    let seenHeader = false;
    let autonumber = false;
    let title = "";

    const actor = (id, kind) => {
        const key = id.trim();
        if (!key) return null;
        if (!byId.has(key)) {
            const a = { id: key, label: key, actor: kind === "actor" };
            byId.set(key, a);
            order.push(a);
        }
        const a = byId.get(key);
        if (kind === "actor") a.actor = true;
        return a;
    };

    for (const raw of lines) {
        const t = raw.trim();
        if (!t || t.startsWith("%%")) continue;

        if (!seenHeader) {
            if (!/^sequenceDiagram\b/i.test(t)) return null;
            seenHeader = true;
            continue;
        }

        let m;
        if (/^autonumber\b/i.test(t)) { autonumber = true; continue; }
        if ((m = /^title\s+(.+)$/i.exec(t))) { title = m[1].trim(); continue; }

        // participant / actor declarations, with optional "as" label.
        if ((m = /^(participant|actor)\s+(.+)$/i.exec(t))) {
            const kind = m[1].toLowerCase();
            const body = m[2].trim();
            const as = /^(.+?)\s+as\s+(.+)$/i.exec(body);
            const a = actor(as ? as[1] : body, kind);
            if (a && as) a.label = as[2].trim();
            continue;
        }

        // rect rgb(r,g,b) / rgba(r,g,b,a)
        if ((m = /^rect\s+(.+)$/i.exec(t))) {
            const c = /rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)/i.exec(m[1]);
            events.push({
                type: "rect-start",
                fill: c ? "rgb(" + c[1] + "," + c[2] + "," + c[3] + ")" : "#1c2128",
                opacity: c && c[4] !== undefined ? Number(c[4]) : 0.4,
            });
            continue;
        }
        if (/^end$/i.test(t)) { events.push({ type: "rect-end" }); continue; }

        // Note over A,B: text  |  Note left of A: text  |  Note right of A: text
        if ((m = /^note\s+(over|left of|right of)\s+([^:]+):\s*(.*)$/i.exec(t))) {
            const place = m[1].toLowerCase();
            const ids = m[2].split(",").map((s) => s.trim()).filter(Boolean);
            const actors = ids.map((id) => actor(id, "participant")).filter(Boolean);
            if (actors.length) events.push({ type: "note", place, actors, label: m[3].trim() });
            continue;
        }

        // Structural keywords we don't lay out yet — skip the line rather than
        // failing the whole diagram.
        if (/^(loop|alt|else|opt|par|and|critical|option|break|activate|deactivate|box|link|links)\b/i.test(t)) continue;

        // A->>B: message
        let hit = null;
        for (const a of ARROWS) {
            const idx = t.indexOf(a.op);
            if (idx <= 0) continue;
            const colon = t.indexOf(":", idx);
            if (colon < 0) continue;
            const from = t.slice(0, idx).trim();
            const to = t.slice(idx + a.op.length, colon).trim();
            if (!/^[^\s:,;]+$/.test(from) || !/^[^\s:,;]+$/.test(to)) continue;
            hit = { arrow: a, from, to, label: t.slice(colon + 1).trim() };
            break;
        }
        if (hit) {
            const f = actor(hit.from, "participant");
            const g = actor(hit.to, "participant");
            if (f && g) events.push({ type: "msg", from: f, to: g, label: hit.label, arrow: hit.arrow });
        }
    }

    if (!seenHeader || !order.length) return null;
    if (!events.some((e) => e.type === "msg" || e.type === "note")) return null;
    return { actors: order, events, autonumber, title };
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

function measure(lines) {
    let w = 0;
    for (const l of lines) w = Math.max(w, textWidth(l, FONT));
    return w;
}

function layout(d) {
    const A = d.actors;
    const n = A.length;
    const index = new Map(A.map((a, i) => [a.id, i]));

    // Column boxes sized to their own header text.
    for (const a of A) {
        a.lines = textLines(a.label).filter((s) => s !== "");
        if (!a.lines.length) a.lines = [a.id];
        a.w = Math.max(HEAD_MIN_W, Math.ceil(measure(a.lines)) + HEAD_PAD_X * 2);
        a.h = a.lines.length * LINE_H + HEAD_PAD_Y * 2;
    }
    const headH = Math.max(...A.map((a) => a.h));

    // Gaps start uniform, then widen to fit message and note text.
    const gap = new Array(Math.max(0, n - 1)).fill(COL_GAP);
    const centers = () => {
        const c = [];
        let x = 0;
        for (let i = 0; i < n; i++) {
            if (i) x += A[i - 1].w / 2 + gap[i - 1] + A[i].w / 2;
            c.push(x);
        }
        return c;
    };

    let rightPad = 0;
    const spans = [];
    for (const e of d.events) {
        if (e.type === "msg") {
            e.lines = textLines(e.label).filter((s) => s !== "");
            const a = index.get(e.from.id);
            const b = index.get(e.to.id);
            e.a = a;
            e.b = b;
            const w = Math.ceil(measure(e.lines));
            if (a === b) rightPad = Math.max(rightPad, SELF_W + w + 24);
            else spans.push({ lo: Math.min(a, b), hi: Math.max(a, b), need: w + MSG_PAD * 2 });
        } else if (e.type === "note") {
            e.lines = textLines(e.label).filter((s) => s !== "");
            const idx = e.actors.map((a) => index.get(a.id)).filter((i) => i !== undefined);
            e.a = Math.min(...idx);
            e.b = Math.max(...idx);
            const w = Math.ceil(measure(e.lines)) + NOTE_PAD_X * 2;
            if (e.place === "over") spans.push({ lo: e.a, hi: e.b, need: w });
            else if (e.place === "right of") rightPad = Math.max(rightPad, w + 20);
        }
    }

    // Widen narrow spans first so wide ones can reuse the room that creates.
    spans.sort((p, q) => p.hi - p.lo - (q.hi - q.lo));
    for (const s of spans) {
        if (s.hi === s.lo) continue;
        const c = centers();
        const have = c[s.hi] - c[s.lo];
        const deficit = s.need - have;
        if (deficit <= 0) continue;
        const per = deficit / (s.hi - s.lo);
        for (let i = s.lo; i < s.hi; i++) gap[i] += per;
    }

    const c = centers();
    const shift = MARGIN + A[0].w / 2;
    for (let i = 0; i < n; i++) A[i].cx = c[i] + shift;

    // A "Note left of" hangs outside its column and can run past the left
    // edge — most obviously on the first participant, which has only MARGIN
    // to its left. Push every column right by whatever the widest one needs.
    let extraLeft = 0;
    for (const e of d.events) {
        if (e.type !== "note" || e.place !== "left of") continue;
        const w = Math.ceil(measure(e.lines)) + NOTE_PAD_X * 2;
        extraLeft = Math.max(extraLeft, w + 12 - (A[e.a].cx - MARGIN));
    }
    if (extraLeft > 0) for (let i = 0; i < n; i++) A[i].cx += extraLeft;

    // Stack rows.
    let y = MARGIN + (d.title ? TITLE_SIZE + 12 : 0) + headH + 18;
    let num = 0;
    const open = [];
    for (const e of d.events) {
        if (e.type === "rect-start") { e.y0 = y - 6; open.push(e); y += 8; continue; }
        if (e.type === "rect-end") {
            const s = open.pop();
            if (s) { s.y1 = y + 4; y += 10; }
            continue;
        }
        if (e.type === "msg") {
            if (d.autonumber && e.lines.length) e.num = ++num;
            const h = Math.max(1, e.lines.length) * LINE_H;
            if (e.a === e.b) {
                e.y = y + 6;
                e.h = h + 26;
                y += e.h + 10;
            } else {
                e.textTop = y + 4;
                e.y = y + h + 12;
                e.h = h + 20;
                y += e.h + 8;
            }
            continue;
        }
        if (e.type === "note") {
            e.h = Math.max(1, e.lines.length) * LINE_H + NOTE_PAD_Y * 2;
            e.y = y + 4;
            y += e.h + 14;
        }
    }
    // An unterminated rect still needs a bottom edge.
    for (const s of open) s.y1 = y;

    const bottomY = y + 6;
    const width = Math.ceil(A[n - 1].cx + A[n - 1].w / 2 + rightPad + MARGIN);
    const height = Math.ceil(bottomY + headH + MARGIN);
    return { headH, bottomY, width, height };
}

// ---------------------------------------------------------------------------
// SVG emission
// ---------------------------------------------------------------------------

function block(lines, cx, top, color, size, weight) {
    let out = "";
    for (let i = 0; i < lines.length; i++) {
        out += svgText(lines[i], cx, top + (i + 1) * LINE_H - 4, size || FONT, color, "middle", weight ? ' font-weight="' + weight + '"' : "");
    }
    return out;
}

function actorBox(a, y, h) {
    const x = a.cx - a.w / 2;
    const top = y + (h - a.h) / 2;
    let out = "";
    if (a.actor) {
        // Stick figure above the name, so human participants read at a glance.
        const hy = top + 9;
        out += '<circle cx="' + a.cx + '" cy="' + hy.toFixed(1) + '" r="5" fill="none" stroke="' + THEME.boxStroke + '" stroke-width="1.4"/>';
        out += '<path d="M' + a.cx + " " + (hy + 5).toFixed(1) + "v9M" + (a.cx - 6) + " " + (hy + 8).toFixed(1) +
            "h12M" + (a.cx - 5) + " " + (hy + 20).toFixed(1) + "l5-6l5 6" +
            '" fill="none" stroke="' + THEME.boxStroke + '" stroke-width="1.4" stroke-linecap="round"/>';
        out += block(a.lines, a.cx, top + 24, THEME.text, FONT, 600);
    } else {
        out += '<rect x="' + x.toFixed(1) + '" y="' + top.toFixed(1) + '" width="' + a.w + '" height="' + a.h +
            '" rx="5" fill="' + THEME.boxFill + '" stroke="' + THEME.boxStroke + '" stroke-width="1.2"/>';
        out += block(a.lines, a.cx, top + HEAD_PAD_Y, THEME.text, FONT, 600);
    }
    return out;
}

export function renderSequence(src) {
    const d = parseSequence(src);
    if (!d) return null;
    const geo = layout(d);
    if (!isFinite(geo.width) || !isFinite(geo.height) || geo.width <= 0 || geo.height <= 0) return null;

    const headTop = MARGIN + (d.title ? TITLE_SIZE + 12 : 0);
    let out = '<svg xmlns="http://www.w3.org/2000/svg" width="' + geo.width + '" height="' + geo.height +
        '" viewBox="0 0 ' + geo.width + " " + geo.height + '" role="img">';
    out += '<defs>' +
        '<marker id="seqSolid" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">' +
        '<path d="M0 0L10 5L0 10z" fill="' + THEME.line + '"/></marker>' +
        '<marker id="seqOpen" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">' +
        '<path d="M0 0L10 5L0 10" fill="none" stroke="' + THEME.line + '" stroke-width="1.6"/></marker>' +
        "</defs>";

    if (d.title) out += svgText(d.title, geo.width / 2, MARGIN + TITLE_SIZE, TITLE_SIZE, THEME.text, "middle", ' font-weight="600"');

    // Coloured bands sit behind everything else.
    for (const e of d.events) {
        if (e.type !== "rect-start" || e.y1 == null) continue;
        out += '<rect x="' + (MARGIN / 2) + '" y="' + e.y0.toFixed(1) + '" width="' + (geo.width - MARGIN) +
            '" height="' + Math.max(0, e.y1 - e.y0).toFixed(1) + '" rx="6" fill="' + esc(e.fill) +
            '" fill-opacity="' + e.opacity + '"/>';
    }

    // Lifelines, then the participant boxes at both ends.
    const lifeTop = headTop + geo.headH;
    for (const a of d.actors) {
        out += '<line x1="' + a.cx.toFixed(1) + '" y1="' + lifeTop + '" x2="' + a.cx.toFixed(1) + '" y2="' + geo.bottomY.toFixed(1) +
            '" stroke="' + THEME.lifeline + '" stroke-width="1.2" stroke-dasharray="4 4"/>';
        out += actorBox(a, headTop, geo.headH);
        out += actorBox(a, geo.bottomY, geo.headH);
    }

    for (const e of d.events) {
        if (e.type === "msg") {
            const marker = e.arrow.head === "line" ? "seqOpen" : "seqSolid";
            const dash = e.arrow.dashed ? ' stroke-dasharray="6 4"' : "";
            const label = e.num ? String(e.num) + ". " + (e.lines[0] || "") : e.lines[0] || "";
            const shown = e.lines.length ? [label, ...e.lines.slice(1)] : [];

            if (e.a === e.b) {
                // Self-call: out to the right and back.
                const x = e.from.cx;
                const top = e.y;
                const bot = e.y + e.h - 16;
                out += '<path d="M' + x.toFixed(1) + " " + top.toFixed(1) + "h" + SELF_W + "v" + (bot - top).toFixed(1) +
                    "H" + (x + 6).toFixed(1) + '" fill="none" stroke="' + THEME.line + '" stroke-width="1.5"' + dash +
                    ' marker-end="url(#' + marker + ')"/>';
                // Label sits to the right of the loop, left-aligned.
                for (let i = 0; i < shown.length; i++) {
                    out += svgText(shown[i], x + SELF_W + 10, top + (i + 1) * LINE_H - 4, FONT, THEME.muted, "start");
                }
                continue;
            }

            const x1 = e.from.cx;
            const x2 = e.to.cx;
            out += '<line x1="' + x1.toFixed(1) + '" y1="' + e.y.toFixed(1) + '" x2="' + x2.toFixed(1) + '" y2="' + e.y.toFixed(1) +
                '" stroke="' + THEME.line + '" stroke-width="1.5"' + dash + ' marker-end="url(#' + marker + ')"/>';
            if (shown.length) out += block(shown, (x1 + x2) / 2, e.textTop, THEME.muted, FONT);
            continue;
        }

        if (e.type === "note") {
            let x, w;
            if (e.place === "over") {
                const lo = d.actors[e.a];
                const hi = d.actors[e.b];
                const c1 = Math.min(lo.cx, hi.cx);
                const c2 = Math.max(lo.cx, hi.cx);
                w = Math.max(c2 - c1 + lo.w * 0.7, Math.ceil(measure(e.lines)) + NOTE_PAD_X * 2);
                x = (c1 + c2) / 2 - w / 2;
            } else {
                w = Math.ceil(measure(e.lines)) + NOTE_PAD_X * 2;
                const a = d.actors[e.a];
                x = e.place === "right of" ? a.cx + 12 : a.cx - 12 - w;
            }
            out += '<rect x="' + x.toFixed(1) + '" y="' + e.y.toFixed(1) + '" width="' + w.toFixed(1) + '" height="' + e.h +
                '" rx="4" fill="' + THEME.noteFill + '" stroke="' + THEME.noteStroke + '" stroke-width="1.1"/>';
            out += block(e.lines, x + w / 2, e.y + NOTE_PAD_Y, THEME.muted, FONT);
        }
    }

    return out + "</svg>";
}
