// Minimal, dependency-free Mermaid *flowchart* -> inline SVG renderer for the
// Mission Control markdown preview.
//
// The preview is a standalone HTML page served by the extension's local HTTP
// server and loaded into an iframe, so diagrams are generated server-side as
// finished SVG markup: no client script, no CDN, no CSP surface, works offline.
//
// Scope is deliberately narrow — `flowchart` / `graph` in any direction, plus
// `xychart-beta` (delegated to xychart.mjs), which together cover every mermaid
// block this repo produces. Anything else (sequenceDiagram, gantt, pie, ...)
// returns null so md.mjs can fall back to rendering the block as source,
// exactly as it did before.

import { renderXYChart } from "./xychart.mjs";
import { renderPie } from "./pie.mjs";
import { renderSequence } from "./sequence.mjs";
import { esc, textWidth } from "./svgutil.mjs";


// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// Label text -> display lines. <br> variants break the line; any other inline
// HTML (e.g. <small>) is stripped to its text content rather than honored.
// Inline formatting tags mermaid passes through to the label. Restricted to a
// known set so placeholder text like "<Agent Name>" or "<tool / connector>"
// survives as literal text instead of being mistaken for markup.
const INLINE_TAG = /<\/?(?:b|i|u|em|strong|small|span|code|sub|sup|font|div|p)(?:\s[^>]*)?\/?>/gi;

export function labelLines(raw) {
    return String(raw)
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(INLINE_TAG, "")
        .replace(/&quot;|#quot;/g, '"')
        .replace(/&nbsp;/g, " ")
        .split("\n")
        .map((l) => l.trim())
        .filter((l, i, a) => l !== "" || a.length === 1);
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

// Two-character openers must be tested before their one-character prefixes.
const SHAPES = [
    ["([", "])", "stadium"],
    ["[[", "]]", "subroutine"],
    ["[(", ")]", "cylinder"],
    ["((", "))", "circle"],
    ["{{", "}}", "hexagon"],
    ["[/", "/]", "parallelogram"],
    ["[\\", "\\]", "parallelogram"],
    ["[", "]", "rect"],
    ["(", ")", "round"],
    ["{", "}", "diamond"],
    [">", "]", "asymmetric"],
];

// Edge operators. Mid-label forms (`-- text -->`) are more specific than the
// bare operators and must be tried first. Each entry captures an optional
// quoted or bare label and an optional `>` that marks an arrowhead.
const EDGE_FORMS = [
    { re: /^-\.\s*(?:"([^"]*)"|([^.]*?))\s*\.-+(>?)/, style: "dotted" },
    { re: /^={2,}\s+(?:"([^"]*)"|(.*?))\s+={2,}(>?)/, style: "thick" },
    { re: /^-{2,}\s+(?:"([^"]*)"|(.*?))\s+-{2,}(>?)/, style: "solid" },
    { re: /^-\.-+(>?)/, style: "dotted", noLabel: true },
    { re: /^={2,}(>?)/, style: "thick", noLabel: true },
    { re: /^-{2,}(>?)/, style: "solid", noLabel: true },
];

// Read a node's shape body starting just after the opener. Quoted bodies are
// taken verbatim; bare bodies scan to the closer, tracking nesting depth on the
// opener/closer punctuation so `A[foo[bar]]` doesn't terminate early.
function readShapeBody(s, i, open, close) {
    if (s[i] === '"') {
        let out = "";
        i++;
        while (i < s.length && s[i] !== '"') out += s[i++];
        i++;
        while (s[i] === " ") i++;
        if (!s.startsWith(close, i)) return null;
        return { text: out, end: i + close.length };
    }
    const oc = open[0];
    const cc = close[close.length - 1];
    let out = "";
    let depth = 0;
    while (i < s.length) {
        if (depth === 0 && s.startsWith(close, i)) return { text: out.trim(), end: i + close.length };
        if (s[i] === oc) depth++;
        else if (s[i] === cc) depth--;
        out += s[i++];
    }
    return null;
}

// Parse `ID`, `ID["text"]`, `ID(["text"])`, ... optionally followed by `:::cls`.
// Returns { id, text, shape, cls, end } or null.
function parseNodeRef(s, pos) {
    while (s[pos] === " ") pos++;
    const m = /^\w+/.exec(s.slice(pos));
    if (!m) return null;
    const id = m[0];
    let i = pos + id.length;
    let text = null;
    let shape = "rect";
    for (const [open, close, kind] of SHAPES) {
        if (!s.startsWith(open, i)) continue;
        const body = readShapeBody(s, i + open.length, open, close);
        if (!body) continue;
        text = body.text;
        shape = kind;
        i = body.end;
        break;
    }
    let cls = null;
    const cm = /^:::(\w+)/.exec(s.slice(i));
    if (cm) {
        cls = cm[1];
        i += cm[0].length;
    }
    return { id, text, shape, cls, end: i };
}

function matchEdge(s, pos) {
    const rest = s.slice(pos);
    for (const form of EDGE_FORMS) {
        const m = form.re.exec(rest);
        if (!m) continue;
        const label = form.noLabel ? null : m[1] != null ? m[1] : m[2] || null;
        const arrow = (form.noLabel ? m[1] : m[3]) === ">";
        return { style: form.style, label: label && label.trim() ? label.trim() : null, arrow, len: m[0].length };
    }
    return null;
}

// `fill:#fff,stroke:#000,stroke-dasharray: 4 3` -> { fill, stroke, ... }
function parseStyleProps(s) {
    const out = {};
    for (const part of String(s).split(",")) {
        const at = part.indexOf(":");
        if (at < 0) continue;
        const k = part.slice(0, at).trim().toLowerCase();
        const v = part.slice(at + 1).trim();
        if (k && v) out[k] = v;
    }
    return out;
}

// Parse a whole flowchart body. Returns the graph model, or null when the
// source isn't a flowchart at all.
export function parseFlowchart(src) {
    const raw = String(src).replace(/\r\n/g, "\n").split("\n");
    const lines = [];
    for (const l of raw) {
        const t = l.trim();
        if (!t || t.startsWith("%%")) continue;
        lines.push(t);
    }
    if (!lines.length) return null;

    const head = /^(?:flowchart|graph)(?:\s+(TB|TD|BT|RL|LR))?\s*;?$/i.exec(lines[0]);
    if (!head) return null;
    const dir = (head[1] || "TB").toUpperCase();

    const nodes = new Map();
    const edges = [];
    const classDefs = new Map();
    const subgraphs = [];
    const stack = [];

    const touch = (ref) => {
        let n = nodes.get(ref.id);
        if (!n) {
            n = { id: ref.id, text: ref.id, shape: "rect", classes: [], style: {}, seq: nodes.size };
            nodes.set(ref.id, n);
        }
        if (ref.text != null) {
            n.text = ref.text;
            n.shape = ref.shape;
        }
        if (ref.cls) n.classes.push(ref.cls);
        if (stack.length) stack[stack.length - 1].members.push(ref.id);
        return n;
    };

    for (let li = 1; li < lines.length; li++) {
        const line = lines[li].replace(/;+$/, "").trim();
        if (!line) continue;

        let m;
        if ((m = /^classDef\s+([\w,\s]+?)\s+(.+)$/i.exec(line))) {
            const props = parseStyleProps(m[2]);
            for (const name of m[1].split(",")) {
                const k = name.trim();
                if (k) classDefs.set(k, { ...(classDefs.get(k) || {}), ...props });
            }
            continue;
        }
        if ((m = /^class\s+([\w,\s]+?)\s+(\w+)$/i.exec(line))) {
            for (const id of m[1].split(",")) {
                const k = id.trim();
                if (!k) continue;
                touch({ id: k, text: null, shape: "rect", cls: m[2] });
            }
            continue;
        }
        if ((m = /^style\s+(\w+)\s+(.+)$/i.exec(line))) {
            const n = touch({ id: m[1], text: null, shape: "rect", cls: null });
            Object.assign(n.style, parseStyleProps(m[2]));
            continue;
        }
        if (/^linkStyle\b/i.test(line) || /^direction\b/i.test(line)) continue;
        if ((m = /^subgraph\s+(.+)$/i.exec(line))) {
            const ref = parseNodeRef(m[1], 0);
            const title = ref && ref.text != null ? ref.text : m[1].replace(/^"|"$/g, "").trim();
            const sg = { title, members: [] };
            subgraphs.push(sg);
            stack.push(sg);
            continue;
        }
        if (/^end$/i.test(line)) {
            stack.pop();
            continue;
        }

        // Edge chain, or a bare node declaration.
        let left = parseNodeRef(line, 0);
        if (!left) continue;
        let pos = left.end;
        let leftNode = touch(left);
        let linked = false;
        for (;;) {
            while (line[pos] === " ") pos++;
            const e = matchEdge(line, pos);
            if (!e) break;
            pos += e.len;
            let label = e.label;
            while (line[pos] === " ") pos++;
            if (line[pos] === "|") {
                const close = line.indexOf("|", pos + 1);
                if (close < 0) break;
                label = line.slice(pos + 1, close).trim().replace(/^"|"$/g, "");
                pos = close + 1;
            }
            const right = parseNodeRef(line, pos);
            if (!right) break;
            pos = right.end;
            const rightNode = touch(right);
            edges.push({ from: leftNode.id, to: rightNode.id, label: label || null, style: e.style, arrow: e.arrow });
            leftNode = rightNode;
            linked = true;
        }
        if (!linked && left.text == null && !left.cls && !nodes.has(left.id)) continue;
    }

    if (!nodes.size) return null;
    return { dir, nodes: [...nodes.values()], edges, classDefs, subgraphs: subgraphs.filter((s) => s.members.length) };
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

const FONT = 13;
const LINE_H = 17;
const PAD_X = 15;
const PAD_Y = 11;
const MIN_W = 84;
const MIN_H = 40;
const EDGE_FONT = 11;
const CROSS_GAP = 22;
const FLOW_GAP = 66;
const MARGIN = 18;
const SG_PAD = 16;

function measureNodes(nodes) {
    for (const n of nodes) {
        n.lines = labelLines(n.text);
        let tw = 0;
        for (const l of n.lines) tw = Math.max(tw, textWidth(l, FONT));
        n.w = Math.max(MIN_W, Math.ceil(tw) + PAD_X * 2);
        n.h = Math.max(MIN_H, n.lines.length * LINE_H + PAD_Y * 2);
        if (n.shape === "diamond") {
            n.w += 34;
            n.h += 18;
        } else if (n.shape === "hexagon" || n.shape === "parallelogram" || n.shape === "asymmetric") {
            n.w += 22;
        } else if (n.shape === "circle") {
            n.w = n.h = Math.max(n.w, n.h) + 8;
        }
    }
}

// Longest-path ranking over the acyclic subgraph. Back edges (those closing a
// cycle, found by DFS) are excluded from ranking but still drawn.
function assignRanks(nodes, edges) {
    const succ = new Map(nodes.map((n) => [n.id, []]));
    for (const e of edges) if (e.from !== e.to && succ.has(e.from)) succ.get(e.from).push(e.to);

    const state = new Map(nodes.map((n) => [n.id, 0])); // 0 unseen, 1 on stack, 2 done
    const back = new Set();
    const visit = (id) => {
        state.set(id, 1);
        for (const to of succ.get(id) || []) {
            const st = state.get(to);
            if (st === 1) back.add(id + "\u0000" + to);
            else if (st === 0) visit(to);
        }
        state.set(id, 2);
    };
    for (const n of nodes) if (state.get(n.id) === 0) visit(n.id);

    const live = edges.filter((e) => e.from !== e.to && !back.has(e.from + "\u0000" + e.to));
    const indeg = new Map(nodes.map((n) => [n.id, 0]));
    const out = new Map(nodes.map((n) => [n.id, []]));
    for (const e of live) {
        if (!indeg.has(e.to) || !out.has(e.from)) continue;
        indeg.set(e.to, indeg.get(e.to) + 1);
        out.get(e.from).push(e.to);
    }
    const rank = new Map(nodes.map((n) => [n.id, 0]));
    const queue = nodes.filter((n) => indeg.get(n.id) === 0).map((n) => n.id);
    let guard = nodes.length * 4;
    while (queue.length && guard-- > 0) {
        const id = queue.shift();
        for (const to of out.get(id)) {
            rank.set(to, Math.max(rank.get(to), rank.get(id) + 1));
            indeg.set(to, indeg.get(to) - 1);
            if (indeg.get(to) === 0) queue.push(to);
        }
    }
    return rank;
}

// Barycenter sweeps to reduce edge crossings within each rank.
function orderRanks(nodes, edges, rank) {
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const ranks = [];
    for (const n of [...nodes].sort((a, b) => a.seq - b.seq)) {
        const r = rank.get(n.id);
        (ranks[r] = ranks[r] || []).push(n.id);
    }
    for (let i = 0; i < ranks.length; i++) ranks[i] = ranks[i] || [];

    const preds = new Map(nodes.map((n) => [n.id, []]));
    const succs = new Map(nodes.map((n) => [n.id, []]));
    for (const e of edges) {
        if (!byId.has(e.from) || !byId.has(e.to)) continue;
        if (rank.get(e.from) === rank.get(e.to)) continue;
        succs.get(e.from).push(e.to);
        preds.get(e.to).push(e.from);
    }

    const idx = new Map();
    const reindex = () => ranks.forEach((r) => r.forEach((id, i) => idx.set(id, i)));
    reindex();

    const sweep = (r, usePreds) => {
        const list = ranks[r];
        if (!list || list.length < 2) return;
        const key = new Map();
        list.forEach((id, i) => {
            const nb = (usePreds ? preds : succs).get(id).map((x) => idx.get(x)).filter((v) => v != null);
            key.set(id, nb.length ? nb.reduce((a, b) => a + b, 0) / nb.length : i);
        });
        const order = new Map(list.map((id, i) => [id, i]));
        list.sort((a, b) => key.get(a) - key.get(b) || order.get(a) - order.get(b));
        reindex();
    };

    for (let pass = 0; pass < 3; pass++) {
        for (let r = 1; r < ranks.length; r++) sweep(r, true);
        for (let r = ranks.length - 2; r >= 0; r--) sweep(r, false);
    }
    return ranks.map((r) => r.map((id) => byId.get(id)));
}

function layout(g) {
    measureNodes(g.nodes);
    const rank = assignRanks(g.nodes, g.edges);
    const ranks = orderRanks(g.nodes, g.edges, rank);
    const horiz = g.dir === "LR" || g.dir === "RL";
    const flowOf = (n) => (horiz ? n.w : n.h);
    const crossOf = (n) => (horiz ? n.h : n.w);

    // Widen the gap between two ranks to fit the widest edge label crossing it.
    const gapAfter = new Array(Math.max(0, ranks.length - 1)).fill(FLOW_GAP);
    for (const e of g.edges) {
        if (!e.label) continue;
        const a = rank.get(e.from);
        const b = rank.get(e.to);
        if (b !== a + 1) continue;
        const lines = labelLines(e.label);
        if (!lines.join("").trim()) continue;
        let need;
        if (horiz) {
            let w = 0;
            for (const l of lines) w = Math.max(w, textWidth(l, EDGE_FONT));
            need = Math.ceil(w) + 34;
        } else {
            need = lines.length * (EDGE_FONT + 3) + 34;
        }
        gapAfter[a] = Math.max(gapAfter[a], need);
    }

    // Position along the flow axis, then stack within each rank on the cross axis.
    let flow = MARGIN;
    let crossMax = 0;
    const crossStart = [];
    for (let r = 0; r < ranks.length; r++) {
        const list = ranks[r];
        let span = 0;
        for (const n of list) span += crossOf(n);
        span += CROSS_GAP * Math.max(0, list.length - 1);
        crossStart.push(span);
        crossMax = Math.max(crossMax, span);
        let bandMax = 0;
        for (const n of list) bandMax = Math.max(bandMax, flowOf(n));
        for (const n of list) n._flow = flow + (bandMax - flowOf(n)) / 2;
        flow += bandMax + (gapAfter[r] || 0);
    }
    // The loop adds no gap after the final rank (gapAfter has one entry per
    // rank *boundary*), so `flow` is already the trailing edge of the diagram.
    const flowTotal = flow + MARGIN;

    for (let r = 0; r < ranks.length; r++) {
        let c = MARGIN + (crossMax - crossStart[r]) / 2;
        for (const n of ranks[r]) {
            n._cross = c;
            c += crossOf(n) + CROSS_GAP;
        }
    }

    const W = horiz ? flowTotal : crossMax + MARGIN * 2;
    const H = horiz ? crossMax + MARGIN * 2 : flowTotal;
    for (const n of g.nodes) {
        if (n._flow == null) {
            n._flow = MARGIN;
            n._cross = MARGIN;
        }
        if (horiz) {
            n.x = g.dir === "RL" ? W - n._flow - n.w : n._flow;
            n.y = n._cross;
        } else {
            n.x = n._cross;
            n.y = g.dir === "BT" ? H - n._flow - n.h : n._flow;
        }
        n.cx = n.x + n.w / 2;
        n.cy = n.y + n.h / 2;
    }

    for (const sg of g.subgraphs) {
        const mem = sg.members.map((id) => g.nodes.find((n) => n.id === id)).filter(Boolean);
        if (!mem.length) continue;
        sg.x = Math.min(...mem.map((n) => n.x)) - SG_PAD;
        sg.y = Math.min(...mem.map((n) => n.y)) - SG_PAD - 14;
        sg.w = Math.max(...mem.map((n) => n.x + n.w)) + SG_PAD - sg.x;
        sg.h = Math.max(...mem.map((n) => n.y + n.h)) + SG_PAD - sg.y;
    }

    // Subgraph frames sit outside their members (title bar above, padding around),
    // so they can poke past the top-left margin. Shift everything back inside.
    let minX = MARGIN;
    let minY = MARGIN;
    for (const sg of g.subgraphs) {
        if (sg.w == null) continue;
        minX = Math.min(minX, sg.x);
        minY = Math.min(minY, sg.y);
    }
    const dx = MARGIN - minX;
    const dy = MARGIN - minY;
    if (dx || dy) {
        for (const n of g.nodes) {
            n.x += dx;
            n.y += dy;
            n.cx += dx;
            n.cy += dy;
        }
        for (const sg of g.subgraphs) {
            if (sg.w == null) continue;
            sg.x += dx;
            sg.y += dy;
        }
    }

    let maxX = W + dx;
    let maxY = H + dy;
    for (const sg of g.subgraphs) {
        if (sg.w == null) continue;
        maxX = Math.max(maxX, sg.x + sg.w + MARGIN);
        maxY = Math.max(maxY, sg.y + sg.h + MARGIN);
    }
    return { rank, ranks, horiz, width: Math.ceil(maxX), height: Math.ceil(maxY) };
}

// ---------------------------------------------------------------------------
// SVG emission
// ---------------------------------------------------------------------------

const THEME = {
    fill: "#161b22",
    stroke: "#3d4753",
    text: "#c9d1d9",
    edge: "#8b949e",
    edgeText: "#adbac7",
    bg: "#0f141a",
    sg: "#30363d",
};

function nodeStyle(n, classDefs) {
    const s = { fill: THEME.fill, stroke: THEME.stroke, color: THEME.text };
    for (const c of n.classes) Object.assign(s, classDefs.get(c) || {});
    Object.assign(s, n.style);
    return s;
}

function shapeMarkup(n, s) {
    const { x, y, w, h } = n;
    const sw = s["stroke-width"] || "1.4px";
    const dash = s["stroke-dasharray"] ? ' stroke-dasharray="' + esc(s["stroke-dasharray"]) + '"' : "";
    const attrs = ' fill="' + esc(s.fill) + '" stroke="' + esc(s.stroke) + '" stroke-width="' + esc(sw) + '"' + dash;
    const poly = (pts) => '<polygon points="' + pts.map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ") + '"' + attrs + "/>";
    const r = (rx) => '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="' + rx + '"' + attrs + "/>";
    switch (n.shape) {
        case "stadium":
            return r(h / 2);
        case "round":
            return r(14);
        case "circle":
            return '<ellipse cx="' + n.cx + '" cy="' + n.cy + '" rx="' + w / 2 + '" ry="' + h / 2 + '"' + attrs + "/>";
        case "diamond":
            return poly([[n.cx, y], [x + w, n.cy], [n.cx, y + h], [x, n.cy]]);
        case "hexagon": {
            const k = Math.min(18, w * 0.16);
            return poly([[x + k, y], [x + w - k, y], [x + w, n.cy], [x + w - k, y + h], [x + k, y + h], [x, n.cy]]);
        }
        case "parallelogram": {
            const k = Math.min(16, w * 0.14);
            return poly([[x + k, y], [x + w, y], [x + w - k, y + h], [x, y + h]]);
        }
        case "asymmetric":
            return poly([[x, y], [x + w - 14, y], [x + w, n.cy], [x + w - 14, y + h], [x, y + h]]);
        case "subroutine":
            return r(4) + '<line x1="' + (x + 8) + '" y1="' + y + '" x2="' + (x + 8) + '" y2="' + (y + h) + '" stroke="' + esc(s.stroke) + '" stroke-width="1.4"/>' +
                '<line x1="' + (x + w - 8) + '" y1="' + y + '" x2="' + (x + w - 8) + '" y2="' + (y + h) + '" stroke="' + esc(s.stroke) + '" stroke-width="1.4"/>';
        case "cylinder":
            return r(10) + '<path d="M' + x + " " + (y + 10) + " Q" + n.cx + " " + (y + 20) + " " + (x + w) + " " + (y + 10) + '" fill="none" stroke="' + esc(s.stroke) + '" stroke-width="1.2"/>';
        default:
            return r(7);
    }
}

function centeredText(lines, cx, cy, size, lineH, color, weight) {
    const top = cy - ((lines.length - 1) * lineH) / 2;
    let out = '<text text-anchor="middle" font-size="' + size + '" fill="' + esc(color) + '"' +
        (weight ? ' font-weight="' + weight + '"' : "") + ' font-family="-apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif">';
    lines.forEach((l, i) => {
        out += '<tspan x="' + cx.toFixed(1) + '" y="' + (top + i * lineH + size * 0.35).toFixed(1) + '">' + esc(l) + "</tspan>";
    });
    return out + "</text>";
}

// Clip the centre-to-centre line at the source box boundary.
function boxExit(n, tx, ty) {
    const dx = tx - n.cx;
    const dy = ty - n.cy;
    if (!dx && !dy) return [n.cx, n.cy];
    const sx = dx ? n.w / 2 / Math.abs(dx) : Infinity;
    const sy = dy ? n.h / 2 / Math.abs(dy) : Infinity;
    const t = Math.min(sx, sy);
    return [n.cx + dx * t, n.cy + dy * t];
}

function edgePath(from, to, horiz, forward) {
    if (forward) {
        // Rank-aligned: leave the leading face, enter the trailing face.
        if (horiz) {
            const x1 = from.x + from.w;
            const x2 = to.x;
            const k = Math.max(20, (x2 - x1) * 0.45);
            return {
                d: "M" + x1.toFixed(1) + " " + from.cy.toFixed(1) + " C" + (x1 + k).toFixed(1) + " " + from.cy.toFixed(1) +
                    " " + (x2 - k).toFixed(1) + " " + to.cy.toFixed(1) + " " + x2.toFixed(1) + " " + to.cy.toFixed(1),
                mid: [(x1 + x2) / 2, (from.cy + to.cy) / 2],
            };
        }
        const y1 = from.y + from.h;
        const y2 = to.y;
        const k = Math.max(20, (y2 - y1) * 0.45);
        return {
            d: "M" + from.cx.toFixed(1) + " " + y1.toFixed(1) + " C" + from.cx.toFixed(1) + " " + (y1 + k).toFixed(1) +
                " " + to.cx.toFixed(1) + " " + (y2 - k).toFixed(1) + " " + to.cx.toFixed(1) + " " + y2.toFixed(1),
            mid: [(from.cx + to.cx) / 2, (y1 + y2) / 2],
        };
    }
    const [x1, y1] = boxExit(from, to.cx, to.cy);
    const [x2, y2] = boxExit(to, from.cx, from.cy);
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const off = horiz ? [0, 26] : [26, 0];
    return {
        d: "M" + x1.toFixed(1) + " " + y1.toFixed(1) + " Q" + (mx + off[0]).toFixed(1) + " " + (my + off[1]).toFixed(1) + " " + x2.toFixed(1) + " " + y2.toFixed(1),
        mid: [mx + off[0] / 2, my + off[1] / 2],
    };
}

// Edge labels sit at the path midpoint, which on back edges and same-rank edges
// can land on top of a node. Slide the pill along the cross axis until it clears.
function clearLabelPos(mid, bw, bh, nodes, horiz) {
    const hits = (x, y) =>
        nodes.some((n) => x - bw / 2 < n.x + n.w - 2 && n.x < x + bw / 2 - 2 && y - bh / 2 < n.y + n.h - 2 && n.y < y + bh / 2 - 2);
    if (!hits(mid[0], mid[1])) return mid;
    for (const step of [16, 32, 48, 64, 80]) {
        for (const dir of [-1, 1]) {
            const x = horiz ? mid[0] : mid[0] + dir * step;
            const y = horiz ? mid[1] + dir * step : mid[1];
            if (!hits(x, y)) return [x, y];
        }
    }
    return mid;
}

function renderSvg(g, geo) {
    const { horiz, width, height } = geo;
    const byId = new Map(g.nodes.map((n) => [n.id, n]));
    let out =
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + width + " " + height + '" width="' + width + '" height="' + height +
        '" role="img" class="mermaid-svg">' +
        '<defs>' +
        '<marker id="mmA" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">' +
        '<path d="M0 0 L10 5 L0 10 z" fill="' + THEME.edge + '"/></marker>' +
        '<marker id="mmB" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">' +
        '<path d="M0 0 L10 5 L0 10 z" fill="' + THEME.edge + '"/></marker>' +
        "</defs>";

    for (const sg of g.subgraphs) {
        if (sg.w == null) continue;
        out += '<rect x="' + sg.x + '" y="' + sg.y + '" width="' + sg.w + '" height="' + sg.h +
            '" rx="10" fill="none" stroke="' + THEME.sg + '" stroke-width="1.2" stroke-dasharray="5 4"/>' +
            '<text x="' + (sg.x + 12) + '" y="' + (sg.y + 16) + '" font-size="11" fill="' + THEME.edgeText +
            '" font-family="-apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif">' + esc(sg.title) + "</text>";
    }

    for (const e of g.edges) {
        const from = byId.get(e.from);
        const to = byId.get(e.to);
        if (!from || !to || from === to) continue;
        const forward = geo.rank.get(e.to) === geo.rank.get(e.from) + 1;
        const p = edgePath(from, to, horiz, forward);
        const thick = e.style === "thick";
        const attrs =
            ' fill="none" stroke="' + THEME.edge + '" stroke-width="' + (thick ? 2.6 : 1.5) + '"' +
            (e.style === "dotted" ? ' stroke-dasharray="6 5"' : "") +
            (e.arrow ? ' marker-end="url(#' + (thick ? "mmA" : "mmB") + ')"' : "");
        out += '<path d="' + p.d + '"' + attrs + "/>";
        if (!e.label) continue;
        const lines = labelLines(e.label);
        // Diagrams use -->|" "| to force spacing without a caption; drawing an
        // empty pill for that is worse than drawing nothing.
        if (!lines.join("").trim()) continue;
        let lw = 0;
        for (const l of lines) lw = Math.max(lw, textWidth(l, EDGE_FONT));
        const bw = Math.ceil(lw) + 12;
        const bh = lines.length * (EDGE_FONT + 3) + 6;
        const at = clearLabelPos(p.mid, bw, bh, g.nodes, horiz);
        out += '<rect x="' + (at[0] - bw / 2).toFixed(1) + '" y="' + (at[1] - bh / 2).toFixed(1) + '" width="' + bw +
            '" height="' + bh + '" rx="4" fill="' + THEME.bg + '" stroke="' + THEME.sg + '" stroke-width="1"/>';
        out += centeredText(lines, at[0], at[1], EDGE_FONT, EDGE_FONT + 3, THEME.edgeText);
    }

    for (const n of g.nodes) {
        const s = nodeStyle(n, g.classDefs);
        // Wrapped in a class-tagged group so check-mermaid.mjs can probe node
        // boxes for overlap in a real DOM.
        out += '<g class="mmnode">' + shapeMarkup(n, s) +
            centeredText(n.lines, n.cx, n.cy, FONT, LINE_H, s.color || THEME.text, 500) + "</g>";
    }
    return out + "</svg>";
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

// Render a mermaid source block to an SVG string, or return null when the
// diagram type isn't supported (caller falls back to a code block).
//
// Each renderer is tried inside its own guard: a parse or layout failure in one
// diagram type must never take down the whole preview page.
const RENDERERS = [
    [/^\s*xychart-beta\b/im, renderXYChart],
    [/^\s*pie\b/im, renderPie],
    [/^\s*sequenceDiagram\b/im, renderSequence],
];

export function renderMermaid(src) {
    for (const [test, fn] of RENDERERS) {
        if (!test.test(src)) continue;
        try {
            const svg = fn(src);
            if (svg) return svg;
        } catch {
            /* fall through to the flowchart attempt, then to source */
        }
        return null;
    }

    let g;
    try {
        g = parseFlowchart(src);
    } catch {
        return null;
    }
    if (!g || !g.nodes.length) return null;
    try {
        const geo = layout(g);
        if (!isFinite(geo.width) || !isFinite(geo.height) || geo.width <= 0 || geo.height <= 0) return null;
        return renderSvg(g, geo);
    } catch {
        return null;
    }
}
