// xychart-beta -> SVG. A small companion to mermaid.mjs covering the bar/line
// chart subset that turns up in generated activity reports:
//
//   xychart-beta
//     title "Events per day"
//     x-axis ["08-11", "08-12"]          (or: x-axis "Day" [..] / x-axis "Day" 0 --> 30)
//     y-axis "Events" 0 --> 16           (or: y-axis "Events" / y-axis 0 --> 16)
//     bar [14, 4]
//     line [9, 3]
//
// Text helpers are shared with the other renderers via svgutil.mjs, which
// imports nothing — mermaid.mjs imports this module, so pulling helpers from a
// leaf module keeps the graph acyclic.

import { esc, textWidth, unquote } from "./svgutil.mjs";

const THEME = {
    text: "#c9d1d9",
    muted: "#8b949e",
    grid: "#21262d",
    axis: "#3d4753",
    bar: "#4f9ae8",
    line: "#d29922",
};

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

// Split a bracketed list on commas that aren't inside quotes.
function splitList(body) {
    const out = [];
    let cur = "";
    let q = null;
    for (const ch of body) {
        if (q) {
            if (ch === q) q = null;
            else cur += ch;
            continue;
        }
        if (ch === '"' || ch === "'") { q = ch; continue; }
        if (ch === ",") { out.push(cur.trim()); cur = ""; continue; }
        cur += ch;
    }
    if (cur.trim()) out.push(cur.trim());
    return out.filter((s) => s !== "");
}

// "0 --> 16" -> [0, 16]
function readRange(s) {
    const m = /(-?[\d.]+)\s*-->\s*(-?[\d.]+)/.exec(s);
    if (!m) return null;
    const lo = Number(m[1]);
    const hi = Number(m[2]);
    return isFinite(lo) && isFinite(hi) ? [lo, hi] : null;
}

export function parseXYChart(src) {
    const lines = String(src).replace(/\r\n/g, "\n").split("\n");
    const c = { title: "", horizontal: false, categories: [], xTitle: "", yTitle: "", yRange: null, series: [] };
    let seenHeader = false;

    for (const raw of lines) {
        const t = raw.trim();
        if (!t || t.startsWith("%%")) continue;

        if (!seenHeader) {
            if (!/^xychart(-beta)?\b/i.test(t)) return null;
            seenHeader = true;
            if (/\bhorizontal\b/i.test(t)) c.horizontal = true;
            continue;
        }

        let m;
        if ((m = /^title\s+(.+)$/i.exec(t))) { c.title = unquote(m[1]); continue; }

        if ((m = /^(x-axis|y-axis)\s*(.*)$/i.exec(t))) {
            const axis = m[1].toLowerCase();
            let rest = m[2].trim();

            // Optional leading axis title, quoted or a bare word before a list/range.
            let title = "";
            const q = /^"([^"]*)"|^'([^']*)'/.exec(rest);
            if (q) {
                title = q[1] !== undefined ? q[1] : q[2];
                rest = rest.slice(q[0].length).trim();
            }

            const br = /^\[([\s\S]*)\]$/.exec(rest);
            if (br) {
                const items = splitList(br[1]);
                if (axis === "x-axis") { c.categories = items; c.xTitle = title; }
                else { c.yTitle = title; }
                continue;
            }

            const range = readRange(rest);
            if (axis === "y-axis") {
                c.yTitle = title || (range ? "" : unquote(rest));
                if (range) c.yRange = range;
            } else {
                c.xTitle = title || (range ? "" : unquote(rest));
            }
            continue;
        }

        if ((m = /^(bar|line)\s*(?:"([^"]*)"\s*)?\[([\s\S]*)\]\s*$/i.exec(t))) {
            const values = splitList(m[3]).map(Number);
            if (values.some((v) => !isFinite(v))) continue;
            c.series.push({ kind: m[1].toLowerCase(), name: m[2] || "", values });
            continue;
        }
    }

    if (!seenHeader || !c.series.length) return null;
    const n = Math.max(...c.series.map((s) => s.values.length));
    if (!n) return null;
    // Categories are optional; fall back to 1-based indices.
    if (c.categories.length < n) {
        for (let i = c.categories.length; i < n; i++) c.categories.push(String(i + 1));
    }
    c.categories = c.categories.slice(0, n);
    c.count = n;
    return c;
}

// ---------------------------------------------------------------------------
// Scale
// ---------------------------------------------------------------------------

// Round a raw step up to 1/2/2.5/5 x 10^k so tick labels stay readable.
function niceStep(raw) {
    if (!(raw > 0)) return 1;
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const norm = raw / mag;
    const step = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10;
    return step * mag;
}

function ticksFor(lo, hi, target) {
    const step = niceStep((hi - lo) / Math.max(1, target));
    const start = Math.ceil(lo / step - 1e-9) * step;
    const out = [];
    for (let v = start; v <= hi + step * 1e-6 && out.length < 40; v += step) {
        out.push(Math.abs(v) < step * 1e-6 ? 0 : Number(v.toFixed(10)));
    }
    return out;
}

function fmtTick(v) {
    const a = Math.abs(v);
    if (a >= 1e9) return (v / 1e9).toFixed(a % 1e9 ? 1 : 0) + "B";
    if (a >= 1e6) return (v / 1e6).toFixed(a % 1e6 ? 1 : 0) + "M";
    if (a >= 1e4) return (v / 1e3).toFixed(a % 1e3 ? 1 : 0) + "k";
    if (Number.isInteger(v)) return String(v);
    return String(Number(v.toFixed(2)));
}

// ---------------------------------------------------------------------------
// SVG emission
// ---------------------------------------------------------------------------

const MARGIN = 18;
const TITLE_SIZE = 14;
const TICK_SIZE = 11;
const AXIS_TITLE_SIZE = 12;
const PLOT_H = 250;
const MIN_SLOT = 16;
const MIN_PLOT_W = 380;

function txt(s, x, y, size, color, anchor, extra) {
    return '<text x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" font-family="' +
        'ui-sans-serif,-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="' + size +
        '" fill="' + color + '" text-anchor="' + (anchor || "middle") + '"' + (extra || "") + ">" + esc(s) + "</text>";
}

export function renderXYChart(src) {
    const c = parseXYChart(src);
    if (!c) return null;
    // Horizontal orientation isn't laid out yet; fall back rather than lie.
    if (c.horizontal) return null;

    const all = c.series.flatMap((s) => s.values);
    const dataMax = Math.max(...all, 0);
    const dataMin = Math.min(...all, 0);
    let lo = c.yRange ? Math.min(c.yRange[0], c.yRange[1]) : Math.min(0, dataMin);
    let hi = c.yRange ? Math.max(c.yRange[0], c.yRange[1]) : dataMax;
    if (!(hi > lo)) hi = lo + 1;
    if (!c.yRange) hi = niceStep((hi - lo) / 4) * Math.ceil((hi - lo) / niceStep((hi - lo) / 4)) + lo;

    const ticks = ticksFor(lo, hi, 5);
    const tickW = Math.max(...ticks.map((t) => textWidth(fmtTick(t), TICK_SIZE)), 0);

    // X labels go flat if they fit the slot, otherwise rotate 45 degrees.
    const labelW = Math.max(...c.categories.map((s) => textWidth(s, TICK_SIZE)), 0);
    const slotNeeded = Math.max(MIN_SLOT, labelW + 8);
    // The title is centered over the plot, so the plot has to be wide enough to
    // hold it or it overflows the viewBox on both sides.
    const titleW = c.title ? textWidth(c.title, TITLE_SIZE) : 0;
    const plotW = Math.max(MIN_PLOT_W, c.count * slotNeeded, Math.ceil(titleW) + 4);
    const slot = plotW / c.count;
    const rotate = labelW + 6 > slot;
    const xLabelH = rotate ? Math.min(78, labelW * 0.72) + 10 : TICK_SIZE + 10;
    // A rotated first label runs up and to the left of its anchor; give it room.
    const leftPad = rotate ? Math.max(0, labelW * 0.71 - slot / 2) : 0;

    const yTitleX = MARGIN + AXIS_TITLE_SIZE;
    const left = MARGIN + leftPad + (c.yTitle ? AXIS_TITLE_SIZE + 6 : 0) + tickW + 8;
    const top = MARGIN + (c.title ? TITLE_SIZE + 12 : 0);
    const bottom = top + PLOT_H;
    const right = left + plotW;
    const width = Math.ceil(right + MARGIN);
    const height = Math.ceil(bottom + xLabelH + (c.xTitle ? AXIS_TITLE_SIZE + 6 : 0) + MARGIN);

    const yOf = (v) => bottom - ((v - lo) / (hi - lo)) * PLOT_H;

    let out = '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height +
        '" viewBox="0 0 ' + width + " " + height + '" role="img">';

    if (c.title) out += txt(c.title, (left + right) / 2, MARGIN + TITLE_SIZE, TITLE_SIZE, THEME.text, "middle", ' font-weight="600"');

    // Gridlines and y ticks.
    for (const t of ticks) {
        const y = yOf(t);
        if (y < top - 1 || y > bottom + 1) continue;
        out += '<line x1="' + left + '" y1="' + y.toFixed(1) + '" x2="' + right + '" y2="' + y.toFixed(1) +
            '" stroke="' + THEME.grid + '" stroke-width="1"/>';
        out += txt(fmtTick(t), left - 6, y + TICK_SIZE * 0.36, TICK_SIZE, THEME.muted, "end");
    }

    // Axes.
    out += '<line x1="' + left + '" y1="' + top + '" x2="' + left + '" y2="' + bottom +
        '" stroke="' + THEME.axis + '" stroke-width="1.2"/>';
    out += '<line x1="' + left + '" y1="' + bottom + '" x2="' + right + '" y2="' + bottom +
        '" stroke="' + THEME.axis + '" stroke-width="1.2"/>';

    // Bars, grouped side by side when there is more than one bar series.
    const bars = c.series.filter((s) => s.kind === "bar");
    const bandW = slot * 0.66;
    const barW = bars.length ? bandW / bars.length : bandW;
    bars.forEach((s, si) => {
        for (let i = 0; i < c.count; i++) {
            const v = s.values[i];
            if (!isFinite(v)) continue;
            const x = left + i * slot + (slot - bandW) / 2 + si * barW;
            const yTop = yOf(Math.max(v, lo));
            const yBase = yOf(Math.max(lo, Math.min(0, hi)));
            const h = Math.abs(yBase - yTop);
            out += '<rect x="' + x.toFixed(1) + '" y="' + Math.min(yTop, yBase).toFixed(1) +
                '" width="' + Math.max(1, barW - 1.5).toFixed(1) + '" height="' + Math.max(0.5, h).toFixed(1) +
                '" rx="2" fill="' + THEME.bar + '" fill-opacity="' + (si ? 0.6 : 0.85) + '"/>';
        }
    });

    // Line series on top of the bars.
    for (const s of c.series.filter((x) => x.kind === "line")) {
        const pts = [];
        for (let i = 0; i < c.count; i++) {
            const v = s.values[i];
            if (!isFinite(v)) continue;
            pts.push([left + i * slot + slot / 2, yOf(v)]);
        }
        if (pts.length > 1) {
            out += '<polyline points="' + pts.map((p) => p[0].toFixed(1) + "," + p[1].toFixed(1)).join(" ") +
                '" fill="none" stroke="' + THEME.line + '" stroke-width="2" stroke-linejoin="round"/>';
        }
        for (const p of pts) {
            out += '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="2.6" fill="' + THEME.line + '"/>';
        }
    }

    // X category labels.
    for (let i = 0; i < c.count; i++) {
        const cx = left + i * slot + slot / 2;
        if (rotate) {
            const y = bottom + 8;
            out += txt(c.categories[i], 0, 0, TICK_SIZE, THEME.muted, "end",
                ' transform="translate(' + cx.toFixed(1) + "," + y.toFixed(1) + ') rotate(-45)"');
        } else {
            out += txt(c.categories[i], cx, bottom + TICK_SIZE + 6, TICK_SIZE, THEME.muted, "middle");
        }
    }

    if (c.xTitle) {
        out += txt(c.xTitle, (left + right) / 2, height - MARGIN, AXIS_TITLE_SIZE, THEME.text, "middle");
    }
    if (c.yTitle) {
        const cy = (top + bottom) / 2;
        out += txt(c.yTitle, 0, 0, AXIS_TITLE_SIZE, THEME.text, "middle",
            ' transform="translate(' + yTitleX.toFixed(1) + "," + cy.toFixed(1) + ') rotate(-90)"');
    }

    return out + "</svg>";
}
