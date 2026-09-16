// pie -> SVG. Covers the mermaid pie syntax used in generated reports:
//
//   pie showData title Tool Calls by Type (10 total)
//     "getForecast (Weather)" : 6
//     "getLatestRate (FX)" : 4
//
// `showData` appends the raw value to each legend entry.

import { esc, textWidth, unquote, svgText } from "./svgutil.mjs";

const THEME = {
    text: "#c9d1d9",
    muted: "#8b949e",
    stroke: "#0f141a",
};

// Distinguishable at small sizes on the report page's dark background.
const PALETTE = [
    "#4f9ae8", "#d29922", "#3fb950", "#db6d5a", "#a371f7",
    "#39c5cf", "#e5849b", "#8ddb8c", "#f0883e", "#6e7bd2",
];

export function parsePie(src) {
    const lines = String(src).replace(/\r\n/g, "\n").split("\n");
    const out = { title: "", showData: false, slices: [] };
    let seenHeader = false;

    for (const raw of lines) {
        const t = raw.trim();
        if (!t || t.startsWith("%%")) continue;

        if (!seenHeader) {
            const m = /^pie\b\s*(.*)$/i.exec(t);
            if (!m) return null;
            seenHeader = true;
            let rest = m[1].trim();
            if (/^showdata\b/i.test(rest)) {
                out.showData = true;
                rest = rest.slice(8).trim();
            }
            const tm = /^title\s+(.+)$/i.exec(rest);
            if (tm) out.title = unquote(tm[1]);
            continue;
        }

        // A title may also appear on its own line.
        let m;
        if ((m = /^title\s+(.+)$/i.exec(t))) { out.title = unquote(m[1]); continue; }
        if ((m = /^showdata\b/i.exec(t))) { out.showData = true; continue; }

        // "label" : value
        if ((m = /^(?:"([^"]*)"|'([^']*)'|([^:]+?))\s*:\s*(-?[\d.]+)\s*$/.exec(t))) {
            const label = m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3].trim();
            const value = Number(m[4]);
            if (!isFinite(value) || value < 0) continue;
            out.slices.push({ label, value });
        }
    }

    if (!seenHeader || !out.slices.length) return null;
    out.total = out.slices.reduce((a, s) => a + s.value, 0);
    if (!(out.total > 0)) return null;
    return out;
}

const MARGIN = 18;
const TITLE_SIZE = 14;
const LEGEND_SIZE = 12;
const LEGEND_ROW = 20;
const SWATCH = 11;
const RADIUS = 92;

// Slice arc as an SVG path. A single slice covering the whole circle can't be
// drawn with arcs (start and end coincide), so the caller special-cases it.
function arcPath(cx, cy, r, from, to) {
    const x1 = cx + r * Math.cos(from);
    const y1 = cy + r * Math.sin(from);
    const x2 = cx + r * Math.cos(to);
    const y2 = cy + r * Math.sin(to);
    const large = to - from > Math.PI ? 1 : 0;
    return "M" + cx.toFixed(1) + " " + cy.toFixed(1) +
        " L" + x1.toFixed(1) + " " + y1.toFixed(1) +
        " A" + r + " " + r + " 0 " + large + " 1 " + x2.toFixed(1) + " " + y2.toFixed(1) + " Z";
}

export function renderPie(src) {
    const p = parsePie(src);
    if (!p) return null;

    const entries = p.slices.map((s, i) => ({
        ...s,
        color: PALETTE[i % PALETTE.length],
        pct: (s.value / p.total) * 100,
        legend: s.label + (p.showData ? "  " + (Number.isInteger(s.value) ? s.value : s.value.toFixed(2)) : "") +
            "  (" + ((s.value / p.total) * 100).toFixed(1) + "%)",
    }));

    const legendW = Math.ceil(Math.max(...entries.map((e) => textWidth(e.legend, LEGEND_SIZE)))) + SWATCH + 10;
    const chartW = RADIUS * 2;
    const titleW = p.title ? textWidth(p.title, TITLE_SIZE) : 0;

    const top = MARGIN + (p.title ? TITLE_SIZE + 12 : 0);
    const bodyW = chartW + 26 + legendW;
    const width = Math.ceil(Math.max(bodyW, titleW) + MARGIN * 2);
    const legendH = entries.length * LEGEND_ROW;
    const bodyH = Math.max(RADIUS * 2, legendH);
    const height = Math.ceil(top + bodyH + MARGIN);

    const bodyLeft = MARGIN + Math.max(0, (width - MARGIN * 2 - bodyW) / 2);
    const cx = bodyLeft + RADIUS;
    const cy = top + bodyH / 2;

    let out = '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height +
        '" viewBox="0 0 ' + width + " " + height + '" role="img">';

    if (p.title) out += svgText(p.title, width / 2, MARGIN + TITLE_SIZE, TITLE_SIZE, THEME.text, "middle", ' font-weight="600"');

    // Start at 12 o'clock and sweep clockwise, as mermaid does.
    let angle = -Math.PI / 2;
    for (const e of entries) {
        const sweep = (e.value / p.total) * Math.PI * 2;
        if (sweep <= 0) continue;
        if (entries.length === 1 || sweep >= Math.PI * 2 - 1e-9) {
            out += '<circle cx="' + cx + '" cy="' + cy.toFixed(1) + '" r="' + RADIUS +
                '" fill="' + e.color + '" stroke="' + THEME.stroke + '" stroke-width="1.5"/>';
        } else {
            out += '<path d="' + arcPath(cx, cy, RADIUS, angle, angle + sweep) +
                '" fill="' + e.color + '" stroke="' + THEME.stroke + '" stroke-width="1.5"/>';
        }
        // Only label slices with room for the text.
        if (e.pct >= 6) {
            const mid = angle + sweep / 2;
            const lx = cx + RADIUS * 0.62 * Math.cos(mid);
            const ly = cy + RADIUS * 0.62 * Math.sin(mid);
            out += svgText(e.pct.toFixed(0) + "%", lx, ly + 4, 12, "#0f141a", "middle", ' font-weight="700"');
        }
        angle += sweep;
    }

    // Legend.
    const lx = bodyLeft + chartW + 26;
    let ly = top + (bodyH - legendH) / 2 + LEGEND_ROW / 2;
    for (const e of entries) {
        out += '<rect x="' + lx + '" y="' + (ly - SWATCH + 2).toFixed(1) + '" width="' + SWATCH +
            '" height="' + SWATCH + '" rx="2" fill="' + e.color + '"/>';
        out += svgText(e.legend, lx + SWATCH + 8, ly, LEGEND_SIZE, THEME.text, "start");
        ly += LEGEND_ROW;
    }

    return out + "</svg>";
}
