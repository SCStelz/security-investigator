// Shared SVG/text helpers for the server-side mermaid renderers.
//
// mermaid.mjs, xychart.mjs, pie.mjs and sequence.mjs all need the same escaping
// and text-measurement primitives. This module imports nothing so it can never
// participate in a cycle.

export const FONT_STACK = "ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif";

export function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// Approximate advance width per character, as a fraction of the font size, for
// the report page's UI sans stack. There is no DOM to measure with, so padding
// absorbs the error. Non-ASCII (emoji, box glyphs) is assumed full-width so
// emoji-bearing labels don't clip.
export function charWidth(ch) {
    const c = ch.codePointAt(0);
    if (c > 0x2e80) return 1.0; // CJK / emoji / pictographs
    if (c > 0x2000) return 0.62; // punctuation, arrows, middots, dashes
    if ("mwMW@".includes(ch)) return 0.9;
    if ("iIl|'`.,;:!ijft[]()".includes(ch)) return 0.32;
    if (ch === " ") return 0.28;
    if (ch >= "A" && ch <= "Z") return 0.68;
    if (ch >= "0" && ch <= "9") return 0.56;
    return 0.55;
}

export function textWidth(s, size) {
    let w = 0;
    for (const ch of String(s)) w += charWidth(ch);
    return w * size;
}

// Strip one layer of matching quotes.
export function unquote(s) {
    const t = String(s).trim();
    const m = /^"([\s\S]*)"$|^'([\s\S]*)'$/.exec(t);
    return m ? (m[1] !== undefined ? m[1] : m[2]) : t;
}

// Inline formatting tags mermaid passes through to a label. Restricted to a
// known set so placeholder text like "<Agent Name>" or "<tool / connector>"
// survives as literal text instead of being mistaken for markup.
const INLINE_TAG = /<\/?(?:b|i|u|em|strong|small|span|code|sub|sup|font|div|p)(?:\s[^>]*)?\/?>/gi;

// Label text -> display lines, splitting on <br> variants.
export function textLines(raw) {
    return String(raw == null ? "" : raw)
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(INLINE_TAG, "")
        .replace(/&nbsp;/gi, " ")
        .split("\n")
        .map((s) => s.trim());
}

export function svgText(s, x, y, size, color, anchor, extra) {
    return '<text x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" font-family="' + FONT_STACK +
        '" font-size="' + size + '" fill="' + color + '" text-anchor="' + (anchor || "middle") + '"' +
        (extra || "") + ">" + esc(s) + "</text>";
}
