// Minimal, dependency-free Markdown -> HTML renderer for the Mission Control
// report preview. Handles the subset our reports use: headings, GitHub tables,
// fenced + inline code, bold/italic, links, blockquotes, ordered/unordered
// lists, and horizontal rules. Blockquote bodies are rendered recursively (so
// tables, fences, nested quotes and lists inside a quote work), and a small
// allow-list of raw HTML is honoured: <details>/<summary> (collapsible
// sections), <br>, <strong>/<em>-style tags and <a id="..."></a> anchors.
// Everything else is escaped. Perception's verbatim reports depend on all of
// this. Not a full CommonMark implementation — just enough to render
// investigation reports legibly inside the canvas modal.

import { renderMermaid } from "./mermaid.mjs";

function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// GitHub-compatible heading anchor slug. MUST match scripts/generate_tocs.py
// heading_to_anchor() exactly so TOC links (#anchor) resolve to our heading IDs:
// lowercase, strip all but [a-z0-9 -], spaces -> hyphens, no dedupe/collapse.
function slugify(raw) {
    return String(raw)
        .toLowerCase()
        .replace(/[^a-z0-9 -]/g, "")
        .replace(/ /g, "-");
}

// Inline: code spans first (protected), then links, bold, italic.
// _base is the repo-relative path of the file being rendered (set by
// renderMarkdown); used to resolve relative links like ../../email/foo.md.
let _base = "";

// Repo files the preview can display: markdown (rendered) and text-like report
// artefacts (shown in the code viewer, see codeReportPage).
const VIEW_EXT = /\.(md|markdown|kql|txt|json)$/i;

// Resolve a link href found in a markdown file into an href the preview can
// open. Relative/repo-relative .md paths become /api/report?path=... so they
// open in the same preview iframe; http(s)/mailto/#fragment are left as-is.
// Returns { href, inPlace } or null when the link can't be routed.
function resolveHref(href) {
    const hashAt = href.indexOf("#");
    const frag = hashAt >= 0 ? href.slice(hashAt) : "";
    let pathPart = hashAt >= 0 ? href.slice(0, hashAt) : href;
    if (/^(https?:|mailto:)/i.test(href)) return { href: href, inPlace: false };
    // Report artefacts (tuned KQL, wizard-link text, rule JSON) open in the code viewer.
    if (/^\/?reports\//.test(pathPart) && VIEW_EXT.test(pathPart)) {
        return { href: "/api/report?path=" + encodeURIComponent(pathPart.replace(/^\/+/, "")) + frag, inPlace: true };
    }
    if (pathPart === "" && frag) return { href: frag, inPlace: true }; // pure in-page anchor
    let repoRel = null;
    if (/^\.\.?\//.test(pathPart)) {
        // relative to the current file's directory
        const norm = _base.replace(/\\/g, "/");
        const baseDir = norm.includes("/") ? norm.slice(0, norm.lastIndexOf("/")) : "";
        const parts = baseDir ? baseDir.split("/") : [];
        for (const seg of pathPart.split("/")) {
            if (seg === "" || seg === ".") continue;
            if (seg === "..") { if (parts.length) parts.pop(); }
            else parts.push(seg);
        }
        repoRel = parts.join("/");
    } else if (/^\/?(queries|\.github|docs|scripts)\//.test(pathPart) && /\.(md|markdown)$/i.test(pathPart)) {
        // repo-root-relative path (with or without a leading slash)
        repoRel = pathPart.replace(/^\/+/, "");
    }
    if (repoRel && VIEW_EXT.test(repoRel)) {
        return { href: "/api/report?path=" + encodeURIComponent(repoRel) + frag, inPlace: true };
    }
    return null;
}

function inline(text) {
    const codes = [];
    let s = text.replace(/`([^`]+)`/g, (_, c) => {
        // A code span that is exactly a repo path to a report artefact becomes a link.
        const isPath = /^reports\/[A-Za-z0-9._\/-]+$/.test(c) && VIEW_EXT.test(c);
        codes.push(isPath
            ? '<a href="/api/report?path=' + encodeURIComponent(c) + '"><code>' + escapeHtml(c) + "</code></a>"
            : "<code>" + escapeHtml(c) + "</code>");
        return "\u0000" + (codes.length - 1) + "\u0000";
    });
    s = escapeHtml(s);
    // Re-enable a tiny allow-list of tags (no attributes except a sanitized
    // anchor id) on the already-escaped text; anything else stays visible text.
    s = s
        .replace(/&lt;br\s*\/?&gt;/gi, "<br>")
        .replace(/&lt;(\/?)(strong|b|em|i|u|sub|sup|kbd)&gt;/gi, "<$1$2>")
        .replace(/&lt;a id=&quot;([A-Za-z0-9_-]+)&quot;&gt;&lt;\/a&gt;/g, '<a id="$1"></a>');
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, t, href) => {
        const r = resolveHref(href);
        if (!r) return '<a href="#">' + t + "</a>";
        const attrs = r.inPlace ? "" : ' target="_blank" rel="noopener"';
        return '<a href="' + r.href + '"' + attrs + ">" + t + "</a>";
    });
    // Autolink bare repo-relative markdown paths (e.g. "Companion files:
    // queries/.../foo.md") so they open in the preview iframe. The negative
    // lookbehind skips paths already inside a tag/attribute or a longer path.
    s = s.replace(/(?<!["'>=/])((?:queries|\.github)\/[A-Za-z0-9._/-]+\.md)(#[A-Za-z0-9_-]+)?/g, (_, p, frag) => {
        const href = "/api/report?path=" + encodeURIComponent(p) + (frag || "");
        return '<a href="' + href + '">' + p + (frag || "") + "</a>";
    });
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, "$1<em>$2</em>");
    // _italic_ only at word boundaries so snake_case identifiers are left alone.
    s = s.replace(/(^|[^\w])_([^_\n]+)_(?!\w)/g, "$1<em>$2</em>");
    s = s.replace(/~~([^~]+)~~/g, "<del>$1</del>");
    s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => codes[Number(i)]);
    return s;
}

// Split a table row on unescaped pipes that are not inside a code span; `\|`
// becomes a literal pipe. Perception puts KQL fragments with pipes in cells.
function splitCells(line) {
    let s = line.trim();
    if (s.startsWith("|")) s = s.slice(1);
    if (s.endsWith("|") && !s.endsWith("\\|")) s = s.slice(0, -1);
    const cells = [];
    let cur = "";
    let inCode = false;
    for (let k = 0; k < s.length; k++) {
        const ch = s[k];
        if (ch === "`") { inCode = !inCode; cur += ch; continue; }
        if (ch === "\\" && s[k + 1] === "|") { cur += "|"; k++; continue; }
        if (ch === "|" && !inCode) { cells.push(cur.trim()); cur = ""; continue; }
        cur += ch;
    }
    cells.push(cur.trim());
    return cells;
}

function renderTable(rows) {
    // rows: array of raw "| a | b |" lines; row[1] is the --- separator.
    const header = splitCells(rows[0]);
    const body = rows.slice(2).map(splitCells);
    let html = '<div class="tw"><table><thead><tr>';
    html += header.map((h) => "<th>" + inline(h) + "</th>").join("");
    html += "</tr></thead><tbody>";
    for (const r of body) {
        html += "<tr>" + header.map((_, i) => "<td>" + inline(r[i] || "") + "</td>").join("") + "</tr>";
    }
    html += "</tbody></table></div>";
    return html;
}

export function renderMarkdown(md, basePath) {
    _base = basePath || "";
    // Strip leading YAML frontmatter (--- ... ---) and HTML comments
    // (e.g. <!-- cd-metadata ... -->) so neither renders as visible text —
    // matches how VSCode's markdown preview hides them.
    let src = String(md).replace(/\r\n/g, "\n")
        .replace(/^\uFEFF?\s*---\n[\s\S]*?\n---[ \t]*(?:\n|$)/, "");
    // Repeat until stable so overlapping input like "<!<!-- -->--" can't
    // reassemble a comment opener after a single pass.
    let prev;
    do {
        prev = src;
        src = src.replace(/<!--[\s\S]*?-->/g, "");
    } while (src !== prev);
    return renderBlocks(src.split("\n")).join("\n");
}

const DETAILS_OPEN = /^\s*<details(\s+open)?\s*>/i;
const DETAILS_CLOSE = /^\s*<\/details\s*>/i;
const SUMMARY_OPEN = /^\s*<summary\s*>/i;
const SUMMARY_FULL = /^\s*<summary\s*>([\s\S]*?)<\/summary\s*>/i;
const ANCHOR_ONLY = /^\s*(?:<a id="[A-Za-z0-9_-]+"><\/a>\s*)+$/;
const isHtmlBlockStart = (l) => DETAILS_OPEN.test(l) || DETAILS_CLOSE.test(l) || SUMMARY_OPEN.test(l) || ANCHOR_ONLY.test(l);

// Render a list of source lines to an array of HTML chunks. Recursive: a
// blockquote renders its stripped body through this same function.
function renderBlocks(lines) {
    lines = lines.slice();
    const out = [];
    let i = 0;
    let listType = null; // 'ul' | 'ol'
    let depth = 0; // open <details> elements

    const closeList = () => {
        if (listType) {
            out.push(listType === "ul" ? "</ul>" : "</ol>");
            listType = null;
        }
    };

    while (i < lines.length) {
        const line = lines[i];

        // Fenced code block
        const fence = line.match(/^ {0,3}```(.*)$/);
        if (fence) {
            closeList();
            const lang = fence[1].trim();
            const buf = [];
            i++;
            while (i < lines.length && !/^ {0,3}```/.test(lines[i])) {
                buf.push(lines[i]);
                i++;
            }
            i++; // skip closing fence
            // Mermaid flowcharts render to inline SVG. Unsupported diagram
            // types (and any parse failure) return null and fall through to
            // the plain code block below.
            if (/^mermaid$/i.test(lang)) {
                let svg = null;
                try {
                    svg = renderMermaid(buf.join("\n"));
                } catch {
                    svg = null;
                }
                if (svg) {
                    out.push('<div class="mermaid">' + svg + "</div>");
                    continue;
                }
            }
            out.push('<pre class="code' + (lang ? " lang-" + escapeHtml(lang) : "") + '"><code>' + escapeHtml(buf.join("\n")) + "</code></pre>");
            continue;
        }

        // Raw HTML disclosure blocks. Any text after the tag on the same line
        // is put back and processed as the next line.
        let hm;
        const rest = (m) => {
            lines[i] = line.slice(m[0].length);
            if (/^\s*$/.test(lines[i])) i++;
        };
        if ((hm = line.match(DETAILS_OPEN))) {
            closeList();
            out.push(hm[1] ? "<details open>" : "<details>");
            depth++;
            rest(hm);
            continue;
        }
        if ((hm = line.match(DETAILS_CLOSE))) {
            closeList();
            if (depth > 0) { out.push("</details>"); depth--; }
            rest(hm);
            continue;
        }
        if (SUMMARY_OPEN.test(line)) {
            closeList();
            let joined = line;
            let end = i;
            while (!/<\/summary\s*>/i.test(joined) && end + 1 < lines.length && end - i < 6) {
                end++;
                joined += " " + lines[end].trim();
            }
            const sm = joined.match(SUMMARY_FULL);
            if (sm) {
                out.push("<summary>" + inline(sm[1].trim()) + "</summary>");
                i = end;
                lines[i] = joined.slice(sm[0].length);
                if (/^\s*$/.test(lines[i])) i++;
                continue;
            }
        }
        if (ANCHOR_ONLY.test(line)) {
            closeList();
            out.push(line.trim());
            i++;
            continue;
        }

        // Table: a header line followed by a |---|---| separator
        if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1]) && lines[i + 1].includes("-")) {
            closeList();
            const tbl = [line, lines[i + 1]];
            i += 2;
            while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
                tbl.push(lines[i]);
                i++;
            }
            out.push(renderTable(tbl));
            continue;
        }

        // Headings
        const h = line.match(/^(#{1,6})\s+(.*)$/);
        if (h) {
            closeList();
            const lvl = h[1].length;
            const text = h[2].trim();
            out.push("<h" + lvl + ' id="' + escapeHtml(slugify(text)) + '">' + inline(text) + "</h" + lvl + ">");
            i++;
            continue;
        }

        // Horizontal rule
        if (/^\s*([-*_])\1{2,}\s*$/.test(line)) {
            closeList();
            out.push("<hr>");
            i++;
            continue;
        }

        // Blockquote
        if (/^\s*>\s?/.test(line)) {
            closeList();
            const buf = [];
            while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
                buf.push(lines[i].replace(/^\s*>\s?/, ""));
                i++;
            }
            out.push("<blockquote>" + renderBlocks(buf).join("\n") + "</blockquote>");
            continue;
        }

        // Unordered list
        const ul = line.match(/^\s*[-*+]\s+(.*)$/);
        if (ul) {
            if (listType !== "ul") {
                closeList();
                out.push("<ul>");
                listType = "ul";
            }
            out.push("<li>" + inline(ul[1]) + "</li>");
            i++;
            continue;
        }

        // Ordered list
        const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
        if (ol) {
            if (listType !== "ol") {
                closeList();
                out.push("<ol>");
                listType = "ol";
            }
            out.push("<li>" + inline(ol[1]) + "</li>");
            i++;
            continue;
        }

        // Blank line
        if (/^\s*$/.test(line)) {
            closeList();
            i++;
            continue;
        }

        // Paragraph (gather consecutive non-blank, non-structural lines)
        closeList();
        const buf = [line];
        i++;
        while (
            i < lines.length &&
            !/^\s*$/.test(lines[i]) &&
            !/^ {0,3}```/.test(lines[i]) &&
            !isHtmlBlockStart(lines[i]) &&
            !/^(#{1,6})\s+/.test(lines[i]) &&
            !/^\s*[-*+]\s+/.test(lines[i]) &&
            !/^\s*\d+[.)]\s+/.test(lines[i]) &&
            !/^\s*\|.*\|\s*$/.test(lines[i]) &&
            !/^\s*>\s?/.test(lines[i])
        ) {
            buf.push(lines[i]);
            i++;
        }
        // "**Label:** value" header lines stay on their own line (reports lay out
        // their header block that way); other wrapped lines join as usual.
        const text = buf.reduce((acc, ln, k) => (k === 0 ? ln : acc + (/^\s*\*\*[^*]+\*\*/.test(ln) ? "\u0001" : " ") + ln), "");
        out.push("<p>" + inline(text).replace(/\u0001/g, "<br>") + "</p>");
    }
    closeList();
    while (depth-- > 0) out.push("</details>");
    return out;
}

// Light KQL highlighter: comments, strings, keywords/functions, numbers, pipes.
// Operates on the raw text and escapes every piece, so it cannot inject markup.
const KQL_KW = new Set(("let where project project-away project-rename project-reorder extend summarize join union take limit top order sort by asc desc distinct count dcount ago between has has_any has_all " +
    "contains in not and or on kind datatable mv-expand mv-apply parse parse_json tostring toint tolong todouble todatetime todynamic dynamic iff iif case isnotempty isempty isnull isnotnull " +
    "startswith endswith matches regex bin make_set make_list arg_max arg_min min max sum avg strcat split extract replace_string coalesce lookup materialize " +
    "inner leftouter rightouter fullouter leftanti leftsemi rightanti rightsemi ingestion_time now datetime timespan true false").split(" "));
function highlightKql(text) {
    const re = /(\/\/[^\n]*)|("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|(\b[A-Za-z_][\w-]*\b)|(\b\d+(?:\.\d+)?(?:ms|[dhms])?\b)|(\|)/g;
    let out = "";
    let last = 0;
    let m;
    while ((m = re.exec(text))) {
        out += escapeHtml(text.slice(last, m.index));
        const tok = escapeHtml(m[0]);
        if (m[1]) out += '<span class="k-c">' + tok + "</span>";
        else if (m[2]) out += '<span class="k-s">' + tok + "</span>";
        else if (m[3]) out += KQL_KW.has(m[3].toLowerCase()) ? '<span class="k-k">' + tok + "</span>" : tok;
        else if (m[4]) out += '<span class="k-n">' + tok + "</span>";
        else out += '<span class="k-p">' + tok + "</span>";
        last = m.index + m[0].length;
    }
    return out + escapeHtml(text.slice(last));
}

// Standalone page for text artefacts (tuned .kql, wizard-link .txt, rule .json).
// Only security.microsoft.com URLs are turned into links (the Detection Wizard
// link is the point of the .txt files); everything else is escaped text.
export function codeReportPage(title, text, lang) {
    text = String(text).replace(/\r\n?/g, "\n");
    const body = lang === "kql" ? highlightKql(text) : escapeHtml(text).replace(
        /https:\/\/security\.microsoft\.com\/[^\s<"']+/g,
        (u) => '<a href="' + u + '" target="_blank" rel="noopener">' + u + "</a>");
    const lines = text.length ? text.split("\n").length : 0;
    return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0d1117; color: #c9d1d9; font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .bar { position: sticky; top: 0; display: flex; gap: 12px; align-items: center; padding: 10px 22px; background: #161b22; border-bottom: 1px solid #21262d; }
  .bar b { color: #e6edf3; font-weight: 620; } .bar span { color: #8b949e; font-size: 12px; flex: 1; }
  button { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 4px 12px; cursor: pointer; font: inherit; font-size: 12px; }
  button:hover { background: #30363d; }
  pre { margin: 0; padding: 18px 22px 60px; white-space: pre-wrap; overflow-wrap: anywhere; tab-size: 4;
    font: 13px/1.55 "SF Mono", "Cascadia Code", Consolas, monospace; color: #c9d1d9; }
  a { color: #58a6ff; }
  .k-c { color: #8b949e; font-style: italic; } .k-s { color: #a5d6ff; } .k-k { color: #ff7b72; } .k-n { color: #79c0ff; } .k-p { color: #d2a8ff; }
</style></head><body>
<div class="bar"><b>${escapeHtml(title)}</b><span>${lines} line${lines === 1 ? "" : "s"}</span><button id="cp">Copy</button></div>
<pre id="src">${body}</pre>
<script>
document.getElementById("cp").onclick = function () {
  var t = document.getElementById("src").innerText, b = this;
  (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject()).catch(function () {
    var r = document.createRange(); r.selectNodeContents(document.getElementById("src"));
    var s = getSelection(); s.removeAllRanges(); s.addRange(r); document.execCommand("copy"); s.removeAllRanges();
  }).then(function () { b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1200); });
};
</script></body></html>`;
}

// Full standalone HTML page with a dark theme matching the canvas.
export function htmlReportPage(title, bodyHtml) {
    return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0d1117; color: #c9d1d9;
    font: 14px/1.6 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .wrap { max-width: none; margin: 0; padding: 28px 34px 80px; }
  h1, h2, h3, h4, h5, h6 { color: #e6edf3; line-height: 1.25; margin: 1.4em 0 .5em; font-weight: 640; }
  h1 { font-size: 26px; border-bottom: 1px solid #21262d; padding-bottom: .3em; }
  h2 { font-size: 21px; border-bottom: 1px solid #21262d; padding-bottom: .3em; }
  h3 { font-size: 17px; } h4 { font-size: 15px; }
  a { color: #58a6ff; text-decoration: none; } a:hover { text-decoration: underline; }
  p { margin: .6em 0; }
  code { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: .12em .4em; font-size: 85%;
    font-family: "SF Mono", "Cascadia Code", Consolas, monospace; color: #d2a8ff; }
  pre.code { background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 14px 16px; overflow: auto; }
  pre.code code { background: none; border: none; padding: 0; color: #c9d1d9; }
  a code { color: #58a6ff; }
  a:hover code { text-decoration: underline; }
  .mermaid { margin: 1.2em 0; padding: 14px 12px; background: #0f141a; border: 1px solid #21262d;
    border-radius: 10px; overflow-x: auto; text-align: center; }
  .mermaid svg { max-width: 100%; height: auto; }
  blockquote { border-left: 3px solid #30363d; margin: .8em 0; padding: .2em 14px; color: #b1bac4; }
  blockquote blockquote { margin: .4em 0; padding: .1em 10px; }
  details { margin: .6em 0; border: 1px solid #21262d; border-radius: 8px; background: #0f141a; padding: .1em .9em; }
  details details { background: #0d1117; }
  summary { cursor: pointer; padding: .45em 0; color: #e6edf3; font-weight: 600; }
  details[open] > summary { border-bottom: 1px solid #21262d; margin-bottom: .6em; }
  summary strong { font-weight: 600; }
  hr { border: none; border-top: 1px solid #21262d; margin: 1.6em 0; }
  ul, ol { padding-left: 1.5em; margin: .5em 0; }
  li { margin: .25em 0; }
  /* Wide tables scroll inside a wrapper capped to the viewport height, so the horizontal
     scrollbar is always on screen (not at the foot of a very tall table). The edge shadows
     hint that more columns are off-screen; the header stays pinned while scrolling. */
  .tw { margin: 1em 0; max-width: 100%; max-height: 78vh; overflow: auto; border: 1px solid #30363d; border-radius: 8px;
    scrollbar-width: auto; scrollbar-color: #6e7681 #161b22;
    background: linear-gradient(90deg, #0d1117 30%, rgba(13,17,23,0)) left center / 28px 100% no-repeat local,
      linear-gradient(270deg, #0d1117 30%, rgba(13,17,23,0)) right center / 28px 100% no-repeat local,
      linear-gradient(90deg, rgba(88,166,255,.35), rgba(88,166,255,0)) left center / 10px 100% no-repeat scroll,
      linear-gradient(270deg, rgba(88,166,255,.35), rgba(88,166,255,0)) right center / 10px 100% no-repeat scroll; }
  .tw::-webkit-scrollbar { width: 12px; height: 12px; }
  .tw::-webkit-scrollbar-track { background: #161b22; }
  .tw::-webkit-scrollbar-thumb { background: #6e7681; border-radius: 6px; border: 2px solid #161b22; }
  .tw::-webkit-scrollbar-thumb:hover { background: #8b949e; }
  table { border-collapse: separate; border-spacing: 0; width: 100%; margin: 0; font-size: 13px; }
  th, td { border-right: 1px solid #30363d; border-bottom: 1px solid #30363d; padding: 6px 11px; text-align: left; vertical-align: top; min-width: 96px; overflow-wrap: break-word; }
  th:last-child, td:last-child { border-right: none; }
  tr:last-child td { border-bottom: none; }
  th { background: #161b22; color: #e6edf3; font-weight: 620; position: sticky; top: 0; z-index: 1; }
  tr:nth-child(even) td { background: #0f141a; }
  del { color: #6e7681; }
</style></head><body><div class="wrap">${bodyHtml}</div>
<script>
// In-page links often point inside collapsed <details>; open every ancestor so
// the target is visible, then scroll to it.
(function () {
  function openTo(id) {
    var el = id && document.getElementById(id);
    if (!el) return;
    for (var p = el.parentElement; p; p = p.parentElement) if (p.tagName === "DETAILS") p.open = true;
    el.scrollIntoView();
  }
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest('a[href^="#"]');
    if (a && a.getAttribute("href").length > 1) openTo(decodeURIComponent(a.getAttribute("href").slice(1)));
  });
  window.addEventListener("hashchange", function () { openTo(decodeURIComponent(location.hash.slice(1))); });
  if (location.hash) openTo(decodeURIComponent(location.hash.slice(1)));
})();
</script></body></html>`;
}
