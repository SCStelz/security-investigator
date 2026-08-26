// Minimal, dependency-free Markdown -> HTML renderer for the Mission Control
// report preview. Handles the subset our reports use: headings, GitHub tables,
// fenced + inline code, bold/italic, links, blockquotes, ordered/unordered
// lists, and horizontal rules. Not a full CommonMark implementation — just
// enough to render investigation reports legibly inside the canvas modal.

function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// Inline: code spans first (protected), then links, bold, italic.
function inline(text) {
    const codes = [];
    let s = text.replace(/`([^`]+)`/g, (_, c) => {
        codes.push("<code>" + escapeHtml(c) + "</code>");
        return "\u0000" + (codes.length - 1) + "\u0000";
    });
    s = escapeHtml(s);
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, t, href) => {
        const safe = /^(https?:|mailto:|#|\/)/i.test(href) ? href : "#";
        return '<a href="' + safe + '" target="_blank" rel="noopener">' + t + "</a>";
    });
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, "$1<em>$2</em>");
    s = s.replace(/~~([^~]+)~~/g, "<del>$1</del>");
    s = s.replace(/\u0000(\d+)\u0000/g, (_, i) => codes[Number(i)]);
    return s;
}

function renderTable(rows) {
    // rows: array of raw "| a | b |" lines; row[1] is the --- separator.
    const cells = (line) =>
        line
            .trim()
            .replace(/^\||\|$/g, "")
            .split("|")
            .map((c) => c.trim());
    const header = cells(rows[0]);
    const body = rows.slice(2).map(cells);
    let html = "<table><thead><tr>";
    html += header.map((h) => "<th>" + inline(h) + "</th>").join("");
    html += "</tr></thead><tbody>";
    for (const r of body) {
        html += "<tr>" + header.map((_, i) => "<td>" + inline(r[i] || "") + "</td>").join("") + "</tr>";
    }
    html += "</tbody></table>";
    return html;
}

export function renderMarkdown(md) {
    const lines = String(md).replace(/\r\n/g, "\n").split("\n");
    const out = [];
    let i = 0;
    let listType = null; // 'ul' | 'ol'

    const closeList = () => {
        if (listType) {
            out.push(listType === "ul" ? "</ul>" : "</ol>");
            listType = null;
        }
    };

    while (i < lines.length) {
        const line = lines[i];

        // Fenced code block
        const fence = line.match(/^```(.*)$/);
        if (fence) {
            closeList();
            const lang = fence[1].trim();
            const buf = [];
            i++;
            while (i < lines.length && !/^```/.test(lines[i])) {
                buf.push(lines[i]);
                i++;
            }
            i++; // skip closing fence
            out.push('<pre class="code' + (lang ? " lang-" + escapeHtml(lang) : "") + '"><code>' + escapeHtml(buf.join("\n")) + "</code></pre>");
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
            out.push("<h" + lvl + ">" + inline(h[2].trim()) + "</h" + lvl + ">");
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
            out.push("<blockquote>" + inline(buf.join(" ")) + "</blockquote>");
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
            !/^```/.test(lines[i]) &&
            !/^(#{1,6})\s+/.test(lines[i]) &&
            !/^\s*[-*+]\s+/.test(lines[i]) &&
            !/^\s*\d+[.)]\s+/.test(lines[i]) &&
            !/^\s*\|.*\|\s*$/.test(lines[i]) &&
            !/^\s*>\s?/.test(lines[i])
        ) {
            buf.push(lines[i]);
            i++;
        }
        out.push("<p>" + inline(buf.join(" ")) + "</p>");
    }
    closeList();
    return out.join("\n");
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
  .wrap { max-width: 920px; margin: 0 auto; padding: 28px 34px 80px; }
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
  blockquote { border-left: 3px solid #30363d; margin: .8em 0; padding: .2em 14px; color: #8b949e; }
  hr { border: none; border-top: 1px solid #21262d; margin: 1.6em 0; }
  ul, ol { padding-left: 1.5em; margin: .5em 0; }
  li { margin: .25em 0; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 13px; display: block; overflow-x: auto; }
  th, td { border: 1px solid #30363d; padding: 6px 11px; text-align: left; vertical-align: top; }
  th { background: #161b22; color: #e6edf3; font-weight: 620; }
  tr:nth-child(even) td { background: #0f141a; }
  del { color: #6e7681; }
</style></head><body><div class="wrap">${bodyHtml}</div></body></html>`;
}
