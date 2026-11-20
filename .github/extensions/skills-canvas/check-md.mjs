// Regression check for the markdown preview. Perception's verbatim detection
// reports use constructs the original renderer flattened into a wall of text:
// nested blockquotes, tables / fences inside quotes, <details>/<summary>, <br>
// and <a id> anchors. Renders synthetic cases plus every saved Perception
// report and fails on leftovers.
//
//   node .github/extensions/skills-canvas/check-md.mjs
//   node .github/extensions/skills-canvas/check-md.mjs --html <out.html>

import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderMarkdown, htmlReportPage, codeReportPage } from "./md.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
let failures = 0;
const check = (name, ok, detail = "") => {
    if (!ok) failures++;
    console.log((ok ? "PASS " : "FAIL ") + name + (ok || !detail ? "" : "  -> " + detail));
};
const has = (h, s) => h.includes(s);

// 1) synthetic cases
const quoted = [
    "<a id=\"det-1\"></a>",
    "",
    "> <details open>",
    "> <summary><strong>1. Rule name (T1566)</strong></summary>",
    ">",
    "> | Field | Value |",
    "> | --- | --- |",
    "> | Severity | Low |",
    "> | Evidence | - one<br>- two |",
    "> | Code | `a | b` and x\\|y |",
    ">",
    "> > <details>",
    "> > <summary>Query</summary>",
    "> >",
    "> > ```kql",
    "> > let X = 1; // <b>not html</b>",
    "> > T | take 1",
    "> > ```",
    "> >",
    "> > </details>",
    "> </details>",
    "",
    "After <script>alert(1)</script> and <random> text.",
    "[jump](#det-1)",
].join("\n");
const h = renderMarkdown(quoted, "x.md");
check("details open + summary rendered", has(h, "<details open>") && has(h, "<summary><strong>1. Rule name (T1566)</strong></summary>"), h.slice(0, 300));
check("nested details closed in balance", (h.match(/<details/g) || []).length === (h.match(/<\/details>/g) || []).length);
check("table inside quote is a real table", has(h, "<table>") && has(h, "<td>Low</td>"));
check("tables sit in a scroll wrapper (visible horizontal scrollbar)", has(h, '<div class="tw"><table>') && has(h, "</table></div>"));
check("br in cell is a line break", has(h, "- one<br>- two"));
check("pipe inside code span stays in one cell", has(h, "<code>a | b</code>") && has(h, "x|y"));
check("fence inside nested quote is a code block", has(h, '<pre class="code lang-kql"><code>let X = 1; // &lt;b&gt;not html&lt;/b&gt;'));
check("anchor-only line emitted", has(h, '<a id="det-1"></a>'));
check("script tag escaped", !has(h, "<script>") && has(h, "&lt;script&gt;"));
check("unknown tag <random> stays visible text", has(h, "&lt;random&gt;"));
check("no leaked raw markdown pipes/quotes", !/<p>[^<]*\|\s*---/.test(h) && !has(h, "&gt; &gt;"));
check("unclosed details auto-closed", (renderMarkdown("<details>\n<summary>x</summary>\ntext", "x.md").match(/<\/details>/g) || []).length === 1);
check("stray </details> ignored", !has(renderMarkdown("</details>\ntext", "x.md"), "</details>"));
check("underscore italics at word boundaries only", has(renderMarkdown("_Every one_ and snake_case_name", "x.md"), "<em>Every one</em>") && has(renderMarkdown("snake_case_name", "x.md"), "snake_case_name") && !has(renderMarkdown("snake_case_name", "x.md"), "<em>"));
check("code inside a link is styled as a link", has(htmlReportPage("t", ""), "a code { color: #58a6ff"));
check("**Label:** lines keep their own line", has(renderMarkdown("**Date:** x\n**Tenant:** y\nwrapped\ntext", "x.md"), "x<br><strong>Tenant:</strong> y wrapped text"));
check("page keeps in-page link opener", has(htmlReportPage("t", h), "openTo"));

// 1b) code viewer + links to report artefacts
const kqlPage = codeReportPage("t.kql", 'let X = dynamic(["<b>a</b>"]); // note <script>\nT\n| where A has_any (X) and N > 5\n| project A', "kql");
check("kql page highlights keywords/comments/strings", has(kqlPage, '<span class="k-k">where</span>') && has(kqlPage, '<span class="k-c">// note &lt;script&gt;</span>') && has(kqlPage, '<span class="k-s">&quot;&lt;b&gt;a&lt;/b&gt;&quot;</span>'));
check("CRLF source renders single-spaced", !has(codeReportPage("t.kql", "a\r\nb\r\n", "kql"), "\r") && has(codeReportPage("t.kql", "a\r\nb", "text"), "2 lines"));
check("kql page cannot inject markup", !has(kqlPage, "<script>alert") && !has(kqlPage, "<b>a</b>"));
const txtPage = codeReportPage("l.txt", "https://security.microsoft.com/v2/custom_detection?tid=x#customDetectionRule=AAA <img src=x>", "text");
check("txt page links only the portal URL and escapes the rest", has(txtPage, '<a href="https://security.microsoft.com/v2/custom_detection') && !has(txtPage, "<img"));
const lk = renderMarkdown("[kql](reports/perception/tune-detection/x/tuned.kql) and `reports/perception/tune-detection/x/tuned.txt` and `reports/a/b` and [rel](./tuned.kql)", "reports/perception/tune-detection/r.md");
check("markdown link to .kql routes to viewer", has(lk, 'href="/api/report?path=reports%2Fperception%2Ftune-detection%2Fx%2Ftuned.kql"'));
check("code-span path to .txt becomes a link", has(lk, '<a href="/api/report?path=reports%2Fperception%2Ftune-detection%2Fx%2Ftuned.txt"><code>'));
check("code-span path without a viewable extension stays plain", has(lk, "<code>reports/a/b</code>") && !has(lk, 'tuned.txt"><code>reports/a/b'));
check("relative ./ link to .kql resolves beside the report", has(lk, "reports%2Fperception%2Ftune-detection%2Ftuned.kql"));

// 2) every saved Perception report
async function walk(dir, out = []) {
    let entries;
    try { entries = await readdir(dir, { withFileTypes: true }); } catch { return out; }
    for (const e of entries) {
        const abs = path.join(dir, e.name);
        if (e.isDirectory()) await walk(abs, out);
        else if (/\.md$/i.test(e.name)) out.push(abs);
    }
    return out;
}
const files = await walk(path.join(REPO_ROOT, "reports", "perception"));
const gallery = [];
for (const f of files) {
    const rel = path.relative(REPO_ROOT, f).replace(/\\/g, "/");
    const html = renderMarkdown(await readFile(f, "utf8"), rel);
    const visible = html.replace(/<pre[\s\S]*?<\/pre>/g, "").replace(/<code>[\s\S]*?<\/code>/g, "");
    const bad = [];
    if (/&lt;\/?(details|summary|strong|br|a)\b/i.test(visible)) bad.push("raw html tag shown as text");
    if (/(^|<p>|<td>)\s*&gt;/.test(visible)) bad.push("quote marker shown as text");
    if (/<p>\s*\|\s*[^<]*\|\s*---/.test(visible)) bad.push("table shown as text");
    if ((html.match(/<details/g) || []).length !== (html.match(/<\/details>/g) || []).length) bad.push("unbalanced details");
    if (/```/.test(visible)) bad.push("fence shown as text");
    check(rel, bad.length === 0, bad.join("; "));
    if (/detection_report/.test(f)) gallery.push([rel, html]);
}
if (process.argv.includes("--html")) {
    const out = process.argv[process.argv.indexOf("--html") + 1];
    await writeFile(out, htmlReportPage("md check", gallery.map(([n, hh]) => "<h1>" + n + "</h1>" + hh).join("\n")), "utf8");
    console.log("wrote", out);
}
console.log(failures ? failures + " FAILED" : "all passed");
process.exit(failures ? 1 : 0);
