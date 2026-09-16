// Mermaid render sweep. The markdown preview renders diagrams server-side, so a
// parser regression turns a diagram back into a wall of source text without any
// error. Catch that here: find every mermaid fence in the repo, render it, and
// report anything that falls back.
//
//   node .github/extensions/skills-canvas/check-mermaid.mjs
//   node .github/extensions/skills-canvas/check-mermaid.mjs --html <out.html>
//
// --html writes a gallery page of every rendered diagram for visual review.
// Write it outside the repo (e.g. the session artifacts folder) — it's scratch.

import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderMermaid, parseFlowchart, labelLines } from "./mermaid.mjs";
import { parseXYChart } from "./xychart.mjs";
import { parsePie } from "./pie.mjs";
import { parseSequence } from "./sequence.mjs";
import { htmlReportPage } from "./md.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SKIP = new Set(["node_modules", ".git", "temp", "state"]);

async function walk(dir, out = []) {
    let entries;
    try {
        entries = await readdir(dir, { withFileTypes: true });
    } catch {
        return out;
    }
    for (const e of entries) {
        if (SKIP.has(e.name)) continue;
        const abs = path.join(dir, e.name);
        if (e.isDirectory()) await walk(abs, out);
        else if (/\.(md|markdown)$/i.test(e.name)) out.push(abs);
    }
    return out;
}

// Pull every ```mermaid fence out of a markdown file, with its 1-based line number.
function extractBlocks(text) {
    const lines = text.replace(/\r\n/g, "\n").split("\n");
    const blocks = [];
    for (let i = 0; i < lines.length; i++) {
        if (!/^\s*```mermaid\s*$/i.test(lines[i])) continue;
        const start = i + 1;
        const buf = [];
        i++;
        while (i < lines.length && !/^\s*```/.test(lines[i])) buf.push(lines[i++]);
        blocks.push({ line: start, src: buf.join("\n") });
    }
    return blocks;
}

const htmlAt = process.argv.indexOf("--html");
const htmlOut = htmlAt > -1 ? process.argv[htmlAt + 1] : null;

// First non-empty, non-comment line names the diagram type.
function diagramType(src) {
    for (const l of String(src).replace(/\r\n/g, "\n").split("\n")) {
        const t = l.trim();
        if (!t || t.startsWith("%%")) continue;
        return (/^[\w-]+/.exec(t) || ["?"])[0];
    }
    return "?";
}

const files = await walk(REPO_ROOT);
let total = 0;
let broken = 0;
const unsupported = new Map();
const gallery = [];

// Syntax that the renderers support but no document in the repo currently uses.
// Without these the code paths ship untested — the "Note left of" case below
// caught a diagram that rendered 70px past its own left edge.
const FIXTURES = [
    ["fixture:rect-bands-self-message", `sequenceDiagram
  autonumber
  actor U as Analyst<br/>(on call)
  participant A as Agent
  participant K as Key Vault
  rect rgb(30,58,95)
    U->>A: investigate alert
    A->>A: retry lookup
    A-->>U: partial result
  end
  rect rgba(120,40,40,0.35)
    A->>K: SecretGet
    K--xA: denied
  end
  Note right of K: policy blocked the read
  Note left of U: escalate to tier 2
  A-)U: async notification`],
    ["fixture:unterminated-rect", `sequenceDiagram
  participant A
  participant B
  rect rgb(20,80,20)
    A->>B: still inside an open block`],
    ["fixture:undeclared-participants", `sequenceDiagram
  Alice->>Bob: hello
  Bob-->>Alice: hi back`],
    ["fixture:single-slice-pie", `pie showData title Only one category
  "Everything" : 42`],
];

const work = FIXTURES.map(([where, src]) => ({ where, src }));
for (const abs of files.sort()) {
    const rel = path.relative(REPO_ROOT, abs).replace(/\\/g, "/");
    for (const b of extractBlocks(await readFile(abs, "utf8"))) {
        work.push({ where: rel + ":" + b.line, src: b.src });
    }
}

for (const { where, src } of work) {
    total++;
    const kind = diagramType(src);
    const svg = renderMermaid(src);
    if (!svg) {
        // A supported type that won't render is a regression; any other
        // diagram type is simply out of scope and renders as source.
        if (/^(flowchart|graph|xychart-beta|xychart|pie|sequenceDiagram)$/i.test(kind)) {
            broken++;
            console.log("BROKEN   " + where + "  (" + kind + " failed to render)");
        } else {
            unsupported.set(kind, (unsupported.get(kind) || 0) + 1);
        }
        continue;
    }
    if (/^xychart/i.test(kind)) {
        const c = parseXYChart(src);
        // Silently dropping every series would render an empty grid.
        if (!c || !c.series.length || !c.count) {
            broken++;
            console.log("BROKEN   " + where + "  xychart parsed with no data");
            continue;
        }
        console.log("OK       " + where + "  " + c.count + " categories, " +
            c.series.map((s) => s.kind).join("+"));
        if (htmlOut) gallery.push("<h2>" + where + '</h2><div class="mermaid">' + svg + "</div>");
        continue;
    }
    if (/^pie$/i.test(kind)) {
        const p = parsePie(src);
        // A slice whose label vanished would render an unidentifiable wedge.
        const blankSlice = p.slices.filter((s) => !String(s.label).trim());
        if (blankSlice.length) {
            broken++;
            console.log("BROKEN   " + where + "  " + blankSlice.length + " slice(s) lost their label");
            continue;
        }
        console.log("OK       " + where + "  " + p.slices.length + " slices, total " + p.total);
        if (htmlOut) gallery.push("<h2>" + where + '</h2><div class="mermaid">' + svg + "</div>");
        continue;
    }
    if (/^sequenceDiagram$/i.test(kind)) {
        const s = parseSequence(src);
        const msgs = s.events.filter((e) => e.type === "msg");
        const notes = s.events.filter((e) => e.type === "note");
        // Dropped messages are the failure mode here: the diagram still
        // renders, just missing rows, which is easy to miss by eye.
        const srcArrows = src.split("\n").filter((l) => /^\s*[^\s:%]+\s*--?-?[>x)]{1,2}\s*[^\s:]+\s*:/.test(l)).length;
        if (msgs.length < srcArrows) {
            broken++;
            console.log("BROKEN   " + where + "  parsed " + msgs.length + " of " + srcArrows + " message lines");
            continue;
        }
        const blankActor = s.actors.filter((a) => !a.label.trim());
        if (blankActor.length) {
            broken++;
            console.log("BROKEN   " + where + "  " + blankActor.length + " participant(s) lost their label");
            continue;
        }
        console.log("OK       " + where + "  " + s.actors.length + " participants, " + msgs.length +
            " messages, " + notes.length + " notes");
        if (htmlOut) gallery.push("<h2>" + where + '</h2><div class="mermaid">' + svg + "</div>");
        continue;
    }
    const g = parseFlowchart(src);
    // A node that renders with no text means the label was swallowed —
    // this is how the "<Agent Name>" placeholder-vs-HTML-tag bug showed up.
    const blank = g.nodes.filter((n) => !labelLines(n.text || "").join("").trim());
    if (blank.length) {
        broken++;
        console.log("BROKEN   " + where + "  " + blank.length + " node(s) lost their label: " + blank.map((n) => n.id).join(", "));
        continue;
    }
    console.log("OK       " + where + "  " + g.nodes.length + " nodes, " + g.edges.length + " edges, " + g.dir);
    if (htmlOut) gallery.push("<h2>" + where + '</h2><div class="mermaid">' + svg + "</div>");
}

if (htmlOut) {
    await writeFile(htmlOut, htmlReportPage("Mermaid gallery", gallery.join("\n")), "utf8");
    console.log("\ngallery -> " + htmlOut);
}

const skipped = [...unsupported.entries()].sort((a, b) => b[1] - a[1]);
if (skipped.length) {
    console.log("\nrendered as source (diagram type not supported):");
    for (const [k, n] of skipped) console.log("  " + String(n).padStart(3) + "  " + k);
}
console.log("\n" + total + " diagram(s), " + (total - broken - [...unsupported.values()].reduce((a, b) => a + b, 0)) + " rendered, " + broken + " broken");
process.exit(broken ? 1 : 0);
