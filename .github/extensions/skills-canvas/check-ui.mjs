// Render-time sanity sweep. The canvas builds its HTML and client JS as one
// big string, so a typo'd element id or a modal toggled with the wrong class
// fails silently at runtime. Catch both statically.
import { renderPage } from "./ui.mjs";

const html = renderPage({});
const i = html.indexOf("<script>");
const js = html.slice(i + 8, html.lastIndexOf("</script>"));
const ids = new Set([...html.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
// Some elements are built at runtime rather than rendered into the markup.
for (const m of js.matchAll(/\.id\s*=\s*"([^"]+)"/g)) ids.add(m[1]);
for (const m of js.matchAll(/id="([^"]+)"/g)) ids.add(m[1]);

let bad = 0;

// 1. Every getElementById target must exist in the markup.
const missing = new Set();
for (const m of js.matchAll(/getElementById\("([^"]+)"\)/g)) {
    if (!ids.has(m[1])) missing.add(m[1]);
}
for (const id of missing) {
    console.log("MISSING ELEMENT: #" + id);
    bad++;
}

// 2. Modals are shown with .on — .open is styled by nothing.
for (const m of js.matchAll(/getElementById\("(\w*[Mm]odal)"\)\.classList\.(add|remove)\("([^"]+)"\)/g)) {
    if (m[3] !== "on") {
        console.log("WRONG MODAL CLASS: #" + m[1] + " uses ." + m[3] + " (must be .on)");
        bad++;
    }
}

// 3. Every modal in the markup should have a backdrop close binding.
for (const id of ids) {
    if (!/[Mm]odal$/.test(id)) continue;
    if (!js.includes('bindBackdropClose("' + id + '"')) {
        console.log("NO BACKDROP CLOSE: #" + id);
        bad++;
    }
}

console.log(bad ? "\n" + bad + " problem(s)" : "clean — " + ids.size + " ids, " + js.length + " chars of client JS");
process.exit(bad ? 1 : 0);
