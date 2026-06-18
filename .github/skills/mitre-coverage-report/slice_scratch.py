# -*- coding: utf-8 -*-
"""
slice_scratch.py - Deterministic verbatim block slicer for the MITRE scratchpad.

The mitre-coverage-report pipeline (Invoke-MitreScan.ps1) writes pre-rendered
markdown tables into temp/mitre_scratch_<ts>.md under stable `### <Section>`
markers. When assembling the final report you must copy those tables VERBATIM
(the SKILL forbids recalculating badges, renaming tactics, or reordering rows).

Hand-copying large tables is exactly where an agent drifts. This tool extracts a
named block (or lists/dumps all of them) so the verbatim content is guaranteed
byte-for-byte, leaving only the narrative for the agent to author.

This script is READ-ONLY. It never writes, deploys, or mutates anything.

Usage:
    python slice_scratch.py --scratch temp/mitre_scratch_<ts>.md --list
    python slice_scratch.py --scratch temp/mitre_scratch_<ts>.md --section CombinedTacticCoverage
    python slice_scratch.py --scratch temp/mitre_scratch_<ts>.md --all
"""
import argparse
import io
import sys

try:  # ensure emoji/box-drawing content prints on legacy code-page consoles
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def read_lines(path):
    with io.open(path, "r", encoding="utf-8") as f:
        return [ln.rstrip("\n") for ln in f.readlines()]


def _is_scaffold(s):
    """True for blank/comment/SectionTitle scaffolding lines (ignored when testing bodies)."""
    return s == "" or s.startswith("<!--") or s.startswith("-->") or s.startswith("SectionTitle:")


def find_sections(lines):
    """Return an ordered list of (name, start_idx) for every real '### <name>' marker.

    Some pipelines emit a heading-skeleton block (e.g. '### Headings') whose body is
    a verbatim list of the report's own section headings — including nested '### '
    lines. A flat scan would mistake those nested headings for section boundaries and
    truncate the skeleton. So a '### ' marker whose body (up to the next '### ', minus
    scaffolding) consists only of markdown heading lines is treated as a nested TOC
    entry: the FIRST marker of such a run is kept as the container, the rest are
    dropped. This is a no-op for scratchpads without a heading-skeleton block.
    """
    raw = []
    for idx, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith("### "):
            raw.append((s[4:].strip(), idx))
    out = []
    in_skeleton = False
    for k, (name, i) in enumerate(raw):
        nxt = raw[k + 1][1] if k + 1 < len(raw) else len(lines)
        body = [ln.strip() for ln in lines[i + 1:nxt]]
        content = [b for b in body if not _is_scaffold(b)]
        heading_only = bool(content) and all(b.startswith("#") for b in content)
        if not content or heading_only:
            if in_skeleton:
                continue  # nested TOC entry — fold into the container block
            in_skeleton = True  # first marker of the skeleton run — keep as container
        else:
            in_skeleton = False
        out.append((name, i))
    return out


def slice_block(lines, name):
    """Return the verbatim block under '### <name>', up to the next '### ' marker.

    Several section names appear twice: once as a raw data block and again as a
    pre-rendered report table under '## PRERENDERED'. The report wants the
    pre-rendered copy, so when duplicates exist we prefer the match at/after the
    '## PRERENDERED' marker and only fall back to an earlier match if none exists.

    Strips scaffolding comment/title lines and surrounding blank lines but keeps
    the table content exactly as the pipeline emitted it. Sub-headings ('#### ')
    inside the block are preserved.
    """
    sections = find_sections(lines)
    prerendered_at = next((i for i, ln in enumerate(lines)
                           if ln.strip() == "## PRERENDERED"), None)
    matches = [idx for idx, (nm, _) in enumerate(sections) if nm == name]
    if not matches:
        raise KeyError("section not found: %r (available: %s)"
                       % (name, ", ".join(nm for nm, _ in sections)))
    chosen = matches[0]
    if prerendered_at is not None:
        preferred = [m for m in matches if sections[m][1] >= prerendered_at]
        if preferred:
            chosen = preferred[0]
    start = sections[chosen][1] + 1
    end = sections[chosen + 1][1] if chosen + 1 < len(sections) else len(lines)
    seg = lines[start:end]

    # Drop pipeline scaffolding wherever it appears in the block: HTML comments
    # (single-line OR multi-line spans) and `SectionTitle:` markers. Keep table
    # rows, `#### ` sub-headings, and narrative prose.
    cleaned = []
    in_comment = False
    for ln in seg:
        s = ln.strip()
        if in_comment:
            if "-->" in s:
                in_comment = False
            continue
        if s.startswith("<!--"):
            if "-->" not in s:
                in_comment = True
            continue
        if s.startswith("SectionTitle:"):
            continue
        cleaned.append(ln)

    # Collapse consecutive blank lines (left behind by removed scaffolding) and
    # trim surrounding blanks so the slice drops cleanly into the report.
    out = []
    for ln in cleaned:
        if ln.strip() == "" and out and out[-1].strip() == "":
            continue
        out.append(ln)
    while out and out[0].strip() == "":
        out.pop(0)
    while out and out[-1].strip() == "":
        out.pop()
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verbatim slicer for the MITRE coverage scratchpad.")
    ap.add_argument("--scratch", required=True, help="Path to mitre_scratch_<ts>.md")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true", help="List all section markers")
    g.add_argument("--section", help="Print one named section verbatim")
    g.add_argument("--all", action="store_true", help="Print every section with its header")
    args = ap.parse_args(argv)

    lines = read_lines(args.scratch)
    sections = find_sections(lines)

    if args.list:
        for nm, i in sections:
            print("%-28s (line %d)" % (nm, i + 1))
        return 0

    if args.section:
        try:
            print(slice_block(lines, args.section))
        except KeyError as e:
            sys.stderr.write(str(e) + "\n")
            return 2
        return 0

    # --all
    for nm, _ in sections:
        body = slice_block(lines, nm)
        if not body.strip():
            continue
        print("### " + nm)
        print()
        print(body)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
