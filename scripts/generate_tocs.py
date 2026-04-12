"""Generate Quick Reference TOC tables for query files that don't have them yet."""
import re
import os
from pathlib import Path

QUERIES_DIR = Path(__file__).resolve().parent.parent / "queries"

# Files to skip (already have TOC or no queries)
SKIP_FILES = {
    # No files skipped — script handles all, including previously-manual TOCs
}

# Map heading keywords to use case
def infer_use_case(heading: str) -> str:
    h = heading.lower()
    if any(w in h for w in ["summary", "overview", "breakdown", "volume", "trend", "dashboard", "efficacy", "baseline"]):
        return "Dashboard"
    if any(w in h for w in ["posture", "hygiene", "inventory", "maturity", "score", "compliance", "assessment"]):
        return "Posture"
    if any(w in h for w in ["detect", "alert", "rule", "scheduled", "singleton", "anomal", "spray", "brute"]):
        return "Detection"
    if any(w in h for w in ["triage", "top ", "most targeted", "most common"]):
        return "Triage"
    if any(w in h for w in ["hunt", "correlation", "chain", "timeline", "forensic", "trace", "drill"]):
        return "Investigation"
    return "Investigation"  # default for query files

def heading_to_anchor(heading: str) -> str:
    """Convert a markdown heading to a GitHub-compatible anchor.
    GitHub's algorithm: lowercase, remove all chars except [a-z0-9 -],
    replace spaces with hyphens, DO NOT collapse consecutive hyphens."""
    anchor = heading.lower()
    anchor = re.sub(r'[^a-z0-9 -]', '', anchor)
    anchor = anchor.replace(' ', '-')
    return anchor

def extract_table_from_kql(lines: list, start_idx: int) -> str:
    """Look for the first KQL table name after a heading."""
    # Common KQL table names
    tables = set()
    in_kql = False
    for i in range(start_idx, min(start_idx + 40, len(lines))):
        line = lines[i]
        if line.strip().startswith("```kql"):
            in_kql = True
            continue
        if line.strip() == "```" and in_kql:
            break
        if in_kql:
            # Match table names at start of line or after let/union
            matches = re.findall(r'\b([A-Z][a-zA-Z]+(?:Events?|Logs?|Info|Indicators?|Activity|Incident|Alert|Graph\w+|Configuration\w+|Vulnerabilit\w+|Inventory|Recommendation|Diagnostics|Score))\b', line)
            for m in matches:
                if m not in ("TimeGenerated", "Timestamp", "IsInternetFacing", "DeviceName",
                             "AccountName", "RemoteIP", "SourceIP", "True", "False",
                             "LogonType", "EventID", "ActionType", "ResultType"):
                    tables.add(m)
    if not tables:
        return "—"
    # Return the first (most likely primary) table, or combine if 2
    table_list = sorted(tables)
    if len(table_list) == 1:
        return f"`{table_list[0]}`"
    if len(table_list) == 2:
        return f"`{table_list[0]}` + `{table_list[1]}`"
    return f"`{table_list[0]}` + multi"


def find_section_headings(lines: list) -> list:
    """Find all ### and ## Query headings and their line indices."""
    headings = []
    _skipped = 0
    _passed = 0
    for i, line in enumerate(lines):
        is_h3 = line.startswith("### ")
        is_h2_query = line.startswith("## Query ") or (line.startswith("## Q") and not line.startswith("## Quick"))
        
        if not is_h3 and not is_h2_query:
            continue
        
        if is_h3 and (line.startswith("### ⚠️") or line.startswith("### Required") 
                      or line.startswith("### Configuration") or line.startswith("### Common") 
                      or line.startswith("### Known")):
            continue
            
        heading_text = line.lstrip("#").strip()
        # Skip non-query headings
        skip_patterns = ["Table Coverage", "NLA LogonType", "Recommended Scheduled",
                         "Reducing False", "Increasing Detection", "Internal Lateral",
                         "External Brute", "Required Data", "Log Analytics", "Test Data",
                         "Attack Flow", "What AiTM", "Known Threat", "Built-In",
                         "Immediate Actions", "Investigation (", "Remediation (", "Post-Incident",
                         "Microsoft Official", "Community", "Tables Reference",
                         "Detection Rule", "Response Playbook",
                         "Key Threat", "Full Attack Chain", "Threat Summary",
                         "MITRE ATT&CK", "IOC ", "Indicators of",
                         "MCP Tool", "Prerequisites",
                         "Deployment", "Tuning", "Operationali",
                         "How to Use", "Usage", "Setup",
                         "Architecture", "Design", "Overview",
                         "Defensive ", "Defense ", "Posture Recommendations",
                         "Appendix", "References", "Resources",
                         "Alert Tuning", "False Positive", "Troubleshoot",
                         "Summary of", "Recap", "Conclusion",
                         "Scoring", "Risk Score", "Maturity",
                         "Recommended MCP", "Column Avail", "Scale Warning",
                         "Recommended Approach", "Notes on Specific",
                         "Additional Resource", "Version History",
                         "Investigation Workflow", "Detection Rule",
                         '"Has Known', '"Status"', "EPSS Score", '"First Detected',
                         "What the Export", "Decision Guide",
                         "Time Range", "User-Specific", "Application-Specific",
                         "High-Priority", "Alert Rule", "Step ",
                         "Key Cloud", "Key ", "Related Tables",
                         "Reconnaissance", "Resource Development", "Initial Access",
                         "Discovery", "Lateral Movement", "Collection",
                         "C2", "Exfiltration", "Impact",
                         "Level ", "Microsoft Threat",
                         "Tool ", "Discover All", "Find All"]
        # Also skip emoji-prefixed tier/level headings
        if any(heading_text.startswith(p) for p in skip_patterns):
            continue
        if re.match(r'^[🔴🟠🟡🟢🔵⚠️]\s*(Tier|Level)\s', heading_text):
            continue
        # Skip section group headers like "1. Critical Devices & Assets (Queries 1-4)"
        if re.match(r'^\d+\.\s.*\(Quer', heading_text):
            continue
        # Skip headings that don't have a KQL code block within 40 lines
        # (non-query descriptive sections)
        has_kql = False
        for j in range(i + 1, min(i + 40, len(lines))):
            if lines[j].strip().startswith("```kql"):
                has_kql = True
                break
            if lines[j].startswith("## ") or lines[j].startswith("### "):
                break  # hit next heading without finding KQL
        if not has_kql:
            continue
        headings.append((i, heading_text))
    return headings


def find_insertion_point(lines: list) -> int:
    """Find where to insert the TOC — after the metadata header, before first ## section."""
    in_metadata = False
    after_metadata = False
    for i, line in enumerate(lines):
        if line.startswith("---") and not in_metadata and i < 15:
            in_metadata = True
            continue
        if line.startswith("---") and in_metadata:
            after_metadata = True
            continue
        if after_metadata and line.startswith("## "):
            # Insert before this ## heading
            return i
    # Fallback: after the first --- block
    for i, line in enumerate(lines):
        if line.startswith("---") and i > 5:
            return i + 1
    return 12  # fallback


def detect_section_groups(headings: list) -> dict:
    """Try to detect ## section groups for the TOC."""
    # Look at the numbering pattern
    groups = {}
    for _, heading in headings:
        # Check for "Query N:" or "N.N" pattern
        m = re.match(r'(?:Query\s+)?(\d+)[\.:]\s*(.*)', heading)
        if m:
            num = m.group(1)
            if num not in groups:
                groups[num] = []
    return groups


def generate_toc(lines: list, headings: list) -> str:
    """Generate the TOC markdown block."""
    if not headings:
        return ""
    
    rows = []
    current_section = None
    
    for line_idx, heading_text in headings:
        anchor = heading_to_anchor(heading_text)
        table = extract_table_from_kql(lines, line_idx)
        use_case = infer_use_case(heading_text)
        
        # Detect section grouping from ## headings above
        # Check for a ## heading between this and the previous query
        
        # Build the row
        # Extract short number if present
        m = re.match(r'(?:Query\s+)?(\d+[\.\d]*)\s*[:\.]?\s*(.*)', heading_text)
        if m:
            num = m.group(1)
            short_name = m.group(2).strip().rstrip('(').strip()
        else:
            num = "—"
            short_name = heading_text
        
        # Truncate long names
        if len(short_name) > 70:
            short_name = short_name[:67] + "..."
        
        linked_name = f"[{short_name}](#{anchor})"
        rows.append(f"| {num} | {linked_name} | {use_case} | {table} |")
    
    toc_lines = [
        "## Quick Reference — Query Index",
        "",
        "| # | Query | Use Case | Key Table |",
        "|---|-------|----------|-----------|",
    ]
    toc_lines.extend(rows)
    toc_lines.append("")
    
    return "\n".join(toc_lines)


def process_file(filepath: Path) -> bool:
    """Add TOC to a single file. Returns True if modified."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Strip existing auto-generated TOC if present (for re-runs)
    # Preserves any manually-added "Investigation shortcuts:" content
    lines = content.split("\n")
    preserved_shortcuts = []
    if "Quick Reference" in content:
        toc_start = None
        table_start = None
        toc_end = None
        for i, line in enumerate(lines):
            if line.startswith("## Quick Reference"):
                toc_start = i
            elif toc_start is not None and table_start is None and line.startswith("|"):
                table_start = i
            elif table_start is not None and toc_end is None:
                if not line.startswith("|") and line.strip() != "":
                    toc_end = i
                    break
        if toc_start is not None and toc_end is not None:
            if table_start is None:
                table_start = toc_start + 1
            # Capture shortcuts between heading and table
            for j in range(toc_start + 1, table_start):
                if lines[j].strip() and not lines[j].startswith("|"):
                    preserved_shortcuts.append(lines[j])
            # Also capture any content between table end and next ## heading
            footer_end = toc_end
            for j in range(toc_end, len(lines)):
                if lines[j].startswith("## ") or lines[j].startswith("---"):
                    footer_end = j
                    break
            for l in lines[toc_end:footer_end]:
                if l.strip():
                    preserved_shortcuts.append(l)
            lines = lines[:toc_start] + lines[footer_end:]
            content = "\n".join(lines)
    
    lines = content.split("\n")
    headings = find_section_headings(lines)
    
    if len(headings) < 2:
        print(f"  Skipping {filepath.name} — only {len(headings)} query heading(s)")
        # Debug: show what headings we DID find vs total ## / ### in file
        total_h = sum(1 for l in lines if l.startswith("## ") or l.startswith("### "))
        print(f"    DEBUG: {total_h} total ##/### headings in file, {len(lines)} lines")
        if total_h > 0:
            for i, l in enumerate(lines[:10]):
                if l.startswith("## ") or l.startswith("### "):
                    print(f"    First heading at line {i}: {l[:60]}")
        return False
    
    toc = generate_toc(lines, headings)
    if not toc:
        return False
    
    insertion_point = find_insertion_point(lines)
    
    # Insert TOC before the first ## section, with preserved shortcuts before the table
    if preserved_shortcuts:
        shortcuts_block = "\n".join(preserved_shortcuts)
        # Insert: heading + shortcuts + blank + table
        toc_with_shortcuts = f"## Quick Reference — Query Index\n\n{shortcuts_block}\n\n" + "\n".join(toc.split("\n")[2:])  # skip the heading from generated toc
        new_lines = lines[:insertion_point] + [toc_with_shortcuts, ""] + lines[insertion_point:]
    else:
        new_lines = lines[:insertion_point] + [toc, ""] + lines[insertion_point:]
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(new_lines))
    
    print(f"  ✅ {filepath.name}: {len(headings)} queries indexed, inserted at line {insertion_point}")
    return True


def main():
    print("TOC Generator — Query Files")
    print("=" * 50)
    
    modified = 0
    skipped = 0
    
    for md_file in sorted(QUERIES_DIR.rglob("*.md")):
        if md_file.name in SKIP_FILES:
            continue
        
        print(f"\nProcessing: {md_file.relative_to(QUERIES_DIR)}")
        if process_file(md_file):
            modified += 1
        else:
            skipped += 1
    
    print(f"\n{'=' * 50}")
    print(f"Done: {modified} files modified, {skipped} skipped")


if __name__ == "__main__":
    main()
