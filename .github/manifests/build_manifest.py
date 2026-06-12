#!/usr/bin/env python3
"""
Discovery Manifest Generator & Validator

Scans all query files (queries/**/*.md) and skill files (.github/skills/*/SKILL.md)
to extract structured metadata, validate it, and emit the discovery manifest.

Default output: .github/manifests/discovery-manifest.yaml (slim — title, path, domains, mitre, prompt)
With --full:     also emits discovery-manifest-full.yaml (all fields including tables, keywords, platform, timeframe)

Usage:
    python .github/manifests/build_manifest.py                  # generate slim + validate
    python .github/manifests/build_manifest.py --full            # also generate full manifest
    python .github/manifests/build_manifest.py --validate-only  # validate without writing
    python .github/manifests/build_manifest.py --verbose         # print details
"""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

# ── Constants ────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
QUERIES_DIR = REPO_ROOT / "queries"
SKILLS_DIR = REPO_ROOT / ".github" / "skills"
MANIFESTS_DIR = REPO_ROOT / ".github" / "manifests"
MANIFEST_PATH = MANIFESTS_DIR / "discovery-manifest.yaml"
MANIFEST_FULL_PATH = MANIFESTS_DIR / "discovery-manifest-full.yaml"

VALID_DOMAINS = {
    "incidents",
    "identity",
    "spn",
    "endpoint",
    "email",
    "admin",
    "cloud",
    "exposure",
}

# Fields extracted from query file markdown headers
QUERY_HEADER_FIELDS = {
    "Tables": "tables",
    "Keywords": "keywords",
    "MITRE": "mitre",
    "Domains": "domains",
    "Platform": "platform",
    "Timeframe": "timeframe",
}


# ── Parsers ──────────────────────────────────────────────────────────────────


def parse_query_file(path: Path) -> dict | None:
    """Parse a query markdown file and extract metadata header fields."""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"  WARNING: Could not read {path}: {e}", file=sys.stderr)
        return None

    lines = text.split("\n")
    if not lines:
        return None

    # Title is the first # heading
    title = None
    for line in lines[:5]:
        if line.startswith("# "):
            title = line[2:].strip()
            break

    if not title:
        return None

    result = {
        "title": title,
        "path": str(path.relative_to(REPO_ROOT)).replace("\\", "/"),
    }

    # Extract **Field:** values from the header block (first 15 lines)
    header_block = "\n".join(lines[:15])
    for md_key, yaml_key in QUERY_HEADER_FIELDS.items():
        pattern = rf"\*\*{md_key}:\*\*\s*(.+)"
        match = re.search(pattern, header_block)
        if match:
            raw = match.group(1).strip()
            # Split comma-separated values into a list
            values = [v.strip() for v in raw.split(",") if v.strip()]
            result[yaml_key] = values

    return result


def parse_skill_file(path: Path) -> dict | None:
    """Parse a skill SKILL.md file and extract YAML frontmatter."""
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        print(f"  WARNING: Could not read {path}: {e}", file=sys.stderr)
        return None

    # Extract YAML frontmatter between --- delimiters
    if not text.startswith("---"):
        return None

    end = text.find("---", 3)
    if end == -1:
        return None

    frontmatter_text = text[3:end].strip()
    try:
        frontmatter = yaml.safe_load(frontmatter_text)
    except yaml.YAMLError as e:
        print(f"  WARNING: Invalid YAML in {path}: {e}", file=sys.stderr)
        return None

    if not isinstance(frontmatter, dict):
        return None

    name = frontmatter.get("name", "")
    if not name:
        return None

    result = {
        "name": name,
        "path": str(path.relative_to(REPO_ROOT)).replace("\\", "/"),
    }

    # Extract threat_pulse_domains if present
    domains = frontmatter.get("threat_pulse_domains")
    if domains:
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",")]
        result["domains"] = domains

    # Extract drill_down_prompt if present
    prompt = frontmatter.get("drill_down_prompt")
    if prompt:
        result["prompt"] = prompt

    return result


# ── Scanner ──────────────────────────────────────────────────────────────────


def scan_queries() -> list[dict]:
    """Scan all query files and return parsed metadata."""
    results = []
    if not QUERIES_DIR.exists():
        print(f"  WARNING: {QUERIES_DIR} not found", file=sys.stderr)
        return results

    for md_file in sorted(QUERIES_DIR.rglob("*.md")):
        parsed = parse_query_file(md_file)
        if parsed:
            results.append(parsed)

    return results


def scan_skills() -> list[dict]:
    """Scan all skill SKILL.md files and return parsed metadata."""
    results = []
    if not SKILLS_DIR.exists():
        print(f"  WARNING: {SKILLS_DIR} not found", file=sys.stderr)
        return results

    for skill_file in sorted(SKILLS_DIR.rglob("SKILL.md")):
        parsed = parse_skill_file(skill_file)
        if parsed:
            results.append(parsed)

    return results


# ── Validator ────────────────────────────────────────────────────────────────


def validate(queries: list[dict], skills: list[dict], verbose: bool = False) -> list[str]:
    """Validate metadata completeness and consistency. Returns list of warnings."""
    warnings = []

    # Validate query files
    for q in queries:
        path = q["path"]
        if "domains" not in q or not q["domains"]:
            warnings.append(f"QUERY  missing Domains: {path}")
        else:
            for d in q["domains"]:
                if d not in VALID_DOMAINS:
                    warnings.append(f"QUERY  unknown domain '{d}': {path}")

        if "tables" not in q:
            warnings.append(f"QUERY  missing Tables: {path}")
        if "keywords" not in q:
            warnings.append(f"QUERY  missing Keywords: {path}")
        if "mitre" not in q:
            warnings.append(f"QUERY  missing MITRE: {path}")

    # Validate skill files
    investigation_skills = [
        s for s in skills
        if s["name"] not in {
            "detection-authoring", "kql-query-authoring",
            "geomap-visualization", "heatmap-visualization",
            "svg-dashboard", "threat-pulse", "sentinel-ingestion-report",
            "threat-intel-campaign", "context-memory-review",
        }
    ]

    for s in investigation_skills:
        path = s["path"]
        if "domains" not in s or not s["domains"]:
            warnings.append(f"SKILL  missing threat_pulse_domains: {path} ({s['name']})")
        else:
            for d in s["domains"]:
                if d not in VALID_DOMAINS:
                    warnings.append(f"SKILL  unknown domain '{d}': {path} ({s['name']})")

        if "prompt" not in s:
            warnings.append(f"SKILL  missing drill_down_prompt: {path} ({s['name']})")

    # Check domain coverage — which domains have no query files?
    query_domains = set()
    for q in queries:
        query_domains.update(q.get("domains", []))

    skill_domains = set()
    for s in skills:
        skill_domains.update(s.get("domains", []))

    for d in VALID_DOMAINS:
        if d not in query_domains:
            warnings.append(f"COVERAGE  no query files tagged with domain '{d}'")
        if d not in skill_domains:
            warnings.append(f"COVERAGE  no skills tagged with domain '{d}'")

    return warnings


# ── Manifest Writer ──────────────────────────────────────────────────────────


def build_manifest(queries: list[dict], skills: list[dict]) -> dict:
    """Build the manifest dictionary."""
    manifest = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valid_domains": sorted(VALID_DOMAINS),
        "skills": skills,
        "queries": queries,
    }
    return manifest


def build_slim_manifest(queries: list[dict], skills: list[dict]) -> dict:
    """Build a slim manifest with only the fields threat-pulse needs."""
    slim_queries = []
    for q in queries:
        entry = {"title": q["title"], "path": q["path"]}
        if "domains" in q:
            entry["domains"] = q["domains"]
        if "mitre" in q:
            entry["mitre"] = q["mitre"]
        slim_queries.append(entry)

    slim_skills = []
    for s in skills:
        entry = {"name": s["name"], "path": s["path"]}
        if "domains" in s:
            entry["domains"] = s["domains"]
        if "prompt" in s:
            entry["prompt"] = s["prompt"]
        slim_skills.append(entry)

    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valid_domains": sorted(VALID_DOMAINS),
        "skills": slim_skills,
        "queries": slim_queries,
    }


def _write_yaml(path: Path, manifest: dict, header: str) -> None:
    """Write a manifest dict to YAML file with a header comment."""
    path.parent.mkdir(parents=True, exist_ok=True)
    yaml_content = yaml.dump(
        manifest,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=120,
    )
    path.write_text(header + yaml_content, encoding="utf-8")


def write_manifest(slim_manifest: dict) -> None:
    """Write the default (slim) manifest."""
    header = (
        "# Discovery Manifest — Auto-generated by build_manifest.py\n"
        "# DO NOT EDIT MANUALLY — run: python .github/manifests/build_manifest.py\n"
        "#\n"
        "# Slim version: title, path, domains, mitre, prompt only.\n"
        "# Use --full flag to generate the verbose manifest with tables, keywords, platform, timeframe.\n"
        "\n"
    )
    _write_yaml(MANIFEST_PATH, slim_manifest, header)


def write_full_manifest(manifest: dict) -> None:
    """Write the full (verbose) manifest."""
    header = (
        "# Discovery Manifest (Full) — Auto-generated by build_manifest.py --full\n"
        "# DO NOT EDIT MANUALLY — run: python .github/manifests/build_manifest.py --full\n"
        "#\n"
        "# Full manifest with all fields (tables, keywords, mitre, domains, platform, timeframe).\n"
        "\n"
    )
    _write_yaml(MANIFEST_FULL_PATH, manifest, header)


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Build discovery manifest for skills and query files")
    parser.add_argument("--validate-only", action="store_true", help="Validate without writing manifest")
    parser.add_argument("--full", action="store_true", help="Also generate the full verbose manifest")
    parser.add_argument("--verbose", action="store_true", help="Print detailed output")
    args = parser.parse_args()

    print("Discovery Manifest Generator")
    print("=" * 40)

    # Scan
    queries = scan_queries()
    skills = scan_skills()
    print(f"  Found {len(queries)} query files")
    print(f"  Found {len(skills)} skill files")

    # Validate
    warnings = validate(queries, skills, args.verbose)
    if warnings:
        print(f"\n[!] {len(warnings)} validation warning(s):")
        for w in warnings:
            print(f"  - {w}")
    else:
        print("\n[OK] All metadata validated -- no warnings")

    if args.verbose:
        print("\n--- Query Files ---")
        for q in queries:
            domains = q.get("domains", ["(none)"])
            print(f"  {q['path']}: domains={domains}")
        print("\n--- Skills ---")
        for s in skills:
            domains = s.get("domains", ["(none)"])
            print(f"  {s['path']}: domains={domains}")

    # Write
    if not args.validate_only:
        slim = build_slim_manifest(queries, skills)
        write_manifest(slim)
        print(f"\nManifest: {MANIFEST_PATH.relative_to(REPO_ROOT)}")
        if args.full:
            full = build_manifest(queries, skills)
            write_full_manifest(full)
            print(f"Full:     {MANIFEST_FULL_PATH.relative_to(REPO_ROOT)}")
    else:
        print("\n  (validate-only mode — manifests not written)")

    # Exit code
    error_count = sum(1 for w in warnings if not w.startswith("COVERAGE"))
    if error_count > 0:
        print(f"\n[ERROR] {error_count} error-level warnings (missing required fields)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
