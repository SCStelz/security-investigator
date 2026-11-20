#!/usr/bin/env python3
"""Helpers for the perception-triage-alert skill (deterministic, no network).

  python triage_helper.py check "<alert title>"            is this alert type on Microsoft's documented Triage Agent list?
  python triage_helper.py list                              the snapshot (categories and counts)
  python triage_helper.py refresh <learn-page.md|.json>     rebuild supported_alerts.json from the Learn "Triage Agent" page
  python triage_helper.py parse-report <triage_report.md>   classification + reasoning from a Perception triage_report.md
  python triage_helper.py compare --perception "<verdict>" --defender <classification> [--determination <d>]
  python triage_helper.py lint-report <report.md>           fail if the report restates alert evidence (IPs, UPNs/emails, user agents, geo)
  python triage_helper.py selftest

The Learn list is a *documented subset that grows*; "not listed" is a warning, not a refusal (see SKILL.md).
Snapshot file: supported_alerts.json next to this script (public Microsoft documentation only, no tenant data).
"""
from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
SNAPSHOT = HERE / "supported_alerts.json"
SOURCE_URL = "https://learn.microsoft.com/en-us/security/agentic-security/triage-agent#supported-alerts"


def norm(s: str) -> str:
    s = re.sub(r"\(preview\)", " ", s or "", flags=re.I)
    s = re.sub(r"[^a-z0-9]+", " ", s.lower())
    return re.sub(r"\s+", " ", s).strip()


def load_snapshot(path: Path = SNAPSHOT) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_supported_section(text: str) -> dict:
    """Parse the '## Supported alerts' table of the Learn page into {category: {scope, alerts[]}}."""
    i = text.index("## Supported alerts")
    j = text.index("## Before you begin")
    out: dict = {}
    for line in text[i:j].splitlines():
        m = re.match(r"^\| \*\*(.+?)\*\* \| (.*) \|\s*$", line)
        if not m:
            continue
        cat, rest = m.group(1), m.group(2)
        parts = rest.split("<br>")
        head = parts[0].strip()
        items = [re.sub(r"^\s*-\s*", "", x).strip() for x in parts[1:] if x.strip()]
        items = [re.sub(r"\s*\(preview\)\s*$", "", x).strip() for x in items]
        if not items:
            items = [re.sub(r"\s*\(preview\)\s*$", "", head).strip()]
            head = ""
        out[cat] = {"scope": head, "alerts": items}
    if not out:
        raise SystemExit("no supported-alert table found in the input")
    return out


def check(title: str, snap: dict) -> dict:
    n = norm(title)
    index = {}
    for cat, v in snap["categories"].items():
        for a in v["alerts"]:
            index.setdefault(norm(a), (cat, a))
    if n in index:
        cat, a = index[n]
        return {"status": "LISTED", "category": cat, "matched": a}
    close = difflib.get_close_matches(n, list(index), n=3, cutoff=0.78)
    return {"status": "NOT LISTED", "closest": [index[c][1] for c in close]}


def parse_report(text: str) -> dict:
    def section(name: str) -> str:
        m = re.search(r"^##\s+" + name + r"\s*$", text, re.M | re.I)
        if not m:
            return ""
        rest = text[m.end():]
        n = re.search(r"^##\s+", rest, re.M)
        return (rest[: n.start()] if n else rest).strip()

    cls = section("Alert classification").splitlines()
    classification = cls[0].strip().strip("*`") if cls else ""
    reasoning = re.sub(r"\\([_*\[\]()])", r"\1", section("Reasoning"))
    return {"classification": classification, "reasoning": reasoning, "hasReport": bool(classification or reasoning)}


def verdict_kind(perception: str) -> str:
    p = norm(perception)
    if "true positive" in p:
        return "TP"
    if "false positive" in p:
        return "FP"
    if "benign" in p or "informational" in p:
        return "BENIGN"
    if not p or p in ("not set", "unknown", "none", "n a"):
        return "NONE"
    return "OTHER"


def compare(perception: str, defender: str | None, determination: str | None = None) -> dict:
    k = verdict_kind(perception)
    d = (defender or "").strip()
    dn = norm(d)
    if k in ("NONE", "OTHER"):
        return {"result": "INCONCLUSIVE", "why": f"Perception returned '{perception or 'no classification'}': not a verdict; do not treat as clean or malicious."}
    if not d or dn in ("unknown", "null", "none", "unknownfuturevalue"):
        return {"result": "NO-BASELINE", "why": "Defender has no classification on the alert yet; Perception's verdict is the only one (still [asserted])."}
    if k == "TP":
        res = "AGREE" if dn == "truepositive" else "DISAGREE"
    elif k == "FP":
        res = "AGREE" if dn == "falsepositive" else ("PARTIAL" if dn == "informationalexpectedactivity" else "DISAGREE")
    else:
        res = "AGREE" if dn == "informationalexpectedactivity" else ("PARTIAL" if dn == "falsepositive" else "DISAGREE")
    why = {"AGREE": "same direction as Defender's current classification",
           "PARTIAL": "both non-malicious, different label (false positive vs informational/expected activity)",
           "DISAGREE": "opposite of Defender's current classification: highlight for human review, never auto-resolve"}[res]
    return {"result": res, "why": why, "defender": d, "determination": determination or "", "perception": perception}


_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_UA = re.compile(r"Mozilla/\d|\b(?:Mobile Safari|iPhone|Android \d)\b|python-requests|curl/\d", re.I)
_URL = re.compile(r"\]\([^)]*\)|https?://\S+")


def lint_report(text: str) -> list[str]:
    """Evidence that must not be restated in a triage report (it lives behind the alert link)."""
    body = _URL.sub(" ", text)
    out = []
    for lineno, line in enumerate(body.splitlines(), 1):
        for rx, what in ((_IPV4, "IP address"), (_EMAIL, "UPN/email"), (_UA, "user agent / device string")):
            m = rx.search(line)
            if m:
                out.append(f"line {lineno}: {what} ({m.group(0)[:40]})")
    return out


def cmd_lint_report(a) -> int:
    problems = lint_report(Path(a.file).read_text(encoding="utf-8-sig"))
    for p in problems:
        print("PROBLEM:", p)
    print("OK: no alert evidence restated" if not problems else f"{len(problems)} problem(s): rewrite generically (\"the involved account\", \"a residential IP\") and cite memory rule names, not values")
    return 1 if problems else 0


def cmd_check(a) -> int:
    snap = load_snapshot()
    r = check(a.title, snap)
    r["snapshotDate"] = snap.get("snapshotDate")
    r["source"] = snap.get("source")
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    elif r["status"] == "LISTED":
        print(f"LISTED: '{r['matched']}' under {r['category']} (Learn snapshot {r['snapshotDate']})")
    else:
        print(f"NOT LISTED: '{a.title}' is not in the documented Triage Agent alert list (Learn snapshot {r['snapshotDate']}; the list grows, re-check {r['source']}).")
        if r["closest"]:
            print("closest documented names: " + "; ".join(r["closest"]))
    return 0


def cmd_list(_) -> int:
    snap = load_snapshot()
    print(f"snapshot {snap.get('snapshotDate')} from {snap.get('source')}")
    for cat, v in snap["categories"].items():
        print(f"- {cat}: {len(v['alerts'])} alert name(s)" + (f" ({v['scope']})" if v["scope"] else ""))
    return 0


def cmd_refresh(a) -> int:
    raw = Path(a.file).read_text(encoding="utf-8-sig")
    try:
        j = json.loads(raw)
        raw = j["text"] if isinstance(j, dict) and "text" in j else raw
    except json.JSONDecodeError:
        pass
    cats = parse_supported_section(raw)
    SNAPSHOT.write_text(json.dumps({"source": SOURCE_URL, "snapshotDate": date.today().isoformat(), "categories": cats}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("snapshot written:", ", ".join(f"{c} ({len(v['alerts'])})" for c, v in cats.items()))
    return 0


def cmd_parse_report(a) -> int:
    r = parse_report(Path(a.file).read_text(encoding="utf-8-sig"))
    r["kind"] = verdict_kind(r["classification"])
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0 if r["hasReport"] else 1


def cmd_compare(a) -> int:
    print(json.dumps(compare(a.perception, a.defender, a.determination), indent=2, ensure_ascii=False))
    return 0


def cmd_selftest(_) -> int:
    doc = (
        "## Supported alerts\n\n| Alert type | Alert name |\n| --- | --- |\n"
        "| **Email and collaboration alerts, including phishing** | Email reported by user as malware or phish |\n"
        "| **Cloud alerts** | View all cloud alerts<br><br>- Unusual access to Bash profile file<br>- SSH server is running inside a container (preview) |\n"
        "| **Endpoint alerts** | Suspicious PowerShell command line |\n\n## Before you begin\n")
    cats = parse_supported_section(doc)
    assert cats["Cloud alerts"]["alerts"] == ["Unusual access to Bash profile file", "SSH server is running inside a container"], cats
    assert cats["Endpoint alerts"]["alerts"] == ["Suspicious PowerShell command line"]
    snap = {"categories": cats}
    assert check("suspicious powershell command line", snap)["status"] == "LISTED"
    assert check("SSH server is running inside a container (preview)", snap)["status"] == "LISTED"
    r = check("Suspicious PowerShell commandline", snap)
    assert r["status"] == "NOT LISTED" and r["closest"] == ["Suspicious PowerShell command line"], r
    assert check("Unfamiliar sign-in properties", snap) == {"status": "NOT LISTED", "closest": []}
    rep = "## Summary\n\nAlert Triage Report\n\n## Alert classification\n\nTrue Positive\n\n## Reasoning\n\nBecause \\_x\\_ happened.\n"
    p = parse_report(rep)
    assert p["classification"] == "True Positive" and "_x_" in p["reasoning"], p
    assert parse_report("nothing here")["hasReport"] is False
    assert verdict_kind("Not set") == "NONE" and verdict_kind("False Positive") == "FP" and verdict_kind("True positive") == "TP"
    assert compare("True Positive", "falsePositive")["result"] == "DISAGREE"
    assert compare("True Positive", "truePositive")["result"] == "AGREE"
    assert compare("False Positive", "informationalExpectedActivity")["result"] == "PARTIAL"
    assert compare("False Positive", None)["result"] == "NO-BASELINE"
    assert compare("Not set", "truePositive")["result"] == "INCONCLUSIVE"
    assert lint_report("clean text about the involved account") == []
    assert len(lint_report("sign-in from 203.0.113.42 by user@contoso.com with Mozilla/5.0 (iPhone)")) == 3
    assert lint_report("see [alert](https://security.microsoft.com/alerts/x?ip=1.2.3.4)") == []
    print("selftest ok")
    return 0


def main() -> int:
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            s.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("title"); c.add_argument("--json", action="store_true"); c.set_defaults(fn=cmd_check)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    r = sub.add_parser("refresh"); r.add_argument("file"); r.set_defaults(fn=cmd_refresh)
    pr = sub.add_parser("parse-report"); pr.add_argument("file"); pr.set_defaults(fn=cmd_parse_report)
    cp = sub.add_parser("compare"); cp.add_argument("--perception", required=True); cp.add_argument("--defender", default=""); cp.add_argument("--determination", default=""); cp.set_defaults(fn=cmd_compare)
    lt = sub.add_parser("lint-report"); lt.add_argument("file"); lt.set_defaults(fn=cmd_lint_report)
    sub.add_parser("selftest").set_defaults(fn=cmd_selftest)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
