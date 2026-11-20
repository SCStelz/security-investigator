#!/usr/bin/env python3
"""Decode / re-encode Microsoft Defender custom-detection wizard links.

Perception's Detection Authoring Agent emits "Open in Wizard" links of the form

    https://security.microsoft.com/v2/custom_detection#customDetectionRule=<token>

where <token> is base64url( gzip( JSON ) ) with the padding stripped. The JSON
holds the rule definition (name, queryText, severity, entity mappings, ...).

This format was observed empirically; it is not a documented contract, so every
command fails loudly if the decoded payload doesn't look like a rule.

Usage:
    python wizard_link.py decode <url-or-token-or-file> [--out rule.json] [--query-out rule.kql]
    python wizard_link.py encode --base <url-or-token-or-file> --query-file tuned.kql \
        [--name "..."] [--description "..."] [--tid <tenant-guid>] [--out link.txt]
    python wizard_link.py list-report <detection_report.md> [--out-dir DIR]
    python wizard_link.py insert <report.md> --link-file link.txt [--placeholder "{{WIZARD_LINK}}"] [--text "..."]
    python wizard_link.py verify <file> [--query-file tuned.kql] [--link-file link.txt]
    python wizard_link.py validate <manifest.json> [--index N | --name "..."]
    python wizard_link.py from-manifest <manifest.json> [--index N | --name "..."] [--tid GUID | --no-tid] [--out-dir DIR]
    python wizard_link.py selftest

`validate` / `from-manifest` take the same JSON manifest as Deploy-CustomDetections.ps1 and build one
prefilled wizard link per rule (the analyst reviews and clicks Save; nothing is deployed by the agent).

`encode` starts from an existing link (--base) so every field Perception set
(frequency, severity, MITRE, entity mappings, ...) is preserved; only name,
queryText and ruleDescription may change. The result is round-trip verified.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import re
import sys
from pathlib import Path

WIZARD_URL = "https://security.microsoft.com/v2/custom_detection"
TOKEN_RE = re.compile(r"customDetectionRule=([A-Za-z0-9_\-=]+)")
REQUIRED_KEYS = ("name", "queryText")
EDITABLE_KEYS = {"name", "queryText", "ruleDescription"}

# ---- manifest (Graph model) -> wizard payload mapping, kept as data -------------------------
# Verified = observed in real Perception payloads or confirmed by the wizard experiments.
SCHEDULES = {"1H": (60, 1.0), "3H": (180, 3.0), "12H": (720, 12.0), "24H": (1440, 24.0)}
NRT_SUPPORTED = True    # E2d (2026-11-19): frequencyInMinutes 0 + intervalHours 0 opens as Continuous (NRT); schedule:"0" is ignored (defaults to hourly)
NRT_PAYLOAD: dict = {"frequencyInMinutes": 0, "intervalHours": 0}
VALID_SCHEDULES = {"0", *SCHEDULES}
MAX_URL_CHARS = 14000   # largest link verified to open and save in the wizard (E5b, ~14 KB); Perception links are 1.5-3 KB
VALID_SEVERITY = {"informational", "low", "medium", "high"}
VALID_CATEGORY = {
    "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "Exfiltration", "CommandAndControl", "Impact",
    "Reconnaissance", "ResourceDevelopment", "Malware", "Ransomware", "SuspiciousActivity", "UnwantedSoftware",
}
VALID_IDENTIFIERS = {  # Graph enums (Deploy-CustomDetections.ps1 / SKILL.md Pitfall 9), case-sensitive
    "device": ["deviceId", "deviceName", "remoteDeviceName", "targetDeviceName", "destinationDeviceName"],
    "user": ["accountObjectId", "accountSid", "accountUpn", "accountName", "accountDomain", "accountId",
             "requestAccountSid", "requestAccountName", "requestAccountDomain", "recipientObjectId",
             "processAccountObjectId", "initiatingAccountSid", "initiatingProcessAccountUpn",
             "initiatingAccountName", "initiatingAccountDomain", "servicePrincipalId",
             "servicePrincipalName", "targetAccountUpn"],
    "mailbox": ["accountUpn", "fileOwnerUpn", "initiatingProcessAccountUpn", "lastModifyingAccountUpn",
                "targetAccountUpn", "senderFromAddress", "senderDisplayName", "recipientEmailAddress",
                "senderMailFromAddress"],
}
ENTITY_COLUMN_PROP = {  # identifier -> Graph entityMappings column property (from the deploy script)
    "user": {
        "accountObjectId": "aadUserIdColumn", "accountId": "aadUserIdColumn", "recipientObjectId": "aadUserIdColumn",
        "processAccountObjectId": "aadUserIdColumn", "servicePrincipalId": "aadUserIdColumn",
        "accountSid": "sidColumn", "requestAccountSid": "sidColumn", "initiatingAccountSid": "sidColumn",
        "accountUpn": "upnColumn", "initiatingProcessAccountUpn": "upnColumn", "targetAccountUpn": "upnColumn",
        "accountName": "nameColumn", "requestAccountName": "nameColumn", "initiatingAccountName": "nameColumn",
        "servicePrincipalName": "nameColumn",
        "accountDomain": "ntDomainColumn", "requestAccountDomain": "ntDomainColumn", "initiatingAccountDomain": "ntDomainColumn",
    },
    "device": {"deviceId": "deviceIdColumn", "deviceName": "nameColumn", "remoteDeviceName": "nameColumn",
               "targetDeviceName": "nameColumn", "destinationDeviceName": "nameColumn"},
    "mailbox": {"accountUpn": "primaryAddressColumn", "fileOwnerUpn": "primaryAddressColumn",
                "initiatingProcessAccountUpn": "primaryAddressColumn", "lastModifyingAccountUpn": "primaryAddressColumn",
                "targetAccountUpn": "primaryAddressColumn", "senderFromAddress": "primaryAddressColumn",
                "recipientEmailAddress": "primaryAddressColumn", "senderMailFromAddress": "primaryAddressColumn",
                "senderDisplayName": "displayNameColumn"},
}
ASSET_TO_WIZARD = {  # asset type -> (wizard entityType, Graph column property -> wizard identifier field)
    "user": ("User", {"aadUserIdColumn": "AadUserId", "sidColumn": "Sid", "upnColumn": "UPN",
                      "nameColumn": "Name", "ntDomainColumn": "NTDomain"}),
    "device": ("Machine", {"deviceIdColumn": "DeviceId", "nameColumn": "HostName"}),
    "mailbox": ("Mailbox", {"primaryAddressColumn": "MailboxPrimaryAddress", "displayNameColumn": "DisplayName"}),
}
UNVERIFIED_IDS = {("User", "Name"), ("User", "NTDomain"), ("Mailbox", "DisplayName")}  # experiment E4
RELATED_ENTITIES = {  # manifest entityMappings key -> (wizard entityType, property -> wizard field); unverified Graph property names are skipped with a note
    "ips": ("IP", {"addressColumn": "Address"}),
    "urls": ("Url", {"urlColumn": "Url"}),
    "mailMessages": ("MailMessage", {"networkMessageIdColumn": "NetworkMessageId"}),
    "cloudApplications": ("CloudApplication", {"nameColumn": "Name"}),
}


class WizardLinkError(ValueError):
    pass


def extract_token(url_or_token: str) -> str:
    """Return the bare token from a full URL or a raw token string."""
    s = url_or_token.strip()
    m = TOKEN_RE.search(s)
    if m:
        return m.group(1)
    if re.fullmatch(r"[A-Za-z0-9_\-=]+", s):
        return s
    raise WizardLinkError("No customDetectionRule token found in input")


def decode_token(token: str) -> dict:
    t = token.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        raw = gzip.decompress(base64.b64decode(t))
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - surface any decode failure uniformly
        raise WizardLinkError(f"Token is not gzip+base64url JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise WizardLinkError("Decoded payload is not a JSON object")
    missing = [k for k in REQUIRED_KEYS if not payload.get(k)]
    if missing:
        raise WizardLinkError(
            f"Decoded payload is missing {missing}; the wizard link format may have changed"
        )
    return payload


def encode_payload(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    # mtime=0 keeps output deterministic for identical input.
    return base64.urlsafe_b64encode(gzip.compress(raw, mtime=0)).decode("ascii").rstrip("=")


def strip_comment_header(kql: str) -> str:
    """Drop leading `//` comment lines (documentation headers) from a KQL file."""
    lines = kql.splitlines()
    i = 0
    while i < len(lines) and (lines[i].startswith("//") or not lines[i].strip()):
        i += 1
    return "\n".join(lines[i:]).strip()


def build_link(base: str, query_text: str, name: str | None, description: str | None,
               tid: str | None) -> tuple[str, dict, list[str]]:
    original = decode_token(extract_token(base))
    new = dict(original)
    new["queryText"] = query_text.strip()
    if name:
        new["name"] = name
    if description:
        new["ruleDescription"] = description
    token = encode_payload(new)

    # Round-trip + invariants: fail rather than emit a link we can't vouch for.
    rt = decode_token(token)
    if rt != new:
        raise WizardLinkError("Round-trip mismatch after encoding")
    if list(rt.keys()) != list(original.keys()):
        raise WizardLinkError("Key set/order changed relative to the original payload")
    changed = [k for k in new if new[k] != original.get(k)]
    unexpected = [k for k in changed if k not in EDITABLE_KEYS]
    if unexpected:
        raise WizardLinkError(f"Unexpected fields changed: {unexpected}")

    url = WIZARD_URL + (f"?tid={tid}" if tid else "") + "#customDetectionRule=" + token
    return url, new, changed


def _read_input(value: str) -> str:
    p = Path(value)
    if len(value) < 400 and p.is_file():
        return p.read_text(encoding="utf-8").strip()
    return value


def cmd_decode(args: argparse.Namespace) -> int:
    payload = decode_token(extract_token(_read_input(args.link)))
    if args.out:
        Path(args.out).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.query_out:
        Path(args.query_out).write_text(payload["queryText"] + "\n", encoding="utf-8")
    summary = {k: v for k, v in payload.items() if k != "queryText"}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("\n--- queryText ---\n" + payload["queryText"])
    return 0


def cmd_encode(args: argparse.Namespace) -> int:
    kql = strip_comment_header(Path(args.query_file).read_text(encoding="utf-8"))
    if not kql:
        raise WizardLinkError("Query file is empty after removing comment header")
    url, _, changed = build_link(_read_input(args.base), kql, args.name, args.description, args.tid)
    if args.out:
        Path(args.out).write_text(url, encoding="utf-8")
    print(f"fields changed: {changed}")
    print(f"url length: {len(url)}")
    print(url)
    return 0


def _file_link(path: str) -> str:
    """Full URL (or bare token) stored in a link file, whitespace-trimmed."""
    s = Path(path).read_text(encoding="utf-8").strip()
    extract_token(s)  # fail early if it isn't a wizard link at all
    return s if s.startswith("http") else f"{WIZARD_URL}#customDetectionRule={s}"


def _fingerprint(token: str) -> str:
    import hashlib
    return f"{len(token)} chars, sha256:{hashlib.sha256(token.encode()).hexdigest()[:8]}"


def cmd_insert(args: argparse.Namespace) -> int:
    """Replace a placeholder in a Markdown file with a clickable link built from a link file.

    Models should never retype a 2-3 KB base64 token: write the report with the placeholder,
    then let this fill in the exact link from the saved file.
    """
    report = Path(args.report)
    text = report.read_text(encoding="utf-8")
    n = text.count(args.placeholder)
    if n == 0:
        raise WizardLinkError(f"Placeholder {args.placeholder!r} not found in {report}")
    link = f"[{args.text}]({_file_link(args.link_file)})"
    report.write_text(text.replace(args.placeholder, link), encoding="utf-8")
    print(f"inserted {n} link(s) into {report} ({_fingerprint(extract_token(link))})")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Check every wizard link in a file decodes cleanly and (optionally) matches the expected query/link."""
    text = Path(args.file).read_text(encoding="utf-8")
    tokens = TOKEN_RE.findall(text)
    if not tokens:
        raise WizardLinkError(f"No wizard links found in {args.file}")
    expect_q = strip_comment_header(Path(args.query_file).read_text(encoding="utf-8")).strip() if args.query_file else None
    expect_t = extract_token(_file_link(args.link_file)) if args.link_file else None
    bad = 0
    for i, tok in enumerate(tokens, 1):
        try:
            rule = decode_token(tok)
        except WizardLinkError as exc:
            print(f"FAIL link {i}: {exc}")
            bad += 1
            continue
        problems = []
        if expect_q is not None and rule["queryText"].strip() != expect_q:
            problems.append("queryText differs from --query-file")
        if expect_t is not None and tok != expect_t:
            problems.append("token differs from --link-file")
        bad += bool(problems)
        print(f"{'FAIL' if problems else 'OK'} link {i}: {rule['name'][:70]!r} ({_fingerprint(tok)})"
              + (f" — {'; '.join(problems)}" if problems else ""))
    return 2 if bad else 0


def cmd_list_report(args: argparse.Namespace) -> int:
    """List detection candidates (and decode their wizard links) from a Perception detection report.

    Accepts the Markdown report, or the JSON wrapper ({"text": "..."}) that read_output
    results are saved as when they are too large to return inline.
    """
    raw = Path(args.report).read_text(encoding="utf-8")
    try:
        wrapped = json.loads(raw)
        if isinstance(wrapped, dict) and isinstance(wrapped.get("text"), str):
            raw = wrapped["text"]
    except json.JSONDecodeError:
        pass  # plain Markdown

    # Candidate sections are anchored `<a id="det-CAND-001"></a>`; the same token also
    # appears in the coverage matrix, so use the first token found in each section.
    anchors = list(re.finditer(r'<a id="det-([A-Za-z0-9_-]+)"></a>', raw))
    if not anchors:
        raise WizardLinkError("No detection candidates found (expected <a id=\"det-...\"> anchors)")
    # Readiness comes from the report's own grouping: each candidate sits inside a
    # "Ready to deploy (N)" or "Requires tuning (N)" block. Phrases inside a section
    # are not reliable (e.g. a "ready" rule can still carry an *estimated* volume).
    groups = [(g.start(), "ready to deploy" if g.group(1).lower().startswith("ready") else "requires tuning")
              for g in re.finditer(r"<summary><strong>(Ready to deploy|Requires tuning)[^<]*</strong>", raw, re.I)]
    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for i, m in enumerate(anchors):
        end = anchors[i + 1].start() if i + 1 < len(anchors) else len(raw)
        section = raw[m.end():end]
        t = TOKEN_RE.search(section)
        if not t:
            rows.append({"candidate": m.group(1), "error": "no wizard link in section"})
            continue
        rule = decode_token(t.group(1))
        readiness = next((label for pos, label in reversed(groups) if pos < m.start()), "unknown")
        hits = re.search(r"produced \*\*(\d+)\*\* hits", section)
        row = {
            "candidate": m.group(1),
            "name": rule.get("name"),
            "readiness": readiness,
            "severity": rule.get("alertSeverity"),
            "frequencyMinutes": rule.get("frequencyInMinutes"),
            "mitre": rule.get("mitreTechniques"),
            "measuredHits14d": int(hits.group(1)) if hits else None,
            "volumeEstimatedNotMeasured": bool(re.search(r"measurement_dry_run_unavailable|Estimated risk \(not measured\)", section)),
        }
        if out_dir:
            cid = m.group(1)
            (out_dir / f"{cid}.token.txt").write_text(t.group(1), encoding="utf-8")
            (out_dir / f"{cid}.kql").write_text(rule["queryText"] + "\n", encoding="utf-8")
            (out_dir / f"{cid}.rule.json").write_text(json.dumps(rule, indent=2, ensure_ascii=False), encoding="utf-8")
            row["files"] = f"{cid}.token.txt / .kql / .rule.json"
        rows.append(row)
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()[:60] or "rule"


def load_manifest(path: str) -> list[dict]:
    """Load a Deploy-CustomDetections.ps1 manifest (JSON array of rule objects)."""
    raw = Path(path).read_text(encoding="utf-8-sig")
    data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("rules", [data])
    if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
        raise WizardLinkError(f"{path}: expected a JSON array of rule objects")
    return data


def _pascal(identifier: str) -> str:
    return identifier[:1].upper() + identifier[1:]


def validate_rule(rule: dict) -> tuple[list[str], list[str]]:
    """Port of Deploy-CustomDetections.ps1 pre-flight checks. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []
    name = rule.get("displayName")
    query = rule.get("queryText") or ""
    if not name:
        errors.append("displayName is required")
    if not query.strip():
        errors.append("queryText is required")
    schedule = str(rule.get("schedule", ""))
    if schedule not in VALID_SCHEDULES:
        errors.append(f"schedule {schedule!r} is not one of {sorted(VALID_SCHEDULES)}")
    if rule.get("severity") not in VALID_SEVERITY:
        errors.append(f"severity {rule.get('severity')!r} is not one of {sorted(VALID_SEVERITY)}")
    if rule.get("category") not in VALID_CATEGORY:
        errors.append(f"category {rule.get('category')!r} is not a valid (case-sensitive) category")
    for t in rule.get("mitreTechniques") or []:
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", str(t)):
            errors.append(f"mitreTechniques entry {t!r} is not a technique ID like T1059 or T1059.001")
    if rule.get("responseActions"):
        errors.append("responseActions must be empty: automated response actions are prohibited")

    assets = rule.get("impactedAssets") or []
    if not assets:
        errors.append("impactedAssets must contain at least 1 element (the API rejects empty arrays)")
    for a in assets:
        valid = VALID_IDENTIFIERS.get(a.get("type"))
        if valid is None:
            errors.append(f"unknown asset type {a.get('type')!r} (expected device, user or mailbox)")
            continue
        if a.get("identifier") not in valid:
            errors.append(f"invalid {a['type']} identifier {a.get('identifier')!r}; valid (case-sensitive): {', '.join(valid)}")
            continue
        col = a.get("column") or _pascal(a["identifier"])
        if not re.search(rf"\b{re.escape(col)}\b", query):
            warnings.append(f"query does not obviously project column {col!r} for {a['type']}/{a['identifier']}")

    title = rule.get("title") or rule.get("displayName") or ""
    dyn = sorted(set(re.findall(r"\{\{(\w+)\}\}", f"{title} {rule.get('description') or ''}")))
    if len(dyn) > 3:
        errors.append(f"title + description reference {len(dyn)} unique dynamic columns ({', '.join(dyn)}); max 3")

    if re.search(r"Timestamp\s*=\s*TimeGenerated|TimeGenerated\s*=\s*Timestamp", query):
        errors.append("timestamp column must be projected as-is (no Timestamp/TimeGenerated aliasing)")
    if schedule == "0":
        if re.search(r"(?m)^\s*let\s", query):
            errors.append("NRT rules reject `let` statements")
        if "ingestion_time()" in query:
            errors.append("NRT rules reject ingestion_time()")
        if re.search(r"(?m)^\s*//", query):
            errors.append("NRT query must not contain comment lines")
    return errors, warnings


def manifest_to_payload(rule: dict) -> tuple[dict, list[str]]:
    """Map one manifest rule to a wizard payload. Returns (payload, not_carried_warnings)."""
    errors, _ = validate_rule(rule)
    if errors:
        raise WizardLinkError("rule fails validation: " + "; ".join(errors))
    notes: list[str] = []
    schedule = str(rule["schedule"])
    if schedule == "0":
        if not NRT_SUPPORTED:
            raise WizardLinkError("NRT ('0') has no verified wizard representation; deploy via the Graph script")
        freq = NRT_PAYLOAD
    else:
        freq = {"frequencyInMinutes": SCHEDULES[schedule][0], "intervalHours": SCHEDULES[schedule][1]}

    # Alert settings use alertTitle/alertDescription (verified E3a, {{Column}} text preserved);
    # the plain title/description keys are ignored by the wizard (E3b). ruleDescription is the
    # rule's own description, so dynamic placeholders there are shown as <Col>.
    alert_title = rule.get("title") or rule["displayName"]
    alert_description = rule.get("description") or ""
    description = re.sub(r"\{\{(\w+)\}\}", r"<\1>", alert_description)

    entities: list[dict] = []
    if rule.get("entityDefinitions"):
        entities = list(rule["entityDefinitions"])  # explicit wizard-native override
    else:
        for a in rule["impactedAssets"]:
            etype, idmap = ASSET_TO_WIZARD[a["type"]]
            prop = ENTITY_COLUMN_PROP[a["type"]].get(a["identifier"])
            wiz_id = idmap.get(prop) if prop else None
            if not wiz_id:
                notes.append(f"asset {a['type']}/{a['identifier']} has no wizard identifier mapping; skipped")
                continue
            if (etype, wiz_id) in UNVERIFIED_IDS:
                notes.append(f"entity {etype}.{wiz_id} is unverified in the wizard (see experiment E4)")
            col = a.get("column") or _pascal(a["identifier"])
            entities.append({"entityType": etype, "entityIdFields": {wiz_id: col}, "isAsset": True})
        for key, items in (rule.get("entityMappings") or {}).items():
            spec = RELATED_ENTITIES.get(key)
            if not spec:
                notes.append(f"related entity type {key!r} has no verified wizard mapping; skipped")
                continue
            etype, idmap = spec
            for item in items:
                fields = {idmap[k]: v for k, v in item.items() if k in idmap}
                if not fields:
                    notes.append(f"{key} entry {item} has no mappable column; skipped")
                    continue
                entities.append({"entityType": etype, "entityIdFields": fields, "isAsset": False})
    if not entities:
        raise WizardLinkError("no entities could be mapped; refusing to emit a rule with no impacted entity")

    payload = {"name": rule["displayName"], "queryText": rule["queryText"].strip(), "ruleDescription": description}
    payload["alertTitle"] = alert_title
    if alert_description:
        payload["alertDescription"] = alert_description
    payload.update(freq)
    payload["alertSeverity"] = rule["severity"]
    payload["alertCategory"] = rule["category"]
    payload["mitreTechniques"] = list(rule.get("mitreTechniques") or [])
    if rule.get("recommendedActions"):
        payload["recommendedActions"] = rule["recommendedActions"]
    payload["entityDefinitions"] = entities
    return payload, notes


def _repo_tid() -> str | None:
    for parent in Path(__file__).resolve().parents:
        cfg = parent / "config.json"
        if cfg.is_file():
            try:
                tid = json.loads(cfg.read_text(encoding="utf-8-sig")).get("tenant_id", "")
            except (OSError, json.JSONDecodeError):
                return None
            return tid if tid and not tid.upper().startswith("YOUR") else None
    return None


def _select(rules: list[dict], index: int | None, name: str | None) -> list[tuple[int, dict]]:
    pairs = list(enumerate(rules))
    if index is not None:
        if not 0 <= index < len(rules):
            raise WizardLinkError(f"--index {index} out of range (manifest has {len(rules)} rules)")
        return [pairs[index]]
    if name:
        hit = [p for p in pairs if p[1].get("displayName") == name]
        if not hit:
            raise WizardLinkError(f"no rule with displayName {name!r}")
        return hit
    return pairs


def cmd_validate(args: argparse.Namespace) -> int:
    rules = load_manifest(args.manifest)
    bad = 0
    for i, rule in _select(rules, args.index, args.name):
        errors, warnings = validate_rule(rule)
        bad += bool(errors)
        print(f"{'FAIL' if errors else 'PASS'} [{i}] {rule.get('displayName')!r}")
        for e in errors:
            print(f"    error: {e}")
        for w in warnings:
            print(f"    warn:  {w}")
    return 2 if bad else 0


def cmd_from_manifest(args: argparse.Namespace) -> int:
    rules = load_manifest(args.manifest)
    tid = None if args.no_tid else (args.tid or _repo_tid())
    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    failed = 0
    for i, rule in _select(rules, args.index, args.name):
        label = f"[{i}] {rule.get('displayName')!r}"
        try:
            payload, notes = manifest_to_payload(rule)
        except WizardLinkError as exc:
            print(f"REFUSED {label}: {exc}")
            failed += 1
            continue
        token = encode_payload(payload)
        if decode_token(token) != payload:
            raise WizardLinkError("Round-trip mismatch after encoding")
        url = WIZARD_URL + (f"?tid={tid}" if tid else "") + "#customDetectionRule=" + token
        print(f"OK {label}: {len(url):,} chars ({_fingerprint(token)})")
        if len(url) > MAX_URL_CHARS:
            print(f"    WARN: link is longer than {MAX_URL_CHARS:,} chars; browsers or the wizard may reject it. Prefer the Graph script for this rule.")
        for n in notes:
            print(f"    note: {n}")
        if out_dir:
            slug = _slug(rule["displayName"])
            (out_dir / f"{slug}.txt").write_text(url, encoding="utf-8")
            (out_dir / f"{slug}.rule.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"    files: {slug}.txt / {slug}.rule.json")
        else:
            print(url)
    return 2 if failed else 0


def _selftest_manifest() -> None:
    good = {
        "displayName": "Test: Rule", "title": "T on {{DeviceName}}", "description": "{{AccountName}} did X on {{DeviceName}}.",
        "queryText": "let X = 1;\nDeviceProcessEvents\n| project Timestamp, ReportId, DeviceId, DeviceName, AccountName, AccountUpn",
        "schedule": "1H", "severity": "medium", "category": "Discovery", "mitreTechniques": ["T1087.001"],
        "recommendedActions": "Look.", "responseActions": [],
        "impactedAssets": [{"type": "device", "identifier": "deviceName"}, {"type": "user", "identifier": "accountUpn"}],
        "entityMappings": {"ips": [{"addressColumn": "RemoteIP"}], "dns": [{"x": "y"}]},
    }
    assert validate_rule(good)[0] == []
    payload, notes = manifest_to_payload(good)
    assert payload["frequencyInMinutes"] == 60 and payload["intervalHours"] == 1.0
    assert payload["name"] == "Test: Rule" and "{{" not in payload["ruleDescription"]
    assert payload["alertTitle"] == "T on {{DeviceName}}" and payload["alertDescription"] == good["description"]
    assert "title" not in payload and "description" not in payload  # ignored by the wizard (E3b)
    assert "source" not in payload and "reportId" not in payload, "must not impersonate Perception provenance"
    ents = {(e["entityType"], tuple(e["entityIdFields"].items()), e["isAsset"]) for e in payload["entityDefinitions"]}
    assert ("Machine", (("HostName", "DeviceName"),), True) in ents
    assert ("User", (("UPN", "AccountUpn"),), True) in ents
    assert ("IP", (("Address", "RemoteIP"),), False) in ents
    assert any("'dns'" in n for n in notes), notes
    assert decode_token(encode_payload(payload)) == payload

    def must_fail(mutate, fragment):
        r = json.loads(json.dumps(good))
        mutate(r)
        errs = validate_rule(r)[0]
        assert any(fragment in e for e in errs), (fragment, errs)
        try:
            manifest_to_payload(r)
        except WizardLinkError:
            return
        raise AssertionError(f"expected refusal for {fragment}")

    must_fail(lambda r: r.update(impactedAssets=[]), "impactedAssets")
    must_fail(lambda r: r["impactedAssets"].__setitem__(0, {"type": "device", "identifier": "DeviceName"}), "invalid device identifier")
    must_fail(lambda r: r.update(description="{{A}} {{B}} {{C}} {{D}}"), "dynamic columns")
    must_fail(lambda r: r.update(schedule="2H"), "schedule")
    must_fail(lambda r: r.update(severity="critical"), "severity")
    must_fail(lambda r: r.update(category="discovery"), "category")
    must_fail(lambda r: r.update(responseActions=[{"x": 1}]), "responseActions")
    must_fail(lambda r: r.update(queryText=r["queryText"] + "\n| extend Timestamp = TimeGenerated"), "aliasing")
    must_fail(lambda r: r.update(schedule="0"), "NRT")  # has `let`; also NRT unverified
    nrt = json.loads(json.dumps(good))
    nrt.update(schedule="0", queryText="DeviceProcessEvents\n| where ingestion_time() > ago(1h)\n| project Timestamp, DeviceName, AccountUpn")
    assert any("ingestion_time" in e for e in validate_rule(nrt)[0])
    nrt["queryText"] = "DeviceProcessEvents\n| project Timestamp, ReportId, DeviceId, DeviceName, AccountUpn"
    assert validate_rule(nrt)[0] == [], validate_rule(nrt)
    p_nrt, _ = manifest_to_payload(nrt)
    assert p_nrt["frequencyInMinutes"] == 0 and p_nrt["intervalHours"] == 0, p_nrt


def cmd_selftest(_: argparse.Namespace) -> int:
    base = {
        "name": "Example rule",
        "queryText": "EmailEvents | take 1",
        "ruleDescription": "d",
        "frequencyInMinutes": 60,
        "alertSeverity": "low",
        "mitreTechniques": ["T1566"],
        "entityDefinitions": [{"entityType": "Mailbox"}],
    }
    link = WIZARD_URL + "#customDetectionRule=" + encode_payload(base)
    url, _, changed = build_link(link, "EmailEvents\n| take 5", "Example tuned", None, "tid-123")
    assert changed == ["name", "queryText"], changed
    assert decode_token(extract_token(url))["queryText"] == "EmailEvents\n| take 5"
    assert "?tid=tid-123#customDetectionRule=" in url
    for bad in ("not-a-token", encode_payload({"name": "x"})):
        try:
            decode_token(extract_token(bad))
        except WizardLinkError:
            pass
        else:
            raise AssertionError("expected WizardLinkError")
    assert strip_comment_header("// a\n// b\nlet x = 1;\nx").startswith("let x")

    # insert + verify round trip, and corruption detection (a single dropped character must fail)
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        (d / "link.txt").write_text(url, encoding="utf-8")
        (d / "tuned.kql").write_text("// header\nEmailEvents\n| take 5\n", encoding="utf-8")
        (d / "r.md").write_text("# Report\n\nLink: {{WIZARD_LINK}}\n", encoding="utf-8")
        ns = argparse.Namespace(report=str(d / "r.md"), link_file=str(d / "link.txt"),
                                placeholder="{{WIZARD_LINK}}", text="Open in wizard")
        assert cmd_insert(ns) == 0
        ok = argparse.Namespace(file=str(d / "r.md"), query_file=str(d / "tuned.kql"), link_file=str(d / "link.txt"))
        assert cmd_verify(ok) == 0
        broken = (d / "r.md").read_text(encoding="utf-8")
        i = broken.index("customDetectionRule=") + 40
        (d / "bad.md").write_text(broken[:i] + broken[i + 1:], encoding="utf-8")
        assert cmd_verify(argparse.Namespace(file=str(d / "bad.md"), query_file=None, link_file=str(d / "link.txt"))) == 2
        try:
            cmd_insert(argparse.Namespace(report=str(d / "r.md"), link_file=str(d / "link.txt"),
                                          placeholder="{{WIZARD_LINK}}", text="x"))
        except WizardLinkError:
            pass
        else:
            raise AssertionError("expected missing-placeholder error")
    _selftest_manifest()
    print("selftest ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode")
    d.add_argument("link", help="wizard URL, bare token, or path to a file containing either")
    d.add_argument("--out", help="write full decoded JSON here")
    d.add_argument("--query-out", help="write just the KQL here")
    d.set_defaults(fn=cmd_decode)

    e = sub.add_parser("encode")
    e.add_argument("--base", required=True, help="original wizard URL/token (or file) to start from")
    e.add_argument("--query-file", required=True, help="tuned KQL file (leading // comments are stripped)")
    e.add_argument("--name")
    e.add_argument("--description")
    e.add_argument("--tid", help="tenant GUID to add as ?tid= (repo URL rule)")
    e.add_argument("--out", help="write the URL here")
    e.set_defaults(fn=cmd_encode)

    s = sub.add_parser("selftest")
    s.set_defaults(fn=cmd_selftest)

    lr = sub.add_parser("list-report", help="list candidates + decode their wizard links from a detection report")
    lr.add_argument("report", help="detection_report.md (or the JSON wrapper saved from read_output)")
    lr.add_argument("--out-dir", help="write <candidate>.token.txt / .kql / .rule.json here")
    lr.set_defaults(fn=cmd_list_report)

    ins = sub.add_parser("insert", help="replace a placeholder in a Markdown file with a clickable link from a link file")
    ins.add_argument("report", help="Markdown file containing the placeholder")
    ins.add_argument("--link-file", required=True, help="file holding the full wizard URL (or bare token)")
    ins.add_argument("--placeholder", default="{{WIZARD_LINK}}")
    ins.add_argument("--text", default="Open in the Detection Wizard", help="link text")
    ins.set_defaults(fn=cmd_insert)

    ver = sub.add_parser("verify", help="check every wizard link in a file decodes and matches the expected query/link")
    ver.add_argument("file", help="Markdown/text file containing wizard links")
    ver.add_argument("--query-file", help="expected tuned KQL (leading // comments ignored)")
    ver.add_argument("--link-file", help="expected link (the saved URL/token file)")
    ver.set_defaults(fn=cmd_verify)

    sel = argparse.ArgumentParser(add_help=False)
    sel.add_argument("manifest", help="Deploy-CustomDetections.ps1 manifest (JSON array of rules)")
    sel.add_argument("--index", type=int, help="only this rule (0-based)")
    sel.add_argument("--name", help="only the rule with this displayName")

    va = sub.add_parser("validate", parents=[sel], help="pre-flight checks (port of the deploy script's validation)")
    va.set_defaults(fn=cmd_validate)

    fm = sub.add_parser("from-manifest", parents=[sel], help="build one prefilled wizard link per manifest rule")
    fm.add_argument("--tid", help="tenant GUID for ?tid= (default: tenant_id from the repo's config.json)")
    fm.add_argument("--no-tid", action="store_true", help="omit ?tid= from the URL")
    fm.add_argument("--out-dir", help="write <slug>.txt (link) and <slug>.rule.json here")
    fm.set_defaults(fn=cmd_from_manifest)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except WizardLinkError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
