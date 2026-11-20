#!/usr/bin/env python3
"""Local, gitignored cache of Microsoft Perception sessions (shared by the perception-get-* skills).

The Perception MCP cannot search sessions: `list_sessions` only filters on status/statusDetail, is
newest-first and returns at most 100 sessions (~30-100 KB) per page. This helper keeps an incremental
local cache so questions like "which threat-intelligence articles were analyzed recently?" or "has
anything covered <topic>?" become fast local lookups instead of paging through everything.

The model never reads the raw pages: each `list_sessions` result is saved to a file by the tool; pass that
path to `ingest`. Cache file: temp/perception_session_cache.json (gitignored).

Usage:
    python session_cache.py ingest <page.json>... [--continue] [--depth-days 14]
    python session_cache.py search [terms...] [--any] [--playbook a,b] [--ti-only] [--status succeeded]
                                   [--since YYYY-MM-DD] [--limit 20] [--articles]
    python session_cache.py need-summary [--ti-only] [--limit 30] [--all-sessions]
    python session_cache.py set <session-id-or-prefix> [--summary-file F | --summary-text T | --no-summary] [--ti-report yes|no]
    python session_cache.py set-many <summaries.json>        (one call instead of one `set` per session)
    python session_cache.py coverage
    python session_cache.py show <session-id-or-prefix>
    python session_cache.py check-links <report.md> [--fix]   (every Perception session in a report must be a clickable link)
    python session_cache.py selftest

Refresh protocol (what the skill does):
    1. list_sessions(pageSize=100) -> ingest <saved page file>            (starts a new run)
    2. if the output says CONTINUE: list_sessions(continuationToken=<printed token, unchanged>)
       -> ingest <next page file> --continue                                (repeat; cap 10 pages)
    3. STOP means the page overlapped the cache (refresh complete) or the depth target was reached.
Every answer must state the cache depth (`covers back to ...`) so "none found" is never overstated.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

TI_PLAYBOOKS = {"analyze-article", "proactive-protection", "detect-emerging-threats"}
SUMMARY_CAP = 2500


def _repo_root() -> Path:
    for p in Path(__file__).resolve().parents:
        if (p / ".github").is_dir():
            return p
    return Path.cwd()


CACHE_PATH = _repo_root() / "temp" / "perception_session_cache.json"


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    v = re.sub(r"(\.\d{6})\d+", r"\1", value.strip())
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def iso(d: datetime | None) -> str | None:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def load_cache(path: Path = None) -> dict:
    path = path or CACHE_PATH
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"version": 1, "updatedAt": None, "floor": None, "newest": None, "run": {}, "sessions": {}}


def save_cache(cache: dict, path: Path = None) -> None:
    path = path or CACHE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=1, ensure_ascii=False), encoding="utf-8")


def normalize(s: dict) -> dict:
    tags = s.get("tags") or []
    playbook = next((t.split("=", 1)[1] for t in tags if t.startswith("playbookId=")), None)
    method = next((t.split(":", 1)[1] for t in tags if t.startswith("method:")), None)
    inputs = [{"type": i.get("type"), "value": i.get("value"), "displayName": i.get("displayName"),
               "entityUrl": i.get("entityUrl")} for i in (s.get("inputs") or [])]
    ti = next((i for i in inputs if i["type"] == "defenderThreatIntelligenceId"), None)
    external = bool(ti and ti["value"] == "EXTERNAL")
    return {
        "id": s["id"], "playbook": playbook, "status": s.get("status"), "statusDetail": s.get("statusDetail"),
        "createdAt": s.get("createdAt"), "updatedAt": s.get("updatedAt"), "title": s.get("displayName"),
        "method": method, "initiator": ((s.get("initiatedBy") or {}).get("user") or {}).get("id"),
        "inputs": inputs,
        "articleId": ti["value"] if ti and not external else None,
        "articleTitle": ti["displayName"] if ti and not external else None,
        "articleUrl": ti["displayName"] if external else None,
        "isTi": bool(ti),
    }


def read_page(path: str) -> tuple[list[dict], str | None]:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(data, list):
        return data, None
    return data.get("value", []), data.get("continuationToken")


def cmd_ingest(args) -> int:
    cache = load_cache()
    if not args.cont:
        cache["run"] = {"floorBefore": cache.get("floor"), "overlap": False}
    run = cache.setdefault("run", {"floorBefore": cache.get("floor"), "overlap": False})
    new = upd = known = 0
    oldest = newest = None
    token = None
    for f in args.files:
        sessions, token = read_page(f)
        for s in sessions:
            rec = normalize(s)
            prev = cache["sessions"].get(rec["id"])
            if prev:
                known += 1
                upd += 1
                for k in ("summary", "summaryChecked", "tiReport"):
                    if k in prev:
                        rec[k] = prev[k]
            else:
                new += 1
            cache["sessions"][rec["id"]] = rec
            d = parse_ts(rec["createdAt"])
            if d:
                oldest = d if oldest is None or d < oldest else oldest
                newest = d if newest is None or d > newest else newest
    if oldest is None:
        print("page had no sessions")
        return 0
    run["overlap"] = bool(run.get("overlap")) or known > 0
    floor_before = parse_ts(run.get("floorBefore"))
    if run["overlap"] and floor_before:
        floor = min(floor_before, oldest)
    else:
        floor = oldest
    cache["floor"] = iso(floor)
    prev_newest = parse_ts(cache.get("newest"))
    cache["newest"] = iso(max(prev_newest, newest) if prev_newest else newest)
    cache["updatedAt"] = iso(datetime.now(timezone.utc))
    save_cache(cache)

    depth_target = datetime.now(timezone.utc) - timedelta(days=args.depth_days)
    stop_reason = "page overlapped the cache (refresh complete)" if known > 0 else (
        f"depth target reached (>= {args.depth_days} days)" if floor <= depth_target else None)
    print(f"ingested: {new} new, {upd} already cached (page {iso(newest)} .. {iso(oldest)})")
    print(f"cache: {len(cache['sessions'])} sessions; covers back to {cache['floor']} (last refresh {cache['updatedAt']})")
    if stop_reason or not token:
        print("STOP: " + (stop_reason or "no continuationToken returned (end of history)"))
    else:
        print("CONTINUE: request the next page and pass this continuationToken UNCHANGED, then ingest with --continue")
        print("continuationToken: " + token)
    return 0


def _is_ti(s: dict) -> bool:
    return bool(s.get("isTi")) or s.get("playbook") in TI_PLAYBOOKS


def _candidate(s: dict) -> bool:
    """A TI session that may hold a report. Status alone is not proof either way: a run stopped or still
    running after its Threat Intelligence step keeps the TI report, so only a validated "no report" excludes."""
    return _is_ti(s) and s.get("tiReport") is not False


def _art_key(s: dict) -> str:
    return s.get("articleId") or s.get("articleUrl") or s.get("title") or s["id"]


def _article_summaries(cache: dict) -> dict[str, str]:
    """All cached summaries of an article joined, so a topic match works on any of its sessions."""
    out: dict[str, list[str]] = {}
    for s in cache["sessions"].values():
        if s.get("summary"):
            out.setdefault(_art_key(s), []).append(s["summary"])
    return {k: " ".join(v) for k, v in out.items()}


def _match(s: dict, terms: list[str], any_mode: bool, art_sum: dict[str, str] | None = None) -> bool:
    if not terms:
        return True
    extra = (art_sum or {}).get(_art_key(s), "")
    hay = " ".join(str(x or "") for x in (s.get("title"), s.get("articleTitle"), s.get("articleUrl"),
                                         s.get("playbook"), s.get("summary"), extra)).lower()
    hits = [t.lower() in hay for t in terms]
    return any(hits) if any_mode else all(hits)


def _summary_coverage(cache: dict) -> tuple[int, int]:
    """(articles with a cached summary or an already-checked "no summary", articles with a candidate TI session)."""
    arts: dict[str, bool] = {}
    for s in cache["sessions"].values():
        if _candidate(s):
            k = _art_key(s)
            arts[k] = arts.get(k, False) or bool(s.get("summary")) or bool(s.get("summaryChecked"))
    return sum(arts.values()), len(arts)


def _header(cache: dict) -> str:
    have, total = _summary_coverage(cache)
    return (f"[cache: {len(cache['sessions'])} sessions; covers back to {cache.get('floor') or 'n/a'}; "
            f"last refresh {cache.get('updatedAt') or 'never'}; topic-search summaries cached for {have} of {total} articles]")


def cmd_search(args) -> int:
    cache = load_cache()
    if not cache["sessions"]:
        print("cache is empty: run a refresh first (list_sessions -> ingest)")
        return 0
    pbs = set(args.playbook.split(",")) if args.playbook else None
    since = parse_ts(args.since + "T00:00:00Z") if args.since else None
    rows = []
    art_sum = _article_summaries(cache)
    for s in cache["sessions"].values():
        if pbs and s.get("playbook") not in pbs:
            continue
        if args.status and s.get("status") != args.status:
            continue
        if args.ti_only and not _is_ti(s):
            continue
        d = parse_ts(s.get("createdAt"))
        if since and (not d or d < since):
            continue
        if not _match(s, args.terms, args.any, art_sum):
            continue
        rows.append(s)
    rows.sort(key=lambda s: s.get("createdAt") or "", reverse=True)
    print(_header(cache))
    if args.articles:
        groups: dict[str, list[dict]] = {}
        for s in rows:
            key = s.get("articleId") or s.get("articleUrl") or s.get("title") or s["id"]
            groups.setdefault(key, []).append(s)
        print(f"{len(groups)} article(s) from {len(rows)} session(s)")
        for key, ss in list(groups.items())[: args.limit]:
            first = ss[0]
            title = first.get("articleTitle") or first.get("articleUrl") or first.get("title")
            ok = [x for x in ss if x.get("status") == "succeeded" and _candidate(x)] or [x for x in ss if _candidate(x)]
            has_sum = _art_key(first) in art_sum
            print(f"- {str(title)[:110]}")
            print(f"    latest {first.get('createdAt', '')[:16]} | sessions {len(ss)} (usable? {len(ok)}) | "
                  f"{','.join(sorted({x.get('playbook') or '?' for x in ss}))} | "
                  f"best {ok[0]['id'][:8] if ok else 'none'} | summary {'yes' if has_sum else 'no'}")
        return 0
    print(f"{len(rows)} session(s)")
    for s in rows[: args.limit]:
        print(f"{(s.get('createdAt') or '')[:16]} | {s.get('playbook') or '?':<24} | {s.get('status'):<9} | "
              f"{s['id'][:8]} | {str(s.get('title') or '')[:90]}"
              + (" | [summary]" if s.get("summary") else ""))
    if len(rows) > args.limit:
        print(f"... {len(rows) - args.limit} more (raise --limit)")
    return 0


def _find(cache: dict, prefix: str) -> dict:
    hits = [s for sid, s in cache["sessions"].items() if sid.startswith(prefix)]
    if len(hits) != 1:
        raise SystemExit(f"{len(hits)} sessions match {prefix!r}")
    return hits[0]


def cmd_need_summary(args) -> int:
    """Candidate TI sessions (succeeded, stopped or running; not validated report-less) lacking a summary; one per
    article (newest) by default, since sessions of the same article share the intelligence."""
    cache = load_cache()
    art_sum = _article_summaries(cache)
    todo = [s for s in cache["sessions"].values()
            if (_candidate(s) if args.ti_only else s.get("status") == "succeeded" or _candidate(s))
            and not s.get("summary") and not s.get("summaryChecked")]
    todo.sort(key=lambda s: s.get("createdAt") or "", reverse=True)
    if not args.all_sessions:
        seen: set[str] = set()
        picked = []
        for s in todo:
            k = _art_key(s)
            if k in seen or k in art_sum:
                continue
            seen.add(k)
            picked.append(s)
        todo = picked
    print(f"{len(todo)} session(s) to fetch a summary for" + ("" if args.all_sessions else " (one per article)")
          + f" (showing {min(len(todo), args.limit)})")
    for s in todo[: args.limit]:
        print(s["id"])
    return 0


def cmd_set(args) -> int:
    cache = load_cache()
    s = _find(cache, args.session)
    if args.summary_file:
        raw = Path(args.summary_file).read_text(encoding="utf-8-sig")
        try:
            wrapped = json.loads(raw)
            if isinstance(wrapped, dict) and isinstance(wrapped.get("text"), str):
                raw = wrapped["text"]
        except json.JSONDecodeError:
            pass
        s["summary"] = re.sub(r"\s+", " ", raw).strip()[:SUMMARY_CAP]
        s["summaryChecked"] = True
    if args.summary_text:
        s["summary"] = re.sub(r"\s+", " ", args.summary_text).strip()[:SUMMARY_CAP]
        s["summaryChecked"] = True
    if args.no_summary:
        s["summaryChecked"] = True
    if args.ti_report:
        s["tiReport"] = args.ti_report == "yes"
    save_cache(cache)
    print(f"updated {s['id'][:8]}: summary={'yes' if s.get('summary') else 'no'} tiReport={s.get('tiReport')}")
    return 0


def cmd_set_many(args) -> int:
    """Store many summaries in one call: a JSON array of {"session": id-or-prefix, "summary": text,
    "tiReport": true|false (optional), "noSummary": true (optional)}."""
    cache = load_cache()
    items = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
    if not isinstance(items, list):
        raise SystemExit("expected a JSON array")
    ok = bad = 0
    for it in items:
        hits = [s for sid, s in cache["sessions"].items() if sid.startswith(str(it.get("session", "")))]
        if len(hits) != 1 or not it.get("session"):
            print(f"skip {it.get('session')!r}: {len(hits)} match(es)")
            bad += 1
            continue
        s = hits[0]
        if it.get("summary"):
            s["summary"] = re.sub(r"\s+", " ", str(it["summary"])).strip()[:SUMMARY_CAP]
            s["summaryChecked"] = True
        if it.get("noSummary"):
            s["summaryChecked"] = True
        if "tiReport" in it and it["tiReport"] is not None:
            s["tiReport"] = bool(it["tiReport"])
        ok += 1
    save_cache(cache)
    have, total = _summary_coverage(cache)
    print(f"stored {ok}, skipped {bad}; summaries cached for {have} of {total} articles")
    return 0 if not bad else 1


def cmd_coverage(_: argparse.Namespace) -> int:
    cache = load_cache()
    have, total = _summary_coverage(cache)
    print(_header(cache))
    print(f"{have} of {total} articles with a candidate TI run (succeeded, stopped or running) have a cached summary ({total - have} missing)")
    return 0


def cmd_show(args) -> int:
    print(json.dumps(_find(load_cache(), args.session), indent=2, ensure_ascii=False))
    return 0


_SESSION_LINK = re.compile(r"\(https://security\.microsoft\.com/perception/session/([0-9a-fA-F-]{36})([^)\s]*)\)")
_NO_SESSION = re.compile(r"^\*\*Perception session:\*\*\s*none\b", re.M | re.I)
_BARE_ID8 = re.compile(r"`([0-9a-f]{8})`")
_MD_LINK = re.compile(r"\[[^\]]*\]\([^)\s]*\)")


def _link_spans(text: str) -> list[tuple[int, int]]:
    return [m.span() for m in _MD_LINK.finditer(text)]


def _tenant_id() -> str:
    try:
        v = json.loads((_repo_root() / "config.json").read_text(encoding="utf-8-sig")).get("tenant_id", "")
    except (OSError, ValueError):
        return ""
    return v if re.fullmatch(r"[0-9a-fA-F-]{36}", v or "") else ""


def check_report_links(text: str, cache: dict, tid: str, fix: bool = False) -> tuple[list[str], str]:
    """Problems with Perception session links in a report, and the (optionally fixed) text.
    Rules: a clickable session link within the first 30 lines; every session link carries ?tid=;
    every backticked 8-hex session id is a link (fixable from the cache's full GUID)."""
    problems: list[str] = []
    head = "\n".join(text.splitlines()[:30])
    if not _SESSION_LINK.search(head) and not _NO_SESSION.search(head):
        problems.append("no clickable Perception session link in the first 30 lines (add a `**Perception session:** [...](...)` header line)")
    for guid, rest in _SESSION_LINK.findall(text):
        if "tid=" not in rest:
            problems.append(f"session link {guid[:8]} has no ?tid=")
    full = {sid[:8]: sid for sid in cache.get("sessions", {})}
    fixed = 0
    unknown: set[str] = set()

    spans = _link_spans(text)

    def inside_link(m: re.Match) -> bool:
        return any(a <= m.start() < b for a, b in spans)

    def link(m: re.Match) -> str:
        nonlocal fixed
        if inside_link(m):
            return m.group(0)
        sid = full.get(m.group(1))
        if not sid:
            unknown.add(m.group(1))
            return m.group(0)
        fixed += 1
        return f"[`{m.group(1)}`](https://security.microsoft.com/perception/session/{sid}" + (f"?tid={tid}" if tid else "") + ")"

    new = _BARE_ID8.sub(link, text)
    bare = {m.group(1) for m in _BARE_ID8.finditer(text) if not inside_link(m)}
    if bare - unknown:
        problems.append(f"{len(bare - unknown)} session id(s) are not links: " + ", ".join(sorted(bare - unknown)))
    if unknown:
        problems.append("ids not in the session cache (cannot link; refresh the cache or check): " + ", ".join(sorted(unknown)))
    return problems, (new if fix else text)


def cmd_check_links(args) -> int:
    path = Path(args.file)
    text = path.read_text(encoding="utf-8-sig")
    problems, new = check_report_links(text, load_cache(), _tenant_id(), fix=args.fix)
    if args.fix and new != text:
        path.write_bytes(new.encode("utf-8"))
        print(f"fixed: linked unlinked session ids in {path.name}")
        problems, _ = check_report_links(new, load_cache(), _tenant_id())
    for pr in problems:
        print("PROBLEM:", pr)
    print("OK: all Perception sessions are clickable links" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


def cmd_selftest(_: argparse.Namespace) -> int:
    import tempfile
    global CACHE_PATH
    saved = CACHE_PATH
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        CACHE_PATH = d / "cache.json"

        def sess(i, minutes_ago, playbook="analyze-article", title="Activity Profile: Test Article", status="succeeded"):
            ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S.1234567+00:00")
            return {"id": f"{i:08x}-0000-0000-0000-000000000000", "status": status, "statusDetail": "completed",
                    "createdAt": ts, "displayName": f"Detect - {title}",
                    "inputs": [{"value": "aaaaaaaa-0000-0000-0000-%012x" % sum(map(ord, title)), "type": "defenderThreatIntelligenceId",
                                "displayName": title, "entityUrl": "https://example.invalid"}],
                    "initiatedBy": {"user": {"id": "u1"}}, "tags": [f"playbookId={playbook}", "method:Manual"]}

        p1 = d / "p1.json"
        p1.write_text(json.dumps({"value": [sess(1, 10), sess(2, 20, "proactive-protection", "Activity Profile: Other"),
                                            {"id": "dead0000-0", "status": "succeeded", "createdAt": "2026-01-01T00:00:00+00:00",
                                             "displayName": "Investigate attack - 1", "inputs": [{"type": "defenderIncidentId", "value": "1"}],
                                             "tags": ["playbookId=investigate-incident"]}],
                                  "continuationToken": "tok-1"}), encoding="utf-8")
        ns = lambda **k: argparse.Namespace(**{"files": [], "cont": False, "depth_days": 14, **k})  # noqa: E731
        assert cmd_ingest(ns(files=[str(p1)])) == 0
        c = load_cache()
        assert len(c["sessions"]) == 3 and c["sessions"][next(iter(c["sessions"]))]["id"]
        s1 = c["sessions"]["00000001-0000-0000-0000-000000000000"]
        assert s1["articleId"] and s1["articleTitle"] == "Activity Profile: Test Article" and s1["isTi"]
        assert not c["sessions"]["dead0000-0"]["isTi"]

        # incremental refresh: a newer page overlapping the cache must STOP and keep the old floor
        floor0 = c["floor"]
        p2 = d / "p2.json"
        p2.write_text(json.dumps({"value": [sess(3, 1), sess(1, 10)]}), encoding="utf-8")
        cmd_ingest(ns(files=[str(p2)]))
        c = load_cache()
        assert len(c["sessions"]) == 4 and c["floor"] == floor0, (c["floor"], floor0)

        # summaries survive re-ingest; search finds them
        sf = d / "sum.json"
        sf.write_text(json.dumps({"text": "Covers a supply chain attack using npm packages."}), encoding="utf-8")
        cmd_set(argparse.Namespace(session="00000001", summary_file=str(sf), summary_text=None, no_summary=False, ti_report="yes"))
        cmd_ingest(ns(files=[str(p2)]))
        assert load_cache()["sessions"]["00000001-0000-0000-0000-000000000000"]["summary"].startswith("Covers")
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_search(argparse.Namespace(terms=["npm"], any=False, playbook=None, ti_only=True, status=None,
                                          since=None, limit=20, articles=False))
        out = buf.getvalue()
        assert "00000001" in out and "00000002" not in out, out
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_search(argparse.Namespace(terms=[], any=False, playbook=None, ti_only=True, status=None,
                                          since=None, limit=20, articles=True))
        assert "article(s)" in buf.getvalue()
        # one summary per article: need-summary dedupes, and a topic match works on sibling sessions
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_need_summary(argparse.Namespace(ti_only=True, limit=30, all_sessions=False))
        assert "(one per article)" in buf.getvalue(), buf.getvalue()
        art = {"id": "0000000a-0000-0000-0000-000000000000", "status": "succeeded", "createdAt": "2026-11-19T10:00:00+00:00",
               "displayName": "Protect - Activity Profile: Test Article", "tags": ["playbookId=proactive-protection"],
               "inputs": [{"value": "aaaaaaaa-0000-0000-0000-%012x" % sum(map(ord, "Activity Profile: Test Article")),
                           "type": "defenderThreatIntelligenceId", "displayName": "Activity Profile: Test Article"}]}
        p3 = d / "p3.json"
        p3.write_text(json.dumps({"value": [art]}), encoding="utf-8")
        cmd_ingest(ns(files=[str(p3)]))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_search(argparse.Namespace(terms=["npm"], any=False, playbook="proactive-protection", ti_only=True,
                                          status=None, since=None, limit=20, articles=False))
        assert "0000000a" in buf.getvalue(), buf.getvalue()
        # set-many + coverage
        sm = d / "many.json"
        sm.write_text(json.dumps([{"session": "00000003", "summary": "npm supply chain test", "tiReport": True},
                                  {"session": "ffffffff", "summary": "nope"}]), encoding="utf-8")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cmd_set_many(argparse.Namespace(file=str(sm)))
        assert rc == 1 and "stored 1, skipped 1" in buf.getvalue(), buf.getvalue()
        assert load_cache()["sessions"]["00000003-0000-0000-0000-000000000000"]["summary"].startswith("npm")
        have, total = _summary_coverage(load_cache())
        assert total >= 1 and have >= 1
        CACHE_PATH = saved
    sid = "abcdef12-0000-4000-8000-000000000000"
    fake = {"sessions": {sid: {"id": sid}}}
    bad = "# R\n\nSession `abcdef12` and [`abcdef12`](https://security.microsoft.com/perception/session/" + sid + ")\n"
    pr, fixed = check_report_links(bad, fake, "11111111-1111-1111-1111-111111111111", fix=True)
    assert "[`abcdef12`](https://security.microsoft.com/perception/session/" + sid + "?tid=11111111" in fixed
    pr2, _ = check_report_links(fixed.replace("(https://security.microsoft.com/perception/session/" + sid + ")", "(https://security.microsoft.com/perception/session/" + sid + "?tid=1)"), fake, "")
    assert not pr2, pr2
    assert not check_report_links("[Open `abcdef12` here](https://security.microsoft.com/perception/session/" + sid + "?tid=1)", fake, "")[0]
    assert any("no clickable" in x for x in check_report_links("# R\n\nnothing\n", fake, "")[0])
    assert not check_report_links("# R\n\n**Perception session:** none (no run exists; nothing started)\n", fake, "")[0]
    assert any("no ?tid=" in x for x in check_report_links("[x](https://security.microsoft.com/perception/session/" + sid + ")", fake, "")[0])
    print("selftest ok")
    return 0


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("ingest")
    i.add_argument("files", nargs="+")
    i.add_argument("--continue", dest="cont", action="store_true", help="this page continues the previous ingest run")
    i.add_argument("--depth-days", type=int, default=14, help="STOP once the cache covers this many days back")
    i.set_defaults(fn=cmd_ingest)
    s = sub.add_parser("search")
    s.add_argument("terms", nargs="*")
    s.add_argument("--any", action="store_true", help="match any term (default: all)")
    s.add_argument("--playbook")
    s.add_argument("--ti-only", action="store_true")
    s.add_argument("--status")
    s.add_argument("--since")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--articles", action="store_true", help="group by article")
    s.set_defaults(fn=cmd_search)
    n = sub.add_parser("need-summary")
    n.add_argument("--ti-only", action="store_true")
    n.add_argument("--limit", type=int, default=30)
    n.add_argument("--all-sessions", action="store_true", help="do not dedupe by article")
    n.set_defaults(fn=cmd_need_summary)
    st = sub.add_parser("set")
    st.add_argument("session")
    st.add_argument("--summary-file")
    st.add_argument("--summary-text", help="condensed, keyword-rich description (threat, techniques, malware, sectors)")
    st.add_argument("--no-summary", action="store_true")
    st.add_argument("--ti-report", choices=["yes", "no"])
    st.set_defaults(fn=cmd_set)
    sm = sub.add_parser("set-many", help="store many summaries from one JSON file")
    sm.add_argument("file")
    sm.set_defaults(fn=cmd_set_many)
    cv = sub.add_parser("coverage", help="how many articles have a cached summary")
    cv.set_defaults(fn=cmd_coverage)
    sh = sub.add_parser("show")
    sh.add_argument("session")
    sh.set_defaults(fn=cmd_show)
    cl = sub.add_parser("check-links", help="verify every Perception session in a report is a clickable link")
    cl.add_argument("file")
    cl.add_argument("--fix", action="store_true", help="link bare backticked session ids using the cache")
    cl.set_defaults(fn=cmd_check_links)
    t = sub.add_parser("selftest")
    t.set_defaults(fn=cmd_selftest)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
