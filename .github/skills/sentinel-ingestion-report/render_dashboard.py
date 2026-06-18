# -*- coding: utf-8 -*-
"""
render_dashboard.py - Deterministic, data-driven SVG dashboard renderer for the
Sentinel Ingestion Analysis report.

Renders the 7-row layout defined in svg-widgets.yaml. ALL values are parsed from
the pipeline scratchpad (temp/ingest_scratch_<ts>.md) and, for the narrative
panels (recommendations, overall assessment, key findings), from the rendered
report's section 1. Nothing is hard-coded per run -- point it at a different
scratchpad/report and it renders that week's data.

Canvas geometry and palette are loaded from the manifest so layout tweaks live in
the YAML, not in code.

This script is READ-ONLY apart from writing the single --out .svg file.

Usage:
    python render_dashboard.py \
        --scratch  temp/ingest_scratch_<ts>.md \
        --manifest .github/skills/sentinel-ingestion-report/svg-widgets.yaml \
        --report   reports/sentinel/sentinel_ingestion_<label>_<ts>.md \
        --out      reports/sentinel/sentinel_ingestion_<label>_<ts>_dashboard.svg

--report is optional: if omitted (or section 1 narrative is not found) the
recommendation/assessment panels are derived from the scratchpad where possible
and rendered empty otherwise. Quantitative widgets render entirely from the
scratchpad.
"""
import argparse
import io
import math
import os
import re
import sys

import yaml

# ───────────────────────── name maps ─────────────────────────
TIER_KEYS = {"Analytics": "analytics", "Basic": "basic", "Data Lake": "data_lake"}
SEV_KEY = {
    "\U0001F534": "High", "\U0001F7E0": "Medium", "\U0001F7E1": "Low",
    "\U0001F535": "Informational", "\u26AA": "Informational", "\u26aa": "Informational",
}
EMOJI = ("\U0001F534", "\U0001F7E0", "\U0001F7E1", "\u2705", "\U0001F535",
         "\U0001F7E2", "\u26AA", "\u26aa", "\u26A0\uFE0F", "\u26A0", "\uFE0F",
         "\U0001F6E1", "\U0001F4E6", "\U0001F4CA", "\U0001F4C8", "\U0001F4C9",
         "\U0001F552", "\U0001F4CF", "\U0001F4B0", "\U0001F3AF", "\U0001F525",
         "\U0001F4A4", "\U0001F501")


def strip_emoji(s):
    for e in EMOJI:
        s = s.replace(e, "")
    return s.strip()


def first_emoji(s, table):
    for ch, val in table.items():
        if ch in s:
            return val
    return None


# ───────────────────────── scratchpad parsing ─────────────────────────
def read_text(path):
    with io.open(path, "r", encoding="utf-8") as f:
        return f.read()


def num(s):
    m = re.search(r"-?\d+(?:\.\d+)?", str(s).replace("**", "").replace(",", ""))
    return float(m.group(0)) if m else 0.0


def last_num(s):
    nums = re.findall(r"\d+(?:\.\d+)?", str(s).replace(",", ""))
    return float(nums[-1]) if nums else 0.0


def parse_kv_block(text, header):
    """Parse 'Key: Value' lines under a '## header'/'### header' until blank/next marker."""
    out = {}
    started = False
    for ln in text.splitlines():
        s = ln.strip()
        if not started:
            if s == "## " + header or s == "### " + header:
                started = True
            continue
        if s == "" or s.startswith("## ") or s.startswith("### "):
            break
        m = re.match(r"^([A-Za-z0-9_&. ]+?):\s*(.*)$", s)
        if m:
            out[m.group(1).strip()] = m.group(2).strip()
    return out


def _is_sep(cells):
    return set("".join(cells)) <= set("-: ")


def md_table_rows(text, header, subheader=None):
    """Return list of cell-lists for a markdown table under '### header' (optionally '#### subheader')."""
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n and lines[i].strip() != "### " + header:
        i += 1
    if i >= n:
        raise KeyError("section not found: " + header)
    i += 1
    if subheader:
        while i < n and lines[i].strip() != "#### " + subheader:
            if lines[i].strip().startswith("### "):
                raise KeyError("subsection not found: " + subheader)
            i += 1
        i += 1
    rows = []
    seen_sep = False
    while i < n:
        s = lines[i].strip()
        if s.startswith("### ") or (s.startswith("#### ") and rows):
            break
        if s.startswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if _is_sep(cells):
                seen_sep = True
                # Discard rows collected before the separator -- in a markdown
                # table that's the column-header row (e.g. 'Volume | # | DataType
                # | ...'), not data. Keeping it leaks 'DataType' into the charts.
                rows = []
                i += 1
                continue
            rows.append(cells)
        elif rows and s == "":
            if seen_sep:
                break
        i += 1
    return rows


def raw_block_lines(text, header):
    """Return the raw body lines under a '### header' until the next '### '/'## ' marker."""
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n and lines[i].strip() != "### " + header:
        i += 1
    i += 1
    out = []
    while i < n:
        s = lines[i].strip()
        if s.startswith("### ") or s.startswith("## "):
            break
        out.append(lines[i])
        i += 1
    return out


def rules_count(cell):
    """Extract integer rule count from a 'emoji N' cell (e.g. '🟢 13', '⚠️ 0')."""
    return int(num(cell))


def subheader_by_prefix(text, header, prefix):
    """Find the full '#### ...' subheader text under '### header' that starts with prefix.

    The ingestion scratchpad varies the lookback suffix (e.g. 'Alert-Producing
    Rules (7d)' vs '(30d)'), so match on the stable prefix rather than the exact
    string. Returns the subheader text (without '#### ') or None.
    """
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n and lines[i].strip() != "### " + header:
        i += 1
    i += 1
    while i < n:
        s = lines[i].strip()
        if s.startswith("### ") or s.startswith("## "):
            break
        if s.startswith("#### ") and s[5:].strip().startswith(prefix):
            return s[5:].strip()
        i += 1
    return None


# ───────────────────────── report (section 1) parsing ─────────────────────────
def parse_report(report_path):
    out = {"workspace": "", "period": "", "generated": "",
           "risks": [], "strengths": [], "recs": [], "findings": []}
    if not (report_path and os.path.exists(report_path)):
        return out
    t = read_text(report_path)
    lines = t.splitlines()
    for ln in lines[:15]:
        m = re.match(r"\*\*(Workspace|Report Period|Generated):\*\*\s*(.*)", ln.strip())
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key == "Workspace":
                out["workspace"] = val
            elif key == "Report Period":
                out["period"] = val
            else:
                out["generated"] = val[:10]

    # Overall Assessment bullets → risks (🔴/🟠) and strengths (🟢)
    in_assess = False
    for ln in lines:
        s = ln.strip()
        if s.startswith("### ") and "Overall Assessment" in s:
            in_assess = True
            continue
        if in_assess:
            if s.startswith("### ") or s.startswith("## "):
                break
            if s.startswith("- "):
                body = s[2:].strip()
                txt = re.sub(r"`([^`]*)`", r"\1", body)
                txt = txt.replace("**", "")
                if "\U0001F534" in body:
                    out["risks"].append(("High", strip_emoji(txt)))
                elif "\U0001F7E0" in body or "\U0001F7E1" in body:
                    out["risks"].append(("Medium", strip_emoji(txt)))
                elif "\U0001F7E2" in body or "\u2705" in body:
                    out["strengths"].append(strip_emoji(txt))

    # Top 3 Recommendations table
    rows = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith("###") and "Top 3 Recommendations" in ln:
            rows = _table_from(lines, i + 1)
            break
    if rows:
        for r in rows:
            if not r or not r[0].strip().isdigit():
                continue
            sev = r[1] if len(r) > 1 else ""
            color = ("danger" if "\U0001F534" in sev else
                     "accent" if ("\U0001F7E0" in sev or "\U0001F7E1" in sev) else "secondary")
            rec_cell = r[2].strip() if len(r) > 2 else ""
            scope = r[3].strip() if len(r) > 3 else ""
            impact = r[4].strip() if len(r) > 4 else ""
            risk = r[5].strip() if len(r) > 5 else ""
            m = re.match(r"\*\*(.+?)\*\*\s*(.*)", rec_cell)
            if m:
                title, desc = m.group(1).strip(), m.group(2).strip()
            else:
                title, desc = rec_cell.replace("**", ""), ""

            def clean(s):
                return re.sub(r"`([^`]*)`", r"\1", s).replace("**", "").strip()

            desc_clean = clean(desc)
            desc_clean = re.sub(r"^[\u2014\u2013-]\s*", "", desc_clean)
            out["recs"].append({
                "color": color,
                "title": clean(title),
                "scope": clean(scope),
                "desc": desc_clean,
                "impact": clean(strip_emoji(impact)),
                "risk": clean(strip_emoji(risk)),
            })
        out["recs"] = out["recs"][:3]

    # Key findings = the assessment bullets, prioritized
    for pri, txt in out["risks"][:5]:
        out["findings"].append({"priority": pri, "finding": txt})
    if len(out["findings"]) < 5:
        for txt in out["strengths"]:
            if len(out["findings"]) >= 5:
                break
            out["findings"].append({"priority": "OK", "finding": txt})
    return out


def _table_from(lines, start):
    rows = []
    i = start
    while i < len(lines) and lines[i].strip() == "":
        i += 1
    while i < len(lines) and lines[i].strip().startswith("|"):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        if not _is_sep(cells):
            rows.append(cells)
        i += 1
    return rows


# ───────────────────────── master parse ─────────────────────────
def parse_data(scratch_path, report_path):
    t = read_text(scratch_path)
    metrics = parse_kv_block(t, "Metrics")
    health = parse_kv_block(t, "Health")
    rep = parse_report(report_path)

    # Detection posture KV (markdown table Metric|Value)
    posture = {}
    try:
        for r in md_table_rows(t, "DetectionPosture"):
            posture[strip_emoji(r[0]).strip()] = r[1].strip()
    except KeyError:
        pass

    def posture_val(key_contains, default="0"):
        for k, v in posture.items():
            if key_contains.lower() in k.lower():
                return v
        return default

    ar_count = int(num(posture_val("Enabled Analytic Rules")))
    cd_count = int(num(posture_val("Enabled Custom Detections")))
    cov_cell = posture_val("Tables with Rules")          # "13 of 20"
    cm = re.search(r"(\d+)\s*of\s*(\d+)", cov_cell)
    cov_have, cov_total = (int(cm.group(1)), int(cm.group(2))) if cm else (0, 20)
    zero_cell = posture_val("Zero Rules")                # "7 of 20"
    zm = re.search(r"(\d+)\s*of\s*(\d+)", zero_cell)
    zero_tables = int(zm.group(1)) if zm else 0
    dl_tables = int(num(posture_val("Data Lake Tier")))
    coverage_pct = round(cov_have / cov_total * 100, 1) if cov_total else 0.0
    rule_health = num(health.get("OverallSuccessRate", "0"))

    # Cost waterfall (ASCII) — take the avg/day (last number) per labelled line
    cw = {"gross": 0.0, "e5": 0.0, "dfsp2": 0.0, "net": 0.0}
    for ln in raw_block_lines(t, "CostWaterfall"):
        low = ln.lower()
        if "gross billable" in low:
            cw["gross"] = last_num(ln)
        elif "e5" in low and "benefit" in low:
            cw["e5"] = last_num(ln)
        elif "dfs p2" in low or ("dfs" in low and "benefit" in low):
            cw["dfsp2"] = last_num(ln)
        elif "net billable" in low:
            cw["net"] = last_num(ln)

    avg_daily = num(metrics.get("AvgDailyGB", "0"))
    net_billable = cw["net"]

    # Tier distribution (raw pipe rows: tier | totalGB | billableGB | count | pct)
    tiers = []
    for ln in raw_block_lines(t, "TierSummary"):
        if "|" not in ln:
            continue
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) >= 4 and cells[0] in TIER_KEYS:
            tiers.append({"label": cells[0], "key": TIER_KEYS[cells[0]],
                          "gb": num(cells[1]), "count": int(num(cells[3]))})

    # Daily trend (ASCII 'date │ gb ███')
    trend = []
    for ln in raw_block_lines(t, "DailyChart"):
        m = re.match(r"^\s*(\d{4}-\d{2}-\d{2})\s*[\u2502|]\s*([\d.]+)", ln)
        if m:
            trend.append({"date": m.group(1), "gb": float(m.group(2))})

    # Top tables by volume (markdown table)
    top_tables = []
    cross = {}
    try:
        for r in md_table_rows(t, "TopTables"):
            # Volume | # | DataType | BillableGB | Avg/Day | % | Rules | Tier
            name = r[2].strip()
            top_tables.append({
                "name": name, "gb": num(r[3]), "gb_day": num(r[4]),
                "pct": num(r[5]), "rules": rules_count(r[6]), "tier": strip_emoji(r[7]).strip(),
            })
    except KeyError:
        pass
    # Cross-reference (AR/CD split) keyed by table name
    try:
        for r in md_table_rows(t, "CrossReference"):
            # Coverage | Table | AR Rules | CD Rules | Total | Key Rule Names
            cross[r[1].strip()] = {"ar": int(num(r[2])), "cd": int(num(r[3]))}
    except KeyError:
        pass

    detection_coverage = []
    for tt in top_tables[:8]:
        xr = cross.get(tt["name"], {"ar": 0, "cd": 0})
        ar, cd = xr["ar"], xr["cd"]
        if (ar + cd) == 0 and tt["rules"] > 0:
            ar = tt["rules"]  # rules present but table not in cross-ref top list
        detection_coverage.append({
            "name": tt["name"], "gb_day": tt["gb_day"], "tier": tt["tier"],
            "ar": ar, "cd": cd, "gap": (ar + cd) == 0,
        })

    # WoW anomalies (markdown table) — keep rows with a real WoW change, top 5 by |Δ|
    anomalies = []
    try:
        for r in md_table_rows(t, "AnomalyTable"):
            # DataType | 24h | 7dAvg | 24hDev | ThisWeek | LastWeek | WoW | Severity
            wow = r[6].strip() if len(r) > 6 else "—"
            if wow in ("", "—"):
                continue
            sev = first_emoji(r[7], SEV_KEY) if len(r) > 7 else None
            anomalies.append({
                "name": r[0].strip(), "current": r[4].strip(), "prior": r[5].strip(),
                "change": wow, "change_val": abs(num(wow)), "severity": sev or "Info",
            })
    except KeyError:
        pass
    anomalies.sort(key=lambda x: x["change_val"], reverse=True)

    # Alert-producing rules (markdown table under a window-suffixed subheader)
    alert_rules = []
    sub = subheader_by_prefix(t, "HealthAlerts", "Alert-Producing Rules")
    if sub:
        try:
            for r in md_table_rows(t, "HealthAlerts", sub):
                # Volume | Rule Name | Alert Count | Severity | Product Component
                sev = first_emoji(r[3], SEV_KEY) if len(r) > 3 else "Info"
                alert_rules.append({
                    "name": r[1].strip(), "count": int(num(r[2])), "severity": sev or "Info",
                })
        except KeyError:
            pass
    alert_rules.sort(key=lambda x: x["count"], reverse=True)

    # Detection posture score (gauge) — manifest formula
    gap_penalty = (zero_tables / cov_total * 100) if cov_total else 0
    posture_score = round(rule_health * 0.3 + coverage_pct * 0.4 + (100 - gap_penalty) * 0.3, 1)
    posture_score = max(0.0, min(100.0, posture_score))

    workspace = rep["workspace"] or metrics.get("Workspace", "") or "Workspace"
    period = rep["period"]
    if not period and trend:
        period = "%s to %s" % (trend[0]["date"], trend[-1]["date"])
    gen = rep["generated"] or "n/a"

    return {
        "title": "Sentinel Ingestion Dashboard",
        "subtitle": "%s  \u00b7  %s  \u00b7  generated %s" % (workspace, period, gen),
        "posture_score": posture_score,
        "kpis": [
            ("Avg Daily", "%.1f" % avg_daily, "GB/day", "primary"),
            ("Net Billable", "%.1f" % net_billable, "GB/day", "success"),
            ("Analytic Rules", str(ar_count), "%d enabled \u00b7 %d CD" % (ar_count, cd_count), "primary"),
            ("Rule Health", "%g%%" % rule_health, "success rate", "success"),
            ("Coverage", "%g%%" % coverage_pct, "%d of %d top tables" % (cov_have, cov_total), "accent"),
            ("DL Tables", str(dl_tables), "Data Lake tier", "secondary"),
        ],
        "top_tables": top_tables[:8],
        "detection_coverage": detection_coverage,
        "cov_summary": (cov_have, cov_total),
        "trend": trend,
        "cost_waterfall": cw,
        "tiers": tiers,
        "anomalies": anomalies[:5],
        "alert_rules": alert_rules[:5],
        "recs": rep["recs"],
        "risks": rep["risks"],
        "strengths": rep["strengths"],
        "findings": rep["findings"][:5],
        "avg_daily": avg_daily,
    }


# ───────────────────────── SVG rendering ─────────────────────────
def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(data, manifest, out_path):
    cv = manifest["canvas"]
    pal = manifest["palette"]
    tierc = manifest.get("tier_colors", {})
    W, H = cv["width"], cv["height"]
    PAD, RG = cv["padding"], cv["row_gap"]
    FONT = cv["font_family"]
    UW = W - 2 * PAD

    def col(name):
        return pal.get(name, "#ffffff")

    TP, TS = pal.get("text_primary", "#e6edf3"), pal.get("text_secondary", "#b2b2b2")
    CARD, BORDER = pal.get("card_bg", "#161b22"), pal.get("card_border", "#30363d")
    MUTED = pal.get("muted", "#b2b2b2")
    tier_color = {
        "Analytics": tierc.get("analytics", col("primary")),
        "Basic": tierc.get("basic", col("accent")),
        "Data Lake": tierc.get("data_lake", col("secondary")),
    }
    sev_color = {
        "High": col("danger"), "Medium": col("accent"),
        "Low": col("success"), "Informational": MUTED, "Info": MUTED,
    }

    S = []
    a = S.append
    a('<?xml version="1.0" encoding="UTF-8"?>')
    a('<!-- Generated by Copilot SVG Dashboard Generator -->')
    a('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="%s" fill="%s">'
      % (W, H, W, H, FONT, TP))
    a('<rect x="0" y="0" width="%d" height="%d" fill="%s"/>' % (W, H, cv["background"]))

    def card(x, y, w, h, rx=12):
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%d" fill="%s" stroke="%s" stroke-width="1"/>'
          % (x, y, w, h, rx, CARD, BORDER))

    def text(x, y, s, size=12, fill=None, anchor="start", weight="normal", rotate=None):
        tr = ' transform="rotate(%s %.1f %.1f)"' % (rotate, x, y) if rotate is not None else ""
        a('<text x="%.1f" y="%.1f" font-size="%g" fill="%s" text-anchor="%s" font-weight="%s"%s>%s</text>'
          % (x, y, size, fill or TP, anchor, weight, tr, esc(s)))

    def badge(cx_center, cy, label, color):
        bw = 10 + len(str(label)) * 6.6
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="18" rx="4" fill="none" stroke="%s" stroke-width="1.4"/>'
          % (cx_center - bw / 2, cy - 13, bw, color))
        text(cx_center, cy, label, size=9, weight="bold", fill=color, anchor="middle")

    def pill(x, y, w, h, label, color, size=9, rx=4):
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="%d" fill="%s" opacity="0.2"/>'
          % (x, y, w, h, rx, color))
        text(x + w / 2, y + h / 2 + size * 0.35, label, size=size, weight="bold", fill=color, anchor="middle")

    def wrap(s, x, y0, width_chars, size, fill, line_h, max_y, weight="normal"):
        ly = y0
        line = ""
        for wd in str(s).split(" "):
            if len(line) + len(wd) + 1 > width_chars and ly < max_y:
                text(x, ly, line, size=size, fill=fill, weight=weight)
                ly += line_h
                line = wd
            else:
                line = (line + " " + wd).strip()
        if line and ly <= max_y:
            text(x, ly, line, size=size, fill=fill, weight=weight)
            ly += line_h
        return ly

    # ── Row 1 — title ──────────────────────────────────────────────────────────
    y1 = PAD
    text(W / 2, y1 + 32, data["title"], size=26, weight="bold", anchor="middle")
    text(W / 2, y1 + 56, data["subtitle"], size=13, fill=TS, anchor="middle")
    a('<rect x="%.1f" y="%.1f" width="%d" height="3" rx="1.5" fill="%s"/>' % (W / 2 - 200, y1 + 66, 400, col("primary")))

    # ── Row 2 — posture gauge + 6 KPI cards ────────────────────────────────────
    y2 = y1 + 80 + RG
    h2 = 160
    g_w = UW * 0.25
    kpis = data["kpis"]
    kpi_w = (UW - g_w - (len(kpis)) * RG) / len(kpis)
    # gauge card
    card(PAD, y2, g_w, h2)
    text(PAD + g_w / 2, y2 + 26, "Detection Posture", size=13, weight="bold", anchor="middle")
    sc = data["posture_score"]
    band, bcol = (("Critical", col("danger")) if sc < 41 else
                  ("Weak", "#EF6950") if sc < 61 else
                  ("Moderate", col("accent")) if sc < 81 else
                  ("Strong", col("success")))
    gcx, gcy, gr = PAD + g_w / 2, y2 + 116, 60
    # 180° gauge track + value arc (semicircle, left→right)
    def arc_path(cx, cy, rr, frac):
        ang = math.pi * (1 - frac)
        x2 = cx + rr * math.cos(ang)
        y2a = cy - rr * math.sin(ang)
        large = 0
        sweep = 1
        return "M %.1f %.1f A %.1f %.1f 0 %d %d %.1f %.1f" % (cx - rr, cy, rr, rr, large, sweep, x2, y2a)
    a('<path d="%s" fill="none" stroke="%s" stroke-width="16" stroke-linecap="round"/>'
      % (arc_path(gcx, gcy, gr, 1.0), BORDER))
    a('<path d="%s" fill="none" stroke="%s" stroke-width="16" stroke-linecap="round"/>'
      % (arc_path(gcx, gcy, gr, sc / 100.0), bcol))
    text(gcx, gcy - 6, "%g" % sc, size=34, weight="bold", fill=bcol, anchor="middle")
    text(gcx, gcy + 14, band.upper(), size=12, weight="bold", fill=bcol, anchor="middle")
    # KPI cards
    kx = PAD + g_w + RG
    for label, val, sub, cn in kpis:
        card(kx, y2, kpi_w, h2)
        text(kx + kpi_w / 2, y2 + 34, label, size=12, fill=TS, anchor="middle")
        text(kx + kpi_w / 2, y2 + 88, val, size=30, weight="bold", fill=col(cn), anchor="middle")
        wrap_sub = sub if len(sub) <= 20 else sub
        text(kx + kpi_w / 2, y2 + 116, wrap_sub, size=9.5, fill=TS, anchor="middle")
        kx += kpi_w + RG

    # ── Row 3 — top tables bar (40%) + detection coverage table (60%) ──────────
    y3 = y2 + h2 + RG
    h3 = 300
    bw_w = UW * 0.40
    card(PAD, y3, bw_w, h3)
    text(PAD + 16, y3 + 24, "Top Tables by Volume (GB / 30d)", size=14, weight="bold")
    tt = data["top_tables"]
    bx0 = PAD + 16
    bly = y3 + 46
    bar_area = bw_w - 32
    label_w = 200
    bar_max_w = bar_area - label_w - 70
    maxgb = max((x["gb"] for x in tt), default=1) or 1
    rh3 = (h3 - 60) / max(len(tt), 1)
    for i, row in enumerate(tt):
        ry = bly + i * rh3
        nm = row["name"]
        nm = nm if len(nm) <= 30 else nm[:29] + "\u2026"
        text(bx0, ry + rh3 / 2 + 2, nm, size=10, fill=TP)
        bxs = bx0 + label_w
        bwid = bar_max_w * (row["gb"] / maxgb)
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="3" fill="%s"><title>%s: %.1f GB</title></rect>'
          % (bxs, ry + 4, max(bwid, 1), rh3 - 10, col("primary"), esc(row["name"]), row["gb"]))
        text(bxs + bwid + 6, ry + rh3 / 2 + 2, "%.1f" % row["gb"], size=9.5, fill=TS)
        rc = row["rules"]
        rcol = col("danger") if rc == 0 else col("success")
        text(bx0 + bar_area, ry + rh3 / 2 + 2, "%d rule%s" % (rc, "" if rc == 1 else "s"),
             size=9, fill=rcol, anchor="end")

    # detection coverage table
    cx = PAD + bw_w + RG
    cw_w = UW * 0.60 - RG
    card(cx, y3, cw_w, h3)
    text(cx + 16, y3 + 24, "Detection Coverage \u2014 Top Tables", size=14, weight="bold")
    cov = data["detection_coverage"]
    cols = [("Table", 0.42, "start"), ("GB/day", 0.13, "end"), ("Tier", 0.16, "middle"),
            ("AR", 0.08, "middle"), ("CD", 0.08, "middle"), ("Gap", 0.13, "middle")]
    tx0 = cx + 16
    tcw = cw_w - 32
    hy = y3 + 46
    cxx = tx0
    colx = []
    for name, frac, anch in cols:
        w = tcw * frac
        ax = cxx + (w / 2 if anch == "middle" else (w if anch == "end" else 0))
        colx.append((cxx, w, anch, ax))
        text(ax, hy, name, size=10, fill=TS, anchor=anch)
        cxx += w
    a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>' % (tx0, hy + 6, tx0 + tcw, hy + 6, BORDER))
    ry0 = hy + 12
    rh = (h3 - 92) / max(len(cov), 1)
    for ridx, row in enumerate(cov):
        rcy = ry0 + ridx * rh + rh / 2
        if ridx % 2 == 1:
            a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="#1d2430" opacity="0.4"/>'
              % (tx0, rcy - rh / 2, tcw, rh))
        nm = row["name"]
        nm = nm if len(nm) <= 30 else nm[:29] + "\u2026"
        vals = [nm, "%.2f" % row["gb_day"], row["tier"], str(row["ar"]), str(row["cd"]),
                "Gap" if row["gap"] else "OK"]
        for ci, val in enumerate(vals):
            cx0, w, anch, ax = colx[ci]
            head = cols[ci][0]
            if head == "Tier":
                badge(ax, rcy + 4, val, tier_color.get(val, MUTED))
            elif head == "Gap":
                badge(ax, rcy + 4, val, col("danger") if row["gap"] else col("success"))
            elif head in ("AR", "CD"):
                zcol = col("danger") if val == "0" else TP
                text(ax, rcy + 4, val, size=10.5, fill=zcol, anchor="middle")
            else:
                text(ax if anch != "start" else cx0, rcy + 4, val, size=10.5, fill=TP, anchor=anch)
    have, total = data["cov_summary"]
    text(tx0, y3 + h3 - 14, "Coverage: %d of %d top tables carry \u22651 rule" % (have, total),
         size=10, fill=TS)

    # ── Row 4 — daily trend line (55%) + cost waterfall (45%) ──────────────────
    y4 = y3 + h3 + RG
    h4 = 350
    ln_w = UW * 0.55
    card(PAD, y4, ln_w, h4)
    text(PAD + 16, y4 + 24, "Daily Ingestion Trend (GB)", size=14, weight="bold")
    tr = data["trend"]
    if tr:
        cl, ct = PAD + 50, y4 + 50
        cw2, ch2 = ln_w - 80, h4 - 110
        cb = ct + ch2
        vals = [p["gb"] for p in tr]
        vmax = max(vals) or 1
        vmin = min(vals)
        avg = sum(vals) / len(vals)
        n = len(tr)
        def px(i):
            return cl + (cw2 * i / (n - 1) if n > 1 else 0)
        def py(v):
            return cb - ch2 * (v / vmax)
        # axes
        a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>' % (cl, cb, cl + cw2, cb, BORDER))
        # average dashed line
        ay = py(avg)
        a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1.2" stroke-dasharray="5,4"/>'
          % (cl, ay, cl + cw2, ay, MUTED))
        text(cl + cw2, ay - 4, "avg %.1f" % avg, size=9, fill=MUTED, anchor="end")
        # area fill
        pts = " ".join("%.1f,%.1f" % (px(i), py(v)) for i, v in enumerate(vals))
        a('<polygon points="%.1f,%.1f %s %.1f,%.1f" fill="%s" opacity="0.15"/>'
          % (cl, cb, pts, cl + cw2, cb, col("primary")))
        a('<polyline points="%s" fill="none" stroke="%s" stroke-width="2"/>' % (pts, col("primary")))
        # peak / low markers
        imax = vals.index(vmax)
        imin = vals.index(vmin)
        a('<circle cx="%.1f" cy="%.1f" r="4" fill="%s"/>' % (px(imax), py(vmax), col("danger")))
        text(px(imax), py(vmax) - 8, "peak %.1f" % vmax, size=9, fill=col("danger"), anchor="middle")
        a('<circle cx="%.1f" cy="%.1f" r="4" fill="%s"/>' % (px(imin), py(vmin), col("success")))
        text(px(imin), py(vmin) + 16, "low %.1f" % vmin, size=9, fill=col("success"), anchor="middle")
        # y ticks
        for fr in (0.0, 0.5, 1.0):
            yy = cb - ch2 * fr
            text(cl - 6, yy + 3, "%.0f" % (vmax * fr), size=9, fill=MUTED, anchor="end")
        # x labels (first / mid / last)
        for idx in (0, n // 2, n - 1):
            text(px(idx), cb + 16, tr[idx]["date"][5:], size=9, fill=MUTED, anchor="middle")

    # cost waterfall
    wx = PAD + ln_w + RG
    ww = UW * 0.45 - RG
    card(wx, y4, ww, h4)
    text(wx + 16, y4 + 24, "Cost Waterfall (GB/day)", size=14, weight="bold")
    cwf = data["cost_waterfall"]
    segs = [
        ("Gross", cwf["gross"], col("danger"), False),
        ("- E5/XDR", cwf["e5"], col("success"), True),
        ("- DfS P2", cwf["dfsp2"], col("success"), True),
        ("Net", cwf["net"], col("primary"), False),
    ]
    wcl, wct = wx + 30, y4 + 56
    wcw, wch = ww - 90, h4 - 130
    wcb = wct + wch
    wmax = cwf["gross"] or 1
    n_s = len(segs)
    sgap = 18
    sw = (wcw - (n_s - 1) * sgap) / n_s
    running = 0.0
    def wy(v):
        return wcb - wch * (v / wmax)
    a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>' % (wcl, wcb, wcl + wcw, wcb, BORDER))
    for i, (lab, val, c, neg) in enumerate(segs):
        sx = wcl + i * (sw + sgap)
        if lab == "Gross":
            top, bot = val, 0.0
            running = val
        elif lab == "Net":
            top, bot = val, 0.0
        else:
            bot = running - val
            top = running
            running = bot
        yt, yb = wy(top), wy(bot)
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="2" fill="%s"><title>%s: %.2f GB/day</title></rect>'
          % (sx, yt, sw, max(yb - yt, 1), c, esc(lab), val))
        text(sx + sw / 2, yt - 6, "%.2f" % val, size=9.5, weight="bold", fill=c, anchor="middle")
        text(sx + sw / 2, wcb + 16, lab, size=9, fill=TS, anchor="middle")

    # ── Row 5 — tier donut (25%) + anomalies table (40%) + alert rules bar (35%)
    y5 = y4 + h4 + RG
    h5 = 280
    dn_w = UW * 0.25
    card(PAD, y5, dn_w, h5)
    text(PAD + 16, y5 + 24, "Tier Distribution", size=14, weight="bold")
    tiers = data["tiers"]
    tot_tables = sum(x["count"] for x in tiers) or 1
    r = 64
    cxd, cyd = PAD + dn_w / 2, y5 + 130
    C = 2 * math.pi * r
    cum = 0.0
    for ti in tiers:
        frac = ti["count"] / tot_tables
        arc = frac * C
        c = tier_color.get(ti["label"], MUTED)
        a('<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="%s" stroke-width="22" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 %.1f %.1f)"><title>%s: %d tables, %.1f GB</title></circle>'
          % (cxd, cyd, r, c, arc, C - arc, C - cum, cxd, cyd, ti["label"], ti["count"], ti["gb"]))
        cum += arc
    text(cxd, cyd - 2, str(tot_tables), size=26, weight="bold", anchor="middle")
    text(cxd, cyd + 18, "TABLES", size=9, fill=TS, anchor="middle")
    ly = y5 + h5 - 70
    for ti in tiers:
        c = tier_color.get(ti["label"], MUTED)
        a('<rect x="%.1f" y="%.1f" width="11" height="11" rx="2" fill="%s"/>' % (PAD + 16, ly, c))
        text(PAD + 34, ly + 10, "%s  %d (%.0f GB)" % (ti["label"], ti["count"], ti["gb"]), size=10, fill=TP)
        ly += 20

    # anomalies table
    ax0 = PAD + dn_w + RG
    aw = UW * 0.40 - RG
    card(ax0, y5, aw, h5)
    text(ax0 + 16, y5 + 24, "Ingestion Anomalies (WoW)", size=14, weight="bold")
    anoms = data["anomalies"]
    acols = [("Table", 0.40, "start"), ("This Wk", 0.16, "end"), ("Last Wk", 0.16, "end"),
             ("\u0394%", 0.14, "end"), ("Risk", 0.14, "middle")]
    atx = ax0 + 16
    atw = aw - 32
    ahy = y5 + 46
    cxx = atx
    acolx = []
    for name, frac, anch in acols:
        w = atw * frac
        axp = cxx + (w / 2 if anch == "middle" else (w if anch == "end" else 0))
        acolx.append((cxx, w, anch, axp))
        text(axp, ahy, name, size=9.5, fill=TS, anchor=anch)
        cxx += w
    a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>' % (atx, ahy + 6, atx + atw, ahy + 6, BORDER))
    ar0 = ahy + 12
    arh = (h5 - 86) / max(len(anoms), 1)
    for ridx, row in enumerate(anoms):
        rcy = ar0 + ridx * arh + arh / 2
        if ridx % 2 == 1:
            a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="#1d2430" opacity="0.4"/>' % (atx, rcy - arh / 2, atw, arh))
        nm = row["name"]
        nm = nm if len(nm) <= 24 else nm[:23] + "\u2026"
        chg = num(row["change"])
        chg_col = col("danger") if chg > 0 else col("success")
        vals = [nm, row["current"], row["prior"], row["change"], row["severity"]]
        for ci, val in enumerate(vals):
            cx0, w, anch, axp = acolx[ci]
            head = acols[ci][0]
            if head == "Risk":
                badge(axp, rcy + 4, val, sev_color.get(val, MUTED))
            elif head == "\u0394%":
                text(axp, rcy + 4, val, size=10, weight="bold", fill=chg_col, anchor="end")
            else:
                text(axp if anch != "start" else cx0, rcy + 4, val, size=10, fill=TP, anchor=anch)

    # alert-producing rules bar
    rx0 = ax0 + aw + RG
    rw = UW * 0.35 - RG
    card(rx0, y5, rw, h5)
    text(rx0 + 16, y5 + 24, "Top Alert-Producing Rules", size=14, weight="bold")
    arules = data["alert_rules"]
    amax = max((x["count"] for x in arules), default=1) or 1
    abx = rx0 + 16
    aby = y5 + 50
    a_area = rw - 32
    a_label = 0
    a_barw = a_area - 60
    rrh = (h5 - 70) / max(len(arules), 1)
    for i, row in enumerate(arules):
        ry = aby + i * rrh
        nm = row["name"]
        nm = nm if len(nm) <= 34 else nm[:33] + "\u2026"
        text(abx, ry + 12, nm, size=9.5, fill=TP)
        bwid = a_barw * (row["count"] / amax)
        c = sev_color.get(row["severity"], MUTED)
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="10" rx="2" fill="%s"><title>%s: %d alerts</title></rect>'
          % (abx, ry + 18, max(bwid, 1), c, esc(row["name"]), row["count"]))
        text(abx + a_area, ry + 27, str(row["count"]), size=9.5, weight="bold", fill=c, anchor="end")

    # ── Row 6 — recommendation cards ───────────────────────────────────────────
    y6 = y5 + h5 + RG
    h6 = 150
    recs = data["recs"]
    sev_emoji = {"danger": "\U0001F534", "accent": "\U0001F7E0", "success": "\U0001F7E2"}
    if recs:
        rwid = (UW - (len(recs) - 1) * RG) / max(len(recs), 1)
        rxp = PAD
        for idx, rec in enumerate(recs):
            c = col(rec["color"])
            ix = rxp + 18
            card(rxp, y6, rwid, h6)
            a('<rect x="%.1f" y="%.1f" width="5" height="%d" rx="2" fill="%s"/>' % (rxp, y6, h6, c))
            # numbered severity pill badge
            emoji = sev_emoji.get(rec["color"], "\U0001F535")
            pill(rxp + 16, y6 + 14, 54, 20, "#%d %s" % (idx + 1, emoji), c, size=10)
            # title (bold) to the right of the badge, truncated to fit one line
            title_chars = max(14, int((rwid - 96) / 7.4))
            ttl = rec["title"]
            ttl = ttl if len(ttl) <= title_chars else ttl[:title_chars - 1] + "\u2026"
            text(rxp + 80, y6 + 28, ttl, size=12.5, weight="bold", fill=TP)
            ty = y6 + 48
            # table/scope chip
            if rec.get("scope"):
                text(ix, ty, "Table: " + rec["scope"], size=10, weight="bold", fill=c)
                ty += 16
            # description / action (muted, up to 2 lines) — flows directly into Impact/Risk
            ty = wrap(rec["desc"], ix, ty + 2, int((rwid - 36) / 5.8), 10, TS, 14, ty + 16)
            imp_chars = max(20, int((rwid - 36) / 5.6))
            if rec.get("impact"):
                im = "Impact: " + rec["impact"]
                im = im if len(im) <= imp_chars else im[:imp_chars - 1] + "\u2026"
                text(ix, ty + 4, im, size=10, fill=TP)
                ty += 18
            if rec.get("risk"):
                rk = "Risk: " + rec["risk"]
                rk = rk if len(rk) <= imp_chars else rk[:imp_chars - 1] + "\u2026"
                text(ix, ty + 4, rk, size=10, fill=c)
            rxp += rwid + RG
    else:
        card(PAD, y6, UW, h6)
        text(PAD + 16, y6 + 28, "Top Recommendations", size=14, weight="bold")
        text(PAD + 16, y6 + 56, "No recommendations parsed (run with --report for narrative panels).", size=11, fill=TS)

    # ── Row 7 — assessment banner (50%) + key findings table (50%) ─────────────
    y7 = y6 + h6 + RG
    h7 = 220
    ab_w = UW * 0.50
    card(PAD, y7, ab_w, h7)
    a('<rect x="%.1f" y="%.1f" width="5" height="%d" rx="2" fill="%s"/>' % (PAD, y7, h7, col("primary")))
    text(PAD + 18, y7 + 28, "Overall Assessment", size=15, weight="bold")
    a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1.5"/>'
      % (PAD + 18, y7 + 36, PAD + 215, y7 + 36, col("primary")))
    risk_chars = int((ab_w - 60) / 5.6)
    ly = y7 + 60
    if data["risks"]:
        text(PAD + 18, ly, "Key Risks", size=11, weight="bold", fill=col("danger"))
        ly += 20
        for pri, txt in data["risks"][:4]:
            t1 = txt if len(txt) <= risk_chars else txt[:risk_chars - 1] + "\u2026"
            text(PAD + 22, ly, "\u2022 " + t1, size=10, fill=TP)
            ly += 18
            if ly > y7 + h7 - 86:
                break
    if data["strengths"] and ly < y7 + h7 - 50:
        ly += 4
        text(PAD + 18, ly, "Strengths", size=11, weight="bold", fill=col("success"))
        ly += 20
        for txt in data["strengths"][:3]:
            t1 = txt if len(txt) <= risk_chars else txt[:risk_chars - 1] + "\u2026"
            text(PAD + 22, ly, "\u2022 " + t1, size=10, fill=TP)
            ly += 18
            if ly > y7 + h7 - 14:
                break
    if not data["risks"] and not data["strengths"]:
        text(PAD + 18, ly, "No assessment narrative parsed (run with --report).", size=11, fill=TS)

    # key findings table
    kx = PAD + ab_w + RG
    kw = UW * 0.50 - RG
    card(kx, y7, kw, h7)
    text(kx + 18, y7 + 28, "Key Findings", size=15, weight="bold")
    finds = data["findings"]
    pri_pill = {
        "High": ("\U0001F534 High", col("danger")),
        "Medium": ("\U0001F7E0 Med", col("accent")),
        "Low": ("\U0001F7E2 Low", col("success")),
        "OK": ("\U0001F7E2 Good", col("success")),
    }
    ktx = kx + 18
    khy = y7 + 52
    text(ktx, khy, "Priority", size=10, weight="bold", fill=TS)
    text(ktx + 80, khy, "Finding", size=10, weight="bold", fill=TS)
    a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>' % (ktx, khy + 6, kx + kw - 18, khy + 6, BORDER))
    find_chars = int((kw - 110) / 5.6)
    ky = khy + 12
    krh = (h7 - 78) / max(len(finds), 1)
    for i, f in enumerate(finds):
        rcy = ky + i * krh
        lbl, pc = pri_pill.get(f["priority"], ("\U0001F535 Info", MUTED))
        pill(ktx, rcy + (krh - 18) / 2, 64, 18, lbl, pc, size=9)
        nm = f["finding"]
        nm = nm if len(nm) <= find_chars else nm[:find_chars - 1] + "\u2026"
        text(ktx + 80, rcy + krh / 2 + 4, nm, size=10, fill=TP)

    a('</svg>')
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with io.open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(S))
    return len(S)


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Render the Sentinel ingestion SVG dashboard from pipeline data.")
    ap.add_argument("--scratch", required=True, help="temp/ingest_scratch_<ts>.md")
    ap.add_argument("--manifest", required=True, help="svg-widgets.yaml")
    ap.add_argument("--report", help="rendered ingestion report .md (for narrative panels)")
    ap.add_argument("--out", required=True, help="output .svg path")
    args = ap.parse_args(argv)

    with io.open(args.manifest, "r", encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    data = parse_data(args.scratch, args.report)
    n = render(data, manifest, args.out)
    print("WROTE %s (%d bytes, %d elements)" % (args.out, os.path.getsize(args.out), n))
    print("posture=%g  top_tables=%d  trend_pts=%d  tiers=%d  anomalies=%d  alert_rules=%d  recs=%d"
          % (data["posture_score"], len(data["top_tables"]), len(data["trend"]),
             len(data["tiers"]), len(data["anomalies"]), len(data["alert_rules"]), len(data["recs"])))


if __name__ == "__main__":
    main()
