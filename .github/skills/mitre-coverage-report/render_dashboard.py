# -*- coding: utf-8 -*-
"""
render_dashboard.py - Deterministic, data-driven SVG dashboard renderer for the
MITRE ATT&CK Coverage report.

Renders the 5-row layout defined in svg-widgets.yaml. ALL values are parsed from
the pipeline scratchpad (temp/mitre_scratch_<ts>.md) and, for the recommendation
cards, from the rendered report's "Top 3 Recommendations" table. Nothing is
hard-coded per run -- point it at a different scratchpad/report and it renders
that week's data.

Canvas geometry, palette and rating/dimension colors are loaded from the manifest
so layout tweaks live in the YAML, not in code.

This script is READ-ONLY apart from writing the single --out .svg file.

Usage:
    python render_dashboard.py \
        --scratch  temp/mitre_scratch_<ts>.md \
        --manifest .github/skills/mitre-coverage-report/svg-widgets.yaml \
        --report   reports/sentinel/mitre_coverage_report_<label>_<ts>.md \
        --out      reports/sentinel/mitre_coverage_report_<label>_<ts>_dashboard.svg

--report is optional: if omitted (or no recommendations table is found) the
recommendation row is derived from the top threat-scenario gaps in the scratchpad.
"""
import argparse
import io
import math
import os
import re
import sys

import yaml

# ───────────────────────── name maps ─────────────────────────
TACTIC_ABBR = {
    "Reconnaissance": "Recon", "Resource Development": "ResDev",
    "Initial Access": "InitAcc", "Execution": "Exec", "Persistence": "Persist",
    "Privilege Escalation": "PrivEsc", "Defense Evasion": "DefEvas",
    "Credential Access": "CredAcc", "Discovery": "Disc",
    "Lateral Movement": "LatMov", "Collection": "Collect",
    "Command and Control": "C2", "Exfiltration": "Exfil", "Impact": "Impact",
}
TACTIC_ORDER = list(TACTIC_ABBR.keys())

PRODUCT_ABBR = {
    "Microsoft Entra ID Protection": "AADIP",
    "Microsoft Defender for Cloud": "MDC",
    "Microsoft Defender XDR": "MXDR",
    "Microsoft Defender for Cloud Apps": "MDCA",
    "Microsoft Defender for Endpoint": "MDE",
    "Microsoft Defender for Identity": "MDI",
    "Microsoft Defender for Office 365": "MDO",
    "Analytic Rules (AR)": "AR",
    "Custom Detections (CD)": "CD",
}
# Donut colors keyed by product abbreviation (deterministic, palette-aligned).
PRODUCT_COLORS = {
    "MDE": "#409AE1", "MXDR": "#b4a0ff", "MDC": "#40C5AF", "AR": "#8B5CF6",
    "MDI": "#FFC83D", "MDCA": "#ff8c00", "AADIP": "#EF6950", "MDO": "#6e7681",
    "CD": "#2d6a5a",
}
EMOJI = ("\U0001F534", "\U0001F7E0", "\U0001F7E1", "\u2705", "\U0001F535", "\U0001F7E2")


def strip_emoji(s):
    for e in EMOJI:
        s = s.replace(e, "")
    return s.strip()


# ───────────────────────── scratchpad parsing ─────────────────────────
def read_text(path):
    with io.open(path, "r", encoding="utf-8") as f:
        return f.read()


def parse_kv_block(text, header):
    """Parse 'Key: Value' lines under a '## header' or '### header' until blank/next marker."""
    out = {}
    lines = text.splitlines()
    started = False
    for ln in lines:
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


def md_table_rows(text, header, subheader=None):
    """Return list of cell-lists for a markdown table under '### header' (optionally '#### subheader')."""
    lines = text.splitlines()
    i = 0
    n = len(lines)
    # advance to header
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
            if set("".join(cells)) <= set("-: "):  # separator row
                seen_sep = True
                i += 1
                continue
            rows.append(cells)
        elif rows and s == "":
            # table ended
            if seen_sep:
                break
        i += 1
    return rows


def num(s):
    m = re.search(r"-?\d+(?:\.\d+)?", s.replace("**", ""))
    return float(m.group(0)) if m else 0.0


def parse_data(scratch_path, report_path):
    t = read_text(scratch_path)
    meta = parse_kv_block(t, "META")
    score = parse_kv_block(t, "SCORE")
    ar = parse_kv_block(t, "AR_Summary")
    cd = parse_kv_block(t, "CD_Summary")

    # combined tactic coverage: Tactic | Rule-Based | T1 | T2 | T3 | Combined | Framework | Coverage
    tactics = []
    rb_total = fw_total = comb_total = 0
    for r in md_table_rows(t, "CombinedTacticCoverage"):
        name = strip_emoji(r[0]).replace("*", "").strip()
        if name.upper() == "TOTAL":
            rb_total, comb_total, fw_total = int(num(r[1])), int(num(r[5])), int(num(r[6]))
            continue
        if name not in TACTIC_ABBR:
            continue
        tactics.append({
            "abbr": TACTIC_ABBR[name], "rule_based": int(num(r[1])),
            "combined": int(num(r[5])), "framework": int(num(r[6])),
        })
    tactics.sort(key=lambda x: TACTIC_ORDER.index(
        next(k for k, v in TACTIC_ABBR.items() if v == x["abbr"])))

    # threat scenarios (Active Gaps): Priority | Scenario | Active | Rec. | Rate | Gap | ... | State | ...
    scen = []
    for r in md_table_rows(t, "ThreatScenarios", "Active Gaps"):
        if r[0].strip().lower() == "priority":
            continue
        pe = r[0]
        pri = ("HIGH" if "\U0001F534" in pe else "MED" if ("\U0001F7E1" in pe or "\U0001F7E0" in pe)
               else "OK")
        scen.append({
            "scenario": r[1], "active": r[2], "rec": r[3], "gap": int(num(r[5])),
            "priority": pri, "state": r[9].strip(),
        })
    scen.sort(key=lambda x: x["gap"], reverse=True)

    # deployed products (donut)
    products = []
    in_dp = False
    for ln in t.splitlines():
        s = ln.strip()
        if s == "### DeployedProducts":
            in_dp = True
            continue
        if in_dp:
            if s.startswith("### ") or s == "":
                if products:
                    break
                continue
            m = re.match(r"^(.+?)\s*\|\s*(\d+)\s*techniques?$", s)
            if m and m.group(1).strip() in PRODUCT_ABBR:
                ab = PRODUCT_ABBR[m.group(1).strip()]
                products.append({"abbr": ab, "value": int(m.group(2)),
                                 "color": PRODUCT_COLORS.get(ab, "#6e7681")})
    products.sort(key=lambda x: x["value"], reverse=True)

    # recommendations
    recs = parse_recommendations(report_path, scen)

    # weights for dimension labels
    wmap = {}
    for part in score.get("Weights", "").split(","):
        if "=" in part:
            k, v = part.split("=")
            wmap[k.strip()] = float(v)

    ar_en = int(num(ar.get("AR_Enabled", "0")))
    cd_en = int(num(cd.get("CD_Enabled", "0")))
    rb_pct = round(rb_total / fw_total * 100, 1) if fw_total else 0.0
    comb_str = score.get("RuleBasedPlusPlatform_Coverage", "%d / %d" % (comb_total, fw_total))
    cm = re.match(r"\s*(\d+)\s*/\s*(\d+)\s*\(([\d.]+)%\)", comb_str)
    comb_val = "%s/%s" % (cm.group(1), cm.group(2)) if cm else "%d/%d" % (comb_total, fw_total)
    comb_pct = cm.group(3) if cm else (str(round(comb_total / fw_total * 100, 1)) if fw_total else "0")

    gen_date = (meta.get("Generated", "")[:10]) or "n/a"
    days = meta.get("Days", "?")
    attck = meta.get("ATT&CK_Version", "")
    workspace = meta.get("Workspace", "")

    return {
        "subtitle": "%s  \u00b7  Enterprise v%s  \u00b7  %s  \u00b7  %s-day lookback"
                    % (workspace, attck, gen_date, days),
        "score": num(score.get("MITRE_Score", "0")),
        "dimensions": [
            ("Breadth", num(score.get("Breadth", "0")), "breadth", wmap.get("breadth")),
            ("Balance", num(score.get("Balance", "0")), "balance", wmap.get("balance")),
            ("Operational", num(score.get("Operational", "0")), "operational", wmap.get("operational")),
            ("Tagging", num(score.get("Tagging", "0")), "tagging", wmap.get("tagging")),
            ("SOC Align", num(score.get("SOC_Alignment", "0")), "soc_alignment", wmap.get("socAlign")),
        ],
        "kpis": [
            ("Rule-Based Techniques", "%d/%d" % (rb_total, fw_total), "%s%% of framework" % rb_pct, "primary"),
            ("Enabled Rules", str(ar_en + cd_en), "%d AR + %d CD" % (ar_en, cd_en), "primary"),
            ("Combined Coverage", comb_val, "%s%% (rules + platform)" % comb_pct, "success"),
            ("Data Readiness", "%s%%" % score.get("DataReadiness_Pct", "0"),
             "%s ready \u00b7 %s partial \u00b7 %s no data" % (
                 score.get("DataReadiness_Ready", "0"), score.get("DataReadiness_Partial", "0"),
                 score.get("DataReadiness_NoData", "0")), "success"),
        ],
        "tactics": tactics,
        "scenarios": scen[:8],
        "products": products,
        "donut_center": int(num(score.get("Platform_Tier1", "0"))),
        "recs": recs,
    }


def parse_recommendations(report_path, scenarios):
    """Parse the report's 'Top 3 Recommendations' table; fall back to top scenario gaps."""
    if report_path and os.path.exists(report_path):
        t = read_text(report_path)
        try:
            rows = md_table_rows(t, "\U0001F3AF Top 3 Recommendations".strip())
        except KeyError:
            rows = None
        if not rows:
            # heading may carry the emoji differently; locate loosely
            lines = t.splitlines()
            for i, ln in enumerate(lines):
                if ln.strip().startswith("###") and "Top 3 Recommendations" in ln:
                    rows = _table_from(lines, i + 1)
                    break
        if rows:
            out = []
            for r in rows:
                if r[0].strip() == "#" or not r[0].strip().isdigit():
                    continue
                pe = r[1]
                color = ("danger" if "\U0001F534" in pe else "warning" if ("\U0001F7E0" in pe or "\U0001F7E1" in pe)
                         else "primary")
                rec_cell = r[2].strip()
                impact = r[3].strip() if len(r) > 3 else ""
                m = re.match(r"\*\*(.+?)\*\*\s*[\u2014\-]{1,2}\s*(.*)", rec_cell)
                if m:
                    title, desc = m.group(1).strip(), m.group(2).strip()
                else:
                    title, desc = rec_cell.replace("**", ""), ""
                out.append({"color": color, "title": title,
                            "desc": re.sub(r"`([^`]*)`", r"\1", desc),
                            "impact": "Impact: " + re.sub(r"`([^`]*)`", r"\1", impact)})
            if out:
                return out[:3]
    # fallback: top 3 scenario gaps
    out = []
    cmap = {"HIGH": "danger", "MED": "warning", "OK": "primary"}
    for s in scenarios[:3]:
        out.append({"color": cmap.get(s["priority"], "primary"),
                    "title": "Close gap: " + s["scenario"],
                    "desc": "%d of %s recommended detections deployed; gap of %d."
                            % (int(num(s["active"])), s["rec"], s["gap"]),
                    "impact": "Impact: SOC Optimization alignment"})
    return out


def _table_from(lines, start):
    rows = []
    i = start
    while i < len(lines) and lines[i].strip() == "":
        i += 1
    while i < len(lines) and lines[i].strip().startswith("|"):
        cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
        if not (set("".join(cells)) <= set("-: ")):
            rows.append(cells)
        i += 1
    return rows


# ───────────────────────── SVG rendering ─────────────────────────
def esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(data, manifest, out_path):
    cv = manifest["canvas"]
    pal = manifest["palette"]
    rate = manifest["score_rating_colors"]
    dimc = manifest.get("dimension_colors", {})
    W, H = cv["width"], cv["height"]
    PAD, RG = cv["padding"], cv["row_gap"]
    FONT = cv["font_family"]
    UW = W - 2 * PAD

    def col(name):
        return pal.get(name, "#ffffff")

    TP, TS = pal.get("text_primary", "#e6edf3"), pal.get("text_secondary", "#b2b2b2")
    CARD, BORDER = pal.get("card_bg", "#161b22"), pal.get("card_border", "#30363d")

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

    # Row 1 — title
    y1 = PAD
    text(W / 2, y1 + 30, "MITRE ATT&CK Coverage Dashboard", size=22, weight="bold", anchor="middle")
    text(W / 2, y1 + 52, data["subtitle"], size=12, fill=TS, anchor="middle")
    a('<rect x="%d" y="%.1f" width="%d" height="3" rx="1.5" fill="%s"/>' % (W / 2 - 180, y1 + 62, 360, col("primary")))

    # Row 2 — score + KPIs
    y2 = y1 + 72 + RG
    h2 = 130
    sc_w = UW * 0.20
    kpi_w = (UW - sc_w - 4 * RG) / 4
    sc = data["score"]
    band = ("critical" if sc < 20 else "developing" if sc < 40 else "moderate" if sc < 60
            else "good" if sc < 80 else "strong")
    sc_col = rate.get(band, col("accent"))
    card(PAD, y2, sc_w, h2)
    text(PAD + sc_w / 2, y2 + 24, "MITRE Coverage Score", size=12, weight="bold", anchor="middle")
    text(PAD + sc_w / 2, y2 + 76, ("%g" % sc), size=46, weight="bold", fill=sc_col, anchor="middle")
    text(PAD + sc_w / 2 + 58, y2 + 76, "/100", size=16, fill=TS, anchor="middle")
    text(PAD + sc_w / 2, y2 + 104, band.upper(), size=14, weight="bold", fill=sc_col, anchor="middle")
    kx = PAD + sc_w + RG
    for label, val, sub, cn in data["kpis"]:
        card(kx, y2, kpi_w, h2)
        text(kx + kpi_w / 2, y2 + 30, label, size=12, fill=TS, anchor="middle")
        text(kx + kpi_w / 2, y2 + 78, val, size=32, weight="bold", fill=col(cn), anchor="middle")
        text(kx + kpi_w / 2, y2 + 104, sub, size=10, fill=TS, anchor="middle")
        kx += kpi_w + RG

    # Row 3 — stacked tactic bars (65%) + dimensions (35%)
    y3 = y2 + h2 + RG
    h3 = 300
    sb_w = UW * 0.65
    card(PAD, y3, sb_w, h3)
    text(PAD + 16, y3 + 24, "Combined Tactic Coverage (Rule-Based + Platform)", size=14, weight="bold")
    lx = PAD + sb_w - 270
    for off, (cn, lab) in enumerate([("primary", "Rule-Based"), ("success", "Platform Uplift"), ("card_border", "Framework")]):
        bx = lx + off * 100
        a('<rect x="%.1f" y="%.1f" width="11" height="11" fill="%s"/>' % (bx, y3 + 14, col(cn)))
        text(bx + 16, y3 + 23, lab, size=10, fill=TS)
    chart_x = PAD + 40
    chart_w = sb_w - 60
    chart_y = y3 + 40
    chart_h = h3 - 90
    tcs = data["tactics"]
    bar_gap = 8
    bar_w = (chart_w - (len(tcs) - 1) * bar_gap) / len(tcs)
    max_val = max((x["framework"] for x in tcs), default=1)
    scale = chart_h / max_val
    base_y = chart_y + chart_h
    a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>' % (chart_x, base_y, chart_x + chart_w, base_y, BORDER))
    for i, tc in enumerate(tcs):
        bx = chart_x + i * (bar_w + bar_gap)
        gray_h = tc["framework"] * scale
        blue_h = tc["rule_based"] * scale
        green_h = (tc["combined"] - tc["rule_based"]) * scale
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s" opacity="0.45"><title>%s framework: %d</title></rect>'
          % (bx, base_y - gray_h, bar_w, gray_h, BORDER, tc["abbr"], tc["framework"]))
        if blue_h > 0:
            a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"><title>%s rule-based: %d</title></rect>'
              % (bx, base_y - blue_h, bar_w, blue_h, col("primary"), tc["abbr"], tc["rule_based"]))
        if green_h > 0:
            a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="%s"><title>%s platform uplift: %d</title></rect>'
              % (bx, base_y - blue_h - green_h, bar_w, green_h, col("success"), tc["abbr"], tc["combined"] - tc["rule_based"]))
        text(bx + bar_w / 2, base_y - gray_h - 5, "%d/%d" % (tc["combined"], tc["framework"]), size=9, fill=TS, anchor="middle")
        text(bx + bar_w / 2, base_y + 16, tc["abbr"], size=10, fill=TS, anchor="end",
             rotate="-45 %.1f %.1f" % (bx + bar_w / 2, base_y + 16))

    dx = PAD + sb_w + RG
    dw = UW * 0.35 - RG
    card(dx, y3, dw, h3)
    text(dx + 16, y3 + 24, "Score Dimensions", size=14, weight="bold")
    dims = data["dimensions"]
    d_chart_x = dx + 150
    d_chart_w = dw - 214
    d_top = y3 + 50
    bar_h = 28
    row_gap = (h3 - 70) / len(dims)
    ref_x = d_chart_x + d_chart_w * 0.5
    a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1" stroke-dasharray="4,3"/>'
      % (ref_x, d_top - 8, ref_x, d_top + row_gap * len(dims) - 12, pal.get("muted", "#b2b2b2")))
    text(ref_x, d_top - 12, "50", size=9, fill=pal.get("muted", "#b2b2b2"), anchor="middle")
    for i, (lab, val, ckey, wt) in enumerate(dims):
        ry = d_top + i * row_gap
        wlab = (" (%d%%)" % round(wt * 100)) if wt else ""
        text(dx + 16, ry + bar_h / 2 + 4, lab + wlab, size=11, fill=TP)
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="%d" rx="4" fill="%s"/>' % (d_chart_x, ry, d_chart_w, bar_h, BORDER))
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="%d" rx="4" fill="%s"/>'
          % (d_chart_x, ry, d_chart_w * val / 100.0, bar_h, dimc.get(ckey, col("primary"))))
        text(dx + dw - 12, ry + bar_h / 2 + 4, "%g/100" % val, size=11, weight="bold", fill=TP, anchor="end")

    # Row 4 — scenarios table (60%) + donut (40%)
    y4 = y3 + h3 + RG
    h4 = 280
    tw = UW * 0.60
    card(PAD, y4, tw, h4)
    text(PAD + 16, y4 + 24, "Threat Scenario Gaps (SOC Optimization)", size=14, weight="bold")
    cols = [("Scenario", 0.42, "start"), ("Active", 0.12, "middle"), ("Rec.", 0.10, "middle"),
            ("Gap", 0.10, "middle"), ("Priority", 0.13, "middle"), ("State", 0.13, "middle")]
    tx0 = PAD + 16
    tcw = tw - 32
    hy = y4 + 44
    cx = tx0
    colx = []
    for name, frac, anch in cols:
        w = tcw * frac
        ax = cx + (w / 2 if anch == "middle" else 0)
        colx.append((cx, w, anch, ax))
        text(ax, hy, name, size=10, fill=TS, anchor=anch)
        cx += w
    a('<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>' % (tx0, hy + 6, tx0 + tcw, hy + 6, BORDER))
    pri_col = {"HIGH": col("danger"), "MED": col("warning"), "OK": col("success")}
    st_col = {"Active": col("primary"), "InProgress": col("warning")}
    scen = data["scenarios"]
    ry0 = hy + 14
    rh = (h4 - 70) / max(len(scen), 1)

    def badge(cx_center, cy, label, color):
        bw = 8 + len(label) * 7
        a('<rect x="%.1f" y="%.1f" width="%.1f" height="18" rx="4" fill="none" stroke="%s" stroke-width="1.5"/>'
          % (cx_center - bw / 2, cy - 13, bw, color))
        text(cx_center, cy, label, size=9, weight="bold", fill=color, anchor="middle")

    for ridx, row in enumerate(scen):
        rcy = ry0 + ridx * rh
        if ridx % 2 == 1:
            a('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" fill="#1d2430" opacity="0.4"/>' % (tx0, rcy - rh + 6, tcw, rh))
        cell_y = rcy + 2
        vals = [row["scenario"], row["active"], row["rec"], str(row["gap"]), row["priority"], row["state"]]
        for ci, val in enumerate(vals):
            cx0, w, anch, ax = colx[ci]
            if cols[ci][0] == "Priority":
                badge(ax, cell_y, val, pri_col.get(val, col("muted")))
            elif cols[ci][0] == "State":
                badge(ax, cell_y, val, st_col.get(val, col("muted")))
            elif cols[ci][0] == "Gap":
                text(ax, cell_y + 4, val, size=11, weight="bold", fill=col("danger"), anchor=anch)
            else:
                text(ax if anch != "start" else cx0, cell_y + 4, val, size=11, fill=TP, anchor=anch)

    dnx = PAD + tw + RG
    dnw = UW * 0.40 - RG
    card(dnx, y4, dnw, h4)
    text(dnx + 16, y4 + 24, "Alert-Proven Techniques by Source", size=14, weight="bold")
    products = data["products"]
    total = sum(p["value"] for p in products) or 1
    r = 66
    cxd = dnx + 110
    cyd = y4 + 150
    C = 2 * math.pi * r
    cum = 0.0
    for p in products:
        arc = (p["value"] / total) * C
        off = C - cum
        a('<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="%s" stroke-width="20" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 %.1f %.1f)"><title>%s: %d techniques</title></circle>'
          % (cxd, cyd, r, p["color"], arc, C - arc, off, cxd, cyd, p["abbr"], p["value"]))
        cum += arc
    text(cxd, cyd - 4, str(data["donut_center"]), size=30, weight="bold", anchor="middle")
    text(cxd, cyd + 16, "TECHNIQUES", size=9, fill=TS, anchor="middle")
    ly = y4 + 60
    lgx = cxd + 110
    for p in products:
        a('<rect x="%.1f" y="%.1f" width="11" height="11" rx="2" fill="%s"/>' % (lgx, ly, p["color"]))
        text(lgx + 18, ly + 10, "%s  %d" % (p["abbr"], p["value"]), size=11, fill=TP)
        ly += 24
    text(dnx + 16, y4 + h4 - 12, "Center = %d unique Tier 1 (dedup); segments overlap across sources." % data["donut_center"], size=9, fill=TS)

    # Row 5 — recommendation cards
    y5 = y4 + h4 + RG
    h5 = 130
    recs = data["recs"]
    rw = (UW - (len(recs) - 1) * RG) / max(len(recs), 1)
    rx = PAD
    def wrap_lines(s, width_chars):
        out, line = [], ""
        for wd in str(s).split(" "):
            if line and len((line + " " + wd).strip()) > width_chars:
                out.append(line)
                line = wd
            else:
                line = (line + " " + wd).strip()
        if line:
            out.append(line)
        return out

    for rec in recs:
        c = col(rec["color"])
        card(rx, y5, rw, h5)
        a('<rect x="%.1f" y="%.1f" width="5" height="%d" rx="2" fill="%s"/>' % (rx, y5, h5, c))
        # title — truncate to one line
        title_chars = max(16, int((rw - 36) / 7.2))
        ttl = rec["title"]
        ttl = ttl if len(ttl) <= title_chars else ttl[:title_chars - 1] + "\u2026"
        text(rx + 18, y5 + 28, ttl, size=13, weight="bold", fill=TP)
        # description — wrap and truncate so the last line never overflows the card
        wrap_chars = max(20, int((rw - 36) / 5.8))
        desc_y, desc_max_y = y5 + 50, y5 + h5 - 34
        max_lines = max(1, int((desc_max_y - desc_y) // 16) + 1)
        lines = wrap_lines(rec["desc"], wrap_chars)
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            last = lines[-1]
            lines[-1] = (last[:wrap_chars - 1] if len(last) > wrap_chars - 1 else last) + "\u2026"
        ly = desc_y
        for ln in lines:
            text(rx + 18, ly, ln, size=10.5, fill=TS)
            ly += 16
        # impact — truncate to one line
        imp_chars = max(20, int((rw - 36) / 5.4))
        imp = rec["impact"]
        imp = imp if len(imp) <= imp_chars else imp[:imp_chars - 1] + "\u2026"
        text(rx + 18, y5 + h5 - 14, imp, size=10, weight="bold", fill=c)
        rx += rw + RG

    a('</svg>')
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with io.open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(S))
    return len(S)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render the MITRE coverage SVG dashboard from pipeline data.")
    ap.add_argument("--scratch", required=True, help="temp/mitre_scratch_<ts>.md")
    ap.add_argument("--manifest", required=True, help="svg-widgets.yaml")
    ap.add_argument("--report", help="rendered coverage report .md (for recommendation cards)")
    ap.add_argument("--out", required=True, help="output .svg path")
    args = ap.parse_args(argv)

    with io.open(args.manifest, "r", encoding="utf-8") as f:
        manifest = yaml.safe_load(f)
    data = parse_data(args.scratch, args.report)
    n = render(data, manifest, args.out)
    print("WROTE %s (%d bytes, %d elements)" % (args.out, os.path.getsize(args.out), n))
    print("score=%g  tactics=%d  scenarios=%d  products=%d  donut_center=%d  recs=%d"
          % (data["score"], len(data["tactics"]), len(data["scenarios"]),
             len(data["products"]), data["donut_center"], len(data["recs"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
