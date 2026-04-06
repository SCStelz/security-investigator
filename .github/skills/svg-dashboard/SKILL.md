---
name: svg-dashboard
description: 'Use this skill when asked to generate SVG data visualization dashboards from investigation data or skill reports. Triggers on keywords like "generate SVG dashboard", "create a visual dashboard", "visualize this report", "SVG from the report", "visualize results", "create SVG chart", "SVG from this data". Supports two modes: manifest-driven structured dashboards (from skill reports with svg-widgets.yaml) and freeform adaptive visualizations from ad-hoc investigation data. Component library includes KPI cards, score cards, bar charts, line charts, donut charts, waterfall charts, tables, recommendation cards, assessment banners. SharePoint Dark Theme default palette.'
---

# SVG Dashboard Generator

> Renders SVG data visualization dashboards — either from a skill's `svg-widgets.yaml` manifest (structured dashboards) or freeform from ad-hoc investigation data in context.

---

## Mode Detection

Before rendering, determine which mode applies:

| Condition | Mode | Behavior |
|-----------|------|----------|
| User asks for a dashboard **after a skill report** AND the calling skill has an `svg-widgets.yaml` | **Manifest Mode** | Read the YAML manifest → follow its layout exactly → deterministic dashboard |
| User asks to "visualize", "chart", or "create an SVG" from ad-hoc data in context (query results, investigation findings, inline tables) | **Freeform Mode** | Select widget types from the Component Library below based on data shape → creative layout |
| No `svg-widgets.yaml` exists for the current workflow | **Freeform Mode** | Same as above |

**Decision flow:**

```
1. Is there an svg-widgets.yaml for the current skill?
   → YES + user said "dashboard" or "SVG from the report" → Manifest Mode
   → NO  → Freeform Mode

2. Does the user have structured data in context (query results, tables, metrics)?
   → YES → Freeform Mode (use data shape to pick widgets)
   → NO  → Ask user what data to visualize
```

---

## Manifest Mode — Structured Dashboard

Used when a skill provides an `svg-widgets.yaml` manifest (e.g., `mcp-usage-monitoring`, `sentinel-ingestion-report`).

### Execution

```
Step 1:  Read the calling skill's svg-widgets.yaml (widget manifest)
Step 2:  Read this file's Rendering Rules below (component library + quality standards)
Step 3:  Read the completed report file (data source)
         — If same chat: report data is already in context
         — If new chat: read the file path provided by user or find latest in the skill's reports/ subfolder
Step 4:  Map manifest fields → report data using data_sources.field_mapping_notes
Step 5:  Render SVG → save to the same directory as the report: {report_basename}_dashboard.svg
```

### Data Extraction (Manifest Mode)

- Read the report markdown or scratchpad JSON.
- Match fields from the manifest's `data_sources.field_mapping_notes` to locate values.
- For arrays (top_tables, anomalies, etc.), extract the full dataset and render up to `max_items`.
- For single values (KPIs), extract the number and apply the specified `unit`.
- If a field is not found in the report data, render the widget with "N/A" in muted text — never omit the widget.

---

## Freeform Mode — Adaptive Visualization

Used when no manifest exists or the user wants an ad-hoc visualization from investigation data already in context.

### Execution

```
Step 1:  Identify the data in context (query results, investigation findings, report sections, inline tables)
Step 2:  Analyze data shape — what dimensions, metrics, categories, and time series are present?
Step 3:  Read this file's Rendering Rules below (component library + quality standards)
Step 4:  Select appropriate widget types from the Component Library (see Data Shape Guide below)
Step 5:  Design a layout: title banner → KPI summary → detail charts/tables → optional assessment
Step 6:  Render SVG → save to temp/{descriptive_name}_dashboard.svg or user-specified path
```

### Data Shape → Widget Selection Guide

| Data Shape | Best Widget | Example |
|------------|-------------|---------|
| Single metrics / counts | `kpi-card` | Total failed logins: 47, Unique IPs: 12 |
| Metric with period-over-period change | `delta-kpi-card` | Incidents: 47 (↑23% vs last period) |
| Scored assessment (0-100) | `score-card` | Risk Score: 73/100 |
| Categorical counts (top-N) | `horizontal-bar-chart` | Top 10 source IPs by attempt count |
| Composition within categories | `stacked-bar-chart` | Alert severity breakdown per week |
| Time series (values over dates) | `line-chart` | Daily sign-in volume over 30 days |
| Proportional breakdown | `donut-chart` | Auth methods: 60% password, 30% MFA, 10% token |
| Additive/subtractive flow | `waterfall-chart` | Ingestion costs with license benefits |
| Completion / target tracking | `progress-bar` | 72% of critical CVEs patched |
| Inline trend in KPI or table cell | `sparkline` | 7-day mini trend beneath a KPI value |
| Tabular detail rows | `table-widget` | IP enrichment results, alert details |
| Prioritized action items | `recommendation-cards` | High/Medium/Low priority findings |
| Executive summary | `assessment-banner` | Overall risk assessment with key risks/strengths |
| 2D framework coverage (categories × items) | `coverage-matrix` | MITRE ATT&CK tactic × technique map, permission grids |
| Report header | `title-banner` | Investigation title, date, scope |

### Layout Heuristics (Freeform)

- **Row 1:** Always start with a `title-banner` (data source, date range, scope)
- **Row 2:** KPI cards for key metrics (3-6 cards, one row)
- **Rows 3+:** Charts and tables arranged by importance — most critical findings first
- **Final row:** Assessment banner or recommendation cards if actionable findings exist
- **Canvas size:** Default 1400×900, increase height proportionally for more rows (~100-200px per row)
- **Use the default SharePoint Dark palette** (defined below) unless the data context suggests otherwise

### Token Budget & Data Limits (Freeform Mode)

> **Why this matters:** SVG is verbose — every `<rect>`, `<text>`, and `<path>` consumes output tokens. Without limits, freeform dashboards with rich investigation data routinely exceed the model's output token budget, producing truncated/broken SVGs. Manifest-mode dashboards avoid this because the YAML `max_items` and fixed row count act as natural constraints.

**Hard Limits — Always Enforced:**

| Constraint | Limit | Rationale |
|-----------|-------|-----------|
| **Max rows** | 6 (including title banner) | Each row adds ~100-200 SVG elements |
| **Max widgets total** | 12 | Beyond this, SVG size balloons past safe output limits |
| **Max KPI cards per row** | 5 | More than 5 become unreadable at standard canvas width |
| **Max canvas height** | 1200px | Forces prioritization; prevents unbounded vertical growth |

**Per-Widget Data Limits:**

| Widget Type | Max Data Points | What to Do with Excess |
|-------------|----------------|----------------------|
| `horizontal-bar-chart` | 10 bars | Show top 10, add a summary "Other (N remaining)" bar |
| `stacked-bar-chart` | 8 bars × 6 segments | Aggregate smaller segments into "Other" |
| `line-chart` | 30 data points | Resample to weekly if daily exceeds 30; show date range in subtitle |
| `donut-chart` | 7 segments | Merge smallest into "Other" |
| `waterfall-chart` | 8 segments | Combine minor items |
| `table-widget` | 8 rows | Show top 8, add footer "Showing 8 of N" |
| `recommendation-cards` | 4 cards | Prioritize highest-impact recommendations |
| `sparkline` | 14 data points | Resample to fit (e.g., daily → every-other-day) |

**Data Triage Strategy:**

When the data in context exceeds these limits, apply this priority filter:

1. **Summarize first** — Extract the 3-5 most important KPIs before plotting details
2. **Top-N everything** — For ranked data, show top 10 max; group the rest as "Other"
3. **Aggregate time series** — If >30 daily points, resample to weekly; if >30 weekly, resample to monthly
4. **One chart per insight** — Don't render the same data as both a bar chart AND a table; pick the one that communicates better
5. **Cut, don't shrink** — Rather than making unreadable tiny widgets, remove the lowest-priority widget entirely

**If the data is too rich for 6 rows / 12 widgets:** Tell the user what was included vs omitted, and suggest they request a second dashboard for the remaining data or provide an `svg-widgets.yaml` manifest for full control.

### Creative Freedom (Freeform)

In freeform mode, you have latitude to:
- Decide which widget types best represent the data
- Choose how many rows and how to arrange widgets (within the limits above)
- Add contextual annotations on charts (peak markers, threshold lines)
- Combine multiple data points into composite widgets
- Adjust canvas dimensions to fit the content (up to 1400×1200 max)

You are still bound by the **Quality Standards** and **Color & Typography** rules below — these ensure visual consistency regardless of mode.

---

## Rendering Rules (Both Modes)

### Canvas & Layout

- Output a single `<svg>` element with `xmlns="http://www.w3.org/2000/svg"` and the `width`/`height` from the manifest (or chosen dimensions in freeform mode).
- Fill the background with `canvas.background` (manifest) or `#1b1a19` (freeform default).
- Apply `canvas.padding` (manifest) or `40px` (freeform default) on all sides. Usable width = `width - 2 * padding`.
- Render rows top-to-bottom with `canvas.row_gap` (manifest) or `24px` (freeform default) spacing between rows.
- Within each row, widgets are laid out left-to-right. If a widget specifies `width_pct`, it gets that percentage of usable width. Otherwise, widgets share remaining space equally.
- Use `canvas.col_gap` (manifest) or `20px` (freeform default) for spacing between widgets in the same row.

### Color & Typography

- Use `palette.*` values from the manifest. In freeform mode, use the default palette below.
- **🔴 GLOBAL TEXT FILL RULE:** SVG defaults `fill` to black — which is invisible on dark backgrounds. **Every `<text>` element MUST have an explicit `fill` attribute.** Set `fill="{palette.text_primary}"` on the root `<svg>` or a top-level `<g>` so all text inherits white by default. Never rely on SVG's implicit black fill.
- All text uses `canvas.font_family` (manifest) or `Segoe UI, sans-serif` (freeform default).
- KPI values: **bold, 28-36px**, colored with `palette.primary` or widget's `highlight_color`.
- KPI labels: 11-12px, `palette.text_secondary`.
- Widget titles: **bold, 14-16px**, `palette.text_primary`.
- Axis labels and table headers: 10-12px, `palette.text_secondary`.
- Data labels and value labels: 10-11px, `palette.text_primary`. **Never place value labels inside bars** — always position them after/outside the bar.
- The default palette uses a cool dark theme consistent across all skill manifests. Skills may override with their own `palette` in `svg-widgets.yaml`.

#### Default Palette (Freeform Mode)

```yaml
palette:
  background: "#0d1117"
  card_bg: "#161b22"
  primary: "#409AE1"       # Blue — KPI highlights
  secondary: "#b4a0ff"     # Purple — secondary charts
  success: "#40C5AF"       # Teal-green — healthy metrics
  warning: "#ff8c00"       # Orange — moderate risk
  danger: "#EF6950"        # Red — critical findings
  text_primary: "#e6edf3"
  text_secondary: "#b2b2b2"
  accent: "#FFC83D"        # Yellow — warnings, anomalies
  grid_line: "#30363d"
```

### Widget Type Reference — Component Library

#### `title-banner`
Full-width banner. Render the title large and **centered** horizontally on the canvas, subtitle fields centered below on the same line separated by `" · "`. Optional accent underline. Use `text-anchor="middle"` with x at canvas midpoint. If the manifest specifies `title_align: left`, left-align instead — but the default is always **center**.

#### `kpi-card`
Rounded rectangle (`rx="12"`). Show the value large and centered, label below in small text, optional unit suffix. Color the value with `highlight_color` if specified, otherwise `palette.primary`. No actual icon rendering needed — use a colored dot or small indicator instead.

#### `delta-kpi-card`
Extends `kpi-card` with a period-over-period change indicator. Render the primary value the same as `kpi-card`. Below (or beside) the value, show a delta line: an arrow (▲ or ▼) followed by the percentage or absolute change. Color the delta with `palette.success` for favorable changes and `palette.danger` for unfavorable changes. If `invert_color` is true, reverse the color logic (e.g., for metrics where "down" is good, like error rate). Show the comparison period label in `palette.text_secondary` at 10px (e.g., "vs prior 7d"). If no delta data is available, render as a standard `kpi-card` with no delta line.

#### `score-card`
Rounded rectangle card (`rx="12"`) with `card_bg` background. Render the numeric score value large and centered (**bold, 42-48px**), colored by whichever range it falls into (from the widget's `ranges` array). Below the number, show the rating label (e.g., "CONCERNING") in **14px bold**, same color as the number. Above both, render the widget title in **14-16px bold**, `palette.text_primary`. Add a subtle `/100` suffix after the score in smaller muted text (18px, `palette.text_secondary`). Keep it visually clean — no gauge arcs, needles, or scale markers.

#### `stacked-bar-chart`
Vertical or horizontal bars where each bar is subdivided into colored segments representing categories (e.g., severity levels, sources, status). Include a legend mapping segment colors to category names. If `orientation: horizontal`, render left-to-right stacked rows with labels on the left. If `orientation: vertical` (default), render bottom-to-top stacked columns with labels on the x-axis. Show segment values on hover via `<title>` elements. If `show_totals` is true, display the total above each bar. Use `segment_colors` from the manifest or assign from palette automatically.

#### `horizontal-bar-chart`
Horizontal bars sorted by value descending. Layout per row (left to right): **label** → optional inline badges → **bar** (proportional to max value) → **value label** → optional **extra column** (rightmost). **Value labels MUST be positioned outside (after) the bar**, never inside it — use `fill="{palette.text_primary}"` (white on dark themes). Append `value_suffix` if specified. If `show_rule_count: right`, render the rule count as the rightmost column, right-aligned. If a value is 0, render it in `palette.danger`. If `show_tier_badge` is true, render a small colored badge after each label using colors from the YAML `segments` or `badge_colors` definitions. If `bar_color_by: severity` is set, color bars by severity level. If `show_error_overlay` is true, render a red overlay segment proportional to failure count. If `highlight_sensitive` is true, mark flagged items with a warning indicator.

#### `line-chart`
SVG `<polyline>` or `<path>` for the trend line with optional area fill (`fill_opacity`). X-axis = dates, Y-axis = values. Render annotations as labeled markers: peak (triangle up), low (triangle down), average (dashed horizontal line). Grid lines at sensible intervals. If `show_weekday_pattern` is true, add subtle mini-bars along the bottom showing day-of-week averages.

#### `donut-chart`
Render using SVG `<circle>` elements with `stroke-dasharray`/`stroke-dashoffset`. **Use this exact formula — do not iterate or try alternative approaches:**

```
circumference = 2 * π * radius    (e.g., radius=70 → C ≈ 439.82)

For each segment i (ordered by value descending):
  arc_len_i    = (value_i / total) * circumference
  start_i      = sum of all previous arc_lens (0 for first segment)
  dasharray    = "arc_len_i, (circumference - arc_len_i)"
  dashoffset   = circumference - start_i
  transform    = "rotate(-90, cx, cy)"     ← starts at 12 o'clock
```

Each segment is a `<circle cx cy r>` with `fill="none"`, `stroke="{segment_color}"`, `stroke-width="20"`. Stack all circles at the same position — the dasharray/dashoffset combination makes each one draw only its arc portion. Add `<title>` tooltips.

Legend to the right or below. If `show_center_total` is true, display the total count in the donut center. If `compact` is true, reduce the donut radius and legend font size to fit alongside a stacked widget below.

#### `waterfall-chart`
Stacked/cascading vertical bars: each segment starts where the previous ended. Negative segments (benefits) flow downward. Show values on each bar. Final bar shows net total.

#### `progress-bar`
Horizontal bar showing completion percentage against a target. Render a rounded track (`rx="6"`) in `palette.grid_line` (or `card_bg`), filled proportionally with `palette.primary` (or `bar_color` if specified). Show the percentage value (**bold, 18-22px**) to the right of the bar or centered inside the filled portion. Label text above or to the left in `palette.text_primary` at 12-14px. If `target_label` is provided, show it at the 100% mark in `palette.text_secondary`. If `thresholds` are defined (e.g., `[{"at": 90, "color": "success"}, {"at": 50, "color": "warning"}, {"at": 0, "color": "danger"}]`), color the fill bar according to which threshold the value meets. If `show_remaining` is true, display the remaining percentage in muted text after the bar.

#### `sparkline`
Miniature trend line — a compact `<polyline>` rendered inline within a `kpi-card`, `delta-kpi-card`, or `table-widget` cell. Dimensions: typically 60-100px wide × 16-24px tall. No axes, labels, or grid lines — just the trend shape. Stroke width 1.5-2px in `palette.primary` (or `line_color` if specified). Optional: fill the area below with the same color at 10-15% opacity. If `show_endpoints` is true, render small circles (r=2) at the first and last data points. If the last value is higher than the first, color the line `palette.success`; if lower, `palette.danger`; if `auto_color: false`, use the specified `line_color` instead.

#### `table-widget`
Rows of data with alternating row backgrounds (`card_bg` and slightly lighter). Column headers in `text_secondary`. If `color_scale` is true for a column, color positive values red and negative green (or vice versa for cost savings). If `badge` is true, render small severity badges. If `highlight_zero` is true for a column, render zero values in `palette.danger` color. If `summary_row` is specified, add a totals/summary row at the bottom with a top border separator. If `stack_below` is specified, this widget shares the same column as the named widget above it — render it directly below that widget rather than side-by-side.

#### `recommendation-cards`
Side-by-side rounded cards. Left border colored by priority (`card_colors`). Title bold, description in `text_secondary`. If `show_impact_estimate`, add a small impact line.

#### `assessment-banner`
Large panel with a colored left border. Title + main assessment text. Sub-fields rendered as bullet lists (key_risks in `palette.danger`, strengths in `palette.success`).

#### `coverage-matrix`
Compact grid visualization for displaying coverage status across a two-dimensional framework (e.g., MITRE ATT&CK tactics × techniques, permission matrices, data readiness grids). Renders as a grid of small colored `<rect>` cells organized into columns, where each column represents a category (e.g., tactic) and each cell represents an item (e.g., technique) within that category.

**Layout:** Columns are arranged left-to-right. Each column has a **rotated header label** at the top (45° angle, 10-11px text) and a vertical stack of cells below. Columns are variable-height — each has as many cells as items in that category. A **legend** bar is rendered below the grid mapping colors to status labels.

**Cell rendering:** Each cell is a small `<rect>` (default `cell_size: 12` × 12px, `cell_gap: 2`px between cells). Cells are colored according to their `status` field using the `status_colors` map from the manifest. Cells within each column are **sorted by status priority** (covered items at top, uncovered at bottom) to create a visible "waterline" effect. Each cell has a `<title>` element containing the item name and status for hover tooltips — this is essential since cell text is not rendered at this scale.

**Column rendering:** Each column is `cell_size + cell_gap` wide. Columns are separated by `col_gap` (default 6px). Column header text is right-rotated and positioned above the first cell. An optional **column footer** shows the count or percentage (e.g., "5/11" or "45%") in 9px text below the last cell.

**Legend:** Horizontal bar below the grid with colored squares and labels for each status. Rendered in a single row, 10px text, using the `status_colors` map.

**Manifest fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `field` | ✅ | Data source — array of `{column, items: [{name, status}]}` objects |
| `status_colors` | ✅ | Map of status label → hex color (e.g., `custom_rule: "#409AE1"`, `tier_1: "#40C5AF"`, `uncovered: "#21262d"`) |
| `cell_size` | ❌ | Cell width and height in px (default: 12) |
| `cell_gap` | ❌ | Gap between cells in px (default: 2) |
| `col_gap` | ❌ | Gap between columns in px (default: 6) |
| `show_col_footer` | ❌ | Show count/percentage below each column (default: true) |
| `sort_order` | ❌ | Array of status labels defining top-to-bottom cell sort order (covered statuses first) |
| `max_rows` | ❌ | Cap the tallest column at this many cells; excess items are collapsed into a single "+" cell with count in tooltip |

**Token budget:** This widget is compact by design — 250 cells ≈ 250 `<rect>` elements (~15KB SVG). No text per cell keeps it efficient. The primary token cost is the `<title>` tooltip content. For grids exceeding 300 items, set `max_rows` to cap column height and keep SVG size manageable.

**Example use cases:** MITRE ATT&CK tactic × technique coverage map, data source × table readiness grid, permission scope × application access matrix, compliance framework × control status.

### Quality Standards

- All text must be legible — minimum 10px font size.
- Maintain consistent rounded corners (`rx="8"` to `rx="12"`) on all cards and panels.
- Use `<title>` elements on interactive-looking elements for accessibility.
- Encode any special characters in text (`&amp;`, `&lt;`, etc.).
- The SVG must be fully self-contained — no external stylesheets, fonts, or images.
- Add a `<!-- Generated by Copilot SVG Dashboard Generator -->` comment at the top.

### Output

- **Manifest mode:** Save to the same directory as the report, with filename pattern: `{report_basename}_dashboard.svg`
- **Freeform mode:** Save to `temp/{descriptive_name}_dashboard.svg` or a user-specified path
