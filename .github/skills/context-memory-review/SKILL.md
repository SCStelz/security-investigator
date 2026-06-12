---
name: context-memory-review
description: "Weekly review of an investigation tenant-context memory file against the most recent SOC scan reports (e.g. Threat Pulse). Surfaces candidate ADD / MODIFY / FLAG changes to the context file as a propose-only review document for human approval — it NEVER edits the context file, commits, or opens a PR. Trigger on 'review my context file', 'review tenant context', 'propose context updates', 'what should I add to my context memory'."
---

# Context Memory Review — Instructions

## Purpose

Investigation workflows in this project lean on a **tenant-context memory file** — a local, gitignored
living document that records environment-specific ground truth (known automation/orchestration
fingerprints, known-good IPs, account classifications, honeypot/field-device inventory, validated
personnel, and documented false-positive rules). Scan automations (e.g. the daily Threat Pulse) read
that file to render accurate verdicts.

Over a week of scans, drill-down investigations validate **new** ground truth — new IPs, new personas,
new FP classes, new device classes — that is not yet captured in the context file. This skill reads the
last *N* days of scan reports, compares them against the current context file, and produces a
**propose-only review document**: a list of discrete, human-reviewable candidate changes (ADD / MODIFY /
FLAG) with section anchors, proposed text, supporting evidence, recurrence counts, and confidence.

**This skill is the first half of a deliberate two-phase, human-in-the-loop workflow:**

| Phase | Who | Action |
|-------|-----|--------|
| 1. Propose (this skill) | Automation / interactive | Read reports + context file → emit review doc. **No edits.** |
| 2. Apply (separate, manual) | Human-directed interactive session | Operator reviews the doc, says "apply items X, Y, Z" → surgical edits to the context file. |

---

## 🔴 CRITICAL RULES — READ FIRST

1. **PROPOSE-ONLY. NEVER edit the context file in this skill.** Do not write, append to, or modify the
   context memory file. Do not `git commit`, push, or open a PR. The only file this skill writes is the
   review document in the output directory.

2. **Read-only against the tenant.** If any live queries are needed to corroborate a candidate change,
   they MUST be read-only (per the Remediation Output Policy). Prefer evidence already present in the
   reports — only query the tenant to disambiguate a contradiction.

3. **⛔ Feedback-loop guard (the single most important rule).** Scan reports are partly *downstream* of
   the context file: a scan verdict may simply **echo** an existing context entry rather than
   independently confirm it. You MUST distinguish:
   - **First-party validation** — a drill-down in the report actually ran a query/enrichment and
     confirmed the fact (e.g. "enriched IP 203.0.113.10 → datacenter ASN, 0 abuse reports, recurred on
     3 days"). This CAN drive a High-confidence proposal.
   - **Context-derived echo** — the report verdict only restated something the context file already
     said ("🟢 known orchestration IP per tenant context"). This must NOT be promoted into a new or
     strengthened entry. Promoting echoes entrenches errors. When unsure, classify as echo.

4. **Never propose weakening or removing a documented FP/safety guardrail** based solely on its absence
   from the week's reports. Absence of a finding ≠ obsolescence of a guardrail. Staleness candidates are
   FLAG-only, Low confidence, for human judgment — never auto-REMOVE.

5. **Evidence-based only.** Every proposed change cites the specific report file(s), date(s), and
   finding it derives from. Never invent entities, counts, IPs, UPNs, or dates. If the reports don't
   support a change, don't propose it.

6. **PII stays local.** The review document will contain live tenant entities (IPs, UPNs, device names).
   Write it ONLY to the gitignored output directory. Never commit it, never include it in a PR, never
   paste tenant PII into any git artifact.

---

## Inputs (supplied by the invoking prompt / workflow)

The invoking workflow or user supplies these. If invoked interactively without them, ask once, then
proceed with the defaults shown.

| Input | Meaning | Default |
|-------|---------|---------|
| `context_file` | Absolute path to the tenant-context memory file to review | (must be provided) |
| `reports_dir` | Directory (or glob) holding the scan reports to review | (must be provided) |
| `reports_glob` | Filename pattern for the reports of interest | `*.md` |
| `lookback_days` | How far back to include reports (by filename date or mtime) | `7` |
| `output_dir` | Where to write the review document (must be gitignored) | `reports/context-reviews` |

---

## Execution Workflow

### Phase 0 — Load inputs and current state

1. **Read the context file in full** (`context_file`). Build an internal index of its structure: every
   section heading (the anchor targets for proposals), and within sections the discrete entries — table
   rows (e.g. IP tables), bullet points, labelled sub-notes (e.g. "A.2", "Section C"), device entries.
   Note any `validated YYYY-MM-DD` provenance stamps.
2. **Enumerate the reports in window.** List files in `reports_dir` matching `reports_glob`, select those
   whose date (from filename `YYYYMMDD` if present, else file mtime) falls within `lookback_days`. Sort
   oldest→newest. If zero reports are in window, STOP and report "no reports in window — nothing to
   review" (a normal quiet-week outcome, not a failure).
3. **Read each in-window report.** For large reports, read in ranges. Extract structured signal:
   - Concrete entities that appeared with a verdict: IPs, UPNs/accounts, device/host names, OAuth apps,
     incident IDs, CVEs.
   - For each: was the verdict reached by a **first-party drill-down** (a query/enrichment was executed
     in the report) or an **echo** of existing context? Capture the distinction — it gates confidence.
   - New FP classes / tuning notes the report's drill-downs articulated.
   - Any **contradiction**: a drill-down that concluded the opposite of an existing context entry.
   - Note in each report whether the context file was successfully loaded/applied during that scan (the
     reports state this) — echoes only count as echoes if context was actually applied.

### Phase 1 — Correlate across the week

Aggregate signal across all in-window reports:

1. **Recurrence** — For each candidate entity/pattern, count how many distinct report-days it appeared on
   with a consistent first-party classification. Recurrence is the backbone of confidence.
2. **Match against the context file index** — For each candidate, determine whether it is:
   - **Absent** from the context file → ADD candidate.
   - **Present but refined** by the reports (role/volume/scope changed, new regional sibling, expanded
     persona list) → MODIFY candidate.
   - **Present and merely echoed** (no new first-party info) → NOT a candidate (drop it; feedback-loop
     guard). It may at most justify refreshing a `validated` date if a first-party drill-down re-confirmed
     it — and that is a Low/Medium MODIFY, clearly labelled "provenance refresh only".
   - **Contradicted** by a first-party drill-down → FLAG candidate (never auto-resolve).
3. **Staleness sweep (FLAG-only)** — Identify context entries that were NOT referenced by ANY in-window
   report. These are *candidates for human review*, not removal. Low confidence. Exclude documented
   safety/FP guardrails from staleness flags entirely (their value is in preventing future errors, not
   in weekly hit-rate).

### Phase 2 — Score and assemble proposals

Assign each candidate a **type** and **confidence**:

| Type | When |
|------|------|
| **ADD** | New, first-party-validated fact absent from the context file. |
| **MODIFY** | Existing entry that a first-party drill-down refined/expanded, or a provenance-refresh. |
| **FLAG** | A contradiction needing human judgment, or a staleness candidate. Never an auto-edit. |

| Confidence | Criteria |
|------------|----------|
| **High** | First-party validated AND recurred on ≥3 report-days (or a single explicit, thorough validated drill-down with enrichment/queries). Consistent classification, no contradicting evidence. |
| **Medium** | First-party validated on 2 report-days, OR 1 strong drill-down without recurrence. |
| **Low** | Single weak signal, provenance-refresh only, or any FLAG/staleness candidate. |

For every proposal, produce:
- **ID** — sequential (`P1`, `P2`, …).
- **Type** + **Confidence**.
- **Target section** — the exact heading/anchor in the context file where it belongs (for ADD), or the
  exact existing entry text being changed (for MODIFY/FLAG).
- **Proposed text** — for ADD/MODIFY, the literal line/table-row/bullet to insert or the
  before→after change, written in the context file's existing style and including a
  `(validated <today's date>)` stamp where the file uses that convention.
- **Rationale** — one or two sentences.
- **Evidence** — the report file name(s) + date(s) + the specific finding, and an explicit note of
  whether it was first-party or echo (only first-party drives ADD/MODIFY).
- **Recurrence** — "appeared on N of M report-days".
- **Apply instruction** — precise enough for a later interactive session to make a surgical edit (which
  section, insert-after-which-line, exact text). For FLAG items, the question the human must answer.

### Phase 3 — Write the review document

Write the document to `output_dir` (create the folder if needed) as:
`<output_dir>/context-review_<YYYYMMDD>_<HHMMSS>.md`

Use this structure:

```markdown
# Context Memory Review — <today's date>

**Context file reviewed:** <context_file>
**Reports reviewed:** <N> file(s) over <lookback_days>d (<earliest date> → <latest date>)
**Proposed changes:** <A> ADD · <M> MODIFY · <F> FLAG
**Confidence mix:** <High count> High · <Medium count> Medium · <Low count> Low

> ⚠️ PROPOSE-ONLY. No changes have been made to the context file. To apply, open an interactive
> session and say e.g. "apply items P1, P3, P7" — those edits will be made surgically with a
> validated-date stamp. Review each item's evidence before approving.

## Reports in this review window
| Date | File | Context applied during scan? |
|------|------|------------------------------|
| ... | ... | yes / no |

## Proposed changes

### P1 — [ADD · High] <short title>
- **Target section:** <heading/anchor>
- **Proposed text:**
  > <literal text to add, in file style, with (validated <date>)>
- **Rationale:** ...
- **Evidence:** <report file(s) + date(s) + finding>; first-party drill-down.
- **Recurrence:** appeared on N of M report-days.
- **Apply instruction:** Insert under "<section>" after "<anchor line>".

### P2 — [MODIFY · Medium] ...
...

### P3 — [FLAG · Low] <contradiction or staleness> ...
- **Question for human:** ...

## Items considered but NOT proposed (feedback-loop guard)
Brief list of candidate signals that were only context-echoes (already in the file, no new first-party
evidence) and were therefore intentionally dropped — so the reviewer can confirm nothing was missed.

## Summary
One paragraph: the week's theme, the highest-value proposed addition, any contradiction needing
attention, and the count of staleness flags.
```

### Phase 4 — Report to chat

End your response with a concise summary: context file + report window reviewed, counts of ADD/MODIFY/FLAG
by confidence, the single highest-value proposed change, any contradictions surfaced, the output document
path, and a reminder that nothing was applied and how to apply (interactive "apply items …").

---

## Quality Checklist

Before finishing, verify:

- [ ] The context file was **not modified**; no commit/PR/push occurred.
- [ ] The review document was written **only** to the gitignored output directory.
- [ ] Every ADD/MODIFY proposal is backed by **first-party** evidence (not a context echo).
- [ ] No proposal weakens/removes a safety or FP guardrail on the basis of absence alone.
- [ ] Every proposal cites specific report file(s) + date(s) and a recurrence count.
- [ ] Contradictions are FLAG (human decides), never auto-resolved.
- [ ] Staleness candidates are FLAG · Low, and exclude documented guardrails.
- [ ] Proposed text matches the context file's existing style and includes a validated-date stamp where
      the file uses that convention.
- [ ] The "considered but not proposed" section documents the dropped echoes.

---

## Notes

- This skill is environment-agnostic. All tenant-specific values (which context file, which reports,
  output location) are supplied by the invoking workflow or user — keep this file free of any
  tenant-specific identifiers, hostnames, UPNs, or environment names.
- Apply is intentionally **out of scope** here. Keeping propose and apply as separate phases — with apply
  driven by an explicit human instruction — is the safety boundary that prevents an unattended run from
  silently rewriting the ground-truth the scans depend on.
