# Rare Parent–Child Process Chain Detection

**Created:** 2026-02-06  
**Platform:** Microsoft Sentinel  
**Tables:** DeviceProcessEvents  
**Keywords:** rare process, parent child, process chain, LOLBin, discovery, reconnaissance, threat hunting, Pareto, process tree, ipconfig, whoami, unusual execution  
**MITRE:** T1016, T1033, T1057, T1059, T1087, TA0007, TA0002  
**Timeframe:** Last 90 days (configurable)

---

## Overview

This collection contains KQL queries for **threat hunting rare parent–child process combinations** in Defender for Endpoint telemetry. Rare process chains — combinations seen fewer than 5 times in 90 days — are prime hunting ground for:

- **Discovery/recon commands** (T1016 `ipconfig`, T1033 `whoami`, T1087 `net user`)
- **LOLBin abuse** (unusual parents spawning system binaries)
- **Living-off-the-land techniques** (legitimate tools used for malicious purposes)
- **Process injection / hollowing** (unexpected parent–child relationships)

### Key Concepts

- **Pareto principle applies heavily:** ~5% of unique combos generate ~80% of process events. Attackers live in the long tail.
- **Singleton combos** (count = 1) are highest-priority hunting targets.
- **Version-based uniqueness** is expected for auto-update chains (e.g., `wuaucltcore.exe → AM_Delta_Patch_*.exe`) — these are benign but appear rare due to rotating version numbers.

### Known Benign Patterns in the Rare Tail

| Pattern | Explanation |
|---------|-------------|
| `wuauclt*.exe → AM_Delta_Patch_*.exe` | Defender signature delta updates — version rotates daily |
| `omadmclient.exe → ofdeploy.exe → odt*.tmp.exe` | Intune-managed Office Click-to-Run deployment |
| `shellappruntime.exe → packagedcwalauncher.exe → *` | UWP app initialization at user logon |
| Linux GNOME session chains (`dash → gnome-session-binary → ...`) | One-time desktop session startup |
| `python3.8 → wdavdaemonclient` | MDE health check on Linux |

---

## Query 1: Rare Parent–Child Combos with Context (< 5 in 90 days)

**Purpose:** Find parent–child process combinations seen fewer than 5 times in 90 days. Returns device, user, integrity level, command lines, and grandparent process for building ASCII process trees.

**Tuning Notes:**
- Adjust `| take 50` to control output size. The full rare tail can contain 1,000+ combos.
- Consider adding `| where not(ChildProcess startswith "AM_Delta_Patch")` to exclude Defender signature update noise.
- Sort by `Count asc, UniqueDevices asc` to surface the rarest combos first.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical hunting query — aggregates 90 days of DeviceProcessEvents into rare combos (Count < 5). Requires long-term baseline comparison that exceeds CD's 30-day max lookback. Designed for manual threat hunting review, not automated alerting."
-->

```kql
// Query 1: Rare Parent–Child Process Combos (< 5 occurrences in 90 days)
// Surfaces unusual execution chains for threat hunting
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| summarize 
    Count = count(),
    UniqueDevices = dcount(DeviceName),
    UniqueUsers = dcount(AccountName),
    SampleDevice = take_any(DeviceName),
    SampleUser = strcat(take_any(AccountDomain), "\\", take_any(AccountName)),
    SampleChildCmd = take_any(ProcessCommandLine),
    SampleParentCmd = take_any(InitiatingProcessCommandLine),
    ChildIntegrity = take_any(ProcessIntegrityLevel),
    ParentIntegrity = take_any(InitiatingProcessIntegrityLevel),
    GrandparentProcess = take_any(InitiatingProcessParentFileName),
    LastSeen = max(TimeGenerated)
    by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| where Count < 5
| order by Count asc, UniqueDevices asc
| take 50
```

**Columns Returned:**

| Column | Description |
|--------|-------------|
| `ParentProcess` | Initiating (parent) process file name |
| `ChildProcess` | Spawned (child) process file name |
| `Count` | Total occurrences in the time window |
| `UniqueDevices` | Number of distinct devices where this combo appeared |
| `UniqueUsers` | Number of distinct users associated with this combo |
| `SampleDevice` | Example device name |
| `SampleUser` | Example DOMAIN\user |
| `SampleChildCmd` | Example child command line |
| `SampleParentCmd` | Example parent command line |
| `ChildIntegrity` / `ParentIntegrity` | Process integrity level (System, High, Medium, Low) |
| `GrandparentProcess` | Grandparent process for building 3-level process trees |
| `LastSeen` | Most recent occurrence |

---

## Query 2: Pareto Distribution — Ranked Parent–Child Combos with Cumulative %

**Purpose:** Generate a ranked table of ALL parent–child combos by frequency with cumulative percentage for 80/20 (Pareto) analysis. Use this to understand the baseline distribution and identify the split point between "vital few" and "trivial many."

**Interpretation:**
- Top ~5% of combos typically cover ~80% of events (the baseline)
- Bottom ~50% of combos are rare (< 5 occurrences) — this is the hunting zone
- The cumulative % column shows exactly where the 80/20 split falls

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Pareto distribution analysis — ranks all parent–child combos by frequency with cumulative %. Pure analytical/statistical query for understanding baseline distribution, not suitable for alerting."
-->

```kql
// Query 2: Pareto Distribution — All combos ranked by frequency
// Shows cumulative % for 80/20 analysis
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| summarize Count = count() by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| order by Count desc
| extend CumulativeCount = row_cumsum(Count)
| extend TotalEvents = toscalar(DeviceProcessEvents | where TimeGenerated > ago(90d) | count)
| extend CumulativePct = round(100.0 * CumulativeCount / TotalEvents, 2)
| extend Pct = round(100.0 * Count / TotalEvents, 2)
| project Rank = row_number(), ParentProcess, ChildProcess, Count, Pct, CumulativePct
| take 100
```

---

## Query 3: Pareto Summary Statistics

**Purpose:** Quick overview of the distribution — total combos, rare combos, singletons, and the percentage of events they represent. Use this to assess whether the environment has an unusual number of rare process chains.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summary statistics query — produces a single aggregated row with distribution metrics (total combos, rare combos, singletons). Not suitable for per-event detection or alerting."
-->

```kql
// Query 3: Pareto Summary Statistics
// Quick 80/20 health check on parent–child process distribution
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| summarize Count = count() by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| summarize 
    TotalCombos = count(),
    RareCombos = countif(Count < 5),
    TotalEvents = sum(Count),
    RareEvents = sumif(Count, Count < 5),
    SingletonCombos = countif(Count == 1),
    SingletonEvents = sumif(Count, Count == 1),
    Top20PctThreshold = percentile(Count, 80)
| extend RareComboPct = round(100.0 * RareCombos / TotalCombos, 1),
         RareEventPct = round(100.0 * RareEvents / TotalEvents, 2),
         SingletonComboPct = round(100.0 * SingletonCombos / TotalCombos, 1)
```

**Expected Output:**

| Metric | Typical Range | Concern If |
|--------|---------------|------------|
| `RareComboPct` | 40–60% | >70% may indicate noisy or compromised endpoints |
| `RareEventPct` | 0.1–0.5% | >2% may indicate systematic anomalous activity |
| `SingletonComboPct` | 25–35% | Singletons are normal; investigate the *interesting* ones |

---

## Query 4: Find a Specific Parent–Child Combo's Rank

**Purpose:** Look up where a specific parent–child combo falls in the Pareto distribution. Useful when investigating a known-suspicious chain (e.g., `cmd.exe → ipconfig.exe`) to understand how rare it is relative to the baseline.

**Usage:** Replace `cmd.exe` and `ipconfig.exe` with the combo you want to look up.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Ad-hoc lookup query — finds a specific combo's rank in the Pareto distribution. Interactive investigation tool, not a detection pattern."
-->

```kql
// Query 4: Look up a specific combo's rank in the distribution
// Replace parent/child process names as needed
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| summarize Count = count() by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| order by Count desc
| extend Rank = row_number()
| where ParentProcess =~ "cmd.exe" and ChildProcess =~ "ipconfig.exe"
| project Rank, ParentProcess, ChildProcess, Count
```

---

## Query 5: Rare Recon/Discovery Combos (Security-Focused Filter)

**Purpose:** Filter specifically for rare parent–child combos involving known discovery/recon tools. These are the highest-priority threat hunting targets because attackers frequently use these built-in Windows utilities for reconnaissance (MITRE TA0007).

**Covered tools:** `ipconfig`, `whoami`, `net.exe`, `net1.exe`, `nltest`, `nslookup`, `systeminfo`, `tasklist`, `qwinsta`, `arp`, `route`, `netstat`, `query`

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical hunting query — aggregates 90 days of recon tool executions into rare combos (Count < 5). Core concept (recon tools with unusual parents) COULD become a detection if restructured with a hardcoded allow-list of known-good parent processes instead of statistical rarity threshold, but would require a complete rewrite."
-->

```kql
// Query 5: Rare combos involving known recon/discovery tools
// High-priority threat hunting — MITRE TA0007 (Discovery)
let reconTools = dynamic(["ipconfig.exe", "whoami.exe", "net.exe", "net1.exe", 
    "nltest.exe", "nslookup.exe", "systeminfo.exe", "tasklist.exe", 
    "qwinsta.exe", "arp.exe", "route.exe", "netstat.exe", "query.exe",
    "hostname.exe", "cmdkey.exe", "dsquery.exe"]);
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| where FileName in~ (reconTools)
| summarize 
    Count = count(),
    UniqueDevices = dcount(DeviceName),
    Devices = make_set(DeviceName, 5),
    Users = make_set(strcat(AccountDomain, "\\", AccountName), 5),
    CommandLines = make_set(ProcessCommandLine, 5),
    ParentCmds = make_set(InitiatingProcessCommandLine, 5),
    Grandparents = make_set(InitiatingProcessParentFileName, 5),
    IntegrityLevels = make_set(ProcessIntegrityLevel, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| where Count < 5
| order by Count asc, UniqueDevices asc
```

---

## Query 6: Rare Combos Excluding Known Benign Noise

**Purpose:** Same as Query 1 but pre-filters out known benign patterns that appear rare only due to rotating version numbers (Defender patches, ODT temp files). Reduces false positives for cleaner hunting.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Same as Query 1 with noise filtering — statistical hunting baseline requiring 90-day aggregate analysis. Not suitable for CD's scheduled execution model."
-->

```kql
// Query 6: Rare combos with benign noise filtered out
// Excludes Defender delta patches, ODT temp files, and Linux desktop session chains
DeviceProcessEvents
| where TimeGenerated > ago(90d)
| where not(FileName startswith "AM_Delta_Patch")
| where not(FileName matches regex @"^odt[0-9A-Fa-f]+\.tmp\.exe$")
| where not(InitiatingProcessFileName in~ ("gnome-session-binary", "gnome-session-check-accelerated", 
    "ibus-daemon", "at-spi-bus-launcher"))
| summarize 
    Count = count(),
    UniqueDevices = dcount(DeviceName),
    UniqueUsers = dcount(AccountName),
    SampleDevice = take_any(DeviceName),
    SampleUser = strcat(take_any(AccountDomain), "\\", take_any(AccountName)),
    SampleChildCmd = take_any(ProcessCommandLine),
    SampleParentCmd = take_any(InitiatingProcessCommandLine),
    ChildIntegrity = take_any(ProcessIntegrityLevel),
    GrandparentProcess = take_any(InitiatingProcessParentFileName),
    LastSeen = max(TimeGenerated)
    by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| where Count < 5
| order by Count asc, UniqueDevices asc
| take 50
```

---

## Usage Notes

### Building Process Trees from Results

Use the `GrandparentProcess`, `ParentProcess`, and `ChildProcess` columns to construct 3-level ASCII trees:

```
GrandparentProcess
└─ ParentProcess        [SampleParentCmd]
   └─ ChildProcess      [SampleChildCmd]
```

### Risk Prioritization

When reviewing rare combos, prioritize by:

1. **Recon tools with unusual parents** (Query 5) — highest priority
2. **Singletons on servers** — more suspicious than workstations
3. **System/High integrity** spawning user tools — potential privilege abuse
4. **Multi-device singletons** — shouldn't happen; investigate immediately
5. **Interactive cmd.exe or powershell.exe** spawning discovery commands — classic attacker pattern

### Time Window Tuning

| Window | Use Case |
|--------|----------|
| 90 days | Standard baseline — recommended for initial assessment |
| 30 days | Focused recent activity — faster query, less noise |
| 7 days | Active incident investigation — real-time hunting |
| 180 days | Extended baseline for environments with infrequent admin activity |
