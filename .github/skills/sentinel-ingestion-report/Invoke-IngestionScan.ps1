#Requires -Version 7.0
<#
.SYNOPSIS
    Sentinel Ingestion Report — YAML-driven data gathering.

.DESCRIPTION
    Reads KQL query definitions from YAML files in the queries/ folder,
    executes them via 'az monitor log-analytics query' (free, uses existing
    Azure CLI auth), and writes a scratchpad file for report rendering.

    Two modes of operation:
      1. Skill mode: Called from the sentinel-ingestion-report skill workflow.
         Reads config.json automatically from the workspace root.
      2. Standalone mode: Run directly by passing parameters or answering
         interactive prompts. No config.json required.

    Architecture: YAML query files → PowerShell execution via az monitor
    → scratchpad.md → LLM (or human) reads scratchpad and renders report.

.PARAMETER ConfigPath
    Path to config.json. Default: auto-detected from workspace root.
    Not required in standalone mode if -WorkspaceId is provided.

.PARAMETER Phase
    Phase number to execute (0 = all phases, 1-5 = specific phase). Default: 0.

.PARAMETER OutputDir
    Directory for scratchpad output. Default: temp/ in workspace root,
    or ./output/ in standalone mode.

.PARAMETER WorkspaceId
    Sentinel Log Analytics workspace GUID. Overrides config.json value.
    If neither config.json nor this parameter is provided, you will be
    prompted interactively.

.PARAMETER SubscriptionId
    Azure subscription ID. Required for Phase 3 (REST API / tier queries).
    Overrides config.json value.

.PARAMETER ResourceGroup
    Resource group containing the Log Analytics workspace.
    Required for Phase 3 (tier classification). Overrides config.json value.

.PARAMETER WorkspaceName
    Log Analytics workspace display name (not GUID).
    Required for Phase 3 (tier classification). Overrides config.json value.

.EXAMPLE
    # Skill mode — from workspace root (reads config.json automatically):
    & ".github/skills/sentinel-ingestion-report/Invoke-IngestionScan.ps1"

.EXAMPLE
    # Standalone — pass key parameters directly (Phases 1-2 only need WorkspaceId):
    .\Invoke-IngestionScan.ps1 -WorkspaceId "12345678-abcd-1234-abcd-123456789abc"

.EXAMPLE
    # Standalone — all phases with full parameters:
    .\Invoke-IngestionScan.ps1 -WorkspaceId "12345678-abcd-1234-abcd-123456789abc" `
        -SubscriptionId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -ResourceGroup "rg-sentinel" `
        -WorkspaceName "la-sentinel-prod"

.EXAMPLE
    # Standalone — interactive mode (prompts for everything):
    .\Invoke-IngestionScan.ps1

.EXAMPLE
    # Run only Phase 1 (usage summary):
    .\Invoke-IngestionScan.ps1 -WorkspaceId "..." -Phase 1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [ValidateSet(0, 1, 2, 3, 4, 5)]
    [int]$Phase = 0,
    [string]$OutputDir,

    # Standalone parameters — override config.json values
    [Alias('Workspace')]
    [string]$WorkspaceId,
    [Alias('Subscription')]
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$WorkspaceName,

    # Synthetic data mode — load pre-built JSON files instead of querying Azure
    [Alias('Synthetic')]
    [string]$SyntheticDataDir,

    # Export query results to JSON files for later replay via -SyntheticDataDir
    [Alias('Export')]
    [string]$ExportDataDir,

    # Reporting window in days (1, 7, 30, 60, 90)
    [ValidateSet(1, 7, 30, 60, 90)]
    [int]$Days = 30
)
# Phase 0 = run all phases sequentially

$ErrorActionPreference = 'Stop'

#region ═══ Derived Date Windows ══════════════════════════════════════════════
$deepDiveDays = switch ($Days) {
    { $_ -le 7 }  { $Days; break }
    { $_ -le 30 } { 7;     break }
    { $_ -le 60 } { 14;    break }
    default        { 30 }
}
$wowTotalDays = $deepDiveDays * 2

# Labels for period-over-period comparison
$thisPeriodLabel = switch ($deepDiveDays) {
    7       { "This Week" }
    30      { "This Month" }
    default { "This Period" }
}
$lastPeriodLabel = switch ($deepDiveDays) {
    7       { "Last Week" }
    30      { "Last Month" }
    default { "Last Period" }
}
$wowChangeLabel = switch ($deepDiveDays) {
    7       { "WoW Change" }
    30      { "MoM Change" }
    default { "PoP Change" }
}
#endregion

#region ═══ Path Resolution ═══════════════════════════════════════════════════
$ScriptDir = $PSScriptRoot

# Walk up from script location to find workspace root (contains config.json)
$WorkspaceRoot = $ScriptDir
$configFound = $false
for ($i = 0; $i -lt 6; $i++) {
    if (Test-Path (Join-Path $WorkspaceRoot "config.json")) { $configFound = $true; break }
    $WorkspaceRoot = Split-Path $WorkspaceRoot -Parent
}

# Determine if we're in standalone mode (no config.json found AND no explicit -ConfigPath)
$standaloneMode = (-not $configFound) -and (-not $ConfigPath)
if ($standaloneMode) {
    # In standalone mode, default output to ./output relative to script location
    if (-not $OutputDir) { $OutputDir = Join-Path $ScriptDir "output" }
} else {
    if (-not $ConfigPath) { $ConfigPath = Join-Path $WorkspaceRoot "config.json" }
    if (-not $OutputDir)  { $OutputDir  = Join-Path $WorkspaceRoot "temp" }
}

$QueryDir = Join-Path $ScriptDir "queries"

# Validate query files exist (critical for both modes)
if (-not (Test-Path $QueryDir)) {
    Write-Host ""
    Write-Error @"
Query directory not found: $QueryDir

The 'queries/' folder (with phase1-5 subfolders) must be in the same directory as this script.
If you downloaded only the .ps1 file, you also need the queries/ folder.

Expected structure:
  Invoke-IngestionScan.ps1
  queries/
    phase1/   (Q1, Q2, Q3 YAML files)
    phase2/   (Q4-Q8 YAML files)
    phase3/   (Q9, Q9b, Q10, Q10b YAML files)
    phase4/   (Q11, Q11d, Q12, Q13 YAML files)
    phase5/   (Q14-Q17b YAML files)
"@
    return
}
#endregion

#region ═══ Banner ════════════════════════════════════════════════════════════
Write-Host ""
$phaseLabel = if ($Phase -eq 0) { "All Phases" } else { "Phase $Phase" }
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Sentinel Ingestion Report v2 — $phaseLabel Data Gathering" -ForegroundColor Cyan
Write-Host "  Engine: az monitor log-analytics query (free)" -ForegroundColor DarkCyan
Write-Host "  Window: ${Days}d primary, ${deepDiveDays}d deep-dive, ${wowTotalDays}d comparison" -ForegroundColor DarkCyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
#endregion

# Safe double parser: KQL may return "None"/null/empty for numeric fields
function ConvertTo-SafeDouble($val) {
    if ($null -eq $val -or $val -eq '' -or $val -eq 'None') { return 0.0 }
    return [double]$val
}

#region ═══ Synthetic Data Mode ════════════════════════════════════════════════
if ($SyntheticDataDir) {
    # Load pre-built JSON query results instead of querying Azure.
    # This enables deterministic testing, demos, and regression runs.
    if (-not (Test-Path $SyntheticDataDir)) {
        Write-Error "Synthetic data directory not found: $SyntheticDataDir"
        return
    }
    $metaPath = Join-Path $SyntheticDataDir "meta.json"
    if (-not (Test-Path $metaPath)) {
        Write-Error "meta.json not found in $SyntheticDataDir. Required for workspace metadata."
        return
    }

    Write-Host "🧪 SYNTHETIC MODE — loading pre-built query data" -ForegroundColor Magenta
    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    $workspaceId   = $meta.workspace_id
    $workspaceName = $meta.workspace_name
    $phasesToRun   = @(1, 2, 3, 4, 5)
    $allResults    = @{}
    $allQueries    = @{}

    # Load all ingestion-q*.json files
    $jsonFiles = Get-ChildItem $SyntheticDataDir -Filter "ingestion-q*.json" | Sort-Object Name
    foreach ($jf in $jsonFiles) {
        $qId = $jf.BaseName   # e.g. "ingestion-q1", "ingestion-q17b"
        $data = Get-Content $jf.FullName -Raw | ConvertFrom-Json
        $allResults[$qId] = $data
        $allQueries[$qId] = @{ id = $qId; name = $qId; type = "synthetic" }
    }
    $totalQueryTime = 0

    Write-Host "   ✅ Loaded $($jsonFiles.Count) query results from $SyntheticDataDir" -ForegroundColor Green
    Write-Host "   ✅ Workspace: $workspaceName ($workspaceId)" -ForegroundColor Green
    if (-not $OutputDir) { $OutputDir = Join-Path $WorkspaceRoot "temp" }
} else {
#endregion synthetic
#region ═══ Prerequisites ═════════════════════════════════════════════════════
# Check Azure CLI
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI (az) not found. Install from https://aka.ms/installazurecli"
    return
}

# Verify az login
$azAccount = az account show -o json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Not logged in to Azure CLI. Run: az login --tenant <tenant_id>"
    return
}
$accountInfo = $azAccount | ConvertFrom-Json
Write-Host "✅ Azure CLI authenticated — Tenant: $($accountInfo.tenantId)" -ForegroundColor Green

# ─── Config Resolution: CLI params > config.json > interactive prompt ────────
# Initialize variables from config.json if available
$config = $null
if (-not $standaloneMode -and (Test-Path $ConfigPath)) {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    Write-Host "✅ Config loaded — $ConfigPath" -ForegroundColor Green
}

# Resolve workspaceId: CLI param > config > prompt
$workspaceId = if ($WorkspaceId) { $WorkspaceId }
               elseif ($config -and $config.sentinel_workspace_id) { $config.sentinel_workspace_id }
               else { $null }
if (-not $workspaceId) {
    Write-Host ""
    Write-Host "  No Sentinel workspace ID found (no config.json or -WorkspaceId parameter)." -ForegroundColor Yellow
    Write-Host "  This is the Log Analytics workspace GUID (found in Azure Portal → Log Analytics → Properties)." -ForegroundColor DarkGray
    Write-Host ""
    $workspaceId = Read-Host "  Enter Sentinel Workspace ID (GUID)"
    if (-not $workspaceId) {
        Write-Error "Workspace ID is required. Pass -WorkspaceId or create a config.json file."
        return
    }
}

# Resolve subscriptionId: CLI param > config > az account > prompt
$subscriptionId = if ($SubscriptionId) { $SubscriptionId }
                  elseif ($config -and $config.subscription_id) { $config.subscription_id }
                  elseif ($accountInfo.id) { $accountInfo.id }
                  else { $null }

# Resolve resourceGroup: CLI param > config
$resourceGroup = if ($ResourceGroup) { $ResourceGroup }
                 elseif ($config -and $config.azure_mcp -and $config.azure_mcp.resource_group) { $config.azure_mcp.resource_group }
                 else { $null }

# Resolve workspaceName: CLI param > config
$workspaceName = if ($WorkspaceName) { $WorkspaceName }
                 elseif ($config -and $config.azure_mcp -and $config.azure_mcp.workspace_name) { $config.azure_mcp.workspace_name }
                 else { $null }

# Phase 3 requires subscriptionId, resourceGroup, and workspaceName for REST/CLI queries.
# If any are missing, prompt only if Phase 3 is in scope.
$needsPhase3 = ($Phase -eq 0) -or ($Phase -eq 3)
if ($needsPhase3) {
    if (-not $subscriptionId) {
        Write-Host ""
        Write-Host "  Phase 3 needs a subscription ID for REST API and tier classification queries." -ForegroundColor Yellow
        $subscriptionId = Read-Host "  Enter Azure Subscription ID (GUID, or press Enter to skip Phase 3 REST queries)"
    }
    if (-not $resourceGroup) {
        Write-Host ""
        Write-Host "  Phase 3 needs the resource group containing your Log Analytics workspace." -ForegroundColor Yellow
        $resourceGroup = Read-Host "  Enter Resource Group name (or press Enter to skip tier classification)"
    }
    if (-not $workspaceName) {
        Write-Host ""
        Write-Host "  Phase 3 needs the Log Analytics workspace display name (not GUID)." -ForegroundColor Yellow
        $workspaceName = Read-Host "  Enter Workspace Name (or press Enter to skip tier classification)"
    }
}

Write-Host "✅ Workspace: $workspaceId" -ForegroundColor Green
if ($subscriptionId) { Write-Host "✅ Subscription: $subscriptionId" -ForegroundColor Green }
if ($resourceGroup)  { Write-Host "✅ Resource Group: $resourceGroup" -ForegroundColor Green }
if ($workspaceName)  { Write-Host "✅ Workspace Name: $workspaceName" -ForegroundColor Green }
#endregion

#region ═══ YAML Parser ═══════════════════════════════════════════════════════
# Lightweight YAML parser for our constrained schema (flat keys + one multiline block).
# No external module dependency (no powershell-yaml needed).
function Import-QueryYaml {
    param([string]$Path)

    $result = @{}
    $lines = Get-Content $Path
    $currentKey = $null
    $multilineValue = [System.Text.StringBuilder]::new()

    foreach ($line in $lines) {
        # Skip comments and blank lines when not in a multiline block
        if ($null -eq $currentKey) {
            if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        }

        # If currently collecting a multiline block
        if ($null -ne $currentKey) {
            # Indented line = part of the block (2+ spaces)
            if ($line -match '^(\s{2,})(.*)$') {
                [void]$multilineValue.AppendLine($matches[2])
                continue
            }
            # Blank line inside block = preserve it
            if ([string]::IsNullOrWhiteSpace($line)) {
                [void]$multilineValue.AppendLine('')
                continue
            }
            # Non-indented, non-blank = end of multiline block
            $result[$currentKey] = $multilineValue.ToString().TrimEnd()
            $currentKey = $null
            [void]$multilineValue.Clear()
        }

        # key: | (start multiline block scalar)
        if ($line -match '^([a-zA-Z_]\w*):\s*\|\s*$') {
            $currentKey = $matches[1]
            [void]$multilineValue.Clear()
            continue
        }

        # key: value (single-line scalar)
        if ($line -match '^([a-zA-Z_]\w*):\s*(.+)$') {
            $result[$matches[1]] = $matches[2].Trim()
        }
    }

    # Flush last multiline block if file ends mid-block
    if ($null -ne $currentKey) {
        $result[$currentKey] = $multilineValue.ToString().TrimEnd()
    }

    return $result
}
#endregion

#region ═══ Query Execution ═══════════════════════════════════════════════════
function Invoke-KqlQuery {
    param(
        [string]$Query,
        [string]$WorkspaceId,
        [string]$Timespan = "P${Days}D"
    )

    # Collapse multiline KQL to single line (KQL is whitespace-tolerant for pipes)
    # This avoids shell escaping issues with multiline strings passed to az CLI
    $singleLine = ($Query -replace '\r?\n', ' ' -replace '\s+', ' ').Trim()

    $rawResult = az monitor log-analytics query `
        --workspace $WorkspaceId `
        --analytics-query $singleLine `
        --timespan $Timespan `
        -o json 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Query execution failed:`n$rawResult"
        return $null
    }

    try {
        return $rawResult | ConvertFrom-Json
    } catch {
        Write-Warning "Failed to parse query result as JSON:`n$rawResult"
        return $null
    }
}
#endregion

#region ═══ Load & Execute Phase Queries ══════════════════════════════════════
# Step 1: Discover and parse all query files across phases
$phasesToRun = if ($Phase -eq 0) { @(1, 2, 3, 4, 5) } else { @($Phase) }

$allResults = @{}     # key = query id, value = data
$allQueries = @{}     # key = query id, value = parsed YAML
$workQueue  = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($p in $phasesToRun) {
    $phaseDir = Join-Path $QueryDir "phase$p"
    if (-not (Test-Path $phaseDir)) {
        Write-Warning "Query directory not found: $phaseDir — skipping Phase $p"
        continue
    }

    $queryFiles = Get-ChildItem $phaseDir -Filter "*.yaml" | Sort-Object Name
    Write-Host "`n📂 Found $($queryFiles.Count) query files in phase${p}/:" -ForegroundColor Yellow
    $queryFiles | ForEach-Object { Write-Host "   → $($_.Name)" -ForegroundColor DarkGray }

    foreach ($file in $queryFiles) {
        $parsed = Import-QueryYaml -Path $file.FullName
        $qId = $parsed["id"]
        if (-not $qId) {
            Write-Warning "Skipping $($file.Name) — missing 'id' field"
            continue
        }
        $allQueries[$qId] = $parsed

        if ($parsed["type"] -eq "kql" -and -not $parsed["depends_on"]) {
            $rawQuery = $parsed["query"].Replace('{days}', "$Days").Replace('{deepDiveDays}', "$deepDiveDays").Replace('{wowTotalDays}', "$wowTotalDays")
            $rawTimespan = if ($parsed["timespan"]) { $parsed["timespan"] } else { "P${Days}D" }
            $rawTimespan = $rawTimespan.Replace('{days}', "$Days").Replace('{deepDiveDays}', "$deepDiveDays").Replace('{wowTotalDays}', "$wowTotalDays")
            $workQueue.Add([PSCustomObject]@{
                Id       = $qId
                Name     = $parsed["name"]
                Query    = $rawQuery
                Timespan = $rawTimespan
                Phase    = $p
            })
        } elseif ($parsed["type"] -ne "kql") {
            Write-Host "   ⏭️  $($parsed['name']) — type '$($parsed['type'])' not yet supported, skipping" -ForegroundColor DarkYellow
        }
    }
    Write-Host "   ✅ Parsed $($queryFiles.Count) query definitions" -ForegroundColor Green
}

# Step 2: Execute all KQL queries in parallel (max 5 concurrent per Azure Monitor API limits)
$kqlCount = $workQueue.Count
Write-Host "`n🔄 Executing $kqlCount queries in parallel (max 5 concurrent)..." -ForegroundColor Yellow
$execStart = Get-Date

$queryResults = $workQueue | ForEach-Object -Parallel {
    $item = $_
    $wsId = $using:workspaceId

    $singleLine = ($item.Query -replace '\r?\n', ' ' -replace '\s+', ' ').Trim()
    $start = Get-Date

    $rawResult = az monitor log-analytics query `
        --workspace $wsId `
        --analytics-query $singleLine `
        --timespan $item.Timespan `
        -o json 2>&1

    $exitCode = $LASTEXITCODE
    $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)

    $data = $null
    $rowCount = 0
    $success = $false
    if ($exitCode -eq 0) {
        try {
            $data = $rawResult | ConvertFrom-Json
            $rowCount = if ($data -is [array]) { $data.Count } else { 1 }
            $success = $true
        } catch { }
    }

    [PSCustomObject]@{
        Id       = $item.Id
        Name     = $item.Name
        Phase    = $item.Phase
        Data     = $data
        Elapsed  = $elapsed
        RowCount = $rowCount
        Success  = $success
    }
} -ThrottleLimit 5

$totalQueryTime = [math]::Round(((Get-Date) - $execStart).TotalSeconds, 1)

# Step 3: Collect results and display summary (sorted by phase → query id)
$lastPhase = 0
foreach ($r in ($queryResults | Sort-Object Phase, Id)) {
    if ($r.Phase -ne $lastPhase) {
        Write-Host "   Phase $($r.Phase):" -ForegroundColor DarkCyan
        $lastPhase = $r.Phase
    }
    $allResults[$r.Id] = $r.Data
    if ($r.Success) {
        Write-Host "     ✅ $($r.Name) — $($r.RowCount) rows ($($r.Elapsed)s)" -ForegroundColor Green
    } else {
        Write-Host "     ⚠️  $($r.Name) — EMPTY or table not found ($($r.Elapsed)s)" -ForegroundColor DarkYellow
    }
}

$sumSequential = [math]::Round(($queryResults | ForEach-Object { $_.Elapsed } | Measure-Object -Sum).Sum, 1)
$speedup = if ($totalQueryTime -gt 0) { [math]::Round($sumSequential / $totalQueryTime, 1) } else { 1 }
Write-Host "`n   Wall-clock: ${totalQueryTime}s | Sequential: ${sumSequential}s | Speedup: ${speedup}×" -ForegroundColor DarkGray

# Step 4: Execute Phase 3 non-KQL queries (REST, CLI, Graph) sequentially
if ($phasesToRun -contains 3) {
    Write-Host "`n🔄 Executing Phase 3 non-KQL queries (REST, CLI, Graph)..." -ForegroundColor Yellow
    $phase3Start = Get-Date

    # Resolve config placeholders for REST/CLI commands
    $configReplacements = @{
        '{subscription_id}' = $subscriptionId
        '{resource_group}'  = $resourceGroup
        '{workspace_name}'  = $workspaceName
    }

    foreach ($qId in ($allQueries.Keys | Sort-Object)) {
        $parsed = $allQueries[$qId]
        $qType = $parsed["type"]
        $qPhase = [int]$parsed["phase"]
        if ($qPhase -ne 3) { continue }
        if ($qType -eq "kql" -and $parsed["depends_on"]) { continue }  # Q10b handled below

        $qName = $parsed["name"]

        switch ($qType) {
            "rest" {
                Write-Host "   🌐 $qName (REST)..." -ForegroundColor DarkCyan -NoNewline
                $start = Get-Date
                try {
                    $url = $parsed["url"]
                    $jmespath = $parsed["jmespath"]
                    # Resolve config placeholders
                    foreach ($k in $configReplacements.Keys) {
                        $url = $url.Replace($k, $configReplacements[$k])
                    }
                    $rawResult = az rest --method get --url $url --query $jmespath -o json 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $data = $rawResult | ConvertFrom-Json
                        $rowCount = if ($data -is [array]) { $data.Count } else { 1 }
                        $allResults[$qId] = $data
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Host " ✅ $rowCount rules (${elapsed}s)" -ForegroundColor Green
                    } else {
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Warning " FAILED (${elapsed}s): $rawResult"
                        $allResults[$qId] = $null
                    }
                } catch {
                    $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                    Write-Warning " ERROR (${elapsed}s): $_"
                    $allResults[$qId] = $null
                }
            }
            "cli" {
                Write-Host "   🖥️  $qName (CLI)..." -ForegroundColor DarkCyan -NoNewline
                $start = Get-Date
                try {
                    $cmd = $parsed["command"]
                    # Resolve config placeholders
                    foreach ($k in $configReplacements.Keys) {
                        $cmd = $cmd.Replace($k, $configReplacements[$k])
                    }
                    $rawResult = Invoke-Expression $cmd 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $data = $rawResult | ConvertFrom-Json
                        $rowCount = if ($data -is [array]) { $data.Count } else { 1 }
                        $allResults[$qId] = $data
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Host " ✅ $rowCount tables (${elapsed}s)" -ForegroundColor Green
                    } else {
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Warning " FAILED (${elapsed}s): $rawResult"
                        $allResults[$qId] = $null
                    }
                } catch {
                    $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                    Write-Warning " ERROR (${elapsed}s): $_"
                    $allResults[$qId] = $null
                }
            }
            "graph" {
                Write-Host "   📊 $qName (Graph API)..." -ForegroundColor DarkCyan -NoNewline
                $start = Get-Date
                $cdStatus = ""
                try {
                    # Step 0: Check module availability
                    $mgModule = Get-Module -ListAvailable Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
                    if (-not $mgModule) {
                        $cdStatus = "Module Microsoft.Graph.Authentication not found (Get-Module returned empty)"
                        Write-Host " ⏭️  SKIPPED — module not installed" -ForegroundColor DarkYellow
                        $allResults[$qId] = @{ _status = "SKIPPED"; _error = $cdStatus }
                        continue
                    }
                    # Step 1: Check/establish session
                    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
                    $mgContext = Get-MgContext -ErrorAction SilentlyContinue
                    $requiredScope = $parsed["scope"]
                    if (-not $mgContext -or ($requiredScope -and ($mgContext.Scopes -notcontains $requiredScope))) {
                        Connect-MgGraph -Scopes $requiredScope -NoWelcome -ErrorAction Stop
                    }
                    # Step 2: Fetch data
                    $endpoint = $parsed["endpoint"]
                    $selectFields = $parsed["select"]
                    $uri = "${endpoint}?`$select=${selectFields}"
                    $cdResponse = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
                    $data = $cdResponse.value
                    $rowCount = if ($data -is [array]) { $data.Count } else { if ($data) { 1 } else { 0 } }
                    $allResults[$qId] = $data
                    $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                    Write-Host " ✅ $rowCount rules (${elapsed}s)" -ForegroundColor Green
                } catch {
                    $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                    $cdStatus = $_.Exception.Message
                    Write-Host " ⏭️  SKIPPED (${elapsed}s) — $cdStatus" -ForegroundColor DarkYellow
                    $allResults[$qId] = @{ _status = "SKIPPED"; _error = $cdStatus }
                }
            }
        }
    }

    # Step 4b: Execute dependent KQL queries (Q10b depends on Q10)
    $q10Data = $allResults["ingestion-q10"]
    if ($q10Data -and $allQueries.ContainsKey("ingestion-q10b")) {
        Write-Host "   🔗 Tier Summary (KQL, depends on Q10)..." -ForegroundColor DarkCyan -NoNewline
        $start = Get-Date
        try {
            # Build table lists from Q10 output
            $dlTables = @($q10Data | Where-Object { $_.plan -eq "Auxiliary" } | ForEach-Object { "'$($_.name)'" })
            $basicTables = @($q10Data | Where-Object { $_.plan -eq "Basic" } | ForEach-Object { "'$($_.name)'" })
            $dlString = $dlTables -join ","
            $basicString = $basicTables -join ","

            # Get the Q10b query template and substitute table lists
            $q10bQuery = $allQueries["ingestion-q10b"]["query"]
            $q10bQuery = $q10bQuery.Replace('{datalake_tables}', $dlString).Replace('{basic_tables}', $basicString)
            $q10bQuery = $q10bQuery.Replace('{days}', "$Days").Replace('{deepDiveDays}', "$deepDiveDays").Replace('{wowTotalDays}', "$wowTotalDays")
            $q10bTimespan = if ($allQueries["ingestion-q10b"]["timespan"]) { $allQueries["ingestion-q10b"]["timespan"] } else { "P${Days}D" }
            $q10bTimespan = $q10bTimespan.Replace('{days}', "$Days").Replace('{deepDiveDays}', "$deepDiveDays").Replace('{wowTotalDays}', "$wowTotalDays")

            # Execute via az monitor
            $singleLine = ($q10bQuery -replace '\r?\n', ' ' -replace '\s+', ' ').Trim()
            $rawResult = az monitor log-analytics query `
                --workspace $workspaceId `
                --analytics-query $singleLine `
                --timespan $q10bTimespan `
                -o json 2>&1

            if ($LASTEXITCODE -eq 0) {
                $data = $rawResult | ConvertFrom-Json
                $rowCount = if ($data -is [array]) { $data.Count } else { 1 }
                $allResults["ingestion-q10b"] = $data
                $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                Write-Host " ✅ $rowCount tiers (${elapsed}s)" -ForegroundColor Green
            } else {
                $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                Write-Warning " FAILED (${elapsed}s): $rawResult"
            }
        } catch {
            $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
            Write-Warning " ERROR (${elapsed}s): $_"
        }
    }

    $phase3Time = [math]::Round(((Get-Date) - $phase3Start).TotalSeconds, 1)
    Write-Host "`n   Phase 3 complete: ${phase3Time}s" -ForegroundColor DarkGray
}
#endregion
} # end if ($SyntheticDataDir) else

#region ═══ Export Data ═════════════════════════════════════════════════════════
if ($ExportDataDir) {
    if (-not (Test-Path $ExportDataDir)) {
        New-Item -ItemType Directory -Path $ExportDataDir -Force | Out-Null
    }
    Write-Host "`n📦 Exporting query results to $ExportDataDir..." -ForegroundColor Yellow

    # meta.json
    @{ workspace_name = $workspaceName; workspace_id = $workspaceId } |
        ConvertTo-Json | Set-Content (Join-Path $ExportDataDir "meta.json") -Encoding UTF8

    # Individual query result files — use -InputObject to preserve empty arrays
    # (pipeline unwraps @() to nothing, losing the file entirely)
    $exportCount = 0
    foreach ($key in ($allResults.Keys | Sort-Object)) {
        $outPath = Join-Path $ExportDataDir "$key.json"
        ConvertTo-Json -InputObject $allResults[$key] -Depth 10 -Compress:$false |
            Set-Content $outPath -Encoding UTF8
        $exportCount++
    }
    Write-Host "   ✅ Exported meta.json + $exportCount query files" -ForegroundColor Green
    Write-Host "   📁 Replay with: -SyntheticDataDir `"$ExportDataDir`"" -ForegroundColor DarkCyan
}
#endregion

#region ═══ Post-Processing & Scratchpad ═══════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1: Usage Summary
# ═══════════════════════════════════════════════════════════════════════════════
$phase1Block = ""
if ($phasesToRun -contains 1) {
    Write-Host "`n📊 Computing Phase 1 metrics..." -ForegroundColor Yellow

    $q1Data = $allResults["ingestion-q1"]  # Table breakdown
    $q2Data = $allResults["ingestion-q2"]  # Daily trend
    $q3Data = $allResults["ingestion-q3"]  # Workspace summary

    # Validate all queries returned data
    $missing = @()
    if (-not $q1Data) { $missing += "Q1 (Usage by DataType)" }
    if (-not $q2Data) { $missing += "Q2 (Daily Trend)" }
    if (-not $q3Data) { $missing += "Q3 (Workspace Summary)" }
    if ($missing.Count -gt 0) {
        Write-Error "Cannot compute Phase 1 scratchpad — missing query results: $($missing -join ', ')"
        return
    }

    # ─── Extract Q3 summary metrics ─────────────────────────────────────────
    $summary = if ($q3Data -is [array]) { $q3Data[0] } else { $q3Data }
    $totalGB          = [math]::Round([double]$summary.TotalGB, 3)
    $billableGB       = [math]::Round([double]$summary.BillableGB, 3)
    $nonBillableGB    = [math]::Round([double]$summary.NonBillableGB, 3)
    $avgDailyGB       = [math]::Round([double]$summary.AvgDailyGB, 3)
    $totalTableCount  = [int]$summary.TotalTableCount
    $billableTableCount = [int]$summary.BillableTableCount

    # ─── Compute peak/min from Q2 daily trend ───────────────────────────────
    $dailyTrend = $q2Data | ForEach-Object {
        [PSCustomObject]@{
            Date = [datetime]$_.TimeGenerated
            GB   = [math]::Round([double]$_.DailyGB, 3)
        }
    } | Sort-Object Date

    $peakDay = $dailyTrend | Sort-Object GB -Descending | Select-Object -First 1
    $minDay = $dailyTrend | Where-Object { $_.GB -ge 0.01 } | Sort-Object GB | Select-Object -First 1
    if (-not $minDay) { $minDay = $dailyTrend | Sort-Object GB | Select-Object -First 1 }

    Write-Host "   ✅ Summary: ${totalGB} GB total, ${billableGB} GB billable, ${totalTableCount} tables" -ForegroundColor Green
    Write-Host "   ✅ Peak: $($peakDay.GB) GB on $($peakDay.Date.ToString('yyyy-MM-dd')) ($($peakDay.Date.ToString('ddd')))" -ForegroundColor Green
    Write-Host "   ✅ Min:  $($minDay.GB) GB on $($minDay.Date.ToString('yyyy-MM-dd')) ($($minDay.Date.ToString('ddd')))" -ForegroundColor Green

    # ─── Build Tables section from Q1 ────────────────────────────────────────
    $tablesLines = [System.Text.StringBuilder]::new()
    [void]$tablesLines.AppendLine("<!-- DataType | BillableGB | Pct | Solution -->")
    foreach ($row in $q1Data) {
        $rowBillable = [math]::Round([double]$row.BillableGB, 3)
        $pct = if ($billableGB -gt 0) { [math]::Round(100.0 * $rowBillable / $billableGB, 1) } else { 0 }
        $solution = if ($row.Solution) { $row.Solution } else { "" }
        [void]$tablesLines.AppendLine("$($row.DataType) | $(([double]$rowBillable).ToString('F3')) | $(([double]$pct).ToString('F1')) | $solution")
    }

    # ─── Build DailyTrend section from Q2 ────────────────────────────────────
    $trendLines = [System.Text.StringBuilder]::new()
    [void]$trendLines.AppendLine("<!-- Date | GB -->")
    foreach ($day in $dailyTrend) {
        [void]$trendLines.AppendLine("$($day.Date.ToString('yyyy-MM-dd')) | $(([double]$day.GB).ToString('F3'))")
    }

    $periodStart = $dailyTrend[0].Date.ToString('yyyy-MM-dd')
    $periodEnd   = $dailyTrend[-1].Date.ToString('yyyy-MM-dd')

    $phase1Block = @"

## PHASE_1 — Usage Summary

### Metrics
TotalGB: $(([double]$totalGB).ToString('F3'))
BillableGB: $(([double]$billableGB).ToString('F3'))
NonBillableGB: $(([double]$nonBillableGB).ToString('F3'))
AvgDailyGB: $(([double]$avgDailyGB).ToString('F3'))
PeakGB: $(([double]$peakDay.GB).ToString('F3'))
PeakDate: $($peakDay.Date.ToString('yyyy-MM-dd'))
PeakDay: $($peakDay.Date.ToString('ddd'))
MinGB: $(([double]$minDay.GB).ToString('F3'))
MinDate: $($minDay.Date.ToString('yyyy-MM-dd'))
MinDay: $($minDay.Date.ToString('ddd'))
BillableTables: $billableTableCount
TotalTables: $totalTableCount

### Tables
$($tablesLines.ToString().TrimEnd())

### DailyTrend
$($trendLines.ToString().TrimEnd())
"@
}

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2: Deep Dives (SecurityEvent, Syslog, CommonSecurityLog)
# ═══════════════════════════════════════════════════════════════════════════════
$phase2Block = ""
if ($phasesToRun -contains 2) {
    Write-Host "`n📊 Computing Phase 2 metrics..." -ForegroundColor Yellow

    # Helper: count servers from SecurityEvent Computer breakdown
    function Format-DeepDiveTable {
        param(
            [array]$Data,
            [string]$SectionName,
            [string]$ColumnHeader,
            [string[]]$Columns    # property names to extract
        )
        if (-not $Data -or $Data.Count -eq 0) { return "EMPTY" }

        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("<!-- $ColumnHeader -->")
        foreach ($row in $Data) {
            $values = $Columns | ForEach-Object { $row.$_ }
            [void]$sb.AppendLine(($values -join " | "))
        }
        return $sb.ToString().TrimEnd()
    }

    $phase2Sections = [System.Text.StringBuilder]::new()
    [void]$phase2Sections.AppendLine("")
    [void]$phase2Sections.AppendLine("## PHASE_2 — Deep Dives")

    # ─── SE_Computer (Q4) — raw data moved to PRERENDERED blocks ───────────
    # Console status only; table rendered in PRERENDERED.SE_Computer
    $q4Data = $allResults["ingestion-q4"]
    if ($q4Data -and $q4Data.Count -gt 0) {
        Write-Host "   ✅ SE_Computer: $($q4Data.Count) computers" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  SE_Computer: EMPTY (SecurityEvent not found or no data)" -ForegroundColor DarkYellow
    }

    # ─── SE_EventID (Q5) — raw data moved to PRERENDERED blocks ─────────────
    # Console status only; table rendered in PRERENDERED.SE_EventID
    $q5Data = $allResults["ingestion-q5"]
    if ($q5Data -and $q5Data.Count -gt 0) {
        Write-Host "   ✅ SE_EventID: $($q5Data.Count) event IDs" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  SE_EventID: EMPTY" -ForegroundColor DarkYellow
    }

    # ─── Syslog data (Q6a/Q6b/Q6c) — raw data moved to PRERENDERED blocks ──
    # Console status only; tables rendered in PRERENDERED.SyslogHost/Facility/FacSev/Process
    $q6aData = $allResults["ingestion-q6a"]
    if ($q6aData -and $q6aData.Count -gt 0) {
        Write-Host "   ✅ Syslog_Host: $($q6aData.Count) hosts" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  Syslog_Host: EMPTY (Syslog not found or no data)" -ForegroundColor DarkYellow
    }

    $q6bData = $allResults["ingestion-q6b"]
    if ($q6bData -and $q6bData.Count -gt 0) {
        Write-Host "   ✅ Syslog_FacilitySeverity: $($q6bData.Count) combinations" -ForegroundColor Green
        # Derive facility count for console
        $facilityCount = @($q6bData | ForEach-Object { $_.Facility } | Select-Object -Unique).Count
        Write-Host "   ✅ Syslog_Facility: $facilityCount facilities (derived from Q6b)" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  Syslog_FacilitySeverity: EMPTY" -ForegroundColor DarkYellow
    }

    $q6cData = $allResults["ingestion-q6c"]
    if ($q6cData -and $q6cData.Count -gt 0) {
        Write-Host "   ✅ Syslog_Process: $($q6cData.Count) process/facility combos" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  Syslog_Process: EMPTY" -ForegroundColor DarkYellow
    }

    # ─── CSL_Vendor (Q7) ────────────────────────────────────────────────────
    $q7Data = $allResults["ingestion-q7"]
    [void]$phase2Sections.AppendLine("")
    [void]$phase2Sections.AppendLine("### CSL_Vendor")
    if ($q7Data -and $q7Data.Count -gt 0) {
        [void]$phase2Sections.AppendLine("<!-- DeviceVendor | DeviceProduct | EventCount | EstGB | Pct -->")
        foreach ($row in $q7Data) {
            $vendor = $row.DeviceVendor
            $product = $row.DeviceProduct
            $eventCount = $row.EventCount
            $estGB = if ([double]$row.EstimatedGB -gt 0 -and [double]$row.EstimatedGB -lt 0.01) { '< 0.01' } else { ([math]::Round([double]$row.EstimatedGB, 1)).ToString('F1') }
            $pctVal = [double]$row.PercentOfTotal
            $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
            [void]$phase2Sections.AppendLine("$vendor | $product | $eventCount | $estGB | $pct")
        }
        Write-Host "   ✅ CSL_Vendor: $($q7Data.Count) vendor/product combos" -ForegroundColor Green
    } else {
        [void]$phase2Sections.AppendLine("EMPTY")
        Write-Host "   ℹ️  CSL_Vendor: EMPTY (CommonSecurityLog not found or no data)" -ForegroundColor DarkYellow
    }

    # ─── CSL_Activity (Q8) ──────────────────────────────────────────────────
    $q8Data = $allResults["ingestion-q8"]
    [void]$phase2Sections.AppendLine("")
    [void]$phase2Sections.AppendLine("### CSL_Activity")
    if ($q8Data -and $q8Data.Count -gt 0) {
        [void]$phase2Sections.AppendLine("<!-- Activity | LogSeverity | DeviceAction | EventCount | EstGB | Pct -->")
        foreach ($row in $q8Data) {
            $activity = $row.Activity
            $logSeverity = $row.LogSeverity
            $deviceAction = $row.DeviceAction
            $eventCount = $row.EventCount
            $estGB = if ([double]$row.EstimatedGB -gt 0 -and [double]$row.EstimatedGB -lt 0.01) { '< 0.01' } else { ([math]::Round([double]$row.EstimatedGB, 1)).ToString('F1') }
            $pctVal = [double]$row.PercentOfTotal
            $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
            [void]$phase2Sections.AppendLine("$activity | $logSeverity | $deviceAction | $eventCount | $estGB | $pct")
        }
        Write-Host "   ✅ CSL_Activity: $($q8Data.Count) activity/severity combos" -ForegroundColor Green
    } else {
        [void]$phase2Sections.AppendLine("EMPTY")
        Write-Host "   ℹ️  CSL_Activity: EMPTY" -ForegroundColor DarkYellow
    }

    $phase2Block = $phase2Sections.ToString().TrimEnd()
}

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 3: Rules & Tiers
# ═══════════════════════════════════════════════════════════════════════════════
$phase3Block = ""
if ($phasesToRun -contains 3) {
    Write-Host "`n📊 Computing Phase 3 metrics..." -ForegroundColor Yellow

    $phase3Sections = [System.Text.StringBuilder]::new()
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("## PHASE_3 — Rules & Tiers")

    # ─── RuleInventory ──────────────────────────────────────────────────────
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### RuleInventory")

    $q9Data = $allResults["ingestion-q9"]
    if ($q9Data -and ($q9Data -is [array]) -and $q9Data.Count -gt 0) {
        $arTotal     = $q9Data.Count
        $arEnabled   = @($q9Data | Where-Object { $_.enabled -eq $true }).Count
        $arDisabled  = $arTotal - $arEnabled
        $arScheduled = @($q9Data | Where-Object { $_.kind -eq "Scheduled" }).Count
        $arNRT       = @($q9Data | Where-Object { $_.kind -eq "NRT" }).Count
        Write-Host "   ✅ Analytic Rules: $arTotal total ($arEnabled enabled, $arDisabled disabled)" -ForegroundColor Green
    } else {
        $arTotal = 0; $arEnabled = 0; $arDisabled = 0; $arScheduled = 0; $arNRT = 0
        Write-Host "   ⚠️  Analytic Rules: FAILED or 0 rules returned" -ForegroundColor DarkYellow
    }

    # NRT fix: REST API reports NRT rules as kind="Scheduled". Cross-reference
    # with SentinelHealth (Q11) which correctly tracks SentinelResourceKind="NRT".
    $q11Ref = $allResults["ingestion-q11"]
    if ($q11Ref -and $arNRT -eq 0) {
        $healthRef = if ($q11Ref -is [array]) { $q11Ref[0] } else { $q11Ref }
        $shNRT = [int]$healthRef.NRTRules
        if ($shNRT -gt 0) {
            $arNRT = $shNRT
            $arScheduled = [math]::Max(0, $arScheduled - $shNRT)
            Write-Host "   ℹ️  NRT reclassified via SentinelHealth: $shNRT NRT (REST API reported as Scheduled)" -ForegroundColor DarkYellow
        }
    }

    # Custom Detection rules (Q9b)
    $q9bData = $allResults["ingestion-q9b"]
    $cdStatus = ""
    if ($q9bData -is [hashtable] -and $q9bData._status -eq "SKIPPED") {
        $cdTotal = 0; $cdEnabled = 0; $cdDisabled = 0
        $cdStatus = $q9bData._error
        Write-Host "   ℹ️  Custom Detections: SKIPPED — $cdStatus" -ForegroundColor DarkYellow
    } elseif ($q9bData -and ($q9bData -is [array]) -and $q9bData.Count -gt 0) {
        $cdTotal    = $q9bData.Count
        $cdEnabled  = @($q9bData | Where-Object { $_.isEnabled -eq $true }).Count
        $cdDisabled = $cdTotal - $cdEnabled
        Write-Host "   ✅ Custom Detections: $cdTotal total ($cdEnabled enabled, $cdDisabled disabled)" -ForegroundColor Green
    } else {
        $cdTotal = 0; $cdEnabled = 0; $cdDisabled = 0
        Write-Host "   ℹ️  Custom Detections: 0 rules" -ForegroundColor DarkYellow
    }

    $combinedEnabled = $arEnabled + $cdEnabled

    [void]$phase3Sections.AppendLine("AR_Total: $arTotal")
    [void]$phase3Sections.AppendLine("AR_Enabled: $arEnabled")
    [void]$phase3Sections.AppendLine("AR_Disabled: $arDisabled")
    [void]$phase3Sections.AppendLine("AR_Scheduled: $arScheduled")
    [void]$phase3Sections.AppendLine("AR_NRT: $arNRT")
    [void]$phase3Sections.AppendLine("CD_Total: $cdTotal")
    [void]$phase3Sections.AppendLine("CD_Enabled: $cdEnabled")
    [void]$phase3Sections.AppendLine("CD_Disabled: $cdDisabled")
    [void]$phase3Sections.AppendLine("Combined_Enabled: $combinedEnabled")
    if ($cdStatus) {
        [void]$phase3Sections.AppendLine("CD_Status: SKIPPED ($cdStatus)")
    }

    # ─── Build $allRules for Phase 4 cross-reference ────────────────────────
    $allRules = @()
    if ($q9Data -and ($q9Data -is [array])) {
        $allRules += @($q9Data | Where-Object { $_.enabled -eq $true } | ForEach-Object {
            [PSCustomObject]@{ displayName = $_.displayName; query = $_.query; source = "AR" }
        })
    }
    if ($q9bData -and ($q9bData -is [array]) -and -not ($q9bData -is [hashtable] -and $q9bData._status -eq "SKIPPED")) {
        $allRules += @($q9bData | Where-Object { $_.isEnabled -eq $true } | ForEach-Object {
            $queryText = if ($_.queryCondition -and $_.queryCondition.queryText) { $_.queryCondition.queryText } else { "" }
            [PSCustomObject]@{ displayName = $_.displayName; query = $queryText; source = "CD" }
        })
    }
    $arInAll = @($allRules | Where-Object { $_.source -eq 'AR' }).Count
    $cdInAll = @($allRules | Where-Object { $_.source -eq 'CD' }).Count
    Write-Host "   ✅ Built allRules: $($allRules.Count) enabled (AR=$arInAll, CD=$cdInAll) — ready for Phase 4" -ForegroundColor Green

    # ─── Tiers ──────────────────────────────────────────────────────────────
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### Tiers")

    $q10Data = $allResults["ingestion-q10"]
    if ($q10Data -and ($q10Data -is [array]) -and $q10Data.Count -gt 0) {
        # Filter to non-Analytics tables (Data Lake = "Auxiliary" in CLI, Basic = "Basic")
        $nonAnalyticsTables = $q10Data | Where-Object { $_.plan -in @("Auxiliary", "Basic") }
        if ($nonAnalyticsTables -and @($nonAnalyticsTables).Count -gt 0) {
            [void]$phase3Sections.AppendLine("<!-- Table | Plan -->")
            foreach ($row in $nonAnalyticsTables) {
                # Relabel "Auxiliary" as "Data Lake" per v1 convention
                $planLabel = if ($row.plan -eq "Auxiliary") { "Data Lake" } else { $row.plan }
                [void]$phase3Sections.AppendLine("$($row.name) | $planLabel")
            }
            $dlCount = @($nonAnalyticsTables | Where-Object { $_.plan -eq "Auxiliary" }).Count
            $basicCount = @($nonAnalyticsTables | Where-Object { $_.plan -eq "Basic" }).Count
            Write-Host "   ✅ Tiers: $dlCount Data Lake, $basicCount Basic tables" -ForegroundColor Green
        } else {
            [void]$phase3Sections.AppendLine("<!-- All tables on Analytics tier -->")
            Write-Host "   ℹ️  Tiers: All tables on Analytics tier" -ForegroundColor DarkYellow
        }
    } else {
        [void]$phase3Sections.AppendLine("EMPTY")
        Write-Host "   ⚠️  Tiers: CLI query failed or returned no data" -ForegroundColor DarkYellow
    }

    # ─── TierSummary ────────────────────────────────────────────────────────
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### TierSummary")

    $q10bData = $allResults["ingestion-q10b"]
    if ($q10bData -and ($q10bData -is [array]) -and $q10bData.Count -gt 0) {
        [void]$phase3Sections.AppendLine("<!-- Tier | TotalGB | BillableGB | TableCount | PercentOfTotal -->")
        foreach ($row in $q10bData) {
            $tier = $row.Tier
            $tierTotalGB = ([double]$row.TotalGB).ToString("F3")
            $tierBillableGB = ([double]$row.BillableGB).ToString("F3")
            $tableCount = [int]$row.TableCount
            $pctRaw = [double]$row.PercentOfTotal
            $pctTotal = if ([double]::IsNaN($pctRaw) -or [double]::IsInfinity($pctRaw)) { '0.0' } else { $pctRaw.ToString('F1') }
            [void]$phase3Sections.AppendLine("$tier | $tierTotalGB | $tierBillableGB | $tableCount | $pctTotal")
        }
        Write-Host "   ✅ TierSummary: $($q10bData.Count) tiers computed" -ForegroundColor Green
    } else {
        [void]$phase3Sections.AppendLine("EMPTY")
        Write-Host "   ⚠️  TierSummary: KQL cross-reference failed" -ForegroundColor DarkYellow
    }

    $phase3Block = $phase3Sections.ToString().TrimEnd()
}

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 4: Detection Coverage
# ═══════════════════════════════════════════════════════════════════════════════
$phase4Block = ""
$phase5Block = ""
if ($phasesToRun -contains 4) {
    Write-Host "`n📊 Computing Phase 4 metrics..." -ForegroundColor Yellow

    $phase4Sections = [System.Text.StringBuilder]::new()
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("## PHASE_4 — Detection Coverage")

    # ─── Cross-reference: Phase 4.4 ─────────────────────────────────────────
    # For each workspace table, regex-search all enabled rules for that table name
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("### CrossRef")
    [void]$phase4Sections.AppendLine("<!-- Table | AR | CD | Total -->")

    $crossRef = @()
    $zeroRuleTables = @()

    if ($allRules -and $allRules.Count -gt 0) {
        # Use Q1b (all tables with actual billable data) — not Q10 (900 table schemas including empty)
        $tablesToCheck = @()
        $q1bData = $allResults["ingestion-q13"]
        $q1Data  = $allResults["ingestion-q1"]
        if ($q1bData -and ($q1bData -is [array])) {
            $tablesToCheck = @($q1bData | ForEach-Object { $_.DataType } | Where-Object { $_ })
        } elseif ($q1Data -and ($q1Data -is [array])) {
            # Fallback to Q1 top-20 if Q1b unavailable
            $tablesToCheck = @($q1Data | ForEach-Object { $_.DataType } | Where-Object { $_ })
        }

        Write-Host "   🔍 Cross-referencing $($tablesToCheck.Count) tables against $($allRules.Count) enabled rules..." -ForegroundColor DarkCyan
        $crossRefStart = Get-Date

        foreach ($table in $tablesToCheck) {
            # Word-boundary matching: prevents "Event" from matching "SecurityEvent"
            $pattern = "\b" + [regex]::Escape($table) + "\b"
            $matchingRules = @($allRules | Where-Object { $_.query -match $pattern })
            if ($matchingRules.Count -gt 0) {
                $arCount = @($matchingRules | Where-Object { $_.source -eq 'AR' }).Count
                $cdCount = @($matchingRules | Where-Object { $_.source -eq 'CD' }).Count
                # Capture up to 3 key rule names for PRERENDERED.CrossReference
                $names = @($matchingRules | ForEach-Object { $_.displayName } | Select-Object -First 3)
                $keyNames = ($names -join '; ')
                if ($matchingRules.Count -gt 3) { $keyNames += "; +$($matchingRules.Count - 3) more" }
                $crossRef += [PSCustomObject]@{Table=$table; AR=$arCount; CD=$cdCount; Total=$matchingRules.Count; KeyNames=$keyNames}
            } else {
                $zeroRuleTables += $table
            }
        }

        foreach ($row in ($crossRef | Sort-Object Total -Descending)) {
            [void]$phase4Sections.AppendLine("$($row.Table) | $($row.AR) | $($row.CD) | $($row.Total)")
        }
        $crossRefTime = [math]::Round(((Get-Date) - $crossRefStart).TotalSeconds, 1)
        Write-Host "   ✅ CrossRef: $($crossRef.Count) tables with rules, $($zeroRuleTables.Count) zero-rule (${crossRefTime}s)" -ForegroundColor Green
    } else {
        [void]$phase4Sections.AppendLine("EMPTY — allRules not available (Phase 3 required)")
        Write-Host "   ⚠️  CrossRef: SKIPPED — allRules not available" -ForegroundColor DarkYellow
    }

    # ─── Zero Rule Tables (Phase 4.6) ───────────────────────────────────────
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("### ZeroRuleTables")
    if ($zeroRuleTables.Count -gt 0) {
        foreach ($t in ($zeroRuleTables | Sort-Object)) {
            [void]$phase4Sections.AppendLine($t)
        }
    } else {
        [void]$phase4Sections.AppendLine("NONE")
    }

    # ─── Detection Gaps: DL/Basic tables with rules ─────────────────────────
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("### DetectionGaps")
    [void]$phase4Sections.AppendLine("<!-- Tables on DL/Basic with rules -->")

    $q10Data = $allResults["ingestion-q10"]
    if ($crossRef.Count -gt 0 -and $q10Data) {
        $nonAnalyticsTables = @($q10Data | Where-Object { $_.plan -in @("Auxiliary", "Basic") })
        $gaps = @()
        foreach ($nat in $nonAnalyticsTables) {
            $tableName = $nat.name
            $planLabel = if ($nat.plan -eq "Auxiliary") { "Data Lake" } else { $nat.plan }
            $ruleMatch = $crossRef | Where-Object { $_.Table -eq $tableName }
            if ($ruleMatch) {
                $gaps += "$tableName | $planLabel | $($ruleMatch.Total) rules"
            }
        }
        if ($gaps.Count -gt 0) {
            foreach ($g in $gaps) { [void]$phase4Sections.AppendLine($g) }
            Write-Host "   ⚠️  DetectionGaps: $($gaps.Count) table(s) on DL/Basic with active rules" -ForegroundColor DarkYellow
        } else {
            [void]$phase4Sections.AppendLine("NONE")
            Write-Host "   ✅ DetectionGaps: NONE" -ForegroundColor Green
        }
    } else {
        [void]$phase4Sections.AppendLine("NONE")
    }

    # ─── ASIM Parser Detection (Phase 4.5) ──────────────────────────────────
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("### ASIM")
    [void]$phase4Sections.AppendLine("<!-- Pattern | Count | RuleNames -->")

    if ($allRules -and $allRules.Count -gt 0) {
        $asimPatterns = @("_Im_","imDns","imNetworkSession","imWebSession","imAuthentication",
                          "imFileEvent","imProcessEvent","imRegistryEvent","imAuditEvent",
                          "imDhcpEvent","imAlertEvent","imUserManagement","_ASim_")
        $asimResults = @()
        foreach ($p in $asimPatterns) {
            $hits = @($allRules | Where-Object { $_.query -match [regex]::Escape($p) })
            if ($hits.Count -gt 0) {
                $asimResults += [PSCustomObject]@{Pattern=$p; Count=$hits.Count; Rules=($hits.displayName -join "; ")}
            }
        }
        if ($asimResults.Count -gt 0) {
            foreach ($r in $asimResults) {
                [void]$phase4Sections.AppendLine("$($r.Pattern) | $($r.Count) | $($r.Rules)")
            }
            Write-Host "   ✅ ASIM: $($asimResults.Count) pattern(s) detected" -ForegroundColor Green
        } else {
            [void]$phase4Sections.AppendLine("NONE")
            Write-Host "   ✅ ASIM: NONE detected" -ForegroundColor Green
        }
    } else {
        [void]$phase4Sections.AppendLine("NONE")
    }

    # ─── ValueRef_EventID — compute arrays for PRERENDERED, skip scratchpad output
    $valueRefEventID = @()
    $q5Data = $allResults["ingestion-q5"]
    if ($q5Data -and ($q5Data -is [array]) -and $q5Data.Count -gt 0 -and $allRules -and $allRules.Count -gt 0) {
        foreach ($row in $q5Data) {
            $eid = $row.EventID
            $matchingRules = @($allRules | Where-Object { $_.query -match '\bSecurityEvent\b' -and $_.query -match "\b$eid\b" })
            $arCount = @($matchingRules | Where-Object { $_.source -eq 'AR' }).Count
            $cdCount = @($matchingRules | Where-Object { $_.source -eq 'CD' }).Count
            $keyNames = if ($matchingRules.Count -gt 3) {
                $first3 = ($matchingRules[0..2].displayName -join "; ")
                "$first3; +$($matchingRules.Count - 3) more"
            } elseif ($matchingRules.Count -gt 0) {
                ($matchingRules.displayName -join "; ")
            } else { "" }
            $valueRefEventID += [PSCustomObject]@{EventID=$eid; AR=$arCount; CD=$cdCount; Total=$matchingRules.Count; KeyNames=$keyNames}
        }
        Write-Host "   ✅ ValueRef_EventID: $($q5Data.Count) EventIDs checked" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  ValueRef_EventID: EMPTY" -ForegroundColor DarkYellow
    }

    # Facilities from Q6b (unique facility names)
    # ─── ValueRef_Facility — compute arrays for PRERENDERED, skip scratchpad output
    $valueRefFacility = @()
    $q6bData = $allResults["ingestion-q6b"]
    if ($q6bData -and ($q6bData -is [array]) -and $q6bData.Count -gt 0 -and $allRules -and $allRules.Count -gt 0) {
        $facilities = @($q6bData | ForEach-Object { $_.Facility } | Select-Object -Unique)
        foreach ($fac in $facilities) {
            $matchingRules = @($allRules | Where-Object { $_.query -match '\bSyslog\b' -and $_.query -match "\b$([regex]::Escape($fac))\b" })
            $arCount = @($matchingRules | Where-Object { $_.source -eq 'AR' }).Count
            $cdCount = @($matchingRules | Where-Object { $_.source -eq 'CD' }).Count
            $keyNames = if ($matchingRules.Count -gt 3) {
                $first3 = ($matchingRules[0..2].displayName -join "; ")
                "$first3; +$($matchingRules.Count - 3) more"
            } elseif ($matchingRules.Count -gt 0) {
                ($matchingRules.displayName -join "; ")
            } else { "" }
            $valueRefFacility += [PSCustomObject]@{Facility=$fac; AR=$arCount; CD=$cdCount; Total=$matchingRules.Count; KeyNames=$keyNames}
        }
        Write-Host "   ✅ ValueRef_Facility: $($facilities.Count) facilities checked" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  ValueRef_Facility: EMPTY" -ForegroundColor DarkYellow
    }

    # ─── ValueRef_Process — compute arrays for PRERENDERED, skip scratchpad output
    $valueRefProcess = @()
    $q6cData = $allResults["ingestion-q6c"]
    if ($q6cData -and ($q6cData -is [array]) -and $q6cData.Count -gt 0 -and $allRules -and $allRules.Count -gt 0) {
        $procs = @($q6cData | ForEach-Object { $_.ProcessName } | Select-Object -Unique)
        foreach ($proc in $procs) {
            if ([string]::IsNullOrWhiteSpace($proc)) {
                $valueRefProcess += [PSCustomObject]@{Process=$proc; AR=0; CD=0; Total=0; KeyNames=""}
                continue
            }
            $matchingRules = @($allRules | Where-Object { $_.query -match '\bSyslog\b' -and $_.query -match "\b$([regex]::Escape($proc))\b" })
            $arCount = @($matchingRules | Where-Object { $_.source -eq 'AR' }).Count
            $cdCount = @($matchingRules | Where-Object { $_.source -eq 'CD' }).Count
            $keyNames = if ($matchingRules.Count -gt 3) {
                $first3 = ($matchingRules[0..2].displayName -join "; ")
                "$first3; +$($matchingRules.Count - 3) more"
            } elseif ($matchingRules.Count -gt 0) {
                ($matchingRules.displayName -join "; ")
            } else { "" }
            $valueRefProcess += [PSCustomObject]@{Process=$proc; AR=$arCount; CD=$cdCount; Total=$matchingRules.Count; KeyNames=$keyNames}
        }
        Write-Host "   ✅ ValueRef_Process: $($procs.Count) processes checked" -ForegroundColor Green
    } else {
        Write-Host "   ℹ️  ValueRef_Process: EMPTY" -ForegroundColor DarkYellow
    }

    # Activities from Q8
    # ─── ValueRef_Activity — compute arrays for PRERENDERED, also write scratchpad
    $valueRefActivity = @()
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("### ValueRef_Activity")

    $q8Data = $allResults["ingestion-q8"]
    if ($q8Data -and ($q8Data -is [array]) -and $q8Data.Count -gt 0 -and $allRules -and $allRules.Count -gt 0) {
        [void]$phase4Sections.AppendLine("<!-- Activity | AR | CD | Total | RuleNames -->")
        $activities = @($q8Data | ForEach-Object { $_.Activity } | Select-Object -Unique)
        foreach ($act in $activities) {
            $matchingRules = @($allRules | Where-Object { $_.query -match '\bCommonSecurityLog\b' -and $_.query -match "\b$([regex]::Escape($act))\b" })
            $arCount = @($matchingRules | Where-Object { $_.source -eq 'AR' }).Count
            $cdCount = @($matchingRules | Where-Object { $_.source -eq 'CD' }).Count
            $ruleNames = if ($matchingRules.Count -gt 0) { ($matchingRules.displayName -join "; ") } else { [char]0x2014 }
            $keyNames = if ($matchingRules.Count -gt 3) {
                $first3 = ($matchingRules[0..2].displayName -join "; ")
                "$first3; +$($matchingRules.Count - 3) more"
            } elseif ($matchingRules.Count -gt 0) {
                ($matchingRules.displayName -join "; ")
            } else { "" }
            $valueRefActivity += [PSCustomObject]@{Activity=$act; AR=$arCount; CD=$cdCount; Total=$matchingRules.Count; KeyNames=$keyNames}
            [void]$phase4Sections.AppendLine("$act | $arCount | $cdCount | $($matchingRules.Count) | $ruleNames")
        }
        Write-Host "   ✅ ValueRef_Activity: $($activities.Count) activities checked" -ForegroundColor Green
    } else {
        [void]$phase4Sections.AppendLine("EMPTY")
        Write-Host "   ℹ️  ValueRef_Activity: EMPTY" -ForegroundColor DarkYellow
    }

    # Vendors from Q7
    # ─── ValueRef_Vendor — compute arrays for PRERENDERED, also write scratchpad
    $valueRefVendor = @()
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("### ValueRef_Vendor")

    $q7Data = $allResults["ingestion-q7"]
    if ($q7Data -and ($q7Data -is [array]) -and $q7Data.Count -gt 0 -and $allRules -and $allRules.Count -gt 0) {
        [void]$phase4Sections.AppendLine("<!-- DeviceVendor | AR | CD | Total | RuleNames -->")
        $vendors = @($q7Data | ForEach-Object { $_.DeviceVendor } | Select-Object -Unique)
        foreach ($vendor in $vendors) {
            $matchingRules = @($allRules | Where-Object { $_.query -match '\bCommonSecurityLog\b' -and $_.query -match "\b$([regex]::Escape($vendor))\b" })
            $arCount = @($matchingRules | Where-Object { $_.source -eq 'AR' }).Count
            $cdCount = @($matchingRules | Where-Object { $_.source -eq 'CD' }).Count
            $ruleNames = if ($matchingRules.Count -gt 0) { ($matchingRules.displayName -join "; ") } else { [char]0x2014 }
            $keyNames = if ($matchingRules.Count -gt 3) {
                $first3 = ($matchingRules[0..2].displayName -join "; ")
                "$first3; +$($matchingRules.Count - 3) more"
            } elseif ($matchingRules.Count -gt 0) {
                ($matchingRules.displayName -join "; ")
            } else { "" }
            $valueRefVendor += [PSCustomObject]@{Vendor=$vendor; AR=$arCount; CD=$cdCount; Total=$matchingRules.Count; KeyNames=$keyNames}
            [void]$phase4Sections.AppendLine("$vendor | $arCount | $cdCount | $($matchingRules.Count) | $ruleNames")
        }
        Write-Host "   ✅ ValueRef_Vendor: $($vendors.Count) vendors checked" -ForegroundColor Green
    } else {
        [void]$phase4Sections.AppendLine("EMPTY")
        Write-Host "   ℹ️  ValueRef_Vendor: EMPTY" -ForegroundColor DarkYellow
    }

    # ─── Health (Q11) ───────────────────────────────────────────────────────
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("### Health")

    $q11Data = $allResults["ingestion-q11"]
    if ($q11Data) {
        $health = if ($q11Data -is [array]) { $q11Data[0] } else { $q11Data }
        $totalRulesInHealth = [int]$health.TotalRules
        $totalExecutions    = [int64]$health.TotalExec
        $totalFailures      = [int64]$health.TotalFail
        $failingRuleCount   = [int]$health.FailingRules
        $successRate = if ($totalExecutions -gt 0) {
            [math]::Round(100.0 * ($totalExecutions - $totalFailures) / $totalExecutions, 1)
        } else { 0 }

        [void]$phase4Sections.AppendLine("TotalRulesInHealth: $totalRulesInHealth")
        [void]$phase4Sections.AppendLine("TotalExecutions: $totalExecutions")
        [void]$phase4Sections.AppendLine("TotalFailures: $totalFailures")
        [void]$phase4Sections.AppendLine("OverallSuccessRate: ${successRate}%")
        [void]$phase4Sections.AppendLine("FailingRuleCount: $failingRuleCount")
        Write-Host "   ✅ Health: $totalRulesInHealth rules, ${successRate}% success, $failingRuleCount failing" -ForegroundColor Green
    } else {
        [void]$phase4Sections.AppendLine("Status: UNAVAILABLE")
        Write-Host "   ⚠️  Health: Q11 returned no data" -ForegroundColor DarkYellow
    }

    # ─── Failing Rules (Q11d) ───────────────────────────────────────────────
    # Console status only; table rendered in PRERENDERED.HealthAlerts
    $q11dData = $allResults["ingestion-q11d"]
    if ($q11dData -and ($q11dData -is [array]) -and $q11dData.Count -gt 0) {
        Write-Host "   ✅ FailingRules: $($q11dData.Count) failing rules" -ForegroundColor Green
    } else {
        Write-Host "   ✅ FailingRules: NONE" -ForegroundColor Green
    }

    # ─── Alert Producing (Q12) ──────────────────────────────────────────────
    # Console status only; table rendered in PRERENDERED.HealthAlerts
    $q12Data = $allResults["ingestion-q12"]
    if ($q12Data -and ($q12Data -is [array]) -and $q12Data.Count -gt 0) {
        $totalAlerts = ($q12Data | ForEach-Object { [int]$_.AlertCount } | Measure-Object -Sum).Sum
        $alertRuleCount = $q12Data.Count
        Write-Host "   ✅ AlertProducing: $alertRuleCount rules, $totalAlerts total alerts" -ForegroundColor Green
    } else {
        Write-Host "   ✅ AlertProducing: No alerts in $($Days)d" -ForegroundColor Green
    }

    # ─── Cross-Validation: Q11 vs Q9 ───────────────────────────────────────
    [void]$phase4Sections.AppendLine("")
    [void]$phase4Sections.AppendLine("### CrossValidation")

    if ($q11Data) {
        $health = if ($q11Data -is [array]) { $q11Data[0] } else { $q11Data }
        $q11DistinctRules = [int]$health.TotalRules
        # Rule D: SentinelHealth only tracks AR executions, not CD. Use AR_Enabled as denominator.
        $q9Enabled = $arEnabled
        $gap = if ($q9Enabled -gt 0) {
            [math]::Round(100.0 * [math]::Abs($q9Enabled - $q11DistinctRules) / $q9Enabled, 1)
        } else { 0 }
        [void]$phase4Sections.AppendLine("Q11_DistinctRules: $q11DistinctRules")
        [void]$phase4Sections.AppendLine("Q9_AR_Enabled: $q9Enabled")
        [void]$phase4Sections.AppendLine("Gap: ${gap}%")
        Write-Host "   ✅ CrossValidation: Q11=$q11DistinctRules vs Q9_AR=$q9Enabled (gap ${gap}%)" -ForegroundColor Green
    } else {
        [void]$phase4Sections.AppendLine("Q11_DistinctRules: N/A")
        [void]$phase4Sections.AppendLine("Q9_AR_Enabled: $arEnabled")
        [void]$phase4Sections.AppendLine("Gap: N/A")
        Write-Host "   ⚠️  CrossValidation: Q11 unavailable" -ForegroundColor DarkYellow
    }

    $phase4Block = $phase4Sections.ToString().TrimEnd()
}

# Phase 5: Anomalies & Cost
# ═══════════════════════════════════════════════════════════════════════════════
$phase5Block = ""
if ($phasesToRun -contains 5) {
    Write-Host "`n📊 Computing Phase 5 metrics..." -ForegroundColor Yellow

    $phase5Sections = [System.Text.StringBuilder]::new()
    [void]$phase5Sections.AppendLine("")
    [void]$phase5Sections.AppendLine("## PHASE_5 — Anomalies & Cost")

    # ─── Anomaly24h (Q14) ───────────────────────────────────────────────────
    [void]$phase5Sections.AppendLine("")
    [void]$phase5Sections.AppendLine("### Anomaly24h")
    [void]$phase5Sections.AppendLine("<!-- DataType | Last24hGB | Avg7dGB | Deviation% | Severity -->")
    [void]$phase5Sections.AppendLine("<!-- Severity: Rule A thresholds (🟠 ≥200%+0.05GB, 🟡 ≥100%+0.01GB, ⚪ ≥50%+0.01GB) + overrides: rule-count (≥5 rules AND ≥40% → 🟠), near-zero (≤-95% AND ≥0.05GB → 🟠) -->")

    $q14Data = $allResults["ingestion-q14"]
    if ($q14Data -and ($q14Data -is [array]) -and $q14Data.Count -gt 0) {
        foreach ($row in $q14Data) {
            $last24h = [double]$row.Last24hGB
            $avg7d   = [double]$row.Avg7dDailyGB
            $dev     = [double]$row.DeviationPercent
            $maxVol  = [math]::Max($last24h, $avg7d)

            # Rule A severity classification
            $severity = if ([math]::Abs($dev) -ge 200 -and $maxVol -ge 0.05) { [char]::ConvertFromUtf32(0x1F7E0) }  # 🟠
                      elseif ([math]::Abs($dev) -ge 100 -and $maxVol -ge 0.01) { [char]::ConvertFromUtf32(0x1F7E1) }  # 🟡
                      else { [string][char]0x26AA }  # ⚪

            # Override 1 — Rule-count: ≥5 rules AND ≥40% absolute 24h deviation → 🟠
            # Rationale: a significant 24h drop on a table feeding multiple rules signals
            # a connector health emergency that needs same-day attention.
            if ($crossRef -and $crossRef.Count -gt 0) {
                $tableRules = $crossRef | Where-Object { $_.Table -eq $row.DataType }
                if ($tableRules -and $tableRules.Total -ge 5 -and [math]::Abs($dev) -ge 40) {
                    $severity = [char]::ConvertFromUtf32(0x1F7E0)  # 🟠 override
                }
            }

            # Override 2 — Near-zero: deviation ≤ -95% AND maxVol ≥ 0.05 GB → 🟠
            # Rationale: a near-complete signal loss on any significant table is an
            # operational emergency regardless of rule count.
            if ($dev -le -95 -and $maxVol -ge 0.05) {
                $severity = [char]::ConvertFromUtf32(0x1F7E0)  # 🟠 override
            }

            $sign = if ($dev -gt 0) { "+" } else { "" }
            [void]$phase5Sections.AppendLine("$($row.DataType) | $last24h | $avg7d | ${sign}${dev} | $severity")
        }
        Write-Host "   ✅ Anomaly24h: $($q14Data.Count) table(s) with >50% deviation" -ForegroundColor Green
    } else {
        [void]$phase5Sections.AppendLine("NONE — no tables deviate >50% with ≥0.01 GB volume")
        Write-Host "   ✅ Anomaly24h: NONE (no significant deviations)" -ForegroundColor Green
    }

    # ─── AnomalyWoW (Q15) ──────────────────────────────────────────────────
    [void]$phase5Sections.AppendLine("")
    [void]$phase5Sections.AppendLine("### AnomalyWoW")
    [void]$phase5Sections.AppendLine("<!-- DataType | ThisWeekGB | LastWeekGB | WoWChange% | Severity -->")
    [void]$phase5Sections.AppendLine("<!-- Severity: Rule A thresholds (🟠 ≥200%+0.05GB, 🟡 ≥100%+0.01GB, ⚪ ≥50%+0.01GB) + overrides: rule-count (≥5 rules AND ≥40% → 🟠), near-zero (≤-95% AND ≥0.05GB → 🟠) -->")

    $q15Data = $allResults["ingestion-q15"]
    if ($q15Data -and ($q15Data -is [array]) -and $q15Data.Count -gt 0) {
        foreach ($row in $q15Data) {
            $thisWeek = [double]$row.ThisWeekGB
            $lastWeek = [double]$row.LastWeekGB
            $change   = [double]$row.ChangePercent
            $maxVol   = [math]::Max($thisWeek, $lastWeek)

            # Rule A severity classification
            $severity = if ([math]::Abs($change) -ge 200 -and $maxVol -ge 0.05) { [char]::ConvertFromUtf32(0x1F7E0) }  # 🟠
                      elseif ([math]::Abs($change) -ge 100 -and $maxVol -ge 0.01) { [char]::ConvertFromUtf32(0x1F7E1) }  # 🟡
                      else { [string][char]0x26AA }  # ⚪

            # Override 1 — Rule-count: ≥5 rules AND ≥40% absolute WoW change → 🟠
            if ($crossRef -and $crossRef.Count -gt 0) {
                $tableRules = $crossRef | Where-Object { $_.Table -eq $row.DataType }
                if ($tableRules -and $tableRules.Total -ge 5 -and [math]::Abs($change) -ge 40) {
                    $severity = [char]::ConvertFromUtf32(0x1F7E0)  # 🟠 override
                }
            }

            # Override 2 — Near-zero: change ≤ -95% AND maxVol ≥ 0.05 GB → 🟠
            if ($change -le -95 -and $maxVol -ge 0.05) {
                $severity = [char]::ConvertFromUtf32(0x1F7E0)  # 🟠 override
            }

            $sign = if ($change -gt 0) { "+" } else { "" }
            [void]$phase5Sections.AppendLine("$($row.DataType) | $thisWeek | $lastWeek | ${sign}${change} | $severity")
        }
        Write-Host "   ✅ AnomalyWoW: $($q15Data.Count) table(s) with significant WoW change" -ForegroundColor Green
    } else {
        [void]$phase5Sections.AppendLine("NONE — no tables with >20% WoW change or >0.1 GB")
        Write-Host "   ✅ AnomalyWoW: NONE (no significant WoW changes)" -ForegroundColor Green
    }

    # ─── DL Classification (scripted, no query) ────────────────────────────
    [void]$phase5Sections.AppendLine("")
    [void]$phase5Sections.AppendLine("### DL_Script_Output")
    [void]$phase5Sections.AppendLine("<!-- TableName | DL_Eligible -->")

    # Hardcoded DL eligibility reference lists (authoritative — from v1 SKILL.md)
    # XDR tables: always available in Advanced Hunting (30d retention regardless of Sentinel tier).
    # Custom Detection rules work against these even on Data Lake.
    $xdrTables = @(
        "CloudAppEvents","DeviceEvents","DeviceFileCertificateInfo","DeviceFileEvents","DeviceImageLoadEvents",
        "DeviceInfo","DeviceLogonEvents","DeviceNetworkEvents","DeviceNetworkInfo","DeviceProcessEvents",
        "DeviceRegistryEvents","EmailAttachmentInfo","EmailEvents","EmailPostDeliveryEvents","EmailUrlInfo","UrlClickEvents"
    )
    $dlYes = @(
        # Defender XDR tables (GA Feb 2025)
        "CloudAppEvents","DeviceEvents","DeviceFileCertificateInfo","DeviceFileEvents","DeviceImageLoadEvents",
        "DeviceInfo","DeviceLogonEvents","DeviceNetworkEvents","DeviceNetworkInfo","DeviceProcessEvents",
        "DeviceRegistryEvents","EmailAttachmentInfo","EmailEvents","EmailPostDeliveryEvents","EmailUrlInfo","UrlClickEvents",
        # Verified LA tables
        "AADManagedIdentitySignInLogs","AADNonInteractiveUserSignInLogs","AADProvisioningLogs","AADServicePrincipalSignInLogs",
        "AADUserRiskEvents","AuditLogs","AWSCloudTrail","AzureDiagnostics","CommonSecurityLog","Event","GCPAuditLogs",
        "LAQueryLogs","McasShadowItReporting","MicrosoftGraphActivityLogs","OfficeActivity","Perf","SecurityAlert","SecurityEvent","SecurityIncident","SentinelHealth","SigninLogs",
        "StorageBlobLogs","Syslog","W3CIISLog","WindowsEvent","WindowsFirewall"
    )
    $dlNo = @(
        "DeviceTvmSoftwareInventory","DeviceTvmSoftwareVulnerabilities","AlertEvidence","AlertInfo",
        "IdentityDirectoryEvents","IdentityLogonEvents","IdentityQueryEvents",
        "MicrosoftServicePrincipalSignInLogs","MicrosoftNonInteractiveUserSignInLogs","MicrosoftManagedIdentitySignInLogs",
        "ThreatIntelIndicators","ThreatIntelligenceIndicator",
        "AppDependencies","AppMetrics","AppPerformanceCounters","AppTraces","AzureActivity","AzureMetrics",
        "ConfigurationChange","Heartbeat","SecurityRecommendation"
    )

    # Build classification from Q16 migration candidates + Q1 tables
    $q16Data = $allResults["ingestion-q16"]
    $q1Data  = $allResults["ingestion-q1"]
    $dlTables = @()
    if ($q16Data -and ($q16Data -is [array])) {
        $dlTables += @($q16Data | ForEach-Object { $_.DataType } | Where-Object { $_ })
    }
    if ($q1Data -and ($q1Data -is [array])) {
        $dlTables += @($q1Data | ForEach-Object { $_.DataType } | Where-Object { $_ })
    }
    $dlTables = @($dlTables | Select-Object -Unique)

    $dlClass = @{}
    foreach ($t in $dlTables) {
        if     ($t -like "*_KQL_CL")  { $dlClass[$t] = "KQL"     }
        elseif ($t -like "*_CL")      { $dlClass[$t] = "Yes"     }
        elseif ($t -in $dlYes)        { $dlClass[$t] = "Yes"     }
        elseif ($t -in $dlNo)         { $dlClass[$t] = "No"      }
        else                          { $dlClass[$t] = "Unknown" }
    }

    foreach ($entry in ($dlClass.GetEnumerator() | Sort-Object Value, Key)) {
        [void]$phase5Sections.AppendLine("$($entry.Key) | $($entry.Value)")
    }
    Write-Host "   ✅ DL Classification: $($dlClass.Count) tables classified (Yes=$(@($dlClass.Values | Where-Object {$_ -eq 'Yes'}).Count), No=$(@($dlClass.Values | Where-Object {$_ -eq 'No'}).Count), Unknown=$(@($dlClass.Values | Where-Object {$_ -eq 'Unknown'}).Count), KQL=$(@($dlClass.Values | Where-Object {$_ -eq 'KQL'}).Count))" -ForegroundColor Green

    # ─── Migration Table ────────────────────────────────────────────────────
    # Console status only; tables rendered in PRERENDERED.Migration

    if ($q16Data -and ($q16Data -is [array]) -and $q16Data.Count -gt 0) {
        $q10Data = $allResults["ingestion-q10"]
        $migrationRows = @()

        foreach ($row in $q16Data) {
            $table  = $row.DataType
            $gb7d   = [double]$row.BillableGB

            # Rule counts from CrossRef (Phase 4)
            $cr     = if ($crossRef) { $crossRef | Where-Object { $_.Table -eq $table } } else { $null }
            $arCount = if ($cr) { $cr.AR } else { 0 }
            $cdCount = if ($cr) { $cr.CD } else { 0 }
            $total   = if ($cr) { $cr.Total } else { 0 }

            # Tier from Q10
            $tier = "Analytics"
            if ($q10Data -and ($q10Data -is [array])) {
                $tierEntry = $q10Data | Where-Object { $_.name -eq $table }
                if ($tierEntry) {
                    $tier = switch ($tierEntry.plan) {
                        "Auxiliary" { "Data Lake" }
                        "Basic"     { "Basic" }
                        default     { "Analytics" }
                    }
                }
            }

            # DL eligibility from classification above
            $dlElig = if ($dlClass.ContainsKey($table)) { $dlClass[$table] } else { "Unknown" }

            # Category classification (from v1 SKILL.md Q15 criteria)
            $category = ""
            $subTable = ""
            if ($table -like "*_KQL_CL") {
                $category = [char]::ConvertFromUtf32(0x1F535) + " KQL Job"                          # 🔵
                $subTable = "Sub-table 2"
            } elseif ($tier -eq "Data Lake" -and $total -eq 0) {
                $category = [char]::ConvertFromUtf32(0x1F535) + " Already DL"                       # 🔵
                $subTable = "Sub-table 4"
            } elseif ($tier -in @("Data Lake","Basic") -and $total -gt 0) {
                if ($table -in $xdrTables) {
                    $category = [char]::ConvertFromUtf32(0x1F534) + " Detection gap (XDR)"        # 🔴
                } else {
                    $category = [char]::ConvertFromUtf32(0x1F534) + " Detection gap (non-XDR)"    # 🔴
                }
                $subTable = "Sub-table 3"
            } elseif ($total -eq 0 -and $dlElig -eq "Yes") {
                $category = [char]::ConvertFromUtf32(0x1F534) + " Strong (DL-eligible)"             # 🔴
                $subTable = "Sub-table 1"
            } elseif ($total -eq 0 -and $dlElig -in @("No","Unknown")) {
                $category = [char]::ConvertFromUtf32(0x1F7E0) + " Not eligible/unknown"             # 🟠
                $subTable = "Sub-table 2"
            } elseif ($total -in @(1,2) -and $gb7d -ge 5.0 -and $dlElig -eq "Yes") {
                $category = [char]::ConvertFromUtf32(0x1F7E3) + " Split candidate"                  # 🟣
                $subTable = "Sub-table 3"
            } elseif ($total -ge 1) {
                $category = [char]::ConvertFromUtf32(0x1F7E2) + " Keep ($total rules)"              # 🟢
                $subTable = "Sub-table 3"
            } else {
                $category = [char]::ConvertFromUtf32(0x1F7E0) + " Not eligible/unknown"             # 🟠
                $subTable = "Sub-table 2"
            }

            $migrationRows += [PSCustomObject]@{
                Table=$table; GB7d=$gb7d; AR=$arCount; CD=$cdCount; Total=$total
                Tier=$tier; DLElig=$dlElig; Category=$category; SubTable=$subTable
            }
        }

        $dlCandidates = @($migrationRows | Where-Object { $_.SubTable -eq "Sub-table 1" }).Count
        $keepRules    = @($migrationRows | Where-Object { $_.SubTable -eq "Sub-table 3" }).Count
        $alreadyDL    = @($migrationRows | Where-Object { $_.SubTable -eq "Sub-table 4" }).Count
        Write-Host "   ✅ Migration: $($migrationRows.Count) tables — $dlCandidates DL candidates, $keepRules with rules, $alreadyDL already DL" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Migration: Q16 returned no data" -ForegroundColor DarkYellow
    }

    # ─── License Benefits (Q17) ─────────────────────────────────────────────
    [void]$phase5Sections.AppendLine("")
    [void]$phase5Sections.AppendLine("### LicenseBenefits")

    $q17Data = $allResults["ingestion-q17"]
    if ($q17Data -and ($q17Data -is [array]) -and $q17Data.Count -gt 0) {
        $dfsp2Daily = ($q17Data | ForEach-Object { ConvertTo-SafeDouble $_.DFSP2GB } | Measure-Object -Average).Average
        $e5Daily    = ($q17Data | ForEach-Object { ConvertTo-SafeDouble $_.E5GB }    | Measure-Object -Average).Average
        $remDaily   = ($q17Data | ForEach-Object { ConvertTo-SafeDouble $_.RemainingGB } | Measure-Object -Average).Average
        $dfsp2Sum   = ($q17Data | ForEach-Object { ConvertTo-SafeDouble $_.DFSP2GB } | Measure-Object -Sum).Sum
        $e5Sum      = ($q17Data | ForEach-Object { ConvertTo-SafeDouble $_.E5GB }    | Measure-Object -Sum).Sum
        $remSum     = ($q17Data | ForEach-Object { ConvertTo-SafeDouble $_.RemainingGB } | Measure-Object -Sum).Sum

        # Server count from Phase 2 SE_Computer (TotalServers column = dcount(Computer), not row count)
        $q4Data = $allResults["ingestion-q4"]
        $serverCount = if ($q4Data -and ($q4Data -is [array]) -and $q4Data.Count -gt 0 -and $q4Data[0].TotalServers) {
            [int]$q4Data[0].TotalServers
        } elseif ($q4Data -and ($q4Data -is [array])) { $q4Data.Count } else { 0 }
        $dfsp2Pool   = [math]::Round($serverCount * 0.5, 3)

        [void]$phase5Sections.AppendLine("DfSP2_DailyGB: $([math]::Round($dfsp2Daily, 3))")
        [void]$phase5Sections.AppendLine("E5_DailyGB: $([math]::Round($e5Daily, 3))")
        [void]$phase5Sections.AppendLine("Remaining_DailyGB: $([math]::Round($remDaily, 3))")
        [void]$phase5Sections.AppendLine("DfSP2_$($Days)dGB: $([math]::Round($dfsp2Sum, 3))")
        [void]$phase5Sections.AppendLine("E5_$($Days)dGB: $([math]::Round($e5Sum, 3))")
        [void]$phase5Sections.AppendLine("Remaining_$($Days)dGB: $([math]::Round($remSum, 3))")
        [void]$phase5Sections.AppendLine("ServerCount: $serverCount")
        [void]$phase5Sections.AppendLine("DfSP2_PoolGB: $dfsp2Pool")
        Write-Host "   ✅ LicenseBenefits: DfSP2=$([math]::Round($dfsp2Daily, 3)) GB/d, E5=$([math]::Round($e5Daily, 3)) GB/d, Remaining=$([math]::Round($remDaily, 3)) GB/d (${serverCount} servers)" -ForegroundColor Green
    } else {
        [void]$phase5Sections.AppendLine("Status: UNAVAILABLE")
        Write-Host "   ⚠️  LicenseBenefits: Q17 returned no data" -ForegroundColor DarkYellow
    }

    # ─── E5 Per-Table (Q17b) ────────────────────────────────────────────────
    # Console status only; table rendered in PRERENDERED.E5Tables
    $q17bData = $allResults["ingestion-q17b"]
    if ($q17bData -and ($q17bData -is [array]) -and $q17bData.Count -gt 0) {
        Write-Host "   ✅ E5_Tables: $($q17bData.Count) E5-eligible tables with data" -ForegroundColor Green
    } else {
        Write-Host "   ✅ E5_Tables: NONE (no E5-eligible tables with billable data)" -ForegroundColor Green
    }

    # TopRecommendations: deliberately omitted — Rule E scoring is deferred to the
    # LLM at render time. The scratchpad already contains all data the LLM needs
    # (Migration, CrossRef, Health, SE_EventID, Anomalies, Tiers) and the LLM can
    # apply the full 7-category Rule E formula including qualitative categories
    # (DCR filter, Split ingestion, Data loss) that require cross-section reasoning.

    $phase5Block = $phase5Sections.ToString().TrimEnd()
}

# ═══════════════════════════════════════════════════════════════════════════════
# Write combined scratchpad
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "`n📝 Writing scratchpad..." -ForegroundColor Yellow

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$scratchpadPath = Join-Path $OutputDir "ingest_scratch_${timestamp}.md"

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Period comes from Q2 (daily trend) if available, otherwise use current date
$periodLabel = if ($dailyTrend -and $dailyTrend.Count -gt 0) {
    "$($dailyTrend[0].Date.ToString('yyyy-MM-dd')) to $($dailyTrend[-1].Date.ToString('yyyy-MM-dd'))"
} else {
    "$(Get-Date -Format 'yyyy-MM-dd') (partial)"
}

# ReportPeriod: excludes partial report-generation day, includes day count (Rule C)
$reportPeriod = if ($dailyTrend -and $dailyTrend.Count -gt 0) {
    $generatedDateStr = (Get-Date).ToString('yyyy-MM-dd')
    $lastDay = $dailyTrend[-1]
    if ($lastDay.Date.ToString('yyyy-MM-dd') -eq $generatedDateStr -and $dailyTrend.Count -gt 1) {
        # Partial day = last entry; use second-to-last as end date
        $endDay = $dailyTrend[-2]
        $dayCount = $dailyTrend.Count - 1
        "$($dailyTrend[0].Date.ToString('yyyy-MM-dd')) to $($endDay.Date.ToString('yyyy-MM-dd')) ($dayCount days)"
    } else {
        # No partial day detected; use all days
        $dayCount = $dailyTrend.Count
        "$($dailyTrend[0].Date.ToString('yyyy-MM-dd')) to $($lastDay.Date.ToString('yyyy-MM-dd')) ($dayCount days)"
    }
} else {
    "Unknown"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PRERENDERED blocks — deterministic content the LLM copies verbatim
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "📐 Building PRERENDERED blocks..." -ForegroundColor Yellow
$prerenderedSections = [System.Text.StringBuilder]::new()

# ─── PRERENDERED.Headings ────────────────────────────────────────────────
# All report section headings — LLM copies these exactly, eliminating drift
[void]$prerenderedSections.AppendLine("### Headings")
[void]$prerenderedSections.AppendLine(@"
## 1. Executive Summary
### 📊 Workspace at a Glance
### 💰 Cost Waterfall
### 🛡️ Detection Posture
### Overall Assessment
### 🎯 Top 3 Recommendations
## 2. Ingestion Overview
### 2a. Top Tables by Volume
### 2b. Tier Classification
## 3. Deep Dives
### 3a. SecurityEvent
### 3b. Syslog
### 3c. CommonSecurityLog
## 4. Anomaly Detection
### 4a. Per-Table Anomaly Summary (24h + WoW)
### 4b. Daily Trend ($Days Days)
## 5. Detection Coverage
### 5a. Rule Inventory & Table Cross-Reference
### 5b. Rule Health & Alerts
## 6. License Benefit Analysis
### 6a. Defender for Servers P2 Pool Detail
### 6b. E5 / Defender XDR Pool Detail
## 7. Optimization Recommendations
### 7a. Data Lake Migration Candidates
### 7b. ⚡ Quick Wins
### 7c. 🔧 Medium-Term Optimizations
### 7d. 🔄 Ongoing Maintenance
## 8. Appendix
### 8a. Query Reference
### 8b. Data Freshness
### 8c. Methodology
### 8d. Limitations
"@.TrimEnd())

# ─── PRERENDERED.CostWaterfall ───────────────────────────────────────────
# ASCII subtraction diagram — requires Phase 1 + Phase 5 data
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### CostWaterfall")
if ($phasesToRun -contains 1 -and $phasesToRun -contains 5 -and $totalGB -and $remDaily) {
    $dayCount = if ($dailyTrend -and $dailyTrend.Count -gt 0) { $dailyTrend.Count } else { 30 }
    $totalDaily      = [math]::Round($totalGB / $dayCount, 3)
    $nonBillDaily    = [math]::Round($nonBillableGB / $dayCount, 3)
    $grossBillable   = $billableGB
    $grossBillDaily  = [math]::Round($billableGB / $dayCount, 3)

    [void]$prerenderedSections.AppendLine(@"
``````
                                    $($Days)-Day (GB)    Avg/Day (GB)
  Total Ingestion                     $(([double]$totalGB).ToString('F3').PadLeft(7))          $(([double]$totalDaily).ToString('F3').PadLeft(7))
  - Non-Billable                     -$(([double]$nonBillableGB).ToString('F3').PadLeft(7))         -$(([double]$nonBillDaily).ToString('F3').PadLeft(7))
  ──────────────────────────────────────────────────────────────
  Gross Billable                      $(([double]$grossBillable).ToString('F3').PadLeft(7))          $(([double]$grossBillDaily).ToString('F3').PadLeft(7))
  - Est. E5/XDR Benefit              -$(([double]$e5Sum).ToString('F3').PadLeft(7))         -$(([double]$e5Daily).ToString('F3').PadLeft(7))
  - Est. DfS P2 Benefit              -$(([double]$dfsp2Sum).ToString('F3').PadLeft(7))         -$(([double]$dfsp2Daily).ToString('F3').PadLeft(7))
  ──────────────────────────────────────────────────────────────
  🎯 Est. Net Billable               ~$(([double]$remSum).ToString('F3').PadLeft(7))         ~$(([double]$remDaily).ToString('F3').PadLeft(7))
``````
"@.TrimEnd())
    Write-Host "   ✅ CostWaterfall: rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("UNAVAILABLE — requires Phase 1 + Phase 5 data")
    Write-Host "   ⚠️  CostWaterfall: skipped (missing phase data)" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.DailyChart ──────────────────────────────────────────────
# ASCII bar chart with weekday averages — requires Phase 1 data
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### DailyChart")
if ($phasesToRun -contains 1 -and $dailyTrend -and $dailyTrend.Count -gt 0) {
    $generatedDate = (Get-Date).ToString('yyyy-MM-dd')
    $maxBarWidth = 50

    # Rule C: exclude partial day (report-generation day) and days < 0.1 GB
    $fullDays = $dailyTrend | Where-Object {
        $_.Date.ToString('yyyy-MM-dd') -ne $generatedDate -and $_.GB -ge 0.1
    }
    if (-not $fullDays -or $fullDays.Count -eq 0) { $fullDays = $dailyTrend }

    $chartAvg = [math]::Round(($fullDays | Measure-Object -Property GB -Average).Average, 3)
    $chartPeak = $fullDays | Sort-Object GB -Descending | Select-Object -First 1
    $chartMin  = $fullDays | Sort-Object GB | Select-Object -First 1
    $maxGB = ($dailyTrend | Measure-Object -Property GB -Maximum).Maximum
    if ($maxGB -le 0) { $maxGB = 1 }

    # Weekday averages (Rule C applied)
    $weekdayAvgs = @{}
    foreach ($dayName in @('Mon','Tue','Wed','Thu','Fri','Sat','Sun')) { $weekdayAvgs[$dayName] = @() }
    foreach ($d in $fullDays) {
        $wd = $d.Date.ToString('ddd')
        $weekdayAvgs[$wd] += $d.GB
    }
    $weekdayLine = @()
    foreach ($dayName in @('Mon','Tue','Wed','Thu','Fri','Sat','Sun')) {
        $vals = $weekdayAvgs[$dayName]
        if ($vals.Count -gt 0) {
            $avg = [math]::Round(($vals | Measure-Object -Average).Average, 2)
            $weekdayLine += "$dayName $($avg.ToString('F2'))"
        } else {
            $weekdayLine += "$dayName —"
        }
    }

    $chartLines = [System.Text.StringBuilder]::new()
    [void]$chartLines.AppendLine("``````")
    [void]$chartLines.AppendLine("Daily Ingestion — $workspaceName ($periodLabel)")
    [void]$chartLines.AppendLine("Date          GB     Trend (max = $(([double]$maxGB).ToString('F2')) GB)")
    [void]$chartLines.AppendLine([string]::new([char]0x2500, 65))  # ─ line
    foreach ($d in $dailyTrend) {
        $barLen = [math]::Max(1, [math]::Round($d.GB / $maxGB * $maxBarWidth))
        $bar = [string]::new([char]0x2588, $barLen)  # █
        $annotation = ""
        if ($d.Date -eq $chartPeak.Date) { $annotation = " ← peak" }
        elseif ($d.Date -eq $chartMin.Date) { $annotation = " ← min" }
        elseif ($d.Date.ToString('yyyy-MM-dd') -eq $generatedDate) { $annotation = " ← partial" }
        [void]$chartLines.AppendLine("$($d.Date.ToString('yyyy-MM-dd')) │ $(([double]$d.GB).ToString('F3').PadLeft(6))  $bar$annotation")
    }
    [void]$chartLines.AppendLine([string]::new([char]0x2500, 65))
    [void]$chartLines.AppendLine("Avg: $(([double]$chartAvg).ToString('F3')) GB/day  Peak: $(([double]$chartPeak.GB).ToString('F3')) GB ($($chartPeak.Date.ToString('yyyy-MM-dd')))  Min: $(([double]$chartMin.GB).ToString('F3')) GB ($($chartMin.Date.ToString('yyyy-MM-dd')))")
    [void]$chartLines.AppendLine("Weekday Avgs: $($weekdayLine -join ' | ')")
    [void]$chartLines.Append("``````")

    [void]$prerenderedSections.AppendLine($chartLines.ToString())
    Write-Host "   ✅ DailyChart: $($dailyTrend.Count) days, avg $chartAvg GB/day" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("UNAVAILABLE — requires Phase 1 data")
    Write-Host "   ⚠️  DailyChart: skipped (missing Phase 1 data)" -ForegroundColor DarkYellow
}

# Emoji constants for PRERENDERED blocks
$emojiRed    = [char]::ConvertFromUtf32(0x1F534)  # 🔴
$emojiOrange = [char]::ConvertFromUtf32(0x1F7E0)  # 🟠
$emojiYellow = [char]::ConvertFromUtf32(0x1F7E1)  # 🟡
$emojiGreen  = [char]::ConvertFromUtf32(0x1F7E2)  # 🟢
$emojiPurple = [char]::ConvertFromUtf32(0x1F7E3)  # 🟣
$emojiBlue   = [char]::ConvertFromUtf32(0x1F535)  # 🔵
$emojiShield = [char]::ConvertFromUtf32(0x1F6E1)  # 🛡️
$emojiCheck  = [string][char]0x2705               # ✅
$emojiWarn   = "$([string][char]0x26A0)$([string][char]0xFE0F)"  # ⚠️
$emojiWhite  = [string][char]0x26AA               # ⚪
$emDash      = [string][char]0x2014               # —
$enDash      = [string][char]0x2013               # –
$gteq        = [string][char]0x2265               # ≥
$middleDot   = [string][char]0x00B7               # ·
# Syslog facility security-relevance badges
$emojiFacLock  = [char]::ConvertFromUtf32(0x1F512)  # 🔒
$emojiFacGear  = "$([string][char]0x2699)$([string][char]0xFE0F)"  # ⚙️
$emojiFacClock = [string][char]0x23F0               # ⏰
$emojiFacMail  = [char]::ConvertFromUtf32(0x1F4EC)  # 📬
$emojiFacMemo  = [char]::ConvertFromUtf32(0x1F4DD)  # 📝
$emojiFacSat   = [char]::ConvertFromUtf32(0x1F4E1)  # 📡
$emojiBlack    = [string][char]0x26AB               # ⚫
# Facility badge lookup
$facilityBadges = @{
    'auth'=$emojiFacLock; 'authpriv'=$emojiFacLock
    'daemon'=$emojiFacGear; 'kern'=$emojiFacGear
    'cron'=$emojiFacClock
    'mail'=$emojiFacMail
    'user'=$emojiFacMemo; 'syslog'=$emojiFacMemo; 'lpr'=$emojiFacMemo; 'news'=$emojiFacMemo; 'uucp'=$emojiFacMemo; 'ftp'=$emojiFacMemo
}
# Severity emoji lookup (RFC 5424)
$sevEmojis = @{
    'emerg'=$emojiRed; 'alert'=$emojiRed; 'crit'=$emojiRed
    'error'=$emojiOrange
    'warning'=$emojiYellow
    'notice'=$emojiBlue
    'info'=$emojiWhite
    'debug'=$emojiBlack
}

# ─── PRERENDERED.TopTables ───────────────────────────────────────────────
# §2a Top Tables by Volume — merged table with volume bands, rules, tier
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### TopTables")
if ($phasesToRun -contains 1 -and $phasesToRun -contains 3 -and $phasesToRun -contains 4 -and $q1Data -and $q1Data.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Volume | # | DataType | BillableGB ($($Days)d) | Avg/Day (GB) | % | Rules | Current Tier |")
    [void]$prerenderedSections.AppendLine("|--------|---|----------|------------------|--------------|---|-------|--------------|")
    $rowNum = 0
    foreach ($row in $q1Data) {
        $rowNum++
        $gb = [double]$row.BillableGB
        # Volume band emoji
        $volEmoji = if ($gb -ge 500) { $emojiRed }
                   elseif ($gb -ge 100) { $emojiOrange }
                   elseif ($gb -ge 10) { $emojiYellow }
                   else { $emojiGreen }
        # Percentage of workspace-wide total billable (from Q3)
        $pct = if ([double]$billableGB -gt 0) { [math]::Round($gb / [double]$billableGB * 100, 1) } else { 0 }
        # Rules from CrossRef
        $ruleMatch = if ($crossRef -and $crossRef.Count -gt 0) { $crossRef | Where-Object { $_.Table -eq $row.DataType } } else { $null }
        $ruleTotal = if ($ruleMatch) { [int]$ruleMatch.Total } else { 0 }
        # Tier lookup from Q10
        $tierMatch = if ($q10Data -and $q10Data.Count -gt 0) { $q10Data | Where-Object { $_.name -eq $row.DataType } } else { $null }
        $tier = if ($tierMatch -and $tierMatch.plan -eq "Auxiliary") { "Data Lake" }
               elseif ($tierMatch -and $tierMatch.plan -eq "Basic") { "Basic" }
               else { "Analytics" }
        # Rules badge with emoji
        $rulesBadge = if ($ruleTotal -ge 50) { "$emojiPurple $ruleTotal" }
                     elseif ($ruleTotal -ge 10) { "$emojiGreen $ruleTotal" }
                     elseif ($ruleTotal -ge 3) { "$emojiYellow $ruleTotal" }
                     elseif ($ruleTotal -ge 1) { "$emojiOrange $ruleTotal" }
                     elseif ($tier -in @("Analytics","Basic")) { "$emojiWarn 0" }
                     else { "0" }
        $avgDaily = if ($row.AvgDailyGB) { [math]::Round([double]$row.AvgDailyGB, 3) } else {
            $dc = if ($dailyTrend -and $dailyTrend.Count -gt 0) { $dailyTrend.Count } else { 30 }
            [math]::Round($gb / [math]::Max(1, $dc), 3)
        }
        [void]$prerenderedSections.AppendLine("| $volEmoji | $rowNum | $($row.DataType) | $([math]::Round($gb, 3)) | $avgDaily | $pct% | $rulesBadge | $tier |")
    }
    # Totals line
    $pctBillable = if ([double]$totalGB -gt 0) { [math]::Round([double]$billableGB / [double]$totalGB * 100, 1) } else { 0 }
    [void]$prerenderedSections.AppendLine("")
    $avgDailyTotal = [math]::Round([double]$avgDailyGB, 3)
    [void]$prerenderedSections.AppendLine("**Totals (all $totalTableCount tables, $($Days)d):** $([math]::Round([double]$totalGB, 3)) GB total, $([math]::Round([double]$billableGB, 3)) GB billable ($pctBillable%), $([math]::Round([double]$nonBillableGB, 3)) GB non-billable, $avgDailyTotal GB avg/day")
    # Legend (always full 4-band + 5-band)
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed ${gteq}500 GB $middleDot $emojiOrange 100${enDash}499 GB $middleDot $emojiYellow 10${enDash}99 GB $middleDot $emojiGreen <10 GB  |  $emojiPurple 50+ rules $middleDot $emojiGreen 10-49 $middleDot $emojiYellow 3-9 $middleDot $emojiOrange 1-2 $middleDot $emojiWarn 0 (no detections $emDash Analytics/Basic only)")
    Write-Host "   ✅ TopTables: $($q1Data.Count) tables rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("UNAVAILABLE $emDash requires Phase 1 + Phase 3 + Phase 4 data")
    Write-Host "   ⚠️  TopTables: skipped (missing phase data)" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.DetectionPosture ────────────────────────────────────────
# §1 Detection Posture — pre-rendered 7-row metric table
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### DetectionPosture")
if ($phasesToRun -contains 1 -and $phasesToRun -contains 3 -and $phasesToRun -contains 4) {
    # Count "Tables with Rules" vs "Tables with Zero Rules" from top-20
    $tablesWithRules = 0
    $tablesZeroRules = 0
    if ($q1Data -and $q1Data.Count -gt 0) {
        foreach ($row in $q1Data) {
            $rm = if ($crossRef -and $crossRef.Count -gt 0) { $crossRef | Where-Object { $_.Table -eq $row.DataType } } else { $null }
            if ($rm -and [int]$rm.Total -ge 1) { $tablesWithRules++ } else { $tablesZeroRules++ }
        }
    }
    $top20Count = if ($q1Data) { $q1Data.Count } else { 0 }
    # Enabled Scheduled = AR_Enabled − AR_NRT (per SKILL-report.md rule)
    $enabledScheduled = $arEnabled - $arNRT
    # Count Basic and DL tables from Q10
    $basicTierCount = 0; $dlTierCount = 0
    if ($q10Data -and ($q10Data -is [array]) -and $q10Data.Count -gt 0) {
        $basicTierCount = @($q10Data | Where-Object { $_.plan -eq "Basic" }).Count
        $dlTierCount    = @($q10Data | Where-Object { $_.plan -eq "Auxiliary" }).Count
    }
    [void]$prerenderedSections.AppendLine("| Metric | Value |")
    [void]$prerenderedSections.AppendLine("|--------|-------|")
    [void]$prerenderedSections.AppendLine("| $emojiShield Enabled Analytic Rules | $arEnabled ($enabledScheduled Scheduled, $arNRT NRT) |")
    if ($cdStatus) {
        [void]$prerenderedSections.AppendLine("| $emojiWarn Enabled Custom Detections | SKIPPED |")
    } else {
        [void]$prerenderedSections.AppendLine("| $emojiShield Enabled Custom Detections | $cdEnabled |")
    }
    $totalDisabled = $arDisabled + $cdDisabled
    $disabledEmoji = if ($totalDisabled -gt 0) { $emojiYellow } else { $emojiCheck }
    [void]$prerenderedSections.AppendLine("| $disabledEmoji Disabled Rules (AR + CD) | $arDisabled + $cdDisabled |")
    $withRulesEmoji = if ($tablesWithRules -ge 15) { $emojiGreen } elseif ($tablesWithRules -ge 10) { $emojiYellow } else { $emojiOrange }
    [void]$prerenderedSections.AppendLine("| $withRulesEmoji Tables with Rules (top-20) | $tablesWithRules of $top20Count |")
    $zeroEmoji = if ($tablesZeroRules -eq 0) { $emojiCheck } elseif ($tablesZeroRules -le 5) { $emojiYellow } else { $emojiOrange }
    [void]$prerenderedSections.AppendLine("| $zeroEmoji Tables with Zero Rules (top-20) | $tablesZeroRules of $top20Count |")
    [void]$prerenderedSections.AppendLine("| $emojiBlue Tables on Basic Tier | $basicTierCount |")
    [void]$prerenderedSections.AppendLine("| $emojiBlue Tables on Data Lake Tier | $dlTierCount |")
    Write-Host "   ✅ DetectionPosture: $tablesWithRules/$top20Count tables with rules" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("UNAVAILABLE $emDash requires Phase 1 + Phase 3 + Phase 4 data")
    Write-Host "   ⚠️  DetectionPosture: skipped (missing phase data)" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.AnomalyTable ────────────────────────────────────────────
# §4a Anomaly Summary — merged Anomaly24h + AnomalyWoW into single unified table
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### AnomalyTable")
if ($phasesToRun -contains 5) {
    $anomalyMerge = @{}
    # Populate from q14 (24h anomalies)
    if ($q14Data -and ($q14Data -is [array]) -and $q14Data.Count -gt 0) {
        foreach ($row in $q14Data) {
            $dt = $row.DataType
            $last24h = [double]$row.Last24hGB
            $avg7d   = [double]$row.Avg7dDailyGB
            $dev     = [double]$row.DeviationPercent
            $maxVol  = [math]::Max($last24h, $avg7d)
            # Rule A severity + overrides (same logic as phase5Sections)
            $sev = if ([math]::Abs($dev) -ge 200 -and $maxVol -ge 0.05) { $emojiOrange }
                  elseif ([math]::Abs($dev) -ge 100 -and $maxVol -ge 0.01) { $emojiYellow }
                  else { $emojiWhite }
            if ($crossRef -and $crossRef.Count -gt 0) {
                $tr = $crossRef | Where-Object { $_.Table -eq $dt }
                if ($tr -and $tr.Total -ge 5 -and [math]::Abs($dev) -ge 40) { $sev = $emojiOrange }
            }
            if ($dev -le -95 -and $maxVol -ge 0.05) { $sev = $emojiOrange }
            $sign = if ($dev -gt 0) { "+" } else { "" }
            $anomalyMerge[$dt] = @{
                Last24h = $last24h; Avg7d = $avg7d
                Dev24h  = "${sign}${dev}%"; Sev24 = $sev
                ThisWeek = $emDash; LastWeek = $emDash
                WoW = $emDash; SevWoW = $null
            }
        }
    }
    # Merge from q15 (WoW anomalies)
    if ($q15Data -and ($q15Data -is [array]) -and $q15Data.Count -gt 0) {
        foreach ($row in $q15Data) {
            $dt = $row.DataType
            $thisW = [double]$row.ThisWeekGB
            $lastW = [double]$row.LastWeekGB
            $chg   = [double]$row.ChangePercent
            $maxVol = [math]::Max($thisW, $lastW)
            $sev = if ([math]::Abs($chg) -ge 200 -and $maxVol -ge 0.05) { $emojiOrange }
                  elseif ([math]::Abs($chg) -ge 100 -and $maxVol -ge 0.01) { $emojiYellow }
                  else { $emojiWhite }
            if ($crossRef -and $crossRef.Count -gt 0) {
                $tr = $crossRef | Where-Object { $_.Table -eq $dt }
                if ($tr -and $tr.Total -ge 5 -and [math]::Abs($chg) -ge 40) { $sev = $emojiOrange }
            }
            if ($chg -le -95 -and $maxVol -ge 0.05) { $sev = $emojiOrange }
            $sign = if ($chg -gt 0) { "+" } else { "" }
            if ($anomalyMerge.ContainsKey($dt)) {
                $anomalyMerge[$dt].ThisWeek = $thisW
                $anomalyMerge[$dt].LastWeek = $lastW
                $anomalyMerge[$dt].WoW      = "${sign}${chg}%"
                $anomalyMerge[$dt].SevWoW   = $sev
            } else {
                $anomalyMerge[$dt] = @{
                    Last24h = $emDash; Avg7d = $emDash
                    Dev24h = $emDash; Sev24 = $null
                    ThisWeek = $thisW; LastWeek = $lastW
                    WoW = "${sign}${chg}%"; SevWoW = $sev
                }
            }
        }
    }
    if ($anomalyMerge.Count -gt 0) {
        [void]$prerenderedSections.AppendLine("| DataType | Last 24h (GB) | $($deepDiveDays)d Avg (GB) | 24h Deviation | $thisPeriodLabel (GB) | $lastPeriodLabel (GB) | $wowChangeLabel | Severity |")
        [void]$prerenderedSections.AppendLine("|----------|---------------|-------------|---------------|----------------|----------------|------------|----------|")
        # Sort: absolute 24h deviation desc, then absolute WoW desc
        $sorted = $anomalyMerge.GetEnumerator() | Sort-Object {
            $d = $_.Value.Dev24h; if ($d -match '^[+-]?\d') { [math]::Abs([double]($d -replace '%','')) } else { 0 }
        }, {
            $w = $_.Value.WoW; if ($w -match '^[+-]?\d') { [math]::Abs([double]($w -replace '%','')) } else { 0 }
        } -Descending
        foreach ($entry in $sorted) {
            $v = $entry.Value
            # Combined severity = max(24h, WoW): 🟠 > 🟡 > ⚪
            $cs = if ($v.Sev24 -eq $emojiOrange -or $v.SevWoW -eq $emojiOrange) { $emojiOrange }
                 elseif ($v.Sev24 -eq $emojiYellow -or $v.SevWoW -eq $emojiYellow) { $emojiYellow }
                 else { $emojiWhite }
            [void]$prerenderedSections.AppendLine("| $($entry.Key) | $($v.Last24h) | $($v.Avg7d) | $($v.Dev24h) | $($v.ThisWeek) | $($v.LastWeek) | $($v.WoW) | $cs |")
        }
        Write-Host "   ✅ AnomalyTable: $($anomalyMerge.Count) table(s) merged" -ForegroundColor Green
    } else {
        [void]$prerenderedSections.AppendLine("NONE $emDash no anomalies detected")
        Write-Host "   ✅ AnomalyTable: NONE" -ForegroundColor Green
    }
} else {
    [void]$prerenderedSections.AppendLine("UNAVAILABLE $emDash requires Phase 5 data")
    Write-Host "   ⚠️  AnomalyTable: skipped (missing Phase 5 data)" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.CrossReference ──────────────────────────────────────────
# §5a Table-to-Rule Cross-Reference — coverage badges + key rule names
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### CrossReference")
if (($phasesToRun -contains 3) -and ($phasesToRun -contains 4) -and $crossRef -and $crossRef.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Coverage | Table | AR Rules | CD Rules | Total | Key Rule Names |")
    [void]$prerenderedSections.AppendLine("|----------|-------|----------|----------|-------|----------------|")
    foreach ($row in ($crossRef | Sort-Object Total -Descending)) {
        $badge = if ($row.Total -ge 50) { $emojiPurple }
                 elseif ($row.Total -ge 10) { $emojiGreen }
                 elseif ($row.Total -ge 3)  { $emojiYellow }
                 else { $emojiOrange }
        [void]$prerenderedSections.AppendLine("| $badge | $($row.Table) | $($row.AR) | $($row.CD) | $($row.Total) | $($row.KeyNames) |")
    }
    Write-Host "   $([char]0x2705) CrossReference: $($crossRef.Count) tables rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("UNAVAILABLE $emDash requires Phase 3 + Phase 4 data")
    Write-Host "   ⚠️  CrossReference: skipped (missing phase data)" -ForegroundColor DarkYellow
}

# ─── EventID Description Lookup ──────────────────────────────────────────
$eventIdDescriptions = @{
    "1100"="Event logging service shut down"; "1102"="Audit log cleared"
    "4624"="Successful logon"; "4625"="Failed logon"; "4627"="Group membership information"
    "4634"="Logoff"; "4648"="Logon using explicit credentials"
    "4656"="Handle to object requested"; "4658"="Handle to object closed"
    "4660"="Object deleted"; "4661"="Handle to object requested"
    "4662"="Operation performed on object"; "4663"="Object access attempt"
    "4670"="Permissions on object changed"; "4672"="Special privileges assigned"
    "4673"="Privileged service called"; "4688"="New process created"; "4689"="Process exited"
    "4690"="Handle duplicated"; "4696"="Primary token assigned to process"
    "4698"="Scheduled task created"; "4699"="Scheduled task deleted"
    "4700"="Scheduled task enabled"; "4701"="Scheduled task disabled"
    "4702"="Scheduled task updated"; "4703"="Token right adjusted"
    "4704"="User right assigned"; "4706"="Trust to domain created"
    "4713"="Kerberos policy changed"; "4719"="System audit policy changed"
    "4720"="User account created"; "4722"="User account enabled"
    "4723"="Password change attempted"; "4724"="Password reset attempted"
    "4725"="User account disabled"; "4726"="User account deleted"
    "4728"="Member added to global group"; "4729"="Member removed from global group"
    "4732"="Member added to local group"; "4733"="Member removed from local group"
    "4738"="User account changed"; "4740"="User account locked out"
    "4741"="Computer account created"; "4742"="Computer account changed"
    "4743"="Computer account deleted"; "4756"="Member added to universal group"
    "4767"="User account unlocked"
    "4768"="Kerberos TGT requested"; "4769"="Kerberos service ticket requested"
    "4770"="Kerberos service ticket renewed"; "4771"="Kerberos pre-auth failed"
    "4776"="NTLM credential validation"; "4778"="Session reconnected"
    "4797"="Blank password test on account"
    "4798"="Local group membership enumerated"; "4799"="Security group membership enumerated"
    "4800"="Workstation locked"; "4801"="Workstation unlocked"
    "4826"="Boot Configuration Data loaded"
    "4946"="Firewall exception rule added"; "4947"="Firewall exception rule modified"
    "4948"="Firewall exception rule deleted"; "4950"="Firewall setting changed"
    "5024"="Windows Firewall started"; "5025"="Windows Firewall stopped"
    "5140"="Network share accessed"; "5145"="Network share check"
    "5156"="WFP connection allowed"; "5157"="WFP connection blocked"
    "5158"="WFP bind permitted"; "5379"="Credential Manager read"
    "5447"="WFP filter changed"; "6416"="External device recognized"
}

# ─── PRERENDERED.SE_Computer ─────────────────────────────────────────────
# §3a SecurityEvent By Computer table with volume bands
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### SE_Computer")
$q4PreData = $allResults["ingestion-q4"]
if (($phasesToRun -contains 2) -and $q4PreData -and $q4PreData.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Volume | Computer | Event Count | Est. GB ($($deepDiveDays)d) | % |")
    [void]$prerenderedSections.AppendLine("|--------|----------|-------------|---------------|---|")
    foreach ($row in $q4PreData) {
        $gb = [double]$row.EstimatedGB
        $volEmoji = if ($gb -ge 20) { $emojiRed }
                   elseif ($gb -ge 10) { $emojiOrange }
                   elseif ($gb -ge 5) { $emojiYellow }
                   else { $emojiGreen }
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $estGB = if ($gb -gt 0 -and $gb -lt 0.01) { '< 0.01' } else { ([math]::Round($gb, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        [void]$prerenderedSections.AppendLine("| $volEmoji | $($row.Computer) | $eventCount | $estGB | $pct% |")
    }
    [void]$prerenderedSections.AppendLine("")
    $preServerCount = if ($q4PreData[0].TotalServers) { [int]$q4PreData[0].TotalServers } else { $q4PreData.Count }
    [void]$prerenderedSections.AppendLine("ServerCount: $preServerCount")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed ${gteq}20 GB $middleDot $emojiOrange 10${enDash}19 GB $middleDot $emojiYellow 5${enDash}9 GB $middleDot $emojiGreen <5 GB")
    Write-Host "   $emojiCheck SE_Computer: $($q4PreData.Count) computers rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  SE_Computer: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.SE_EventID ──────────────────────────────────────────────
# §3a SecurityEvent By EventID table with volume bands, descriptions, and rules
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### SE_EventID")
$q5PreData = $allResults["ingestion-q5"]
if (($phasesToRun -contains 2) -and ($phasesToRun -contains 4) -and $q5PreData -and $q5PreData.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Volume | EventID | Description | Event Count | Est. GB ($($deepDiveDays)d) | % | Rules Referencing |")
    [void]$prerenderedSections.AppendLine("|--------|---------|-------------|-------------|---------------|---|---|")
    foreach ($row in $q5PreData) {
        $gb = [double]$row.EstimatedGB
        $volEmoji = if ($gb -ge 50) { $emojiRed }
                   elseif ($gb -ge 10) { $emojiOrange }
                   elseif ($gb -ge 1) { $emojiYellow }
                   else { $emojiGreen }
        $eid = "$($row.EventID)"
        $desc = if ($eventIdDescriptions.ContainsKey($eid)) { $eventIdDescriptions[$eid] } else { "" }
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $estGB = if ($gb -gt 0 -and $gb -lt 0.01) { '< 0.01' } else { ([math]::Round($gb, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        # Rules from ValueRef
        $vr = $valueRefEventID | Where-Object { "$($_.EventID)" -eq $eid }
        $rulesCell = if ($vr -and $vr.Total -ge 50) { "$emojiPurple $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 10) { "$emojiGreen $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 3)  { "$emojiYellow $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 1)  { "$emojiOrange $($vr.Total) $emDash $($vr.KeyNames)" }
                     else { "$emojiWarn 0 rules" }
        [void]$prerenderedSections.AppendLine("| $volEmoji | $eid | $desc | $eventCount | $estGB | $pct% | $rulesCell |")
    }
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed ${gteq}50 GB $middleDot $emojiOrange 10${enDash}49 GB $middleDot $emojiYellow 1${enDash}9 GB $middleDot $emojiGreen <1 GB  |  $emojiPurple 50+ rules $middleDot $emojiGreen 10-49 $middleDot $emojiYellow 3-9 $middleDot $emojiOrange 1-2 $middleDot $emojiWarn 0 rules")
    Write-Host "   $emojiCheck SE_EventID: $($q5PreData.Count) EventIDs rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  SE_EventID: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.SyslogHost ──────────────────────────────────────────────
# §3b By Source Host table
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### SyslogHost")
$q6aPreData = $allResults["ingestion-q6a"]
if (($phasesToRun -contains 2) -and $q6aPreData -and $q6aPreData.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Source Host | Event Count | Est. GB ($($deepDiveDays)d) | % | Facilities | Severity Levels |")
    [void]$prerenderedSections.AppendLine("|-------------|-------------|---------------|---|------------|-----------------|")
    foreach ($row in $q6aPreData) {
        $host_ = $row.SourceHost
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $estGB = if ([double]$row.EstimatedGB -gt 0 -and [double]$row.EstimatedGB -lt 0.01) { '< 0.01' } else { ([math]::Round([double]$row.EstimatedGB, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        $facilities = if ($row.Facilities) {
            $parsed = $row.Facilities
            if ($parsed -is [string]) { try { $parsed = $parsed | ConvertFrom-Json } catch { $parsed = @($parsed) } }
            ($parsed -join ", ")
        } else { "" }
        $severities = if ($row.SeverityLevels) {
            $parsed = $row.SeverityLevels
            if ($parsed -is [string]) { try { $parsed = $parsed | ConvertFrom-Json } catch { $parsed = @($parsed) } }
            ($parsed -join ", ")
        } else { "" }
        [void]$prerenderedSections.AppendLine("| $host_ | $eventCount | $estGB | $pct% | $facilities | $severities |")
    }
    Write-Host "   $emojiCheck SyslogHost: $($q6aPreData.Count) hosts rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  SyslogHost: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.SyslogFacility ──────────────────────────────────────────
# §3b By Facility table with security-relevance badge + rules
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### SyslogFacility")
$q6bPreData = $allResults["ingestion-q6b"]
if (($phasesToRun -contains 2) -and ($phasesToRun -contains 4) -and $q6bPreData -and $q6bPreData.Count -gt 0) {
    # Aggregate Q6b by Facility (same derivation as Phase 2 Syslog_Facility)
    $facGroups = $q6bPreData | Group-Object Facility
    $facRows = $facGroups | ForEach-Object {
        $totalGB = [math]::Round(($_.Group | ForEach-Object { [double]$_.EstimatedGB } | Measure-Object -Sum).Sum, 2)
        $totalCount = ($_.Group | ForEach-Object { [int64]$_.EventCount } | Measure-Object -Sum).Sum
        [PSCustomObject]@{ Facility = $_.Name; EventCount = $totalCount; EstGB = $totalGB }
    } | Sort-Object EstGB -Descending
    $syslogTotalGB = ($facRows | ForEach-Object { $_.EstGB } | Measure-Object -Sum).Sum

    [void]$prerenderedSections.AppendLine("| Badge | Facility | Event Count | Est. GB ($($deepDiveDays)d) | % | Rules |")
    [void]$prerenderedSections.AppendLine("|-------|----------|-------------|---------------|---|-------|")
    foreach ($fRow in $facRows) {
        $fac = $fRow.Facility
        # Security-relevance badge
        $badge = if ($facilityBadges.ContainsKey($fac)) { $facilityBadges[$fac] }
                 elseif ($fac -match '^local[0-7]$') { $emojiFacSat }
                 else { $emojiFacMemo }
        $eventCount = '{0:N0}' -f [int64]$fRow.EventCount
        $estGB = if ([double]$fRow.EstGB -gt 0 -and [double]$fRow.EstGB -lt 0.01) { '< 0.01' } else { ([double]$fRow.EstGB).ToString('F2') }
        $pct = if ($syslogTotalGB -gt 0) { ([math]::Round(100.0 * $fRow.EstGB / $syslogTotalGB, 1)).ToString("F1") } else { "0.0" }
        # Rules from ValueRef
        $vr = $valueRefFacility | Where-Object { $_.Facility -eq $fac }
        $rulesCell = if ($vr -and $vr.Total -ge 50) { "$emojiPurple $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 10) { "$emojiGreen $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 3)  { "$emojiYellow $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 1)  { "$emojiOrange $($vr.Total) $emDash $($vr.KeyNames)" }
                     else { "$emojiWarn 0 rules" }
        [void]$prerenderedSections.AppendLine("| $badge | $fac | $eventCount | $estGB | $pct% | $rulesCell |")
    }
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiFacLock Security-critical $middleDot $emojiFacGear System operational $middleDot $emojiFacSat Network/appliance $middleDot $emojiFacClock Scheduler $middleDot $emojiFacMail Messaging $middleDot $emojiFacMemo General/legacy")
    Write-Host "   $emojiCheck SyslogFacility: $($facRows.Count) facilities rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  SyslogFacility: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.SyslogFacSev ────────────────────────────────────────────
# §3b By Facility × Severity Level with dual emojis
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### SyslogFacSev")
if (($phasesToRun -contains 2) -and $q6bPreData -and $q6bPreData.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Badge | Facility | Severity Level | Event Count | Est. GB ($($deepDiveDays)d) | % |")
    [void]$prerenderedSections.AppendLine("|-------|----------|----------------|-------------|---------------|---|")
    foreach ($row in $q6bPreData) {
        $fac = $row.Facility
        $sev = $row.SeverityLevel
        # Facility badge
        $facBadge = if ($facilityBadges.ContainsKey($fac)) { $facilityBadges[$fac] }
                    elseif ($fac -match '^local[0-7]$') { $emojiFacSat }
                    else { $emojiFacMemo }
        # Severity emoji prefix
        $sevEmoji = if ($sevEmojis.ContainsKey($sev)) { $sevEmojis[$sev] } else { $emojiWhite }
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $gbVal = [double]$row.EstimatedGB
        $estGB = if ($gbVal -gt 0 -and $gbVal -lt 0.01) { '< 0.01' } else { ([math]::Round($gbVal, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        [void]$prerenderedSections.AppendLine("| $facBadge | $fac | $sevEmoji $sev | $eventCount | $estGB | $pct% |")
    }
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed Critical $middleDot $emojiOrange Error $middleDot $emojiYellow Warning $middleDot $emojiBlue Notice $middleDot $emojiWhite Info $middleDot $emojiBlack Debug")
    Write-Host "   $emojiCheck SyslogFacSev: $($q6bPreData.Count) combinations rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  SyslogFacSev: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.SyslogProcess ───────────────────────────────────────────
# §3b By ProcessName table with rules
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### SyslogProcess")
$q6cPreData = $allResults["ingestion-q6c"]
if (($phasesToRun -contains 2) -and ($phasesToRun -contains 4) -and $q6cPreData -and $q6cPreData.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Facility | Process Name | Event Count | Est. GB ($($deepDiveDays)d) | % | Rules |")
    [void]$prerenderedSections.AppendLine("|----------|--------------|-------------|---------------|---|-------|")
    $q6cSorted = $q6cPreData | Sort-Object @{Expression={[double]$_.EstimatedGB}; Descending=$true}, @{Expression={[int64]$_.EventCount}; Descending=$true}
    foreach ($row in $q6cSorted) {
        $fac = $row.Facility
        $proc = if ([string]::IsNullOrWhiteSpace($row.ProcessName)) { "(empty)" } else { $row.ProcessName }
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $gbVal = [double]$row.EstimatedGB
        $estGB = if ($gbVal -gt 0 -and $gbVal -lt 0.01) { '< 0.01' } else { ([math]::Round($gbVal, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        # Rules from ValueRef
        $vr = $valueRefProcess | Where-Object { $_.Process -eq $row.ProcessName }
        $rulesCell = if ($vr -and $vr.Total -ge 50) { "$emojiPurple $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 10) { "$emojiGreen $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 3)  { "$emojiYellow $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 1)  { "$emojiOrange $($vr.Total) $emDash $($vr.KeyNames)" }
                     else { "$emojiWarn 0 rules" }
        [void]$prerenderedSections.AppendLine("| $fac | $proc | $eventCount | $estGB | $pct% | $rulesCell |")
    }
    Write-Host "   $emojiCheck SyslogProcess: $($q6cPreData.Count) processes rendered" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  SyslogProcess: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.CSL_Vendor ──────────────────────────────────────────────
# §3c CommonSecurityLog By DeviceVendor/DeviceProduct table with volume bands + rules
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### CSL_Vendor")
$q7PreData = $allResults["ingestion-q7"]
if (($phasesToRun -contains 2) -and ($phasesToRun -contains 4) -and $q7PreData -and $q7PreData.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Volume | Device Vendor | Device Product | Event Count | Est. GB ($($deepDiveDays)d) | % | Rules |")
    [void]$prerenderedSections.AppendLine("|--------|---------------|----------------|-------------|---------------|---|-------|")
    foreach ($row in $q7PreData) {
        $gb = [double]$row.EstimatedGB
        $volEmoji = if ($gb -ge 50) { $emojiRed }
                   elseif ($gb -ge 20) { $emojiOrange }
                   elseif ($gb -ge 5) { $emojiYellow }
                   else { $emojiGreen }
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $estGB = if ($gb -gt 0 -and $gb -lt 0.01) { '< 0.01' } else { ([math]::Round($gb, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        # Rules from ValueRef
        $vr = $valueRefVendor | Where-Object { $_.Vendor -eq $row.DeviceVendor }
        $rulesCell = if ($vr -and $vr.Total -ge 50) { "$emojiPurple $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 10) { "$emojiGreen $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 3)  { "$emojiYellow $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 1)  { "$emojiOrange $($vr.Total) $emDash $($vr.KeyNames)" }
                     else { "$emojiWarn 0 rules" }
        [void]$prerenderedSections.AppendLine("| $volEmoji | $($row.DeviceVendor) | $($row.DeviceProduct) | $eventCount | $estGB | $pct% | $rulesCell |")
    }
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed ${gteq}50 GB $middleDot $emojiOrange 20${enDash}49 GB $middleDot $emojiYellow 5${enDash}19 GB $middleDot $emojiGreen <5 GB")
    Write-Host "   $emojiCheck CSL_Vendor: $($q7PreData.Count) vendors rendered" -ForegroundColor Green
} elseif (($phasesToRun -contains 2) -and $q7PreData -and $q7PreData.Count -gt 0) {
    # Phase 4 not run — render without rules column
    [void]$prerenderedSections.AppendLine("| Volume | Device Vendor | Device Product | Event Count | Est. GB ($($deepDiveDays)d) | % |")
    [void]$prerenderedSections.AppendLine("|--------|---------------|----------------|-------------|---------------|---|")
    foreach ($row in $q7PreData) {
        $gb = [double]$row.EstimatedGB
        $volEmoji = if ($gb -ge 50) { $emojiRed }
                   elseif ($gb -ge 20) { $emojiOrange }
                   elseif ($gb -ge 5) { $emojiYellow }
                   else { $emojiGreen }
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $estGB = if ($gb -gt 0 -and $gb -lt 0.01) { '< 0.01' } else { ([math]::Round($gb, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        [void]$prerenderedSections.AppendLine("| $volEmoji | $($row.DeviceVendor) | $($row.DeviceProduct) | $eventCount | $estGB | $pct% |")
    }
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed ${gteq}50 GB $middleDot $emojiOrange 20${enDash}49 GB $middleDot $emojiYellow 5${enDash}19 GB $middleDot $emojiGreen <5 GB")
    Write-Host "   $emojiCheck CSL_Vendor: $($q7PreData.Count) vendors rendered (no rules)" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  CSL_Vendor: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.CSL_Activity ────────────────────────────────────────────
# §3c CommonSecurityLog By Activity/LogSeverity/DeviceAction with volume bands + rules
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### CSL_Activity")
$q8PreData = $allResults["ingestion-q8"]
if (($phasesToRun -contains 2) -and ($phasesToRun -contains 4) -and $q8PreData -and $q8PreData.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("| Volume | Activity | Log Severity | Device Action | Event Count | Est. GB ($($deepDiveDays)d) | % | Rules |")
    [void]$prerenderedSections.AppendLine("|--------|----------|--------------|---------------|-------------|---------------|---|-------|")
    foreach ($row in $q8PreData) {
        $gb = [double]$row.EstimatedGB
        $volEmoji = if ($gb -ge 50) { $emojiRed }
                   elseif ($gb -ge 20) { $emojiOrange }
                   elseif ($gb -ge 5) { $emojiYellow }
                   else { $emojiGreen }
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $estGB = if ($gb -gt 0 -and $gb -lt 0.01) { '< 0.01' } else { ([math]::Round($gb, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        # Rules from ValueRef
        $vr = $valueRefActivity | Where-Object { $_.Activity -eq $row.Activity }
        $rulesCell = if ($vr -and $vr.Total -ge 50) { "$emojiPurple $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 10) { "$emojiGreen $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 3)  { "$emojiYellow $($vr.Total) $emDash $($vr.KeyNames)" }
                     elseif ($vr -and $vr.Total -ge 1)  { "$emojiOrange $($vr.Total) $emDash $($vr.KeyNames)" }
                     else { "$emojiWarn 0 rules" }
        [void]$prerenderedSections.AppendLine("| $volEmoji | $($row.Activity) | $($row.LogSeverity) | $($row.DeviceAction) | $eventCount | $estGB | $pct% | $rulesCell |")
    }
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed ${gteq}50 GB $middleDot $emojiOrange 20${enDash}49 GB $middleDot $emojiYellow 5${enDash}19 GB $middleDot $emojiGreen <5 GB")
    Write-Host "   $emojiCheck CSL_Activity: $($q8PreData.Count) activities rendered" -ForegroundColor Green
} elseif (($phasesToRun -contains 2) -and $q8PreData -and $q8PreData.Count -gt 0) {
    # Phase 4 not run — render without rules column
    [void]$prerenderedSections.AppendLine("| Volume | Activity | Log Severity | Device Action | Event Count | Est. GB ($($deepDiveDays)d) | % |")
    [void]$prerenderedSections.AppendLine("|--------|----------|--------------|---------------|-------------|---------------|---|")
    foreach ($row in $q8PreData) {
        $gb = [double]$row.EstimatedGB
        $volEmoji = if ($gb -ge 50) { $emojiRed }
                   elseif ($gb -ge 20) { $emojiOrange }
                   elseif ($gb -ge 5) { $emojiYellow }
                   else { $emojiGreen }
        $eventCount = '{0:N0}' -f [int64]$row.EventCount
        $estGB = if ($gb -gt 0 -and $gb -lt 0.01) { '< 0.01' } else { ([math]::Round($gb, 2)).ToString('F2') }
        $pctVal = [double]$row.PercentOfTotal
        $pct = if ([double]::IsNaN($pctVal) -or [double]::IsInfinity($pctVal)) { '< 0.1' } else { ([math]::Round($pctVal, 1)).ToString('F1') }
        [void]$prerenderedSections.AppendLine("| $volEmoji | $($row.Activity) | $($row.LogSeverity) | $($row.DeviceAction) | $eventCount | $estGB | $pct% |")
    }
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed ${gteq}50 GB $middleDot $emojiOrange 20${enDash}49 GB $middleDot $emojiYellow 5${enDash}19 GB $middleDot $emojiGreen <5 GB")
    Write-Host "   $emojiCheck CSL_Activity: $($q8PreData.Count) activities rendered (no rules)" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  CSL_Activity: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.Migration ──────────────────────────────────────────────
# §7a: 4 sub-tables with volume/rule badges, DL eligibility emojis
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### Migration")

if ($migrationRows -and $migrationRows.Count -gt 0) {
    $emojiCross   = [char]::ConvertFromUtf32(0x274C)   # ❌
    $emojiQuestion = [char]::ConvertFromUtf32(0x2753)   # ❓
    $emojiBook    = [char]::ConvertFromUtf32(0x1F4D5)   # 📕
    $emojiExcl    = [char]::ConvertFromUtf32(0x2757)    # ❗

    # Legend
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("$emojiRed DL candidate (zero rules, eligible) $middleDot $emojiOrange Not eligible/unknown $middleDot $emojiGreen Keep Analytics (has rules) $middleDot $emojiPurple Split candidate $middleDot $emojiExcl Detection gap $emDash XDR (CD-convertible) or non-XDR (must move back/disable) $middleDot $emojiBlue Already on DL $middleDot $emojiBook KQL Job output")

    $migTableHeader = "| DataType | $($deepDiveDays)d GB | AR Rules | CD Rules | Total Rules | Tier | DL Eligible | Category |"
    $migTableSep    = "|----------|-------|----------|----------|-------------|------|-------------|----------|"

    $subTableDefs = @(
        @{ Key = "Sub-table 1"; Title = "#### Sub-table 1: $emojiRed DL Migration Candidates" }
        @{ Key = "Sub-table 2"; Title = "#### Sub-table 2: $emojiOrange Zero-Rule Tables $emDash Not Eligible or Unknown" }
        @{ Key = "Sub-table 3"; Title = "#### Sub-table 3: $emojiGreen Tables with Rules $emDash Keep on Analytics" }
        @{ Key = "Sub-table 4"; Title = "#### Sub-table 4: $emojiBlue Already on Data Lake" }
    )

    foreach ($stDef in $subTableDefs) {
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine($stDef.Title)
        [void]$prerenderedSections.AppendLine("")

        $stRows = @($migrationRows | Where-Object { $_.SubTable -eq $stDef.Key } | Sort-Object { [double]$_.GB7d } -Descending)

        if ($stRows.Count -eq 0) {
            [void]$prerenderedSections.AppendLine("*No tables in this category.*")
        } else {
            [void]$prerenderedSections.AppendLine($migTableHeader)
            [void]$prerenderedSections.AppendLine($migTableSep)

            foreach ($r in $stRows) {
                # Volume badge (daily GB = periodGB / deepDiveDays)
                $dailyGB = [double]$r.GB7d / $deepDiveDays
                $volBadge = if ($dailyGB -ge 1.0) { $emojiRed }
                            elseif ($dailyGB -ge 0.1) { $emojiOrange }
                            elseif ($dailyGB -ge 0.01)  { $emojiYellow }
                            else { $emojiGreen }

                # Rule badge on Total
                # Rule badge — tier-aware: DL tables with 0 rules show plain 0 (expected state per global badge reference)
                $ruleBadge = if ($r.Total -ge 50) { $emojiPurple }
                             elseif ($r.Total -ge 10) { $emojiGreen }
                             elseif ($r.Total -ge 3)  { $emojiYellow }
                             elseif ($r.Total -ge 1)  { $emojiOrange }
                             elseif ($r.Tier -eq "Data Lake") { "" }
                             else { $emojiWarn }

                # DL Eligible emoji
                $dlDisplay = switch ($r.DLElig) {
                    "Yes"     { "$emojiCheck Yes" }
                    "No"      { "$emojiCross No" }
                    "KQL"     { "$emojiBook KQL" }
                    default   { "$emojiQuestion Unknown" }
                }

                $gb7dFmt = ([math]::Round([double]$r.GB7d, 2)).ToString("F2")

                [void]$prerenderedSections.AppendLine("| $($r.Table) | $volBadge $gb7dFmt | $($r.AR) | $($r.CD) | $ruleBadge $($r.Total) | $($r.Tier) | $dlDisplay | $($r.Category) |")
            }
        }
    }

    Write-Host "   $emojiCheck Migration: 4 sub-tables rendered ($($migrationRows.Count) rows total)" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("EMPTY")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  Migration: EMPTY" -ForegroundColor DarkYellow
}

# ─── PRERENDERED.HealthAlerts ────────────────────────────────────────────
# §5b tables: Alert-Producing Rules with volume/severity badges,
# Failing Rules with status indicators. Health/CrossValidation stay raw for LLM prose.
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### HealthAlerts")

$q12Pre  = $allResults["ingestion-q12"]
$q11dPre = $allResults["ingestion-q11d"]

$emojiFire  = [char]::ConvertFromUtf32(0x1F525)  # 🔥
$emojiChart = [char]::ConvertFromUtf32(0x1F4CA)  # 📊
$emojiSleep = [char]::ConvertFromUtf32(0x1F4A4)  # 💤

# Legend
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("$emojiFire 100+ alerts $middleDot $emojiChart 10${enDash}99 alerts $middleDot $emojiSleep 1${enDash}9 alerts  |  $emojiRed High $middleDot $emojiOrange Medium $middleDot $emojiYellow Low $middleDot $emojiBlue Informational")

# ── Alert-Producing Rules table ──
if ($q12Pre -and ($q12Pre -is [array]) -and $q12Pre.Count -gt 0) {
    $totalAlertsPre = ($q12Pre | ForEach-Object { [int]$_.AlertCount } | Measure-Object -Sum).Sum
    $alertRuleCountPre = $q12Pre.Count

    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("#### Alert-Producing Rules ($($Days)d)")
    [void]$prerenderedSections.AppendLine("| Volume | Rule Name | Alert Count | Severity | Product Component |")
    [void]$prerenderedSections.AppendLine("|--------|-----------|-------------|----------|-------------------|")

    foreach ($row in ($q12Pre | Sort-Object { [int]$_.AlertCount } -Descending)) {
        $ac = [int]$row.AlertCount
        $volBadge = if ($ac -ge 100) { $emojiFire }
                    elseif ($ac -ge 10) { $emojiChart }
                    else { $emojiSleep }

        # Dominant severity (highest present)
        $h = [int]$row.HighSev; $m = [int]$row.MediumSev; $l = [int]$row.LowSev; $i = [int]$row.InfoSev
        $sevBadge = if ($h -gt 0) { "$emojiRed High" }
                    elseif ($m -gt 0) { "$emojiOrange Medium" }
                    elseif ($l -gt 0) { "$emojiYellow Low" }
                    else { "$emojiBlue Informational" }

        [void]$prerenderedSections.AppendLine("| $volBadge | $($row.AlertName) | $ac | $sevBadge | $($row.ProductComponentName) |")
    }

    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("Total: $totalAlertsPre alerts from $alertRuleCountPre rules")

    Write-Host "   $emojiCheck AlertProducing: $alertRuleCountPre rules, $totalAlertsPre alerts (badges applied)" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("#### Alert-Producing Rules ($($Days)d)")
    [void]$prerenderedSections.AppendLine("No alerts produced in the last $Days days.")
    Write-Host "   $([char]0x2139)$([char]0xFE0F)  AlertProducing: No alerts in $($Days)d" -ForegroundColor DarkYellow
}

# ── Failing Rules table (conditional) ──
if ($q11dPre -and ($q11dPre -is [array]) -and $q11dPre.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("#### Failing Rules")
    [void]$prerenderedSections.AppendLine("| Rule Name | Kind | Failures | Last Failure | Status |")
    [void]$prerenderedSections.AppendLine("|-----------|------|----------|--------------|--------|")

    foreach ($row in $q11dPre) {
        $name = $row.SentinelResourceName
        $kind = if ($name -match '^NRT ') { "NRT" } else { "Scheduled" }
        $failures = $row.FailureCount
        $lastFail = ($row.LastFailure -replace '[\sT].*', '')
        [void]$prerenderedSections.AppendLine("| $name | $kind | $failures | $lastFail | $emojiOrange Failing |")
    }

    Write-Host "   $emojiCheck FailingRules: $($q11dPre.Count) rules (badges applied)" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("#### Failing Rules")
    [void]$prerenderedSections.AppendLine("NONE")
    Write-Host "   $emojiCheck FailingRules: NONE" -ForegroundColor Green
}

# ─── PRERENDERED.BenefitSummary + DfSP2Detail ───────────────────────────
# §6 Combined Benefit Summary + §6a DfS P2 Pool Detail
$q17LB = $allResults["ingestion-q17"]
$q4LB  = $allResults["ingestion-q4"]
if (($phasesToRun -contains 5) -and $q17LB -and ($q17LB -is [array]) -and $q17LB.Count -gt 0) {
    $lbDfsp2Daily = ($q17LB | ForEach-Object { ConvertTo-SafeDouble $_.DFSP2GB } | Measure-Object -Average).Average
    $lbE5Daily    = ($q17LB | ForEach-Object { ConvertTo-SafeDouble $_.E5GB }    | Measure-Object -Average).Average
    $lbRemDaily   = ($q17LB | ForEach-Object { ConvertTo-SafeDouble $_.RemainingGB } | Measure-Object -Average).Average
    $lbDfsp2Sum   = ($q17LB | ForEach-Object { ConvertTo-SafeDouble $_.DFSP2GB } | Measure-Object -Sum).Sum
    $lbE5Sum      = ($q17LB | ForEach-Object { ConvertTo-SafeDouble $_.E5GB }    | Measure-Object -Sum).Sum
    $lbRemSum     = ($q17LB | ForEach-Object { ConvertTo-SafeDouble $_.RemainingGB } | Measure-Object -Sum).Sum

    $lbServerCount = if ($q4LB -and ($q4LB -is [array]) -and $q4LB.Count -gt 0 -and $q4LB[0].TotalServers) {
        [int]$q4LB[0].TotalServers
    } elseif ($q4LB -and ($q4LB -is [array])) { $q4LB.Count } else { 0 }
    $lbPoolGB     = [math]::Round($lbServerCount * 0.5, 3)
    $lbPoolUtil   = if ($lbPoolGB -gt 0) { [math]::Round(($lbDfsp2Daily / $lbPoolGB) * 100, 1) } else { [double]0.0 }

    # ─── BenefitSummary ─── (§6 preamble)
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("### BenefitSummary")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Category | Avg Daily (GB) | Est. $($Days)-Day (GB) | License Required |")
    [void]$prerenderedSections.AppendLine("|----------|---------------|-------------------|------------------|")
    [void]$prerenderedSections.AppendLine("| DfS P2-Eligible | $($lbDfsp2Daily.ToString('F3')) | $($lbDfsp2Sum.ToString('F3')) | Defender for Servers P2 |")
    [void]$prerenderedSections.AppendLine("| E5-Eligible | $($lbE5Daily.ToString('F3')) | $($lbE5Sum.ToString('F3')) | M365 E5 / E5 Security |")
    [void]$prerenderedSections.AppendLine("| **Remaining (truly billable)** | **$($lbRemDaily.ToString('F3'))** | **$($lbRemSum.ToString('F3'))** | **Paid ingestion** |")

    # ─── DfSP2Detail ─── (§6a)
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("### DfSP2Detail")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("Pool calculation: $lbServerCount servers $([char]0x00D7) 500 MB/day = $($lbPoolGB.ToString('F3')) GB/day ([benefit details](https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-ingestion-benefit))")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Metric | Value |")
    [void]$prerenderedSections.AppendLine("|--------|-------|")
    [void]$prerenderedSections.AppendLine("| Eligible Table | SecurityEvent |")
    [void]$prerenderedSections.AppendLine("| Detected Server Count | $lbServerCount |")
    [void]$prerenderedSections.AppendLine("| Pool Size (500 MB/server/day) | $lbServerCount $([char]0x00D7) 500 MB = **$($lbPoolGB.ToString('F3')) GB/day** |")
    [void]$prerenderedSections.AppendLine("| Actual Eligible Daily Ingestion | **$($lbDfsp2Daily.ToString('F3')) GB/day** |")
    [void]$prerenderedSections.AppendLine("| Pool Utilization | **$($lbPoolUtil.ToString('F1'))%** |")
    [void]$prerenderedSections.AppendLine("| $($Days)-Day DfS P2 Deduction | **$($lbDfsp2Sum.ToString('F3')) GB** |")

    # Scenario-based insight
    if ($lbPoolGB -gt 0) {
        [void]$prerenderedSections.AppendLine("")
        if ($lbDfsp2Daily -lt ($lbPoolGB * 0.5)) {
            [void]$prerenderedSections.AppendLine("**Scenario: Pool far exceeds usage.** If DfS P2 is enabled, the pool of $($lbPoolGB.ToString('F3')) GB/day far exceeds actual eligible ingestion of $($lbDfsp2Daily.ToString('F3')) GB/day ${emDash} significant headroom exists. Consider increasing SecurityEvent logging levels (e.g., collecting `"All Events`" instead of `"Common`" or `"Minimal`" via the Windows Security Events data connector) to broaden detection coverage at no additional ingestion cost. Note: increased retention volume may affect long-term storage costs depending on workspace retention settings.")
        } elseif ($lbDfsp2Daily -le $lbPoolGB) {
            [void]$prerenderedSections.AppendLine("**Scenario: Pool covers usage.** If DfS P2 is enabled, the pool of $($lbPoolGB.ToString('F3')) GB/day covers the current eligible ingestion of $($lbDfsp2Daily.ToString('F3')) GB/day. Monitor growth ${emDash} if SecurityEvent volume approaches the pool ceiling, evaluate which EventIDs drive the increase (see $([char]0x00A7)3a).")
        } else {
            $lbOverage = [math]::Round($lbDfsp2Daily - $lbPoolGB, 3)
            [void]$prerenderedSections.AppendLine("**Scenario: Usage exceeds pool.** If DfS P2 is enabled, eligible ingestion ($($lbDfsp2Daily.ToString('F3')) GB/day) exceeds the pool ($($lbPoolGB.ToString('F3')) GB/day). The overage of ~$($lbOverage.ToString('F3')) GB/day is billed at standard Analytics rates. Review $([char]0x00A7)3a EventID breakdown for volume reduction opportunities, or consider onboarding additional servers to DfS P2 to increase the pool.")
        }
    }

    Write-Host "   $emojiCheck BenefitSummary+DfSP2Detail: DfSP2=$($lbDfsp2Daily.ToString('F3')), E5=$($lbE5Daily.ToString('F3')), Rem=$($lbRemDaily.ToString('F3')), Pool=$($lbPoolGB.ToString('F3')) ($($lbPoolUtil.ToString('F1'))%)" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("### BenefitSummary")
    [void]$prerenderedSections.AppendLine("NONE")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("### DfSP2Detail")
    [void]$prerenderedSections.AppendLine("NONE")
    Write-Host "   $emojiCheck BenefitSummary+DfSP2Detail: NONE (Q17 unavailable or Phase 5 skipped)" -ForegroundColor Green
}

# ─── PRERENDERED.E5Tables ────────────────────────────────────────────────
# §6b E5-eligible per-table breakdown with tier lookup, total, and break-even
$q17bPre = $allResults["ingestion-q17b"]
$q17Pre  = $allResults["ingestion-q17"]
if (($phasesToRun -contains 5) -and $q17bPre -and ($q17bPre -is [array]) -and $q17bPre.Count -gt 0) {
    # Build tier lookup from Q10 data
    $q10Pre = $allResults["ingestion-q10"]
    $tierLookup = @{}
    if ($q10Pre -and ($q10Pre -is [array])) {
        foreach ($t in $q10Pre) {
            $planLabel = if ($t.plan -eq "Auxiliary") { "Data Lake" } elseif ($t.plan -eq "Basic") { "Basic" } else { "Analytics" }
            $tierLookup[$t.name] = $planLabel
        }
    }

    # Sort by volume desc (already sorted by KQL, but enforce PS1-side)
    $e5Sorted = $q17bPre | Sort-Object @{Expression={[double]$_.VolumeGB}; Descending=$true}

    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("### E5Tables")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Table | Volume ($($Days)d GB) | Tier |")
    [void]$prerenderedSections.AppendLine("|-------|----------------|------|")

    $e5TotalVol = 0.0
    foreach ($row in $e5Sorted) {
        $vol = [double]$row.VolumeGB
        $e5TotalVol += $vol
        $tier = if ($tierLookup.ContainsKey($row.DataType)) { $tierLookup[$row.DataType] } else { "Analytics" }
        [void]$prerenderedSections.AppendLine("| $($row.DataType) | $($vol.ToString('F3')) | $tier |")
    }
    [void]$prerenderedSections.AppendLine("| **Total ($($e5Sorted.Count) tables)** | **$($e5TotalVol.ToString('F3'))** | |")

    # Break-even license calculation
    # E5_DailyGB from Q17 aggregate (avg daily E5-eligible ingestion)
    if ($q17Pre -and ($q17Pre -is [array]) -and $q17Pre.Count -gt 0) {
        $e5AvgDaily = ($q17Pre | ForEach-Object { ConvertTo-SafeDouble $_.E5GB } | Measure-Object -Average).Average
        $e5AvgDailyMB = $e5AvgDaily * 1024
        $breakEvenLicenses = [math]::Ceiling($e5AvgDailyMB / 5)
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("**Break-even:** $($e5AvgDaily.ToString('F3')) GB/day ($([math]::Round($e5AvgDailyMB, 1)) MB/day) ${emDash} requires **$breakEvenLicenses E5 licenses** to fully cover (at 5 MB/license/day)")

        # Sum reconciliation
        $e5AggSum = ($q17Pre | ForEach-Object { ConvertTo-SafeDouble $_.E5GB } | Measure-Object -Sum).Sum
        $diff = [math]::Abs($e5TotalVol - $e5AggSum)
        if ($diff -gt 0.01) {
            [void]$prerenderedSections.AppendLine("*Per-table sum ($($e5TotalVol.ToString('F3')) GB) differs from aggregate ($($e5AggSum.ToString('F3')) GB) due to rounding in daily averaging.*")
        }
    }

    Write-Host "   $emojiCheck E5Tables: $($e5Sorted.Count) tables, $($e5TotalVol.ToString('F3')) GB total, break-even $breakEvenLicenses licenses" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("### E5Tables")
    [void]$prerenderedSections.AppendLine("NONE")
    Write-Host "   $emojiCheck E5Tables: NONE (no E5-eligible data or Phase 5 skipped)" -ForegroundColor Green
}

# ─── PRERENDERED.QueryTable ──────────────────────────────────────────────
# Static 23-row query reference table for §8a
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### QueryTable")
[void]$prerenderedSections.AppendLine(@"
| Phase | Query ID | File | Description |
|-------|----------|------|-------------|
| 1 | Q1 | phase1/Q1-UsageByDataType.yaml | Usage by DataType |
| 1 | Q2 | phase1/Q2-DailyIngestionTrend.yaml | Daily ingestion trend |
| 1 | Q3 | phase1/Q3-WorkspaceSummary.yaml | Workspace aggregate metrics |
| 2 | Q4 | phase2/Q4-SecurityEventByComputer.yaml | SecurityEvent by Computer |
| 2 | Q5 | phase2/Q5-SecurityEventByEventID.yaml | SecurityEvent by EventID |
| 2 | Q6a | phase2/Q6a-SyslogByHost.yaml | Syslog by source host |
| 2 | Q6b | phase2/Q6b-SyslogByFacilitySeverity.yaml | Syslog by Facility×Severity |
| 2 | Q6c | phase2/Q6c-SyslogByProcess.yaml | Syslog by ProcessName |
| 2 | Q7 | phase2/Q7-CSLByVendor.yaml | CommonSecurityLog by vendor |
| 2 | Q8 | phase2/Q8-CSLByActivity.yaml | CommonSecurityLog by activity |
| 3 | Q9 | phase3/Q9-AnalyticRuleInventory.yaml | AR inventory (REST API) |
| 3 | Q9b | phase3/Q9b-CustomDetectionRules.yaml | CD inventory (Graph API) |
| 3 | Q10 | phase3/Q10-TableTierClassification.yaml | Table tier (Azure CLI) |
| 3 | Q10b | phase3/Q10b-TierSummary.yaml | Per-tier volume summary |
| 4 | Q11 | phase4/Q11-RuleHealthSummary.yaml | SentinelHealth overview |
| 4 | Q11d | phase4/Q11d-FailingRuleDetail.yaml | Failing rule details |
| 4 | Q12 | phase4/Q12-SecurityAlertFiring.yaml | Alert-producing rules |
| 4 | Q13 | phase4/Q13-AllTablesWithData.yaml | Active tables (for CrossRef) |
| 5 | Q14 | phase5/Q14-IngestionAnomaly24h.yaml | 24h anomaly detection |
| 5 | Q15 | phase5/Q15-WeekOverWeek.yaml | Week-over-week changes |
| 5 | Q16 | phase5/Q16-MigrationCandidates.yaml | Migration candidate volumes |
| 5 | Q17 | phase5/Q17-LicenseBenefitAnalysis.yaml | License benefit analysis |
| 5 | Q17b | phase5/Q17b-E5PerTableBreakdown.yaml | E5 per-table breakdown |
"@.TrimEnd())

# ─── PRERENDERED.Footer ──────────────────────────────────────────────────
# Report footer — 3 pipe-delimited fields
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### Footer")
[void]$prerenderedSections.AppendLine("*Report generated: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ') | Skill: sentinel-ingestion-report v2 | Mode: $($Days)-day markdown*")

$prerenderedBlock = $prerenderedSections.ToString().TrimEnd()
Write-Host "   ✅ PRERENDERED blocks complete" -ForegroundColor Green

$scratchpad = @"
# SCRATCHPAD — Sentinel Ingestion Report
<!-- Auto-generated by Invoke-IngestionScan.ps1. DO NOT edit manually. -->

## META
Workspace: $workspaceName
WorkspaceId: $workspaceId
Period: $periodLabel
ReportPeriod: $reportPeriod
Days: $Days
DeepDiveDays: $deepDiveDays
Generated: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
Tool: AzMonitor
QueryCount: $($allQueries.Count)
ExecutionTime: ${totalQueryTime}s
Phases: $($phasesToRun -join ',')
$phase1Block
$phase2Block
$phase3Block
$phase4Block
$phase5Block

## PRERENDERED
<!-- Copy these blocks VERBATIM into the report. Do NOT modify content. -->
$prerenderedBlock
"@

$scratchpad | Out-File -FilePath $scratchpadPath -Encoding utf8

# ─── Summary ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  ✅ Scratchpad written successfully" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  📄 Path: $scratchpadPath" -ForegroundColor White
Write-Host "  📏 Size: $([math]::Round((Get-Item $scratchpadPath).Length / 1024, 1)) KB" -ForegroundColor White
Write-Host "  ⏱️  Total time: ${totalQueryTime}s" -ForegroundColor White
Write-Host "  📊 Phases: $($phasesToRun -join ', ')" -ForegroundColor White
Write-Host ""
#endregion
