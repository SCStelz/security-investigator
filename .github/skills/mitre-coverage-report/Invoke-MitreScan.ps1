#Requires -Version 7.0
<#
.SYNOPSIS
    MITRE ATT&CK Coverage Report — YAML-driven data gathering.

.DESCRIPTION
    Reads query definitions from YAML files in the queries/ folder,
    executes them via 'az rest' (Sentinel API), 'az monitor' (KQL),
    and optionally 'Invoke-MgGraphRequest' (Graph API for Custom Detections),
    then writes a scratchpad file for report rendering by the LLM.

    Architecture: YAML query files → PowerShell execution
    → scratchpad.md → LLM reads scratchpad and renders report.

    Data sources:
      1. Sentinel REST API — Analytic rules with MITRE tactics/techniques (az rest)
      2. Microsoft Graph API — Custom Detection rules with mitreTechniques (Invoke-MgGraphRequest, graceful skip)
      3. SOC Optimization API — Coverage recommendations with threat scenarios (az rest)
      4. KQL — SecurityAlert/SecurityIncident for operational MITRE data (az monitor)
      5. Static reference — mitre-attck-enterprise.json for framework coverage gaps

.PARAMETER ConfigPath
    Path to config.json. Default: auto-detected from workspace root.

.PARAMETER OutputDir
    Directory for scratchpad output. Default: temp/ in workspace root.

.PARAMETER WorkspaceId
    Sentinel Log Analytics workspace GUID. Overrides config.json value.

.PARAMETER SubscriptionId
    Azure subscription ID. Overrides config.json value.

.PARAMETER ResourceGroup
    Resource group containing the Log Analytics workspace. Overrides config.json value.

.PARAMETER WorkspaceName
    Log Analytics workspace display name. Overrides config.json value.

.PARAMETER Days
    Reporting window in days for KQL queries (alert/incident lookback). Default: 30.

.PARAMETER Phase
    Phase number to execute (0 = all, 1-3 = specific). Default: 0.

.EXAMPLE
    # Skill mode (reads config.json):
    & ".github/skills/mitre-coverage-report/Invoke-MitreScan.ps1"

.EXAMPLE
    # Standalone mode:
    .\Invoke-MitreScan.ps1 -WorkspaceId "..." -SubscriptionId "..." -ResourceGroup "..." -WorkspaceName "..."
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [ValidateSet(0, 1, 2, 3)]
    [int]$Phase = 0,
    [string]$OutputDir,
    [Alias('Workspace')]
    [string]$WorkspaceId,
    [Alias('Subscription')]
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$WorkspaceName,
    [ValidateSet(7, 14, 30, 60, 90)]
    [int]$Days = 30
)

$ErrorActionPreference = 'Stop'

#region ═══ Path Resolution ═══════════════════════════════════════════════════
$ScriptDir = $PSScriptRoot
$WorkspaceRoot = $ScriptDir
$configFound = $false
for ($i = 0; $i -lt 6; $i++) {
    if (Test-Path (Join-Path $WorkspaceRoot "config.json")) { $configFound = $true; break }
    $WorkspaceRoot = Split-Path $WorkspaceRoot -Parent
}

$standaloneMode = (-not $configFound) -and (-not $ConfigPath)
if ($standaloneMode) {
    if (-not $OutputDir) { $OutputDir = Join-Path $ScriptDir "output" }
} else {
    if (-not $ConfigPath) { $ConfigPath = Join-Path $WorkspaceRoot "config.json" }
    if (-not $OutputDir)  { $OutputDir  = Join-Path $WorkspaceRoot "temp" }
}

$QueryDir = Join-Path $ScriptDir "queries"
$ReferenceFile = Join-Path $ScriptDir "mitre-attck-enterprise.json"

if (-not (Test-Path $QueryDir)) {
    Write-Error "Query directory not found: $QueryDir"
    return
}
if (-not (Test-Path $ReferenceFile)) {
    Write-Error "ATT&CK reference file not found: $ReferenceFile"
    return
}
#endregion

#region ═══ Banner ════════════════════════════════════════════════════════════
Write-Host ""
$phaseLabel = if ($Phase -eq 0) { "All Phases" } else { "Phase $Phase" }
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  MITRE ATT&CK Coverage Report — $phaseLabel Data Gathering" -ForegroundColor Cyan
Write-Host "  Engine: az rest + az monitor (KQL)" -ForegroundColor DarkCyan
Write-Host "  Alert/Incident lookback: ${Days}d" -ForegroundColor DarkCyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
#endregion

#region ═══ YAML Parser ═══════════════════════════════════════════════════════
function Import-QueryYaml {
    param([string]$Path)
    $result = @{}
    $lines = Get-Content $Path
    $currentKey = $null
    $multilineValue = [System.Text.StringBuilder]::new()

    foreach ($line in $lines) {
        if ($null -eq $currentKey) {
            if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        }
        if ($null -ne $currentKey) {
            if ($line -match '^(\s{2,})(.*)$') {
                [void]$multilineValue.AppendLine($matches[2])
                continue
            }
            if ([string]::IsNullOrWhiteSpace($line)) {
                [void]$multilineValue.AppendLine('')
                continue
            }
            $result[$currentKey] = $multilineValue.ToString().TrimEnd()
            $currentKey = $null
            [void]$multilineValue.Clear()
        }
        if ($line -match '^([a-zA-Z_]\w*):\s*\|\s*$') {
            $currentKey = $matches[1]
            [void]$multilineValue.Clear()
            continue
        }
        if ($line -match '^([a-zA-Z_]\w*):\s*(.+)$') {
            $result[$matches[1]] = $matches[2].Trim()
        }
    }
    if ($null -ne $currentKey) {
        $result[$currentKey] = $multilineValue.ToString().TrimEnd()
    }
    return $result
}
#endregion

#region ═══ Prerequisites ═════════════════════════════════════════════════════
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI (az) not found. Install from https://aka.ms/installazurecli"
    return
}

$azAccount = az account show -o json 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Not logged in to Azure CLI. Run: az login --tenant <tenant_id>"
    return
}
$accountInfo = $azAccount | ConvertFrom-Json
Write-Host "✅ Azure CLI authenticated — Tenant: $($accountInfo.tenantId)" -ForegroundColor Green

# ─── Config Resolution ───────────────────────────────────────────────────
$config = $null
if (-not $standaloneMode -and (Test-Path $ConfigPath)) {
    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    Write-Host "✅ Config loaded — $ConfigPath" -ForegroundColor Green
}

# Resolve parameters: CLI params > config.json > prompt
if (-not $WorkspaceId) {
    $WorkspaceId = if ($config) { $config.sentinel_workspace_id } else { $null }
}
if (-not $SubscriptionId) {
    $SubscriptionId = if ($config) { $config.subscription_id } else { $null }
    if (-not $SubscriptionId -and $config.azure_mcp) { $SubscriptionId = $config.azure_mcp.subscription }
}
if (-not $ResourceGroup) {
    $ResourceGroup = if ($config -and $config.azure_mcp) { $config.azure_mcp.resource_group } else { $null }
}
if (-not $WorkspaceName) {
    $WorkspaceName = if ($config -and $config.azure_mcp) { $config.azure_mcp.workspace_name } else { $null }
}

# Validate required parameters for REST API calls
if (-not $SubscriptionId -or -not $ResourceGroup -or -not $WorkspaceName) {
    Write-Error @"
Missing required parameters for REST API calls.
Required: SubscriptionId, ResourceGroup, WorkspaceName
Provide via config.json or CLI parameters.
"@
    return
}
if (-not $WorkspaceId) {
    Write-Error "Missing WorkspaceId (needed for KQL queries). Provide via config.json or -WorkspaceId parameter."
    return
}

$workspaceId = $WorkspaceId
$subscriptionId = $SubscriptionId
$resourceGroup = $ResourceGroup
$workspaceName = $WorkspaceName

Write-Host "✅ Workspace: $workspaceName ($workspaceId)" -ForegroundColor Green
Write-Host "✅ Subscription: $subscriptionId / RG: $resourceGroup" -ForegroundColor Green
#endregion

#region ═══ Load ATT&CK Reference ════════════════════════════════════════════
Write-Host "`n📚 Loading ATT&CK Enterprise reference..." -ForegroundColor Yellow
$attackRef = Get-Content $ReferenceFile -Raw | ConvertFrom-Json
Write-Host "   ✅ ATT&CK Enterprise v$($attackRef.version) — $($attackRef.totalTechniques) techniques, $($attackRef.totalSubTechniques) sub-techniques" -ForegroundColor Green

# Build technique → tactic reverse lookup from reference
$techToTactics = @{}
foreach ($tacticName in $attackRef.tactics.PSObject.Properties.Name) {
    $tacticData = $attackRef.tactics.$tacticName
    foreach ($tech in $tacticData.techniques) {
        if (-not $techToTactics.ContainsKey($tech.id)) {
            $techToTactics[$tech.id] = @()
        }
        $techToTactics[$tech.id] += $tacticName
    }
}
Write-Host "   ✅ Technique→Tactic lookup: $($techToTactics.Count) techniques mapped" -ForegroundColor Green
#endregion

#region ═══ Load CTID Platform Coverage Reference ════════════════════════════
$ctidFile = Join-Path $ScriptDir "m365-platform-coverage.json"
$ctidRef = $null
if (Test-Path $ctidFile) {
    $ctidRef = Get-Content $ctidFile -Raw | ConvertFrom-Json
    Write-Host "   ✅ CTID M365 Platform Coverage — $($ctidRef.metadata.techniques_with_detect) detect techniques, $($ctidRef.metadata.total_capabilities) capabilities" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  CTID reference not found: $ctidFile — platform coverage analysis will be limited" -ForegroundColor DarkYellow
}
#endregion

#region ═══ Load Known KQL Tables Reference ══════════════════════════════════
$knownTablesFile = Join-Path $ScriptDir "known-kql-tables.json"
$knownTables = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path $knownTablesFile) {
    $knownTablesJson = Get-Content $knownTablesFile -Raw | ConvertFrom-Json
    foreach ($prop in $knownTablesJson.tables.PSObject.Properties) {
        if ($prop.Name -notlike '_*') { [void]$knownTables.Add($prop.Name) }
    }
    Write-Host "   ✅ Known KQL tables reference: $($knownTables.Count) tables loaded" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  Known tables reference not found: $knownTablesFile — all parser candidates treated as Confirmed" -ForegroundColor DarkYellow
}
#endregion

#region ═══ Load & Execute Queries ════════════════════════════════════════════
$phasesToRun = if ($Phase -eq 0) { @(1, 2, 3) } else { @($Phase) }
$allResults = @{}
$allQueries = @{}
$totalStart = Get-Date

foreach ($p in $phasesToRun) {
    $phaseDir = Join-Path $QueryDir "phase$p"
    if (-not (Test-Path $phaseDir)) {
        Write-Warning "Query directory not found: $phaseDir — skipping Phase $p"
        continue
    }

    $queryFiles = Get-ChildItem $phaseDir -Filter "*.yaml" | Sort-Object Name
    Write-Host "`n📂 Phase $p — $($queryFiles.Count) query files:" -ForegroundColor Yellow

    foreach ($file in $queryFiles) {
        $parsed = Import-QueryYaml -Path $file.FullName
        $qId = $parsed["id"]
        if (-not $qId) {
            Write-Warning "Skipping $($file.Name) — missing 'id' field"
            continue
        }
        $allQueries[$qId] = $parsed
        $qType = $parsed["type"]
        $qName = $parsed["name"]
        Write-Host "   🔄 $qName..." -ForegroundColor DarkCyan -NoNewline
        $start = Get-Date

        switch ($qType) {
            'rest' {
                # ─── REST API queries (az rest) ──────────────────────────
                try {
                    $url = $parsed["url"]
                    $url = $url.Replace('{subscription_id}', $subscriptionId)
                    $url = $url.Replace('{resource_group}', $resourceGroup)
                    $url = $url.Replace('{workspace_name}', $workspaceName)
                    $jmespath = $parsed["jmespath"]

                    $rawResult = if ($jmespath) {
                        az rest --method get --url $url --query $jmespath -o json 2>&1
                    } else {
                        az rest --method get --url $url -o json 2>&1
                    }

                    if ($LASTEXITCODE -eq 0) {
                        $data = @($rawResult | ConvertFrom-Json)
                        $rowCount = $data.Count
                        $allResults[$qId] = $data
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Host " ✅ $rowCount items (${elapsed}s)" -ForegroundColor Green
                    } else {
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Host " ❌ FAILED (${elapsed}s)" -ForegroundColor Red
                        Write-Warning "REST query $qId failed: $rawResult"
                        $allResults[$qId] = @{ _status = "FAILED"; _error = "$rawResult" }
                    }
                } catch {
                    $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                    Write-Host " ❌ ERROR (${elapsed}s)" -ForegroundColor Red
                    $allResults[$qId] = @{ _status = "FAILED"; _error = $_.Exception.Message }
                }
            }

            'graph' {
                # ─── Graph API queries (Invoke-MgGraphRequest) — graceful skip ───
                try {
                    $mgModule = Get-Module -ListAvailable Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
                    if (-not $mgModule) {
                        Write-Host " ⏭️  SKIPPED — module not installed" -ForegroundColor DarkYellow
                        $allResults[$qId] = @{ _status = "SKIPPED"; _error = "Module Microsoft.Graph.Authentication not found" }
                        continue
                    }
                    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
                    $mgContext = Get-MgContext -ErrorAction SilentlyContinue
                    $requiredScope = $parsed["scope"]
                    if (-not $mgContext -or ($requiredScope -and ($mgContext.Scopes -notcontains $requiredScope))) {
                        Connect-MgGraph -Scopes $requiredScope -NoWelcome -ErrorAction Stop
                    }
                    $endpoint = $parsed["endpoint"]
                    $selectFields = $parsed["select"]
                    $uri = if ($selectFields) { "${endpoint}?`$select=${selectFields}" } else { $endpoint }
                    $cdResponse = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject -ErrorAction Stop
                    $data = @($cdResponse.value)
                    $rowCount = $data.Count
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

            'kql' {
                # ─── KQL queries (az monitor log-analytics query) ────────
                try {
                    $rawQuery = $parsed["query"].Replace('{days}', "$Days")
                    $rawTimespan = if ($parsed["timespan"]) { $parsed["timespan"].Replace('{days}', "$Days") } else { "P${Days}D" }
                    $singleLine = ($rawQuery -replace '\r?\n', ' ' -replace '\s+', ' ').Trim()

                    $rawResult = az monitor log-analytics query `
                        --workspace $workspaceId `
                        --analytics-query $singleLine `
                        --timespan $rawTimespan `
                        -o json 2>&1

                    if ($LASTEXITCODE -eq 0) {
                        # Filter out stderr warning lines (e.g., cp1252 encoding warnings) that 2>&1 captures
                        $jsonLines = @($rawResult | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] -and $_ -notmatch '^WARNING:' })
                        $data = @($jsonLines | ConvertFrom-Json)
                        $rowCount = $data.Count
                        $allResults[$qId] = $data
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Host " ✅ $rowCount rows (${elapsed}s)" -ForegroundColor Green
                    } else {
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Host " ❌ FAILED (${elapsed}s)" -ForegroundColor Red
                        Write-Warning "KQL query $qId failed: $rawResult"
                        $allResults[$qId] = @{ _status = "FAILED"; _error = "$rawResult" }
                    }
                } catch {
                    $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                    Write-Host " ❌ ERROR (${elapsed}s)" -ForegroundColor Red
                    $allResults[$qId] = @{ _status = "FAILED"; _error = $_.Exception.Message }
                }
            }

            'cli' {
                # ─── CLI commands (az monitor, etc.) ─────────────────────
                try {
                    $cmd = $parsed["command"]
                    $cmd = $cmd.Replace('{subscription_id}', $subscriptionId)
                    $cmd = $cmd.Replace('{resource_group}', $resourceGroup)
                    $cmd = $cmd.Replace('{workspace_name}', $workspaceName)

                    $rawResult = Invoke-Expression $cmd 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $data = @($rawResult | ConvertFrom-Json)
                        $rowCount = $data.Count
                        $allResults[$qId] = $data
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Host " ✅ $rowCount tables (${elapsed}s)" -ForegroundColor Green
                    } else {
                        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                        Write-Host " ❌ FAILED (${elapsed}s)" -ForegroundColor Red
                        Write-Warning "CLI query $qId failed: $rawResult"
                        $allResults[$qId] = @{ _status = "FAILED"; _error = "$rawResult" }
                    }
                } catch {
                    $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
                    Write-Host " ❌ ERROR (${elapsed}s)" -ForegroundColor Red
                    $allResults[$qId] = @{ _status = "FAILED"; _error = $_.Exception.Message }
                }
            }

            default {
                Write-Host " ⏭️  Unknown type '$qType'" -ForegroundColor DarkYellow
            }
        }
    }
}

$totalQueryTime = [math]::Round(((Get-Date) - $totalStart).TotalSeconds, 1)
Write-Host "`n✅ All queries complete — ${totalQueryTime}s total" -ForegroundColor Green
#endregion

#region ═══ Phase 1 Post-Processing: Rule Inventory & MITRE Extraction ════════
Write-Host "`n📊 Computing MITRE coverage metrics..." -ForegroundColor Yellow

$phase1Sections = [System.Text.StringBuilder]::new()
[void]$phase1Sections.AppendLine("## PHASE_1 — Rule Inventory & MITRE Extraction")

# ─── M1: Analytic Rules ─────────────────────────────────────────────────
$m1Data = $allResults["mitre-m1"]
$arTotal = 0; $arEnabled = 0; $arDisabled = 0
$arWithTactics = 0; $arWithTechniques = 0; $arNoMitre = 0; $arNoMitreEnabled = 0

# Per-tactic and per-technique counters (enabled rules only)
$tacticRuleCount = @{}      # tactic → count of enabled rules
$techniqueRuleCount = @{}   # technique → count of enabled rules
$techniqueRuleNames = @{}   # technique → list of rule names (for drill-down)
$techniqueRuleIds = @{}     # technique → list of enabled rule IDs (for phantom coverage detection)
$allRuleTactics = @{}       # ruleId → tactics array
$allRuleTechniques = @{}    # ruleId → techniques array
$untaggedRules = @()        # rules with no tactics AND no techniques

if ($m1Data -is [array] -and $m1Data.Count -gt 0) {
    $arTotal = $m1Data.Count
    foreach ($rule in $m1Data) {
        $isEnabled = $rule.enabled -eq $true -or $rule.enabled -eq 'true'
        if ($isEnabled) { $arEnabled++ } else { $arDisabled++ }

        $hasTactics = $rule.tactics -and $rule.tactics.Count -gt 0
        $hasTechniques = $rule.techniques -and $rule.techniques.Count -gt 0
        if ($hasTactics) { $arWithTactics++ }
        if ($hasTechniques) { $arWithTechniques++ }

        if (-not $hasTactics -and -not $hasTechniques) {
            $arNoMitre++
            if ($isEnabled) { $arNoMitreEnabled++ }
            $untaggedRules += [PSCustomObject]@{
                Name = $rule.displayName
                RuleId = $rule.ruleId
                Enabled = $isEnabled
                Kind = $rule.kind
                Severity = $rule.severity
                Source = "AR"
            }
        }

        # Only count enabled rules for coverage metrics
        if ($isEnabled) {
            if ($hasTactics) {
                foreach ($tactic in $rule.tactics) {
                    if (-not $tacticRuleCount.ContainsKey($tactic)) { $tacticRuleCount[$tactic] = 0 }
                    $tacticRuleCount[$tactic]++
                }
            }
            if ($hasTechniques) {
                foreach ($tech in $rule.techniques) {
                    if (-not $techniqueRuleCount.ContainsKey($tech)) { $techniqueRuleCount[$tech] = 0 }
                    $techniqueRuleCount[$tech]++
                    if (-not $techniqueRuleNames.ContainsKey($tech)) { $techniqueRuleNames[$tech] = @() }
                    $techniqueRuleNames[$tech] += "[AR] $($rule.displayName)"
                    if (-not $techniqueRuleIds.ContainsKey($tech)) { $techniqueRuleIds[$tech] = @() }
                    $techniqueRuleIds[$tech] += $rule.ruleId
                }
            }
        }

        $allRuleTactics[$rule.ruleId] = if ($hasTactics) { $rule.tactics } else { @() }
        $allRuleTechniques[$rule.ruleId] = if ($hasTechniques) { $rule.techniques } else { @() }
    }
}

# ─── Tactic order (needed by both CD processing and TacticCoverage output) ──
$tacticOrder = @('Reconnaissance','ResourceDevelopment','InitialAccess','Execution','Persistence',
    'PrivilegeEscalation','DefenseEvasion','CredentialAccess','Discovery','LateralMovement',
    'Collection','CommandAndControl','Exfiltration','Impact')

# ─── M2: Custom Detection Rules (may be SKIPPED) ────────────────────────
$m2Data = $allResults["mitre-m2"]
$cdTotal = 0; $cdEnabled = 0; $cdDisabled = 0
$cdWithMitre = 0; $cdNoMitre = 0; $cdNoMitreEnabled = 0; $cdStatus = "OK"

if ($m2Data -is [hashtable] -and $m2Data._status) {
    $cdStatus = $m2Data._status
    Write-Host "   ℹ️  Custom Detections: $cdStatus — $($m2Data._error)" -ForegroundColor DarkYellow
} elseif ($m2Data -is [array] -and $m2Data.Count -gt 0) {
    $cdTotal = $m2Data.Count
    foreach ($cd in $m2Data) {
        $isEnabled = $cd.isEnabled -eq $true -or $cd.isEnabled -eq 'true'
        if ($isEnabled) { $cdEnabled++ } else { $cdDisabled++ }

        $cdMitreTechniques = $cd.detectionAction.alertTemplate.mitreTechniques
        $cdCategory = $cd.detectionAction.alertTemplate.category
        $hasTechniques = $cdMitreTechniques -and $cdMitreTechniques.Count -gt 0
        # category is the API's tactic field — valid if it matches a known MITRE tactic
        $hasTactic = $cdCategory -and ($tacticOrder -contains $cdCategory)
        $hasMitre = $hasTechniques -or $hasTactic
        if ($hasMitre) {
            $cdWithMitre++
            if ($isEnabled) {
                if ($hasTechniques) {
                    foreach ($tech in $cdMitreTechniques) {
                        if (-not $techniqueRuleCount.ContainsKey($tech)) { $techniqueRuleCount[$tech] = 0 }
                        $techniqueRuleCount[$tech]++
                        if (-not $techniqueRuleNames.ContainsKey($tech)) { $techniqueRuleNames[$tech] = @() }
                        $techniqueRuleNames[$tech] += "[CD] $($cd.displayName)"
                        if (-not $techniqueRuleIds.ContainsKey($tech)) { $techniqueRuleIds[$tech] = @() }
                        $techniqueRuleIds[$tech] += "CD:$($cd.id)"
                    }
                }
                # Use category (API tactic) as primary; fall back to technique→tactic derivation
                $cdTacticsP1 = @()
                if ($hasTactic) {
                    $cdTacticsP1 = @($cdCategory)
                } else {
                    foreach ($tech in $cdMitreTechniques) {
                        $parentTech = if ($tech -match '^(T\d{4})') { $Matches[1] } else { $tech }
                        if ($techToTactics.ContainsKey($parentTech)) { $cdTacticsP1 += $techToTactics[$parentTech] }
                    }
                    $cdTacticsP1 = $cdTacticsP1 | Select-Object -Unique
                }
                foreach ($tactic in $cdTacticsP1) {
                    if (-not $tacticRuleCount.ContainsKey($tactic)) { $tacticRuleCount[$tactic] = 0 }
                    $tacticRuleCount[$tactic]++
                }
            }
        } else {
            $cdNoMitre++
            if ($isEnabled) { $cdNoMitreEnabled++ }
            $untaggedRules += [PSCustomObject]@{
                Name = $cd.displayName
                RuleId = $cd.id
                Enabled = $isEnabled
                Kind = "CustomDetection"
                Severity = "N/A"
                Source = "CD"
            }
        }
    }
}

# ─── Write Phase 1 scratchpad ───────────────────────────────────────────
[void]$phase1Sections.AppendLine("")
[void]$phase1Sections.AppendLine("### AR_Summary")
[void]$phase1Sections.AppendLine("AR_Total: $arTotal")
[void]$phase1Sections.AppendLine("AR_Enabled: $arEnabled")
[void]$phase1Sections.AppendLine("AR_Disabled: $arDisabled")
[void]$phase1Sections.AppendLine("AR_WithTactics: $arWithTactics")
[void]$phase1Sections.AppendLine("AR_WithTechniques: $arWithTechniques")
[void]$phase1Sections.AppendLine("AR_NoMitre: $arNoMitre")
[void]$phase1Sections.AppendLine("AR_NoMitre_Enabled: $arNoMitreEnabled")
[void]$phase1Sections.AppendLine("")
[void]$phase1Sections.AppendLine("### CD_Summary")
[void]$phase1Sections.AppendLine("CD_Status: $cdStatus")
[void]$phase1Sections.AppendLine("CD_Total: $cdTotal")
[void]$phase1Sections.AppendLine("CD_Enabled: $cdEnabled")
[void]$phase1Sections.AppendLine("CD_Disabled: $cdDisabled")
[void]$phase1Sections.AppendLine("CD_WithMitre: $cdWithMitre")
[void]$phase1Sections.AppendLine("CD_NoMitre: $cdNoMitre")
[void]$phase1Sections.AppendLine("CD_NoMitre_Enabled: $cdNoMitreEnabled")

# ─── Tactic Coverage Matrix ─────────────────────────────────────────────
[void]$phase1Sections.AppendLine("")
[void]$phase1Sections.AppendLine("### TacticCoverage")
[void]$phase1Sections.AppendLine("<!-- Tactic | EnabledRules | FrameworkTechniques | CoveredTechniques | CoveragePct -->")

$totalFrameworkTechs = 0
$totalCoveredTechs = 0
$totalEnabledRules = 0

foreach ($tactic in $tacticOrder) {
    $ruleCount = if ($tacticRuleCount.ContainsKey($tactic)) { $tacticRuleCount[$tactic] } else { 0 }
    $tacticInfo = $attackRef.tactics.$tactic
    $frameworkTechCount = if ($tacticInfo) { $tacticInfo.techniqueCount } else { 0 }

    # Count how many of this tactic's techniques have at least one enabled rule
    $coveredCount = 0
    if ($tacticInfo -and $tacticInfo.techniques) {
        foreach ($tech in $tacticInfo.techniques) {
            if ($techniqueRuleCount.ContainsKey($tech.id) -and $techniqueRuleCount[$tech.id] -gt 0) {
                $coveredCount++
            }
        }
    }

    $coveragePct = if ($frameworkTechCount -gt 0) { [math]::Round(100.0 * $coveredCount / $frameworkTechCount, 1) } else { 0 }
    $totalFrameworkTechs += $frameworkTechCount
    $totalCoveredTechs += $coveredCount
    $totalEnabledRules += $ruleCount

    [void]$phase1Sections.AppendLine("$tactic | $ruleCount | $frameworkTechCount | $coveredCount | $coveragePct")
}

$overallCoverage = if ($totalFrameworkTechs -gt 0) { [math]::Round(100.0 * $totalCoveredTechs / $totalFrameworkTechs, 1) } else { 0 }
[void]$phase1Sections.AppendLine("TOTAL | $totalEnabledRules | $totalFrameworkTechs | $totalCoveredTechs | $overallCoverage")

# ─── Per-Technique Detail (collect for enriched writing after Phase 3) ────
$techDetailRows = [System.Collections.ArrayList]::new()

foreach ($tactic in $tacticOrder) {
    $tacticInfo = $attackRef.tactics.$tactic
    if (-not $tacticInfo -or -not $tacticInfo.techniques) { continue }

    foreach ($tech in ($tacticInfo.techniques | Sort-Object id)) {
        $ruleCount = if ($techniqueRuleCount.ContainsKey($tech.id)) { $techniqueRuleCount[$tech.id] } else { 0 }
        $ruleNames = if ($techniqueRuleNames.ContainsKey($tech.id)) { ($techniqueRuleNames[$tech.id] | Select-Object -First 5) -join "; " } else { "" }
        $subCount = $tech.subTechniques
        [void]$techDetailRows.Add(@{
            Tactic = $tactic
            TechId = $tech.id
            TechName = $tech.name
            SubTechCount = $subCount
            EnabledRules = $ruleCount
            RuleNames = $ruleNames
        })
    }
}

# ─── Untagged Rules ─────────────────────────────────────────────────────
[void]$phase1Sections.AppendLine("")
[void]$phase1Sections.AppendLine("### UntaggedRules")
[void]$phase1Sections.AppendLine("<!-- Name | RuleId | Enabled | Kind | Severity | Source -->")

foreach ($rule in $untaggedRules) {
    [void]$phase1Sections.AppendLine("$($rule.Name) | $($rule.RuleId) | $($rule.Enabled) | $($rule.Kind) | $($rule.Severity) | $($rule.Source)")
}

# ─── ICS Techniques (T0xxx) — separate from Enterprise ──────────────────
$icsTechniques = $techniqueRuleCount.Keys | Where-Object { $_ -match '^T0\d{3}' } | Sort-Object
[void]$phase1Sections.AppendLine("")
[void]$phase1Sections.AppendLine("### ICS_Techniques")
[void]$phase1Sections.AppendLine("<!-- TechniqueID | EnabledRules | RuleNames -->")
foreach ($icsId in $icsTechniques) {
    $ruleCount = $techniqueRuleCount[$icsId]
    $ruleNames = if ($techniqueRuleNames.ContainsKey($icsId)) { ($techniqueRuleNames[$icsId] | Select-Object -First 3) -join "; " } else { "" }
    [void]$phase1Sections.AppendLine("$icsId | $ruleCount | $ruleNames")
}

$phase1Block = $phase1Sections.ToString().TrimEnd()
Write-Host "   ✅ Phase 1 metrics complete — $arEnabled enabled AR, $cdEnabled enabled CD, $overallCoverage% technique coverage" -ForegroundColor Green
#endregion

#region ═══ Phase 2 Post-Processing: SOC Optimization ═════════════════════════
$phase2Sections = [System.Text.StringBuilder]::new()
[void]$phase2Sections.AppendLine("## PHASE_2 — SOC Optimization Insights")

$m3Data = $allResults["mitre-m3"]
$socCoverageRecs = @()
$socMitreTagging = @()
$socStatus = "OK"

if ($m3Data -is [hashtable] -and $m3Data._status) {
    $socStatus = $m3Data._status
    Write-Host "   ℹ️  SOC Optimization: $socStatus" -ForegroundColor DarkYellow
} elseif ($m3Data -is [array]) {
    # Separate coverage recs from MITRE tagging recs
    $socCoverageRecs = @($m3Data | Where-Object { $_.typeId -eq 'Precision_Coverage' -or $_.typeId -eq 'Precision_Coverage_CustomersLikeMe' })
    $socMitreTagging = @($m3Data | Where-Object { $_.typeId -eq 'Precision_Coverage_DetectionMitreTagging' })
}

[void]$phase2Sections.AppendLine("")
[void]$phase2Sections.AppendLine("### SOC_Summary")
[void]$phase2Sections.AppendLine("SOC_Status: $socStatus")
[void]$phase2Sections.AppendLine("SOC_CoverageRecs: $($socCoverageRecs.Count)")
[void]$phase2Sections.AppendLine("SOC_MitreTaggingRecs: $($socMitreTagging.Count)")

# ─── Threat Scenario Coverage ───────────────────────────────────────────
# Deduplicate: when multiple recs exist for the same scenario, prefer Active/InProgress over CompletedBySystem
$dedupedCoverageRecs = @()
$scenarioGroups = $socCoverageRecs | Group-Object { $_.useCaseName }
foreach ($grp in $scenarioGroups) {
    $activeEntries = @($grp.Group | Where-Object { $_.state -ne 'CompletedBySystem' })
    if ($activeEntries.Count -gt 0) {
        # Keep the non-CompletedBySystem entry (Active/InProgress)
        $dedupedCoverageRecs += $activeEntries[0]
    } else {
        # Only CompletedBySystem exists — keep it
        $dedupedCoverageRecs += $grp.Group[0]
    }
}
$dedupeDropped = $socCoverageRecs.Count - $dedupedCoverageRecs.Count
if ($dedupeDropped -gt 0) {
    Write-Host "   ℹ️  Deduplicated SOC scenarios: dropped $dedupeDropped stale CompletedBySystem entries" -ForegroundColor DarkYellow
}

[void]$phase2Sections.AppendLine("")
[void]$phase2Sections.AppendLine("### ThreatScenarios")
[void]$phase2Sections.AppendLine("<!-- Scenario | State | ActiveDetections | RecommendedDetections | PlatformCovered | TemplateCovered | TemplateGap | CompletionRate | TacticSummary -->")

$parsedScenarios = [System.Collections.ArrayList]::new()  # Accumulator for PRERENDERED block

foreach ($rec in ($dedupedCoverageRecs | Sort-Object { $_.useCaseName })) {
    $scenario = if ($rec.useCaseName) { $rec.useCaseName } else { "(unnamed)" }
    $state = $rec.state

    # Parse the additionalProperties from the first suggestion
    $activeCount = 0; $recCount = 0; $tacticSummary = ""
    $platformCovered = 0; $templateCovered = 0; $templateGap = 0
    if ($rec.suggestions -and $rec.suggestions.Count -gt 0) {
        $addlProps = $rec.suggestions[0].additionalProperties
        if ($addlProps) {
            # These may be nested as strings or objects depending on depth
            if ($addlProps.ActiveDetectionsCount) { $activeCount = $addlProps.ActiveDetectionsCount }
            if ($addlProps.RecommendedDetectionsCount) { $recCount = $addlProps.RecommendedDetectionsCount }

            # Parse CoverageEntities: FirstPartyProduct (platform) vs Template (Sentinel rules)
            $coverageRaw = $addlProps.CoverageEntities
            if ($coverageRaw) {
                $coverageEntities = $null
                if ($coverageRaw -is [string]) {
                    try { $coverageEntities = $coverageRaw | ConvertFrom-Json } catch { }
                } elseif ($coverageRaw -is [array]) {
                    $coverageEntities = $coverageRaw
                }
                if ($coverageEntities) {
                    foreach ($ce in $coverageEntities) {
                        $ceType = $ce.Identifier.Type
                        $ceStatus = $ce.Status
                        if ($ceType -eq 'FirstPartyProduct' -and $ceStatus -eq 'Covered') {
                            $platformCovered++
                        } elseif ($ceType -eq 'Template') {
                            if ($ceStatus -eq 'Covered') { $templateCovered++ }
                            elseif ($ceStatus -eq 'NotCovered') { $templateGap++ }
                        }
                    }
                }
            }

            # Extract tactic summary (may be a JSON string)
            $tacticsRaw = $addlProps.Tactics
            if ($tacticsRaw -is [string]) {
                try {
                    $tacticsObj = $tacticsRaw | ConvertFrom-Json
                    $tacticParts = @()
                    foreach ($tp in $tacticsObj) {
                        $tacticParts += "$($tp.Name):$($tp.CurrentCount)/$($tp.RecommendedCount)"
                    }
                    $tacticSummary = $tacticParts -join ", "
                } catch {
                    $tacticSummary = "(parse error)"
                }
            } elseif ($tacticsRaw -is [array]) {
                $tacticParts = @()
                foreach ($tp in $tacticsRaw) {
                    $tacticParts += "$($tp.Name):$($tp.CurrentCount)/$($tp.RecommendedCount)"
                }
                $tacticSummary = $tacticParts -join ", "
            }
        }
    }

    # Compute completion rate (Active / Recommended) as a percentage
    $completionRate = if ($recCount -gt 0) { [math]::Round(100.0 * $activeCount / $recCount, 1) } else { 0 }

    # Accumulate parsed data for PRERENDERED block
    [void]$parsedScenarios.Add(@{
        Scenario        = $scenario
        State           = $state
        Active          = [int]$activeCount
        Recommended     = [int]$recCount
        Platform        = [int]$platformCovered
        Sentinel        = [int]$templateCovered
        SentinelGap     = [int]$templateGap
        CompletionRate  = $completionRate
        TacticSummary   = $tacticSummary
    })

    [void]$phase2Sections.AppendLine("$scenario | $state | $activeCount | $recCount | $platformCovered | $templateCovered | $templateGap | $completionRate | $tacticSummary")
}

# ─── AI MITRE Tagging Suggestions ───────────────────────────────────────
[void]$phase2Sections.AppendLine("")
[void]$phase2Sections.AppendLine("### MitreTaggingSuggestions")

if ($socMitreTagging.Count -gt 0) {
    $taggingRec = $socMitreTagging[0]
    [void]$phase2Sections.AppendLine("State: $($taggingRec.state)")
    [void]$phase2Sections.AppendLine("Description: $($taggingRec.description)")

    if ($taggingRec.suggestions -and $taggingRec.suggestions.Count -gt 0) {
        $addlProps = $taggingRec.suggestions[0].additionalProperties

        # Parse AnalyticRulesRecommendedTags
        $arTags = $addlProps.AnalyticRulesRecommendedTags
        if ($arTags -is [string]) { try { $arTags = $arTags | ConvertFrom-Json } catch { $arTags = @() } }
        if ($arTags -isnot [array]) { $arTags = @() }

        # Cross-reference: verify suggested tags against actual rule definitions from Phase 1
        $arApplied = 0; $arNotApplied = 0; $arPartial = 0; $arNotFound = 0
        $arVerifiedRows = @()
        foreach ($tag in $arTags) {
            $ruleId = $tag.ResourceName
            $sugTactics = if ($tag.Tactics) { @($tag.Tactics) } else { @() }
            $sugTechniques = if ($tag.Techniques) { @($tag.Techniques) } else { @() }
            $sugTacticsStr = if ($sugTactics.Count -gt 0) { $sugTactics -join ", " } else { "(none)" }
            $sugTechniquesStr = if ($sugTechniques.Count -gt 0) { $sugTechniques -join ", " } else { "(none)" }

            # Look up actual tags from Phase 1 rule inventory
            $actualTactics = if ($allRuleTactics.ContainsKey($ruleId)) { @($allRuleTactics[$ruleId]) } else { $null }
            $actualTechniques = if ($allRuleTechniques.ContainsKey($ruleId)) { @($allRuleTechniques[$ruleId]) } else { $null }

            if ($null -eq $actualTactics) {
                $status = "NotFound"
                $arNotFound++
            } else {
                $tacticsApplied = ($sugTactics | Where-Object { $actualTactics -contains $_ }).Count -eq $sugTactics.Count
                $techApplied = ($sugTechniques.Count -eq 0) -or (($sugTechniques | Where-Object { $actualTechniques -contains $_ }).Count -eq $sugTechniques.Count)
                if ($tacticsApplied -and $techApplied) {
                    $status = "Applied"
                    $arApplied++
                } elseif ($tacticsApplied -or $techApplied) {
                    $status = "Partial"
                    $arPartial++
                } else {
                    $status = "NotApplied"
                    $arNotApplied++
                }
            }

            # Check if rule is enabled
            $isEnabled = $false
            if ($m1Data -is [array]) {
                $ruleObj = $m1Data | Where-Object { $_.ruleId -eq $ruleId } | Select-Object -First 1
                if ($ruleObj) { $isEnabled = $ruleObj.enabled -eq $true -or $ruleObj.enabled -eq 'true' }
            }

            $arVerifiedRows += "$ruleId | $sugTacticsStr | $sugTechniquesStr | $status | $isEnabled"
        }

        [void]$phase2Sections.AppendLine("AR_TagSuggestions: $($arTags.Count)")
        [void]$phase2Sections.AppendLine("AR_TagsApplied: $arApplied")
        [void]$phase2Sections.AppendLine("AR_TagsPartial: $arPartial")
        [void]$phase2Sections.AppendLine("AR_TagsNotApplied: $arNotApplied")
        [void]$phase2Sections.AppendLine("AR_TagsNotFound: $arNotFound")
        [void]$phase2Sections.AppendLine("<!-- RuleId | SuggestedTactics | SuggestedTechniques | VerifyStatus | Enabled -->")
        foreach ($row in $arVerifiedRows) {
            [void]$phase2Sections.AppendLine($row)
        }

        # Parse CustomDetectionsRecommendedTags
        $cdTags = $addlProps.CustomDetectionsRecommendedTags
        if ($cdTags -is [string]) { try { $cdTags = $cdTags | ConvertFrom-Json } catch { $cdTags = @() } }
        if ($cdTags -isnot [array]) { $cdTags = @() }
        [void]$phase2Sections.AppendLine("CD_TagSuggestions: $($cdTags.Count)")
    }
} else {
    [void]$phase2Sections.AppendLine("(No MITRE tagging recommendations found)")
}

$phase2Block = $phase2Sections.ToString().TrimEnd()
Write-Host "   ✅ Phase 2 metrics complete — $($dedupedCoverageRecs.Count) coverage scenarios ($dedupeDropped stale dropped), $($socMitreTagging.Count) tagging recs" -ForegroundColor Green
#endregion

#region ═══ Phase 3 Post-Processing: Alert/Incident MITRE Correlation ═════════
$phase3Sections = [System.Text.StringBuilder]::new()
[void]$phase3Sections.AppendLine("## PHASE_3 — Operational MITRE Correlation")

# ─── M4: Alert Firing by MITRE ──────────────────────────────────────────
$m4Data = $allResults["mitre-m4"]
[void]$phase3Sections.AppendLine("")
[void]$phase3Sections.AppendLine("### AlertFiring")

if ($m4Data -is [array] -and $m4Data.Count -gt 0) {
    [void]$phase3Sections.AppendLine("AlertFiring_Count: $($m4Data.Count)")
    [void]$phase3Sections.AppendLine("<!-- Source | AlertName | RuleId | AlertCount | HighSev | MedSev | LowSev | InfoSev -->")
    foreach ($alert in $m4Data) {
        $src = if ($alert.Source) { $alert.Source } else { 'AR' }
        [void]$phase3Sections.AppendLine("$src | $($alert.AlertName) | $($alert.RuleId) | $($alert.AlertCount) | $($alert.HighSev) | $($alert.MediumSev) | $($alert.LowSev) | $($alert.InfoSev)")
    }

    # Cross-reference firing rules with their MITRE tags from M1 (AR) or SecurityAlert Tactics (CD)
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### AlertFiring_MitreCorrelation")
    [void]$phase3Sections.AppendLine("<!-- Source | AlertName | Tactics | Techniques | AlertCount -->")
    foreach ($alert in $m4Data) {
        $src = if ($alert.Source) { $alert.Source } else { 'AR' }
        if ($src -eq 'AR' -and $allRuleTactics.ContainsKey($alert.RuleId)) {
            # AR rules: use M1 inventory for precise tactic/technique mapping
            $ruleTactics = $allRuleTactics[$alert.RuleId] -join ", "
            $ruleTechniques = if ($allRuleTechniques.ContainsKey($alert.RuleId)) { $allRuleTechniques[$alert.RuleId] -join ", " } else { "(no match)" }
        } elseif ($src -eq 'CD') {
            # CD rules: use Tactics from SecurityAlert (Graph API is cross-tenant, no technique-level detail)
            $rawTactics = $alert.Tactics
            if ($rawTactics -is [string]) {
                try { $rawTactics = $rawTactics | ConvertFrom-Json -ErrorAction SilentlyContinue } catch { $rawTactics = @() }
            }
            # Flatten nested arrays: Tactics comes as make_set(Tactics) which is array-of-arrays
            $flatTactics = @()
            if ($rawTactics) {
                foreach ($item in $rawTactics) {
                    if ($item -is [array] -or $item -is [System.Collections.IEnumerable] -and $item -isnot [string]) {
                        foreach ($sub in $item) { if ($sub -and $sub -ne '') { $flatTactics += $sub } }
                    } elseif ($item -and $item -ne '' -and $item -ne '[]') {
                        $flatTactics += $item
                    }
                }
            }
            $flatTactics = $flatTactics | Select-Object -Unique
            $ruleTactics = if ($flatTactics.Count -gt 0) { $flatTactics -join ", " } else { "(no match)" }
            $ruleTechniques = "(CD — no technique-level data)"
        } else {
            $ruleTactics = "(no match)"
            $ruleTechniques = "(no match)"
        }
        [void]$phase3Sections.AppendLine("$src | $($alert.AlertName) | $ruleTactics | $ruleTechniques | $($alert.AlertCount)")
    }

    # Compute "active tactic coverage" — tactics with at least one firing rule
    $firingTactics = @{}
    foreach ($alert in $m4Data) {
        $src = if ($alert.Source) { $alert.Source } else { 'AR' }
        $alertTactics = @()
        if ($src -eq 'AR' -and $allRuleTactics.ContainsKey($alert.RuleId)) {
            $alertTactics = $allRuleTactics[$alert.RuleId]
        } elseif ($src -eq 'CD') {
            # For CDs, extract tactics from SecurityAlert Tactics column
            $rawTactics = $alert.Tactics
            if ($rawTactics -is [string]) {
                try { $rawTactics = $rawTactics | ConvertFrom-Json -ErrorAction SilentlyContinue } catch { $rawTactics = @() }
            }
            if ($rawTactics) {
                foreach ($item in $rawTactics) {
                    if ($item -is [array] -or ($item -is [System.Collections.IEnumerable] -and $item -isnot [string])) {
                        foreach ($sub in $item) { if ($sub -and $sub -ne '') { $alertTactics += $sub } }
                    } elseif ($item -and $item -ne '' -and $item -ne '[]') {
                        $alertTactics += $item
                    }
                }
            }
            $alertTactics = $alertTactics | Select-Object -Unique
        }
        foreach ($t in $alertTactics) {
            if (-not $firingTactics.ContainsKey($t)) { $firingTactics[$t] = 0 }
            $firingTactics[$t] += [int]$alert.AlertCount
        }
    }
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### ActiveTacticCoverage")
    [void]$phase3Sections.AppendLine("<!-- Tactic | FiringRuleAlerts -->")
    foreach ($tactic in $tacticOrder) {
        $alerts = if ($firingTactics.ContainsKey($tactic)) { $firingTactics[$tactic] } else { 0 }
        [void]$phase3Sections.AppendLine("$tactic | $alerts")
    }
} else {
    [void]$phase3Sections.AppendLine("AlertFiring_Count: 0")
    [void]$phase3Sections.AppendLine("(No SecurityAlert data in ${Days}d window)")
}

# ─── M5: Incident Volume by Tactic ──────────────────────────────────────
$m5Data = $allResults["mitre-m5"]
[void]$phase3Sections.AppendLine("")
[void]$phase3Sections.AppendLine("### IncidentsByTactic")

if ($m5Data -is [array] -and $m5Data.Count -gt 0) {
    [void]$phase3Sections.AppendLine("IncidentTactic_Count: $($m5Data.Count)")
    [void]$phase3Sections.AppendLine("<!-- Tactic | Incidents | HighSev | MedSev | LowSev | InfoSev | TP | FP | BP -->")
    foreach ($row in $m5Data) {
        [void]$phase3Sections.AppendLine("$($row.Tactic) | $($row.IncidentCount) | $($row.HighSev) | $($row.MediumSev) | $($row.LowSev) | $($row.InfoSev) | $($row.TP) | $($row.FP) | $($row.BP)")
    }
} elseif ($m5Data -is [hashtable] -and $m5Data._status) {
    [void]$phase3Sections.AppendLine("IncidentTactic_Status: $($m5Data._status)")
} else {
    [void]$phase3Sections.AppendLine("IncidentTactic_Count: 0")
    [void]$phase3Sections.AppendLine("(No SecurityIncident data in ${Days}d window)")
}

# ─── M6: Platform Alert MITRE Coverage ──────────────────────────────────
$m6Data = $allResults["mitre-m6"]
[void]$phase3Sections.AppendLine("")
[void]$phase3Sections.AppendLine("### PlatformAlertCoverage")
$platformTechniques = @{}
$activeProducts = @{}
$familyOnlyProducts = @{}
$displayProducts = @()

# Build product alias map for normalizing SecurityAlert ProductName → CTID canonical name
$prodAliases = @{}
if ($ctidRef -and $ctidRef.product_aliases) {
    foreach ($prop in $ctidRef.product_aliases.PSObject.Properties) {
        $prodAliases[$prop.Name] = $prop.Value
    }
}

# Build product family map (child product active → parent also active for tier matching)
$prodFamilies = @{}
if ($ctidRef -and $ctidRef.product_families) {
    foreach ($prop in $ctidRef.product_families.PSObject.Properties) {
        $prodFamilies[$prop.Name] = $prop.Value
    }
}

# Build display name map for modern branding in output
$prodDisplayNames = @{}
if ($ctidRef -and $ctidRef.display_names) {
    foreach ($prop in $ctidRef.display_names.PSObject.Properties) {
        $prodDisplayNames[$prop.Name] = $prop.Value
    }
}

if ($m6Data -is [array] -and $m6Data.Count -gt 0) {
    [void]$phase3Sections.AppendLine("PlatformAlert_TechniqueCount: $($m6Data.Count)")
    [void]$phase3Sections.AppendLine("<!-- Technique | AlertCount | DistinctAlertTypes | Products | AlertNames -->")
    foreach ($row in $m6Data) {
        $tech = $row.Technique
        $alertCount = [int]$row.AlertCount
        $distinctTypes = [int]$row.DistinctAlertTypes
        $products = $row.Products
        $productList = @()
        if ($products -is [array]) { $productList = @($products) }
        elseif ($products -is [string]) { try { $productList = @($products | ConvertFrom-Json) } catch { $productList = @($products) } }
        $alertNames = $row.AlertNames
        $alertNameList = @()
        if ($alertNames -is [array]) { $alertNameList = @($alertNames) }
        elseif ($alertNames -is [string]) { try { $alertNameList = @($alertNames | ConvertFrom-Json) } catch { $alertNameList = @($alertNames) } }

        # Parse per-alert product mapping from 'ProductName|||AlertName' format
        $alertDetails = @()
        foreach ($entry in $alertNameList) {
            $parts = $entry -split '\|\|\|', 2
            if ($parts.Count -eq 2) {
                $alertDetails += @{ Product = $parts[0]; Name = $parts[1] }
            } else {
                $alertDetails += @{ Product = $null; Name = $entry }
            }
        }

        $platformTechniques[$tech] = @{ AlertCount = $alertCount; DistinctAlertTypes = $distinctTypes; Products = $productList; AlertDetails = $alertDetails }
        foreach ($p in $productList) {
            $normalizedProd = if ($prodAliases.ContainsKey($p)) { $prodAliases[$p] } else { $p }
            $activeProducts[$normalizedProd] = $true
        }
        # Write scratchpad with per-alert product names for traceability
        $scratchAlertNames = @($alertDetails | ForEach-Object {
            if ($_.Product) { "$($_.Product)|||$($_.Name)" } else { $_.Name }
        })
        [void]$phase3Sections.AppendLine("$tech | $alertCount | $distinctTypes | $($productList -join '; ') | $($scratchAlertNames -join '; ')")
    }

    # Expand product families: if a child product is active, mark its parent active too (for tier matching)
    $familyOnlyProducts = @{}
    foreach ($child in @($activeProducts.Keys)) {
        if ($prodFamilies.ContainsKey($child)) {
            $parent = $prodFamilies[$child]
            if (-not $activeProducts.ContainsKey($parent)) {
                $activeProducts[$parent] = $true
                $familyOnlyProducts[$parent] = $true
            }
        }
    }

    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### DeployedProducts")
    # Exclude family-only products from display (they exist only for tier matching)
    $displayProducts = @($activeProducts.Keys | Where-Object { -not $familyOnlyProducts.ContainsKey($_) } | Sort-Object)
    [void]$phase3Sections.AppendLine("ActiveProducts_Count: $($displayProducts.Count)")
    foreach ($prod in $displayProducts) {
        $prodTechCount = @($platformTechniques.GetEnumerator() | Where-Object {
            $normalizedProds = @($_.Value.Products | ForEach-Object {
                if ($prodAliases.ContainsKey($_)) { $prodAliases[$_] } else { $_ }
            })
            $normalizedProds -contains $prod
        }).Count
        $displayName = if ($prodDisplayNames.ContainsKey($prod)) { $prodDisplayNames[$prod] } else { $prod }
        [void]$phase3Sections.AppendLine("$displayName | $prodTechCount techniques")
    }

    # Add AR/CD alert-proven technique counts (for "by Source" donut chart)
    if ($m4Data -is [array] -and $m4Data.Count -gt 0) {
        $arAlertTechniques = @{}
        $cdAlertTechniques = @{}
        # Build CD name→techniques lookup from M2 data
        $cdNameToTechniques = @{}
        if ($m2Data -is [array]) {
            foreach ($cd in $m2Data) {
                $cdTechs = $cd.detectionAction.alertTemplate.mitreTechniques
                if ($cdTechs -and $cdTechs.Count -gt 0) {
                    $cdNameToTechniques[$cd.displayName] = $cdTechs
                }
            }
        }
        foreach ($alert in $m4Data) {
            $src = if ($alert.Source) { $alert.Source } else { 'AR' }
            if ($src -eq 'AR' -and $allRuleTechniques.ContainsKey($alert.RuleId)) {
                foreach ($tech in $allRuleTechniques[$alert.RuleId]) {
                    $arAlertTechniques[$tech] = $true
                }
            } elseif ($src -eq 'CD' -and $cdNameToTechniques.ContainsKey($alert.AlertName)) {
                foreach ($tech in $cdNameToTechniques[$alert.AlertName]) {
                    $cdAlertTechniques[$tech] = $true
                }
            }
        }
        if ($arAlertTechniques.Count -gt 0) {
            [void]$phase3Sections.AppendLine("Analytic Rules (AR) | $($arAlertTechniques.Count) techniques")
        }
        if ($cdAlertTechniques.Count -gt 0) {
            [void]$phase3Sections.AppendLine("Custom Detections (CD) | $($cdAlertTechniques.Count) techniques")
        }
    }
} elseif ($m6Data -is [hashtable] -and $m6Data._status) {
    [void]$phase3Sections.AppendLine("PlatformAlert_Status: $($m6Data._status)")
} else {
    [void]$phase3Sections.AppendLine("PlatformAlert_TechniqueCount: 0")
    [void]$phase3Sections.AppendLine("(No platform alert MITRE data in ${Days}d window)")
}

# ─── Supplementary Active Product Detection ──────────────────────────────
# Always run: M6 only captures products from technique-attributed alerts.
# This supplementary query discovers products with tactic-only alerts (MCAS, DLP, IRM, etc.)
# so they enable Tier 2 (deployed capability) classification in the CTID cross-reference.
try {
    # Discover all active platform products from SecurityAlert (tactic-only included)
    $prodQuery = "SecurityAlert | where TimeGenerated > ago(${Days}d) | where ProviderName !in~ ('ASI Scheduled Alerts', 'ASI NRT Alerts') | where isnotempty(ProductName) | summarize AlertCount = count() by ProductName"
    $prodRaw = az monitor log-analytics query --workspace $workspaceId --analytics-query $prodQuery --timespan "P${Days}D" -o json 2>&1
    if ($LASTEXITCODE -eq 0) {
        $prodData = @($prodRaw | ConvertFrom-Json)
        foreach ($row in $prodData) {
            $rawProd = $row.ProductName
            $normalizedProd = if ($prodAliases.ContainsKey($rawProd)) { $prodAliases[$rawProd] } else { $rawProd }
            if (-not $activeProducts.ContainsKey($normalizedProd)) {
                $activeProducts[$normalizedProd] = $true
            }
        }
        # Expand product families for newly discovered products
        foreach ($child in @($activeProducts.Keys)) {
            if ($prodFamilies.ContainsKey($child)) {
                $parent = $prodFamilies[$child]
                if (-not $activeProducts.ContainsKey($parent)) {
                    $activeProducts[$parent] = $true
                    $familyOnlyProducts[$parent] = $true
                }
            }
        }
        # Update deployed products for scratchpad output
        $displayProducts = @($activeProducts.Keys | Where-Object { -not $familyOnlyProducts.ContainsKey($_) } | Sort-Object)
        if ($displayProducts.Count -gt 0) {
            [void]$phase3Sections.AppendLine("")
            [void]$phase3Sections.AppendLine("### DeployedProducts_Supplementary")
            [void]$phase3Sections.AppendLine("ActiveProducts_Count: $($displayProducts.Count)")
            [void]$phase3Sections.AppendLine("(Detected from all platform SecurityAlerts, including tactic-only alerts)")
            foreach ($prod in $displayProducts) {
                $prodTechCount = @($platformTechniques.GetEnumerator() | Where-Object {
                    $normalizedProds = @($_.Value.Products | ForEach-Object {
                        if ($prodAliases.ContainsKey($_)) { $prodAliases[$_] } else { $_ }
                    })
                    $normalizedProds -contains $prod
                }).Count
                $displayName = if ($prodDisplayNames.ContainsKey($prod)) { $prodDisplayNames[$prod] } else { $prod }
                [void]$phase3Sections.AppendLine("$displayName | $prodTechCount techniques (T1), alerts present")
            }
        }
    } else {
        Write-Warning "Supplementary product detection query failed (exit code $LASTEXITCODE)"
    }
} catch {
    Write-Warning "Supplementary product detection failed: $($_.Exception.Message)"
}

# ─── CTID Cross-Reference: Tier Classification ──────────────────────────
[void]$phase3Sections.AppendLine("")
[void]$phase3Sections.AppendLine("### PlatformTechniquesByTier")
$tier1Techniques = @{}
$tier2Techniques = @{}
$tier3Techniques = @{}

if ($ctidRef) {
    $capToProductLookup = @{}
    foreach ($prop in $ctidRef.capability_to_product.PSObject.Properties) {
        $capToProductLookup[$prop.Name] = $prop.Value
    }

    $classified = @{}
    foreach ($tacticName in $attackRef.tactics.PSObject.Properties.Name) {
        foreach ($tech in $attackRef.tactics.$tacticName.techniques) {
            $techId = $tech.id
            if ($classified.ContainsKey($techId)) { continue }
            $classified[$techId] = $true

            if ($platformTechniques.ContainsKey($techId)) {
                $tier1Techniques[$techId] = $platformTechniques[$techId]
                continue
            }

            $detectCaps = $ctidRef.detect_coverage.$techId
            if ($detectCaps -and @($detectCaps).Count -gt 0) {
                $hasActiveProduct = $false
                foreach ($capId in $detectCaps) {
                    $product = $capToProductLookup[$capId]
                    if ($product -and $activeProducts.ContainsKey($product)) {
                        $hasActiveProduct = $true; break
                    }
                }
                if ($hasActiveProduct) {
                    $tier2Techniques[$techId] = @{
                        Capabilities = @($detectCaps)
                        Products = @($detectCaps | ForEach-Object { $capToProductLookup[$_] } | Where-Object { $_ } | Select-Object -Unique)
                    }
                } else {
                    $tier3Techniques[$techId] = @{ Capabilities = @($detectCaps) }
                }
            }
        }
    }

    [void]$phase3Sections.AppendLine("Tier1_AlertProven: $($tier1Techniques.Count)")
    [void]$phase3Sections.AppendLine("Tier2_DeployedCapability: $($tier2Techniques.Count)")
    [void]$phase3Sections.AppendLine("Tier3_CatalogCapability: $($tier3Techniques.Count)")
    [void]$phase3Sections.AppendLine("CTID_Version: $($ctidRef.metadata.ctid_version)")

    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### Tier1_AlertProven")
    [void]$phase3Sections.AppendLine("<!-- Technique | AlertCount | DistinctAlertTypes | Products -->")
    foreach ($techId in ($tier1Techniques.Keys | Sort-Object)) {
        $t = $tier1Techniques[$techId]
        [void]$phase3Sections.AppendLine("$techId | $($t.AlertCount) | $($t.DistinctAlertTypes) | $($t.Products -join '; ')")
    }

    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### Tier2_DeployedCapability")
    [void]$phase3Sections.AppendLine("<!-- Technique | Capabilities | Products -->")
    foreach ($techId in ($tier2Techniques.Keys | Sort-Object)) {
        $t = $tier2Techniques[$techId]
        $displayProds = @($t.Products | ForEach-Object { if ($prodDisplayNames.ContainsKey($_)) { $prodDisplayNames[$_] } else { $_ } })
        [void]$phase3Sections.AppendLine("$techId | $($t.Capabilities -join ', ') | $($displayProds -join '; ')")
    }

    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### Tier3_CatalogCapability")
    [void]$phase3Sections.AppendLine("<!-- Technique | Capabilities -->")
    foreach ($techId in ($tier3Techniques.Keys | Sort-Object)) {
        $t = $tier3Techniques[$techId]
        [void]$phase3Sections.AppendLine("$techId | $($t.Capabilities -join ', ')")
    }
} else {
    [void]$phase3Sections.AppendLine("(CTID reference not available — tier classification skipped)")
}

# ─── Enriched TechniqueDetail with Tier annotations ─────────────────────
# Written here (Phase 3) instead of Phase 1 so tier data is available
[void]$phase3Sections.AppendLine("")
[void]$phase3Sections.AppendLine("### TechniqueDetail")
[void]$phase3Sections.AppendLine("<!-- Tactic | TechniqueID | TechniqueName | SubTechCount | EnabledRules | Tier | TierProducts | RuleNames | PlatformAlertNames -->")
foreach ($row in $techDetailRows) {
    $tier = [char]0x2014  # em-dash
    $tierProducts = [char]0x2014
    if ($tier1Techniques.ContainsKey($row.TechId)) {
        $tier = "T1"
        $rawProds = @($tier1Techniques[$row.TechId].Products)
        $normProds = @($rawProds | ForEach-Object { if ($prodAliases.ContainsKey($_)) { $prodAliases[$_] } else { $_ } } | Select-Object -Unique)
        $displayProds = @($normProds | ForEach-Object { if ($prodDisplayNames.ContainsKey($_)) { $prodDisplayNames[$_] } else { $_ } })
        $tierProducts = $displayProds -join '; '
    } elseif ($tier2Techniques.ContainsKey($row.TechId)) {
        $tier = "T2"
        $displayProds = @($tier2Techniques[$row.TechId].Products | ForEach-Object { if ($prodDisplayNames.ContainsKey($_)) { $prodDisplayNames[$_] } else { $_ } })
        $tierProducts = $displayProds -join '; '
    } elseif ($tier3Techniques.ContainsKey($row.TechId)) {
        $tier = "T3"
        $tierProducts = "CTID catalog"
    }
    # Resolve platform alert names for Tier 1 techniques
    $platformAlertNames = ""
    if ($tier1Techniques.ContainsKey($row.TechId)) {
        $alertNameList = $tier1Techniques[$row.TechId].AlertNames
        if ($alertNameList -and $alertNameList.Count -gt 0) {
            $platformAlertNames = $alertNameList -join '; '
        }
    }
    [void]$phase3Sections.AppendLine("$($row.Tactic) | $($row.TechId) | $($row.TechName) | $($row.SubTechCount) | $($row.EnabledRules) | $tier | $tierProducts | $($row.RuleNames) | $platformAlertNames")
}

# ─── Platform + Rule-Based Combined Tactic Coverage ─────────────────────────
[void]$phase3Sections.AppendLine("")
[void]$phase3Sections.AppendLine("### PlatformTacticCoverage")
[void]$phase3Sections.AppendLine("<!-- Tactic | Tier1 | Tier2 | Tier3 | RuleBased | Combined | FrameworkTotal | CombinedPct -->")

$totalCombinedTechs = 0
foreach ($tactic in $tacticOrder) {
    $tacticInfo = $attackRef.tactics.$tactic
    if (-not $tacticInfo) { continue }
    $frameworkTechCount = $tacticInfo.techniqueCount
    $t1 = 0; $t2 = 0; $t3 = 0; $ruleBased = 0; $combined = 0
    foreach ($tech in $tacticInfo.techniques) {
        $techId = $tech.id
        if ($tier1Techniques.ContainsKey($techId)) { $t1++ }
        elseif ($tier2Techniques.ContainsKey($techId)) { $t2++ }
        elseif ($tier3Techniques.ContainsKey($techId)) { $t3++ }
        if ($techniqueRuleCount.ContainsKey($techId) -and $techniqueRuleCount[$techId] -gt 0) { $ruleBased++ }
        $hasCoverage = ($techniqueRuleCount.ContainsKey($techId) -and $techniqueRuleCount[$techId] -gt 0) -or
                       $tier1Techniques.ContainsKey($techId) -or $tier2Techniques.ContainsKey($techId)
        if ($hasCoverage) { $combined++ }
    }
    $combinedPct = if ($frameworkTechCount -gt 0) { [math]::Round(100.0 * $combined / $frameworkTechCount, 1) } else { 0 }
    $totalCombinedTechs += $combined
    [void]$phase3Sections.AppendLine("$tactic | $t1 | $t2 | $t3 | $ruleBased | $combined | $frameworkTechCount | $combinedPct")
}

$overallCombinedPct = if ($totalFrameworkTechs -gt 0) { [math]::Round(100.0 * $totalCombinedTechs / $totalFrameworkTechs, 1) } else { 0 }
[void]$phase3Sections.AppendLine("TOTAL | $($tier1Techniques.Count) | $($tier2Techniques.Count) | $($tier3Techniques.Count) | $totalCoveredTechs | $totalCombinedTechs | $totalFrameworkTechs | $overallCombinedPct")

# ─── M7: Table Ingestion Volume — Data Readiness Cross-Reference ─────────
$m7Data = $allResults["mitre-m7"]
$tableVolumes = @{}  # DataType → AvgDailyMB

if ($m7Data -is [array] -and $m7Data.Count -gt 0) {
    foreach ($row in $m7Data) {
        $tableVolumes[$row.DataType] = [double]$row.AvgDailyMB
    }
    Write-Host "   ✅ M7 ingestion data: $($tableVolumes.Count) tables with volume" -ForegroundColor Green
} elseif ($m7Data -is [hashtable] -and $m7Data._status) {
    Write-Host "   ⚠️  M7 ingestion data: $($m7Data._status)" -ForegroundColor DarkYellow
} else {
    Write-Host "   ⚠️  M7 ingestion data: no results" -ForegroundColor DarkYellow
}

# ─── M9: Table Tier Classification — Non-Analytics Tier Detection ────────
$m9Data = $allResults["mitre-m9"]
$tableTiers = @{}  # TableName → plan (Analytics, Basic, Auxiliary)
$nonAnalyticsTables = @{}  # TableName → tier label (Basic or Data Lake)

if ($m9Data -is [array] -and $m9Data.Count -gt 0) {
    foreach ($row in $m9Data) {
        $tableTiers[$row.name] = $row.plan
        if ($row.plan -eq 'Basic') {
            $nonAnalyticsTables[$row.name] = 'Basic'
        } elseif ($row.plan -eq 'Auxiliary') {
            $nonAnalyticsTables[$row.name] = 'Data Lake'
        }
    }
    Write-Host "   ✅ M9 tier data: $($tableTiers.Count) tables ($($nonAnalyticsTables.Count) non-Analytics)" -ForegroundColor Green
} elseif ($m9Data -is [hashtable] -and $m9Data._status) {
    Write-Host "   ⚠️  M9 tier data: $($m9Data._status)" -ForegroundColor DarkYellow
} else {
    Write-Host "   ⚠️  M9 tier data: no results" -ForegroundColor DarkYellow
}

# Extract table dependencies from rule KQL queries (M1 data)
# Parses table names from: top-level table references before |, union operands, join operands, let assignments
function Get-KqlTableNames {
    <#
    .SYNOPSIS
        Extract KQL table names from a rule query using regex heuristics.
    .DESCRIPTION
        Normalizes the query to a single line (eliminating multi-line project/extend
        column continuations), then extracts table-like identifiers from:
        1. First uppercase token of each pipe segment
        2. Union operands
        3. Join parenthesized operands
        4. Let assignments (let x = TableName)
        5. String arguments in function calls: table("Name"), func("Name")
        Uses case-sensitive matching (-cmatch) so lowercase KQL operators and column
        names are naturally excluded. Let-variable names are tracked and excluded.
    #>
    param([string]$Query)
    $tables = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Query)) { return @() }

    # Step 1: Normalize — strip comments, collapse to single line
    $cleaned = ($Query -replace '//[^\r\n]*', '') -replace '\r?\n', ' ' -replace '\s+', ' '

    # Step 2: Collect let-variable names (these shadow table names and must be excluded)
    $letVars = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($m in [regex]::Matches($cleaned, '\blet\s+(\w+)\s*=', 'IgnoreCase')) {
        [void]$letVars.Add($m.Groups[1].Value)
    }

    # Step 3: KQL keywords/functions to exclude (case-insensitive via HashSet)
    $kqlExclude = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @(# Tabular operators
      'let','where','extend','project','summarize','join','union','on','by','and','or','not','in',
      'distinct','evaluate','lookup','find','search','invoke','getschema','consume','serialize',
      'fork','facet','as','set','alias','declare','pattern','restrict','render','print','datatable',
      'take','limit','top','sort','order','asc','desc','with','kind','isfuzzy','table','typeof',
      'mvexpand','mvapply','externaldata',
      # Join flavors
      'inner','outer','leftouter','rightouter','fullouter','anti','leftanti','rightanti','leftsemi','rightsemi',
      # String/comparison operators
      'contains','has','has_any','has_all','startswith','endswith','matches','between','like','notlike',
      # Type conversions
      'tostring','toint','tolong','todecimal','todouble','tobool','todynamic','toscalar','parse_json',
      # Aggregation functions
      'count','dcount','sum','avg','min','max','countif','dcountif','sumif','make_set','make_list',
      'make_bag','make_set_if','make_list_if','make_series','arg_max','arg_min','percentile','percentiles',
      # Scalar functions
      'iff','case','coalesce','isnull','isnotnull','isempty','isnotempty','strlen','tolower','toupper',
      'trim','replace','split','strcat','strcat_delim','format_datetime','format_timespan','bin',
      'round','ceiling','floor','abs','log','exp','pow','sqrt','ago','now','datetime','timespan',
      'pack','bag_pack','array_length','array_index_of','set_difference','set_union','set_has_element',
      'set_intersect','materialize','range','gettype','column_ifexists','columnifexists','ingestion_time',
      'pack_array','bag_keys','bag_has_key','bag_merge','ipv4_is_private','ipv4_is_match',
      'hash_sha256','base64_decode_tostring','url_decode','parse','extract','extract_all',
      'row_number','prev','next','series_stats','series_decompose','geo_point_to_geohash','format_ipv4',
      'extractjson','parse_csv','parse_path','parse_url','parse_urlquery','parse_user_agent',
      # Built-in column names (avoid false positives)
      'TimeGenerated','Timestamp',
      # Constants
      'true','false','dynamic','external_table'
    ) | ForEach-Object { [void]$kqlExclude.Add($_) }

    # Helper: validate candidate (must start uppercase, not keyword, not let-var, min 3 chars)
    # NOTE: All regex matching uses -cmatch (case-sensitive) to enforce uppercase requirement
    $sq = [char]39  # single-quote for regex character class

    # --- Extraction strategies ---

    # 1. String arguments in function calls: table("SigninLogs"), aadFunc("AADNonInteractiveUserSignInLogs")
    #    This catches dynamic table references that no other strategy can detect
    foreach ($m in [regex]::Matches($cleaned, "\w+\s*\(\s*[$sq`"]([A-Z]\w{2,}(?:_CL)?)[$sq`"]")) {
        $c = $m.Groups[1].Value
        if (-not $kqlExclude.Contains($c) -and -not $letVars.Contains($c)) {
            [void]$tables.Add($c)
        }
    }

    # 2. First token of pipe segments (case-sensitive: must start with uppercase letter)
    foreach ($seg in ($cleaned -split '\|')) {
        $seg = $seg.Trim()
        if ([string]::IsNullOrWhiteSpace($seg)) { continue }

        if ($seg -cmatch '^([A-Z]\w{2,}(?:_CL)?)\b') {
            $c = $matches[1]
            if (-not $kqlExclude.Contains($c) -and -not $letVars.Contains($c)) {
                [void]$tables.Add($c)
            }
        }
    }

    # 3. Union operands: union [isfuzzy=true] Table1, Table2, (Table3 | ...)
    foreach ($m in [regex]::Matches($cleaned, '(?i:union)\s+(?:(?i:isfuzzy)\s*=\s*\w+\s+)?(.+?)(?:\||$)')) {
        foreach ($tm in [regex]::Matches($m.Groups[1].Value, '\b([A-Z]\w{2,}(?:_CL)?)\b')) {
            $c = $tm.Groups[1].Value
            if (-not $kqlExclude.Contains($c) -and -not $letVars.Contains($c)) {
                [void]$tables.Add($c)
            }
        }
    }

    # 4. Join operands: join kind=inner (TableName | ...)
    foreach ($m in [regex]::Matches($cleaned, '(?i:join)\b[^(]*\(\s*([A-Z]\w{2,}(?:_CL)?)\b')) {
        $c = $m.Groups[1].Value
        if (-not $kqlExclude.Contains($c) -and -not $letVars.Contains($c)) {
            [void]$tables.Add($c)
        }
    }

    # 5. Let assignments: let varName = TableName | ... (table name is the RHS, not the variable)
    foreach ($m in [regex]::Matches($cleaned, '(?i:let)\s+\w+\s*=\s*\(?\s*([A-Z]\w{2,}(?:_CL)?)\b')) {
        $c = $m.Groups[1].Value
        if (-not $kqlExclude.Contains($c) -and -not $letVars.Contains($c)) {
            [void]$tables.Add($c)
        }
    }

    return @($tables)
}

# Build rule → tables mapping and cross-reference with M7 volume data and M9 tier data
[void]$phase3Sections.AppendLine("")
[void]$phase3Sections.AppendLine("### DataReadiness")
[void]$phase3Sections.AppendLine("<!-- RuleName | RuleId | Enabled | HasMitre | Tables | Status | MissingTables | TableVolumes | UnverifiedTables | TierBlockedTables -->")

$readyCount = 0; $partialCount = 0; $noDataCount = 0; $noQueryCount = 0; $tierBlockedCount = 0
$tierBlockedRuleIds = @{}  # ruleId → $true for rules whose tables are on non-Analytics tier
$ruleReadiness = @{}       # ruleId → Ready/Partial/NoData/TierBlocked (used by readiness-weighted Breadth scoring)
$nonReadyRules = [System.Collections.ArrayList]::new()  # accumulator for pre-rendering §5.5 detail table
$missingTablesSummary = @{}  # table → count of rules needing it
$unverifiedTablesSummary = @{}  # table → count of rules where it appeared as unverified
$tierBlockedTablesSummary = @{}  # table → { tier, rulesAffected }

if ($m1Data -is [array] -and $m1Data.Count -gt 0 -and $tableVolumes.Count -gt 0) {
    foreach ($rule in $m1Data) {
        $isEnabled = $rule.enabled -eq $true -or $rule.enabled -eq 'true'
        if (-not $isEnabled) { continue }  # Only check enabled rules

        $hasMitre = ($rule.tactics -and $rule.tactics.Count -gt 0) -or ($rule.techniques -and $rule.techniques.Count -gt 0)
        $queryText = $rule.query
        if ([string]::IsNullOrWhiteSpace($queryText)) {
            $noQueryCount++
            continue
        }

        $tables = Get-KqlTableNames -Query $queryText
        if ($tables.Count -eq 0) {
            $noQueryCount++
            continue
        }

        $tablesWithData = @()
        $tablesNoData = @()       # Confirmed missing (in known-tables OR is _CL custom table)
        $tablesUnverified = @()   # Not in known-tables reference — likely parser false positive
        $tableVolumeStr = @()
        $tablesTierBlocked = @()  # Tables on non-Analytics tier (Basic/Data Lake) — rule cannot query them

        foreach ($t in $tables) {
            # Check tier FIRST — if table is on non-Analytics tier, it's structurally blocked
            if ($nonAnalyticsTables.ContainsKey($t)) {
                $tablesTierBlocked += $t
                $tierLabel = $nonAnalyticsTables[$t]
                if (-not $tierBlockedTablesSummary.ContainsKey($t)) {
                    $tierBlockedTablesSummary[$t] = @{ Tier = $tierLabel; Count = 0 }
                }
                $tierBlockedTablesSummary[$t].Count++
            } elseif ($tableVolumes.ContainsKey($t)) {
                $tablesWithData += $t
                $tableVolumeStr += "$t=$($tableVolumes[$t])MB"
            } else {
                # Classify: Confirmed (in known-tables or _CL custom table) vs Unverified (potential FP)
                $isKnown = $knownTables.Count -gt 0 -and $knownTables.Contains($t)
                $isCustom = $t -like '*_CL'
                if ($isKnown -or $isCustom -or $knownTables.Count -eq 0) {
                    $tablesNoData += $t
                    if (-not $missingTablesSummary.ContainsKey($t)) { $missingTablesSummary[$t] = 0 }
                    $missingTablesSummary[$t]++
                } else {
                    $tablesUnverified += $t
                    if (-not $unverifiedTablesSummary.ContainsKey($t)) { $unverifiedTablesSummary[$t] = 0 }
                    $unverifiedTablesSummary[$t]++
                }
            }
        }

        # Status hierarchy: TierBlocked > NoData > Partial > Ready
        # TierBlocked: ANY primary table is on non-Analytics tier (rule structurally cannot fire)
        # Even if some tables have data, the tier-blocked table makes the rule non-functional
        $status = if ($tablesTierBlocked.Count -gt 0) { "TierBlocked" }
                  elseif ($tablesNoData.Count -eq 0) { "Ready" }
                  elseif ($tablesWithData.Count -gt 0) { "Partial" }
                  else { "NoData" }

        switch ($status) {
            "Ready"       { $readyCount++ }
            "Partial"     { $partialCount++ }
            "NoData"      { $noDataCount++ }
            "TierBlocked" { $tierBlockedCount++; $tierBlockedRuleIds[$rule.ruleId] = $true }
        }
        $ruleReadiness[$rule.ruleId] = $status

        # Only write detail rows for non-Ready rules to keep scratchpad manageable
        if ($status -ne "Ready") {
            $tablesStr = ($tables -join ', ')
            $missingStr = if ($tablesNoData.Count -gt 0) { $tablesNoData -join ', ' } else { "—" }
            $volumeStr = if ($tableVolumeStr.Count -gt 0) { $tableVolumeStr -join ', ' } else { "—" }
            $unverifiedStr = if ($tablesUnverified.Count -gt 0) { $tablesUnverified -join ', ' } else { "—" }
            $tierBlockedStr = if ($tablesTierBlocked.Count -gt 0) { ($tablesTierBlocked | ForEach-Object { "$_($($nonAnalyticsTables[$_]))" }) -join ', ' } else { "—" }
            [void]$phase3Sections.AppendLine("$($rule.displayName) | $($rule.ruleId) | $isEnabled | $hasMitre | $tablesStr | $status | $missingStr | $volumeStr | $unverifiedStr | $tierBlockedStr")
            [void]$nonReadyRules.Add(@{
                RuleName     = $rule.displayName
                Tables       = $tablesStr
                Status       = $status
                MissingTables = $missingStr
                Volumes      = $volumeStr
            })
        }
    }
}

# ─── CD rule readiness (same constraints as AR — CDs can target any table) ───
if ($m2Data -is [array] -and $m2Data.Count -gt 0 -and $tableVolumes.Count -gt 0) {
    foreach ($cd in $m2Data) {
        $isEnabled = $cd.isEnabled -eq $true -or $cd.isEnabled -eq 'true'
        if (-not $isEnabled) { continue }
        $cdQueryText = $cd.queryCondition.queryText
        if ([string]::IsNullOrWhiteSpace($cdQueryText)) {
            # No query text available — treat as Ready (can't assess)
            $ruleReadiness["CD:$($cd.id)"] = "Ready"
            continue
        }
        $cdTables = Get-KqlTableNames -Query $cdQueryText
        if ($cdTables.Count -eq 0) {
            $ruleReadiness["CD:$($cd.id)"] = "Ready"
            continue
        }
        $cdTablesWithData = @(); $cdTablesNoData = @(); $cdTablesTierBlocked = @()
        foreach ($t in $cdTables) {
            if ($nonAnalyticsTables.ContainsKey($t)) {
                # Note: CDs run via AH which CAN query non-Analytics tables, but at cost.
                # For scoring: treat the same as AR — the table tier issue is real.
                $cdTablesTierBlocked += $t
            } elseif ($tableVolumes.ContainsKey($t)) {
                $cdTablesWithData += $t
            } else {
                $isKnown = $knownTables.Count -gt 0 -and $knownTables.Contains($t)
                $isCustom = $t -like '*_CL'
                if ($isKnown -or $isCustom -or $knownTables.Count -eq 0) {
                    $cdTablesNoData += $t
                }
                # else: unverified — ignore for readiness (parser FP)
            }
        }
        $cdStatus = if ($cdTablesTierBlocked.Count -gt 0) { "TierBlocked" }
                    elseif ($cdTablesNoData.Count -eq 0) { "Ready" }
                    elseif ($cdTablesWithData.Count -gt 0) { "Partial" }
                    else { "NoData" }
        $ruleReadiness["CD:$($cd.id)"] = $cdStatus
    }
    Write-Host "   ✅ CD readiness assessed for $($ruleReadiness.Keys.Where({ $_.StartsWith('CD:') }).Count) enabled custom detection rules" -ForegroundColor Green
}

[void]$phase3Sections.AppendLine("")
[void]$phase3Sections.AppendLine("### DataReadiness_Summary")
[void]$phase3Sections.AppendLine("Rules_Ready: $readyCount")
[void]$phase3Sections.AppendLine("Rules_Partial: $partialCount")
[void]$phase3Sections.AppendLine("Rules_NoData: $noDataCount")
[void]$phase3Sections.AppendLine("Rules_TierBlocked: $tierBlockedCount")
[void]$phase3Sections.AppendLine("Rules_NoQuery: $noQueryCount")
$totalChecked = $readyCount + $partialCount + $noDataCount + $tierBlockedCount
$readinessPct = if ($totalChecked -gt 0) { [math]::Round(100.0 * $readyCount / $totalChecked, 1) } else { 0 }
[void]$phase3Sections.AppendLine("Readiness_Pct: $readinessPct")

# Missing tables summary (confirmed known tables needed by rules but with zero ingestion)
if ($missingTablesSummary.Count -gt 0) {
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### MissingTables")
    [void]$phase3Sections.AppendLine("<!-- Table | RulesAffected | Confidence -->")
    foreach ($entry in ($missingTablesSummary.GetEnumerator() | Sort-Object Value -Descending)) {
        [void]$phase3Sections.AppendLine("$($entry.Key) | $($entry.Value) | Confirmed")
    }
}

# Unverified tables summary (parser candidates NOT in known-tables reference — likely false positives)
if ($unverifiedTablesSummary.Count -gt 0) {
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### UnverifiedTables")
    [void]$phase3Sections.AppendLine("<!-- Table | RulesAffected | Note -->")
    foreach ($entry in ($unverifiedTablesSummary.GetEnumerator() | Sort-Object Value -Descending)) {
        [void]$phase3Sections.AppendLine("$($entry.Key) | $($entry.Value) | NotInReference")
    }
}

# Tier-blocked tables summary (tables on Basic/Data Lake tier — analytics rules cannot query them)
if ($tierBlockedTablesSummary.Count -gt 0) {
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### TierBlockedTables")
    [void]$phase3Sections.AppendLine("<!-- Table | Tier | RulesAffected -->")
    foreach ($entry in ($tierBlockedTablesSummary.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
        [void]$phase3Sections.AppendLine("$($entry.Key) | $($entry.Value.Tier) | $($entry.Value.Count)")
    }
}

$unverifiedCount = $unverifiedTablesSummary.Count
$tierBlockedTableCount = $tierBlockedTablesSummary.Count
Write-Host "   ✅ Data Readiness: $readyCount ready, $partialCount partial, $noDataCount no data, $tierBlockedCount tier-blocked ($readinessPct% readiness)" -ForegroundColor Green
if ($tierBlockedCount -gt 0) {
    Write-Host "   ⚠️  $tierBlockedCount rules target $tierBlockedTableCount non-Analytics tier tables (phantom coverage)" -ForegroundColor Yellow
}
if ($unverifiedCount -gt 0) {
    Write-Host "   ℹ️  Filtered $unverifiedCount unverified table candidates (likely parser false positives)" -ForegroundColor DarkCyan
}

# ─── M8: SentinelHealth Data Connector Health ────────────────────────────
$m8Data = $allResults["mitre-m8"]
$connectorHealth = @{}  # SentinelResourceName → { LastStatus, HealthPct, FailureCount, SuccessCount }

if ($m8Data -is [array] -and $m8Data.Count -gt 0) {
    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### ConnectorHealth")
    [void]$phase3Sections.AppendLine("<!-- ConnectorName | LastStatus | SuccessCount | FailureCount | HealthPct | LastEvent -->")
    $degradedCount = 0
    $failingCount = 0
    foreach ($row in $m8Data) {
        $name = $row.SentinelResourceName
        $lastStatus = $row.LastStatus
        $successCount = [int]$row.SuccessCount
        $failureCount = [int]$row.FailureCount
        $healthPct = [double]$row.HealthPct
        $lastEvent = $row.LastEvent
        $connectorHealth[$name] = @{
            LastStatus   = $lastStatus
            HealthPct    = $healthPct
            FailureCount = $failureCount
            SuccessCount = $successCount
        }
        [void]$phase3Sections.AppendLine("$name | $lastStatus | $successCount | $failureCount | $healthPct | $lastEvent")
        if ($lastStatus -eq 'Failure') { $failingCount++ }
        elseif ($healthPct -lt 90) { $degradedCount++ }
    }

    [void]$phase3Sections.AppendLine("")
    [void]$phase3Sections.AppendLine("### ConnectorHealth_Summary")
    [void]$phase3Sections.AppendLine("Connectors_Total: $($m8Data.Count)")
    [void]$phase3Sections.AppendLine("Connectors_Healthy: $($m8Data.Count - $failingCount - $degradedCount)")
    [void]$phase3Sections.AppendLine("Connectors_Degraded: $degradedCount")
    [void]$phase3Sections.AppendLine("Connectors_Failing: $failingCount")

    Write-Host "   ✅ M8 connector health: $($m8Data.Count) connectors ($failingCount failing, $degradedCount degraded)" -ForegroundColor Green
} elseif ($m8Data -is [hashtable] -and $m8Data._status) {
    Write-Host "   ⚠️  M8 connector health: $($m8Data._status) — SentinelHealth may not be enabled or table empty" -ForegroundColor DarkYellow
} else {
    Write-Host "   ⚠️  M8 connector health: no results (SentinelHealth feature may not be enabled)" -ForegroundColor DarkYellow
}

$phase3Block = $phase3Sections.ToString().TrimEnd()
Write-Host "   ✅ Phase 3 metrics complete — $($platformTechniques.Count) platform techniques (Tier 1), $($tier2Techniques.Count) deployed capability (Tier 2)" -ForegroundColor Green
#endregion

#region ═══ Compute Coverage Score ════════════════════════════════════════════
Write-Host "`n📈 Computing MITRE Coverage Score..." -ForegroundColor Yellow

# Score dimensions (each 0-100, weighted sum → final 0-100 score)
# 1. Technique breadth: readiness-weighted coverage
#    Each covered technique gets fractional credit based on the BEST rule covering it:
#    - Fired (alert-proven): 1.00  — validated by real/simulated attack
#    - Ready (data exists):  0.75  — rule CAN fire, just hasn't been triggered
#    - Partial (some data):  0.50  — partially functional
#    - NoData (zero ingest): 0.25  — paper tiger, but technique is addressed in theory
#    - TierBlocked:          0.00  — structurally impossible (phantom coverage)
#    Credit hierarchy: max across all rules covering a technique (one firing rule = full credit)

# ── Step A: Identify firing MITRE-tagged rules (needed by BOTH Breadth and Operational) ──
$mitreTaggedEnabled = $arEnabled - $arNoMitreEnabled + $cdEnabled - $cdNoMitreEnabled
$firingMitreRuleIds = @{}
if ($m4Data -is [array]) {
    foreach ($alert in $m4Data) {
        $src = if ($alert.Source) { $alert.Source } else { 'AR' }
        if ($src -eq 'AR' -and $allRuleTactics.ContainsKey($alert.RuleId) -and $allRuleTactics[$alert.RuleId].Count -gt 0) {
            $firingMitreRuleIds[$alert.RuleId] = $true
        } elseif ($src -eq 'CD') {
            # CD rules: check if SecurityAlert Tactics column is non-empty
            $rawTactics = $alert.Tactics
            $hasTactics = $false
            if ($rawTactics) {
                if ($rawTactics -is [string]) {
                    try { $rawTactics = $rawTactics | ConvertFrom-Json -ErrorAction SilentlyContinue } catch { $rawTactics = @() }
                }
                foreach ($item in $rawTactics) {
                    if ($item -is [array] -or ($item -is [System.Collections.IEnumerable] -and $item -isnot [string])) {
                        foreach ($sub in $item) { if ($sub -and $sub -ne '') { $hasTactics = $true; break } }
                    } elseif ($item -and $item -ne '' -and $item -ne '[]') { $hasTactics = $true }
                    if ($hasTactics) { break }
                }
            }
            if ($hasTactics) { $firingMitreRuleIds[$alert.RuleId] = $true }
        }
    }
}
$firingMitreRules = $firingMitreRuleIds.Count

# ── Step 1: Readiness-weighted Breadth ──
# Credit map: each technique gets fractional credit based on the BEST rule covering it
$readinessCredit = @{
    'Fired'       = 1.00   # Validated by real/simulated attack
    'Ready'       = 0.75   # Rule CAN fire — data exists, just hasn't been triggered
    'Partial'     = 0.50   # Partially functional (some tables missing)
    'NoData'      = 0.25   # Paper tiger — technique addressed in theory only
    'TierBlocked' = 0.00   # Structurally impossible (phantom coverage)
}
$readinessPriority = @{ 'Fired' = 5; 'Ready' = 4; 'Partial' = 3; 'NoData' = 2; 'TierBlocked' = 1; 'Unknown' = 3 }

$totalWeightedCredit = 0.0
$phantomTechniques = @()
$techCreditBreakdown = @{}  # tech → best status (for diagnostics)
foreach ($tech in @($techniqueRuleCount.Keys)) {
    if ($techniqueRuleCount[$tech] -le 0) { continue }
    if (-not $techniqueRuleIds.ContainsKey($tech)) {
        Write-Warning "Technique $tech has rule count $($techniqueRuleCount[$tech]) but no rule IDs — skipping from breadth score"
        continue
    }
    $ruleIds = $techniqueRuleIds[$tech]
    $bestStatus = 'TierBlocked'
    $bestPriority = 1
    foreach ($rid in $ruleIds) {
        if ($firingMitreRuleIds.ContainsKey($rid)) {
            $bestStatus = 'Fired'; $bestPriority = 5; break
        }
        $rStatus = if ($ruleReadiness.ContainsKey($rid)) { $ruleReadiness[$rid] } else { 'Unknown' }
        $rPriority = if ($readinessPriority.ContainsKey($rStatus)) { $readinessPriority[$rStatus] } else { 3 }
        if ($rPriority -gt $bestPriority) {
            $bestStatus = $rStatus
            $bestPriority = $rPriority
        }
    }
    $credit = if ($readinessCredit.ContainsKey($bestStatus)) { $readinessCredit[$bestStatus] }
              elseif ($bestStatus -eq 'Unknown') { 0.75 }  # no readiness data — treat as Ready
              else { 0.25 }
    $totalWeightedCredit += $credit
    $techCreditBreakdown[$tech] = $bestStatus
    if ($bestStatus -eq 'TierBlocked') { $phantomTechniques += $tech }
}
$phantomTechCount = $phantomTechniques.Count

# Readiness-weighted rule Breadth (0-100)
$ruleBreadth = if ($totalFrameworkTechs -gt 0) { 100.0 * $totalWeightedCredit / $totalFrameworkTechs } else { 0 }
# Blended: 60% readiness-weighted rule-based + 40% combined (rule + platform T1 + T2)
$combinedBreadth = if ($totalFrameworkTechs -gt 0) { 100.0 * $totalCombinedTechs / $totalFrameworkTechs } else { 0 }
$breadthScore = [math]::Round(0.6 * $ruleBreadth + 0.4 * $combinedBreadth, 1)

# Diagnostic: technique credit distribution
$creditStats = @{ Fired = 0; Ready = 0; Partial = 0; NoData = 0; TierBlocked = 0; Unknown = 0 }
foreach ($s in $techCreditBreakdown.Values) {
    if ($creditStats.ContainsKey($s)) { $creditStats[$s]++ } else { $creditStats['Unknown']++ }
}
if ($phantomTechCount -gt 0) {
    Write-Host "   ⚠️  Breadth: $phantomTechCount phantom technique(s) get 0 credit (TierBlocked)" -ForegroundColor Yellow
}
Write-Host "   📊 Technique credit: $($creditStats.Fired) fired (1.0) · $($creditStats.Ready) ready (0.75) · $($creditStats.Partial) partial (0.50) · $($creditStats.NoData) nodata (0.25) · $($creditStats.TierBlocked) blocked (0)" -ForegroundColor DarkCyan

# ── Step 2: Tactic balance ──
$tacticsWithRules = ($tacticOrder | Where-Object { $tacticRuleCount.ContainsKey($_) -and $tacticRuleCount[$_] -gt 0 }).Count
$balanceScore = [math]::Round(100.0 * $tacticsWithRules / $tacticOrder.Count, 1)

# ── Step 3: Operational validation ──
$operationalScore = if ($mitreTaggedEnabled -gt 0) { [math]::Min(100, [math]::Round(100.0 * $firingMitreRules / $mitreTaggedEnabled, 1)) } else { 0 }

# ── Step 4: Tagging completeness ──
$totalRules = $arTotal + $cdTotal
$taggedRules = ($arWithTactics + $cdWithMitre)
$taggingScore = if ($totalRules -gt 0) { [math]::Round(100.0 * $taggedRules / $totalRules, 1) } else { 0 }

# ── Step 5: SOC Optimization alignment ──
$activeSOCRecs = @($socCoverageRecs | Where-Object { $_.state -eq 'Active' -or $_.state -eq 'InProgress' })
$completedSOCRecs = @($socCoverageRecs | Where-Object { $_.state -eq 'CompletedBySystem' -or $_.state -eq 'Completed' -or $_.state -eq 'CompletedByUser' })
$totalSOCRecs = $socCoverageRecs.Count
$socAlignScore = if ($totalSOCRecs -gt 0) { [math]::Round(100.0 * $completedSOCRecs.Count / $totalSOCRecs, 1) } else { 50 }

# ── Weighted final score ──
# Operational boosted to 30% (rewards purple teaming / validated detections)
# Breadth reduced to 25% (now readiness-weighted, less raw weight needed)
# Balance reduced to 10% (least actionable dimension)
$weights = @{ breadth = 0.25; balance = 0.10; operational = 0.30; tagging = 0.15; socAlign = 0.20 }
$finalScore = [math]::Round(
    $breadthScore * $weights.breadth +
    $balanceScore * $weights.balance +
    $operationalScore * $weights.operational +
    $taggingScore * $weights.tagging +
    $socAlignScore * $weights.socAlign
, 1)

Write-Host "   Breadth:      $breadthScore (weight $($weights.breadth)) [rule=$([math]::Round($ruleBreadth,1))% (readiness-weighted) · combined=$([math]::Round($combinedBreadth,1))% · blend 60/40]" -ForegroundColor DarkCyan
Write-Host "   Balance:      $balanceScore (weight $($weights.balance))" -ForegroundColor DarkCyan
Write-Host "   Operational:  $operationalScore (weight $($weights.operational))" -ForegroundColor DarkCyan
Write-Host "   Tagging:      $taggingScore (weight $($weights.tagging))" -ForegroundColor DarkCyan
Write-Host "   SOC Align:    $socAlignScore (weight $($weights.socAlign))" -ForegroundColor DarkCyan
Write-Host "   ━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "   MITRE Score:  $finalScore / 100" -ForegroundColor Cyan
Write-Host "" -ForegroundColor Cyan
Write-Host "   Platform Coverage (supplementary):" -ForegroundColor DarkCyan
Write-Host "   Tier 1 (Alert-Proven):     $($tier1Techniques.Count) techniques" -ForegroundColor DarkCyan
Write-Host "   Tier 2 (Deployed Cap):     $($tier2Techniques.Count) techniques" -ForegroundColor DarkCyan
Write-Host "   Tier 3 (Catalog Cap):      $($tier3Techniques.Count) techniques" -ForegroundColor DarkCyan
Write-Host "   Rule-Based + Platform T1+T2:   $totalCombinedTechs / $totalFrameworkTechs ($overallCombinedPct%)" -ForegroundColor DarkCyan
#endregion

#region ═══ Build PRERENDERED Blocks ══════════════════════════════════════════
Write-Host "`n📐 Building PRERENDERED blocks..." -ForegroundColor Yellow
$prerenderedSections = [System.Text.StringBuilder]::new()

# Product abbreviation map (display name → short code for alert prefixes)
$prodAbbrev = @{
    "Microsoft Defender for Endpoint" = "MDE"
    "Microsoft Defender XDR" = "MXDR"
    "Microsoft Defender for Identity" = "MDI"
    "Microsoft Defender for Cloud Apps" = "MDCA"
    "Microsoft Defender for Office 365" = "MDO"
    "Microsoft Entra ID Protection" = "AADIP"
    "Microsoft Defender for Cloud" = "MDC"
    "Microsoft Purview DLP" = "DLP"
    "Microsoft Defender for IoT" = "MDIoT"
    "Microsoft 365 Insider Risk Management" = "IRM"
    "Microsoft Application Protection" = "MAP"
}

# Tactic display names (CamelCase → human-readable)
$tacticDisplayNames = @{
    "Reconnaissance" = "Reconnaissance"
    "ResourceDevelopment" = "Resource Development"
    "InitialAccess" = "Initial Access"
    "Execution" = "Execution"
    "Persistence" = "Persistence"
    "PrivilegeEscalation" = "Privilege Escalation"
    "DefenseEvasion" = "Defense Evasion"
    "CredentialAccess" = "Credential Access"
    "Discovery" = "Discovery"
    "LateralMovement" = "Lateral Movement"
    "Collection" = "Collection"
    "CommandAndControl" = "Command and Control"
    "Exfiltration" = "Exfiltration"
    "Impact" = "Impact"
}

# Helper: abbreviate a display product name
function Get-ProdAbbrev {
    param([string]$DisplayName)
    if ($prodAbbrev.ContainsKey($DisplayName)) { return $prodAbbrev[$DisplayName] }
    # Try matching through prodDisplayNames (old name → display name → abbrev)
    foreach ($entry in $prodDisplayNames.GetEnumerator()) {
        if ($entry.Value -eq $DisplayName -and $prodAbbrev.ContainsKey($entry.Value)) {
            return $prodAbbrev[$entry.Value]
        }
    }
    return $DisplayName  # fallback: return full name
}

# Helper: format platform alert names with product abbreviation prefix
function Format-PlatformAlerts {
    param([string]$TechId, [int]$MaxAlerts = 5)
    if (-not $tier1Techniques.ContainsKey($TechId)) { return "" }
    $t1 = $tier1Techniques[$TechId]
    $alertDetails = @($t1.AlertDetails | Where-Object { $_ })
    if ($alertDetails.Count -eq 0) { return "" }

    $formatted = @()
    $shown = [Math]::Min($alertDetails.Count, $MaxAlerts)
    for ($i = 0; $i -lt $shown; $i++) {
        $detail = $alertDetails[$i]
        $prodName = $detail.Product
        if ($prodName) {
            if ($prodAliases.ContainsKey($prodName)) { $prodName = $prodAliases[$prodName] }
            if ($prodDisplayNames.ContainsKey($prodName)) { $prodName = $prodDisplayNames[$prodName] }
            $abbrev = Get-ProdAbbrev $prodName
            $formatted += "[$abbrev] $($detail.Name)"
        } else {
            $formatted += $detail.Name
        }
    }
    $result = $formatted -join "; "
    if ($alertDetails.Count -gt $MaxAlerts) {
        $result += "; +$($alertDetails.Count - $MaxAlerts) platform"
    }
    return $result
}

# ─── PRERENDERED.TechniqueTables ─────────────────────────────────────────
# Pre-rendered per-tactic technique tables — LLM copies verbatim
[void]$prerenderedSections.AppendLine("## PRERENDERED")
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### TechniqueTables")
[void]$prerenderedSections.AppendLine("<!-- Pre-rendered per-tactic markdown tables. Copy VERBATIM into §3. DO NOT reorder, rename, or restructure rows. -->")

foreach ($tactic in $tacticOrder) {
    $tacticInfo = $attackRef.tactics.$tactic
    if (-not $tacticInfo) { continue }

    $displayName = if ($tacticDisplayNames.ContainsKey($tactic)) { $tacticDisplayNames[$tactic] } else { $tactic }
    $frameworkTechCount = $tacticInfo.techniqueCount
    $coveredCount = 0      # rule-based only (AR + CD)
    $combinedCount = 0     # rules + platform T1 + T2
    foreach ($tech in $tacticInfo.techniques) {
        $hasRules = $techniqueRuleCount.ContainsKey($tech.id) -and $techniqueRuleCount[$tech.id] -gt 0
        $hasPlatform = $tier1Techniques.ContainsKey($tech.id) -or $tier2Techniques.ContainsKey($tech.id)
        if ($hasRules) { $coveredCount++ }
        if ($hasRules -or $hasPlatform) { $combinedCount++ }
    }
    $coveragePct = if ($frameworkTechCount -gt 0) { [math]::Round(100.0 * $coveredCount / $frameworkTechCount, 1) } else { 0 }
    $combinedPct = if ($frameworkTechCount -gt 0) { [math]::Round(100.0 * $combinedCount / $frameworkTechCount, 1) } else { 0 }

    # Get technique rows for this tactic
    $tacticRows = @($techDetailRows | Where-Object { $_.Tactic -eq $tactic })

    # Classify each row
    $classifiedRows = @()
    foreach ($row in $tacticRows) {
        $techId = $row.TechId
        $ruleCount = $row.EnabledRules
        $tier = $null
        if ($tier1Techniques.ContainsKey($techId)) { $tier = "T1" }
        elseif ($tier2Techniques.ContainsKey($techId)) { $tier = "T2" }
        elseif ($tier3Techniques.ContainsKey($techId)) { $tier = "T3" }

        # Badge
        if ($ruleCount -gt 0) { $badge = "✅" }
        elseif ($tier -eq "T1") { $badge = "🟢" }
        elseif ($tier -eq "T2") { $badge = "🔵" }
        elseif ($tier -eq "T3") { $badge = "⬜" }
        else { $badge = "❌" }

        # Sort priority: ✅=1, 🟢=2, 🔵=3, ⬜=4, ❌=5
        $sortPriority = if ($ruleCount -gt 0) { 1 }
                        elseif ($tier -eq "T1") { 2 }
                        elseif ($tier -eq "T2") { 3 }
                        elseif ($tier -eq "T3") { 4 }
                        else { 5 }

        # Detections column
        # Display budget: 5 total items. Custom rules get priority slots,
        # then platform alerts fill remaining slots. Overflow shows "+N" breakdown.
        $maxDisplay = 5
        $detections = "—"
        if ($ruleCount -gt 0) {
            # ✅ rows: show custom rule names first
            $ruleNameList = @()
            if ($techniqueRuleNames.ContainsKey($techId)) {
                $ruleNameList = @($techniqueRuleNames[$techId])
            }
            $shownRules = @($ruleNameList | Select-Object -First $maxDisplay)
            $remainingSlots = $maxDisplay - $shownRules.Count
            $overflowRules = [Math]::Max(0, $ruleNameList.Count - $maxDisplay)

            # Fill remaining slots with platform alerts (Tier 1 only)
            $shownPlatform = @()
            $overflowPlatform = 0
            if ($tier -eq "T1" -and $remainingSlots -gt 0 -and $tier1Techniques.ContainsKey($techId)) {
                $alertDetails = @($tier1Techniques[$techId].AlertDetails | Where-Object { $_ })
                $platformSlots = [Math]::Min($alertDetails.Count, $remainingSlots)
                for ($p = 0; $p -lt $platformSlots; $p++) {
                    $detail = $alertDetails[$p]
                    $prodName = $detail.Product
                    if ($prodName) {
                        if ($prodAliases.ContainsKey($prodName)) { $prodName = $prodAliases[$prodName] }
                        if ($prodDisplayNames.ContainsKey($prodName)) { $prodName = $prodDisplayNames[$prodName] }
                        $abbrev = Get-ProdAbbrev $prodName
                        $shownPlatform += "[$abbrev] $($detail.Name)"
                    } else {
                        $shownPlatform += $detail.Name
                    }
                }
                $overflowPlatform = [Math]::Max(0, $alertDetails.Count - $platformSlots)
            } elseif ($tier -eq "T1" -and $remainingSlots -le 0 -and $tier1Techniques.ContainsKey($techId)) {
                # No slots left but platform alerts exist — count them for overflow
                $alertDetails = @($tier1Techniques[$techId].AlertDetails | Where-Object { $_ })
                $overflowPlatform = $alertDetails.Count
            }

            # Assemble detections string
            $allShown = @($shownRules) + @($shownPlatform)
            $detections = $allShown -join "; "

            # Append overflow suffix
            $overflowParts = @()
            if ($overflowRules -gt 0) { $overflowParts += "$overflowRules rules" }
            if ($overflowPlatform -gt 0) { $overflowParts += "$overflowPlatform platform" }
            if ($overflowParts.Count -gt 0) {
                $detections += "; +$($overflowParts -join ', ')"
            }
        } elseif ($tier -eq "T1") {
            # 🟢 rows: show platform alert names with product prefix
            $platformAlerts = Format-PlatformAlerts -TechId $techId -MaxAlerts $maxDisplay
            if ($platformAlerts) { $detections = $platformAlerts }
        }

        # Platform column
        $platformCol = "—"
        if ($ruleCount -gt 0 -and $tier -eq "T1") {
            # ✅ with Tier 1: show "Tier 1: MDE, MDI" (same format as 🟢 rows)
            $rawProds = @($tier1Techniques[$techId].Products)
            $normProds = @($rawProds | ForEach-Object {
                $p = $_; if ($prodAliases.ContainsKey($p)) { $p = $prodAliases[$p] }
                if ($prodDisplayNames.ContainsKey($p)) { $prodDisplayNames[$p] } else { $p }
            } | Select-Object -Unique)
            $abbrevProds = @($normProds | ForEach-Object { Get-ProdAbbrev $_ })
            $platformCol = "Tier 1: $($abbrevProds -join ', ')"
        } elseif ($ruleCount -gt 0 -and $tier -eq "T2") {
            $rawProds = @($tier2Techniques[$techId].Products)
            $normProds = @($rawProds | ForEach-Object {
                if ($prodDisplayNames.ContainsKey($_)) { $prodDisplayNames[$_] } else { $_ }
            } | Select-Object -Unique)
            $abbrevProds = @($normProds | ForEach-Object { Get-ProdAbbrev $_ })
            $platformCol = "Tier 2: $($abbrevProds -join ', ')"
        } elseif ($ruleCount -gt 0 -and $tier -eq "T3") {
            $platformCol = "⬜ Tier 3"
        } elseif ($tier -eq "T1") {
            # 🟢: "Tier 1: MDE, MDI"
            $rawProds = @($tier1Techniques[$techId].Products)
            $normProds = @($rawProds | ForEach-Object {
                $p = $_; if ($prodAliases.ContainsKey($p)) { $p = $prodAliases[$p] }
                if ($prodDisplayNames.ContainsKey($p)) { $prodDisplayNames[$p] } else { $p }
            } | Select-Object -Unique)
            $abbrevProds = @($normProds | ForEach-Object { Get-ProdAbbrev $_ })
            $platformCol = "Tier 1: $($abbrevProds -join ', ')"
        } elseif ($tier -eq "T2") {
            $rawProds = @($tier2Techniques[$techId].Products)
            $normProds = @($rawProds | ForEach-Object {
                if ($prodDisplayNames.ContainsKey($_)) { $prodDisplayNames[$_] } else { $_ }
            } | Select-Object -Unique)
            $abbrevProds = @($normProds | ForEach-Object { Get-ProdAbbrev $_ })
            $platformCol = "Tier 2: $($abbrevProds -join ', ')"
        } elseif ($tier -eq "T3") {
            $platformCol = "⬜ Tier 3"
        }

        $classifiedRows += [PSCustomObject]@{
            Badge = $badge
            TechId = $techId
            TechName = $row.TechName
            SubTechCount = $row.SubTechCount
            EnabledRules = $ruleCount
            Detections = $detections
            Platform = $platformCol
            SortPriority = $sortPriority
            SortRules = $ruleCount  # secondary sort for ✅ rows
        }
    }

    # Sort: priority first, then rules desc within ✅
    $sortedRows = @($classifiedRows | Sort-Object SortPriority, @{Expression={$_.SortRules}; Descending=$true}, TechId)

    # For large tactics: limit ❌ rows to 10
    $maxGapRows = 10
    $gapRows = @($sortedRows | Where-Object { $_.SortPriority -eq 5 })
    $nonGapRows = @($sortedRows | Where-Object { $_.SortPriority -lt 5 })
    $truncatedGapCount = 0
    if ($gapRows.Count -gt $maxGapRows) {
        $truncatedGapCount = $gapRows.Count - $maxGapRows
        $gapRows = @($gapRows | Select-Object -First $maxGapRows)
    }
    $displayRows = @($nonGapRows) + @($gapRows)

    # Write tactic section — show both rule-only and combined % when platform adds coverage
    [void]$prerenderedSections.AppendLine("")
    if ($combinedCount -gt $coveredCount) {
        [void]$prerenderedSections.AppendLine("#### $displayName ($coveredCount/$frameworkTechCount rules — ${coveragePct}% · $combinedCount/$frameworkTechCount combined — ${combinedPct}%)")
    } else {
        [void]$prerenderedSections.AppendLine("#### $displayName ($coveredCount/$frameworkTechCount techniques — ${coveragePct}%)")
    }

    if ($coveredCount -eq 0 -and $nonGapRows.Count -eq 0) {
        # Zero coverage, no platform coverage either — just header, LLM adds narrative
        [void]$prerenderedSections.AppendLine("<!-- ZERO_COVERAGE: LLM adds narrative context for this tactic -->")
    } elseif ($displayRows.Count -gt 0) {
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("| Technique | Sub-Techs | Rules | Detections | Platform |")
        [void]$prerenderedSections.AppendLine("|-----------|-----------|-------|------------|----------|")
        foreach ($r in $displayRows) {
            [void]$prerenderedSections.AppendLine("| $($r.Badge) $($r.TechId) $($r.TechName) | $($r.SubTechCount) | $($r.EnabledRules) | $($r.Detections) | $($r.Platform) |")
        }
        if ($truncatedGapCount -gt 0) {
            [void]$prerenderedSections.AppendLine("")
            [void]$prerenderedSections.AppendLine("...and $truncatedGapCount additional uncovered techniques (endpoint/physical access focused).")
        }
    }
}

# ─── PRERENDERED.TacticCoverageMatrix ────────────────────────────────────
# §2 Tactic Coverage Matrix — badge assignment via Rule A thresholds
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### TacticCoverageMatrix")
[void]$prerenderedSections.AppendLine("<!-- Pre-rendered §2 table. Copy VERBATIM. DO NOT recalculate badges or rename tactics. -->")
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("| # | Badge | Tactic | Enabled Rules | Framework Techniques | Covered Techniques | Coverage % |")
[void]$prerenderedSections.AppendLine("|---|-------|--------|---------------|---------------------|--------------------|------------|")

$rowNum = 0
$sumEnabledRules = 0
foreach ($tactic in $tacticOrder) {
    $rowNum++
    $displayName = if ($tacticDisplayNames.ContainsKey($tactic)) { $tacticDisplayNames[$tactic] } else { $tactic }
    $ruleCount = if ($tacticRuleCount.ContainsKey($tactic)) { $tacticRuleCount[$tactic] } else { 0 }
    $tacticInfo = $attackRef.tactics.$tactic
    $frameworkTechCount = if ($tacticInfo) { $tacticInfo.techniqueCount } else { 0 }

    # Count covered techniques for this tactic
    $coveredCount = 0
    if ($tacticInfo -and $tacticInfo.techniques) {
        foreach ($tech in $tacticInfo.techniques) {
            if ($techniqueRuleCount.ContainsKey($tech.id) -and $techniqueRuleCount[$tech.id] -gt 0) {
                $coveredCount++
            }
        }
    }
    $coveragePct = if ($frameworkTechCount -gt 0) { [math]::Round(100.0 * $coveredCount / $frameworkTechCount, 1) } else { 0 }

    # Rule A badge assignment
    $badge = if ($coveragePct -eq 0) { "🔴" }
             elseif ($coveragePct -le 15) { "🟠" }
             elseif ($coveragePct -le 30) { "🟡" }
             elseif ($coveragePct -le 50) { "🔵" }
             elseif ($coveragePct -le 75) { "🟢" }
             else { "✅" }

    [void]$prerenderedSections.AppendLine("| $rowNum | $badge | $displayName | $ruleCount | $frameworkTechCount | $coveredCount | ${coveragePct}% |")
    $sumEnabledRules += $ruleCount
}

[void]$prerenderedSections.AppendLine("| | | **TOTAL** | **$sumEnabledRules** | **$totalFrameworkTechs** | **$totalCoveredTechs** | **${overallCoverage}%** |")

Write-Host "   ✅ PRERENDERED §2 Tactic Coverage Matrix built ($rowNum tactics)" -ForegroundColor Green

# ─── PRERENDERED.CombinedTacticCoverage ──────────────────────────────────
# §5.1 Combined Tactic Coverage (Rule-Based + Platform Tier 1/2)
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### CombinedTacticCoverage")
[void]$prerenderedSections.AppendLine("<!-- Pre-rendered §5.1 table. Copy VERBATIM. DO NOT recalculate numbers or rename tactics. -->")
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("| Tactic | Rule-Based | T1 | T2 | T3 | Combined | Framework | Coverage |")
[void]$prerenderedSections.AppendLine("|--------|--------|----|----|----|---------|-----------|---------|")

$prTotalT1 = 0; $prTotalT2 = 0; $prTotalT3 = 0; $prTotalRuleBased = 0; $prTotalCombined = 0; $prTotalFramework = 0
foreach ($tactic in $tacticOrder) {
    $tacticInfo = $attackRef.tactics.$tactic
    if (-not $tacticInfo) { continue }
    $displayName = if ($tacticDisplayNames.ContainsKey($tactic)) { $tacticDisplayNames[$tactic] } else { $tactic }
    $frameworkTechCount = $tacticInfo.techniqueCount
    $t1 = 0; $t2 = 0; $t3 = 0; $ruleBased = 0; $combined = 0
    foreach ($tech in $tacticInfo.techniques) {
        $techId = $tech.id
        if ($tier1Techniques.ContainsKey($techId)) { $t1++ }
        elseif ($tier2Techniques.ContainsKey($techId)) { $t2++ }
        elseif ($tier3Techniques.ContainsKey($techId)) { $t3++ }
        if ($techniqueRuleCount.ContainsKey($techId) -and $techniqueRuleCount[$techId] -gt 0) { $ruleBased++ }
        $hasCoverage = ($techniqueRuleCount.ContainsKey($techId) -and $techniqueRuleCount[$techId] -gt 0) -or
                       $tier1Techniques.ContainsKey($techId) -or $tier2Techniques.ContainsKey($techId)
        if ($hasCoverage) { $combined++ }
    }
    $combinedPct = if ($frameworkTechCount -gt 0) { [math]::Round(100.0 * $combined / $frameworkTechCount, 1) } else { 0 }
    $covBadge = if ($combinedPct -eq 0) { "🔴 " } elseif ($combinedPct -lt 25) { "🟠 " } elseif ($combinedPct -lt 50) { "🟡 " } else { "🟢 " }
    [void]$prerenderedSections.AppendLine("| $covBadge$displayName | $ruleBased | $t1 | $t2 | $t3 | $combined | $frameworkTechCount | ${combinedPct}% |")
    $prTotalT1 += $t1; $prTotalT2 += $t2; $prTotalT3 += $t3; $prTotalRuleBased += $ruleBased; $prTotalCombined += $combined; $prTotalFramework += $frameworkTechCount
}

$prOverallPct = if ($prTotalFramework -gt 0) { [math]::Round(100.0 * $prTotalCombined / $prTotalFramework, 1) } else { 0 }
[void]$prerenderedSections.AppendLine("| **TOTAL** | **$prTotalRuleBased** | **$prTotalT1** | **$prTotalT2** | **$prTotalT3** | **$prTotalCombined** | **$prTotalFramework** | **${prOverallPct}%** |")

Write-Host "   ✅ PRERENDERED §5.1 Combined Tactic Coverage built ($($tacticOrder.Count) tactics)" -ForegroundColor Green

# ─── PRERENDERED.IncidentsByTactic ───────────────────────────────────────
# §5.4 Incidents by Tactic — human-readable tactic names, sorted by volume desc
# Extended display name map for non-Enterprise tactics that appear in incident data
$extendedTacticDisplayNames = @{
    "PreAttack"                = "Pre-Attack"
    "InhibitResponseFunction"  = "Inhibit Response Function"
    "ImpairProcessControl"     = "Impair Process Control"
}

[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### IncidentsByTactic")

$prIncidentTacticCount = 0
if ($m5Data -is [array] -and $m5Data.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("<!-- Pre-rendered §5.4 table. Copy VERBATIM. DO NOT recalculate numbers or rename tactics. -->")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Tactic | Incidents | High | Medium | Low | Info | TP | FP | BP |")
    [void]$prerenderedSections.AppendLine("|--------|-----------|------|--------|-----|------|----|----|----|")

    # Sort by MITRE kill chain order (tacticOrder), non-Enterprise tactics at end
    $tacticOrderIndex = @{}
    for ($i = 0; $i -lt $tacticOrder.Count; $i++) { $tacticOrderIndex[$tacticOrder[$i]] = $i }
    $sortedM5 = $m5Data | Sort-Object { if ($tacticOrderIndex.ContainsKey($_.Tactic)) { $tacticOrderIndex[$_.Tactic] } else { 999 } }
    $sumInc = 0; $sumH = 0; $sumM = 0; $sumL = 0; $sumI = 0; $sumTP = 0; $sumFP = 0; $sumBP = 0
    foreach ($row in $sortedM5) {
        $rawTactic = $row.Tactic
        $dispTactic = if ($tacticDisplayNames.ContainsKey($rawTactic)) { $tacticDisplayNames[$rawTactic] }
                      elseif ($extendedTacticDisplayNames.ContainsKey($rawTactic)) { $extendedTacticDisplayNames[$rawTactic] }
                      else { $rawTactic }
        $inc = [int]$row.IncidentCount; $h = [int]$row.HighSev; $m = [int]$row.MediumSev
        $l = [int]$row.LowSev; $i = [int]$row.InfoSev
        $tp = [int]$row.TP; $fp = [int]$row.FP; $bp = [int]$row.BP
        $volBadge = if ($inc -ge 100) { "🔴 " } elseif ($inc -ge 25) { "🟠 " } else { "" }
        [void]$prerenderedSections.AppendLine("| $volBadge$dispTactic | $inc | $h | $m | $l | $i | $tp | $fp | $bp |")
        $sumInc += $inc; $sumH += $h; $sumM += $m; $sumL += $l; $sumI += $i
        $sumTP += $tp; $sumFP += $fp; $sumBP += $bp
        $prIncidentTacticCount++
    }
    [void]$prerenderedSections.AppendLine("| **TOTAL** | **$sumInc** | **$sumH** | **$sumM** | **$sumL** | **$sumI** | **$sumTP** | **$sumFP** | **$sumBP** |")
} else {
    [void]$prerenderedSections.AppendLine("<!-- NO_DATA: IncidentsByTactic has no data. LLM should skip this section or note absence. -->")
}

Write-Host "   ✅ PRERENDERED §5.4 Incidents by Tactic built ($prIncidentTacticCount rows)" -ForegroundColor Green

# ─── PRERENDERED.ActiveVsTagged ──────────────────────────────────────────
# §5.3 Active vs Tagged Tactic Coverage — compares tagged rules vs firing alerts
# Also identifies rule-level paper tigers (enabled, MITRE-tagged, but 0 alerts)

# Build set of firing rule IDs from M4 data
$firingRuleIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$firingCdNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if ($m4Data -is [array]) {
    foreach ($alert in $m4Data) {
        $src = if ($alert.Source) { $alert.Source } else { 'AR' }
        if ($src -eq 'AR' -and $alert.RuleId -and $alert.RuleId -ne 'CustomDetection') {
            [void]$firingRuleIds.Add($alert.RuleId)
        } elseif ($src -eq 'CD') {
            [void]$firingCdNames.Add($alert.AlertName)
        }
    }
}

# Walk enabled rule inventory to classify firing vs silent per tactic
$silentRules = [System.Collections.ArrayList]::new()   # list of {Name, Source, Tactics[], Techniques[]}
$tacticFiringRuleCount = @{}   # tactic → count of enabled rules that fired
$tacticSilentRuleCount = @{}   # tactic → count of enabled rules that didn't fire

# AR rules
if ($m1Data -is [array]) {
    foreach ($rule in $m1Data) {
        $isEnabled = $rule.enabled -eq $true -or $rule.enabled -eq 'true'
        $hasTactics = $rule.tactics -and $rule.tactics.Count -gt 0
        if (-not $isEnabled -or -not $hasTactics) { continue }
        $isFiring = $firingRuleIds.Contains($rule.ruleId)
        foreach ($t in $rule.tactics) {
            if ($isFiring) {
                if (-not $tacticFiringRuleCount.ContainsKey($t)) { $tacticFiringRuleCount[$t] = 0 }
                $tacticFiringRuleCount[$t]++
            } else {
                if (-not $tacticSilentRuleCount.ContainsKey($t)) { $tacticSilentRuleCount[$t] = 0 }
                $tacticSilentRuleCount[$t]++
            }
        }
        if (-not $isFiring) {
            $techs = if ($rule.techniques -and $rule.techniques.Count -gt 0) { $rule.techniques -join ", " } else { "—" }
            [void]$silentRules.Add([PSCustomObject]@{
                Name = $rule.displayName
                Source = "AR"
                Tactics = ($rule.tactics | ForEach-Object { if ($tacticDisplayNames.ContainsKey($_)) { $tacticDisplayNames[$_] } else { $_ } }) -join ", "
                Techniques = $techs
            })
        }
    }
}

# CD rules
if ($m2Data -is [array]) {
    foreach ($cd in $m2Data) {
        $isEnabled = $cd.isEnabled -eq $true -or $cd.isEnabled -eq 'true'
        $cdMitreTechniques = $cd.detectionAction.alertTemplate.mitreTechniques
        $cdCategory = $cd.detectionAction.alertTemplate.category
        $hasTechniques = $cdMitreTechniques -and $cdMitreTechniques.Count -gt 0
        $hasTactic = $cdCategory -and ($tacticOrder -contains $cdCategory)
        $hasMitre = $hasTechniques -or $hasTactic
        if (-not $isEnabled -or -not $hasMitre) { continue }
        # Use category (API tactic) as primary; fall back to technique→tactic derivation
        $cdTactics = @()
        if ($hasTactic) {
            $cdTactics = @($cdCategory)
        } else {
            foreach ($tech in $cdMitreTechniques) {
                $parentTech = if ($tech -match '^(T\d{4})') { $Matches[1] } else { $tech }
                if ($techToTactics.ContainsKey($parentTech)) { $cdTactics += $techToTactics[$parentTech] }
            }
            $cdTactics = $cdTactics | Select-Object -Unique
        }
        $isFiring = $firingCdNames.Contains($cd.displayName)
        foreach ($t in $cdTactics) {
            if ($isFiring) {
                if (-not $tacticFiringRuleCount.ContainsKey($t)) { $tacticFiringRuleCount[$t] = 0 }
                $tacticFiringRuleCount[$t]++
            } else {
                if (-not $tacticSilentRuleCount.ContainsKey($t)) { $tacticSilentRuleCount[$t] = 0 }
                $tacticSilentRuleCount[$t]++
            }
        }
        if (-not $isFiring) {
            $dispTactics = ($cdTactics | ForEach-Object { if ($tacticDisplayNames.ContainsKey($_)) { $tacticDisplayNames[$_] } else { $_ } }) -join ", "
            [void]$silentRules.Add([PSCustomObject]@{
                Name = $cd.displayName
                Source = "CD"
                Tactics = $dispTactics
                Techniques = ($cdMitreTechniques -join ", ")
            })
        }
    }
}

[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### ActiveVsTagged")
[void]$prerenderedSections.AppendLine("<!-- Pre-rendered §5.3 table. Copy VERBATIM. DO NOT recalculate numbers or rename tactics. -->")
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("| Tactic | Tagged Rules | Firing | Silent | Active (Alerts) | Status |")
[void]$prerenderedSections.AppendLine("|--------|-------------|--------|--------|-----------------|--------|")

$prPaperTigerCount = 0
foreach ($tactic in $tacticOrder) {
    $tagged = if ($tacticRuleCount.ContainsKey($tactic)) { $tacticRuleCount[$tactic] } else { 0 }
    $firingAlerts = if ($firingTactics -and $firingTactics.ContainsKey($tactic)) { $firingTactics[$tactic] } else { 0 }
    $firingRules = if ($tacticFiringRuleCount.ContainsKey($tactic)) { $tacticFiringRuleCount[$tactic] } else { 0 }
    $silentCount = if ($tacticSilentRuleCount.ContainsKey($tactic)) { $tacticSilentRuleCount[$tactic] } else { 0 }
    $displayName = if ($tacticDisplayNames.ContainsKey($tactic)) { $tacticDisplayNames[$tactic] } else { $tactic }
    $statusBadge = if ($tagged -eq 0) {
        "🔴 No coverage"
    } elseif ($firingAlerts -eq 0) {
        $prPaperTigerCount++
        "⚠️ All silent"
    } elseif ($silentCount -ge $firingRules -and $silentCount -ge 3) {
        "🟡 Mostly silent"
    } else {
        "✅ Validated"
    }
    [void]$prerenderedSections.AppendLine("| $displayName | $tagged | $firingRules | $silentCount | $firingAlerts | $statusBadge |")
}

# Silent Rules detail sub-table — grouped by (Tactics, Techniques) when ≥3 share the same key
if ($silentRules.Count -gt 0) {
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("#### SilentRules")
    [void]$prerenderedSections.AppendLine("<!-- $($silentRules.Count) enabled MITRE-tagged rules with 0 alerts in ${Days}d. Clusters of 3+ rules sharing the same tactic/technique are grouped. -->")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Rule | Source | Tactics | Techniques |")
    [void]$prerenderedSections.AppendLine("|------|--------|---------|------------|")

    # Group by (Tactics, Techniques) composite key
    $srGroups = $silentRules | Sort-Object Tactics, Name | Group-Object { "$($_.Tactics)|$($_.Techniques)" }
    $srRowCount = 0

    foreach ($grp in $srGroups) {
        if ($grp.Count -ge 3) {
            # Collapsed row — find common prefix of rule names for a descriptive label
            $names = $grp.Group | ForEach-Object { $_.Name }
            $prefix = $names[0]
            foreach ($n in $names[1..($names.Count - 1)]) {
                while ($prefix.Length -gt 0 -and -not $n.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $prefix = $prefix.Substring(0, $prefix.Length - 1)
                }
            }
            # Trim trailing separators and whitespace
            $prefix = $prefix.TrimEnd(' ', '-', '_', ':', '(')
            # Build label
            if ($prefix.Length -ge 8) {
                $label = "$prefix* rules ($([char]0x00D7)$($grp.Count))"
            } else {
                # Prefix too short — use tactic/technique as label
                $first = $grp.Group[0]
                $techLabel = if ($first.Techniques -and $first.Techniques -ne '—') { $first.Techniques } else { 'untagged' }
                $label = "$($first.Tactics) / $techLabel rules ($([char]0x00D7)$($grp.Count))"
            }
            # Source: AR, CD, or AR+CD
            $sources = $grp.Group | ForEach-Object { $_.Source } | Sort-Object -Unique
            $srcLabel = $sources -join '+'
            $first = $grp.Group[0]
            [void]$prerenderedSections.AppendLine("| $label | $srcLabel | $($first.Tactics) | $($first.Techniques) |")
            $srRowCount++
        } else {
            # Individual rows
            foreach ($sr in $grp.Group) {
                [void]$prerenderedSections.AppendLine("| $($sr.Name) | $($sr.Source) | $($sr.Tactics) | $($sr.Techniques) |")
                $srRowCount++
            }
        }
    }
    $srCollapsed = $silentRules.Count - $srRowCount
    if ($srCollapsed -gt 0) {
        Write-Host "   ℹ️  SilentRules: $($silentRules.Count) rules condensed to $srRowCount rows ($srCollapsed rules grouped)" -ForegroundColor DarkYellow
    }
}

Write-Host "   ✅ PRERENDERED §5.3 Active vs Tagged built (14 tactics, $prPaperTigerCount fully-silent tactics, $($silentRules.Count) silent rules)" -ForegroundColor Green

# ─── PRERENDERED.ThreatScenarios ─────────────────────────────────────────
# §4b Threat Scenario Alignment — Rule B badges, Rule E CompletedByUser split,
# Key Tactic Gaps from TacticSummary, sorted by gap desc
# Uses $parsedScenarios array accumulated during Phase 2 post-processing

[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### ThreatScenarios")

$prMainScenarios = [System.Collections.ArrayList]::new()
$prReviewedScenarios = [System.Collections.ArrayList]::new()
$prScenarioCount = 0

if ($parsedScenarios.Count -gt 0) {
    foreach ($s in $parsedScenarios) {
        # Skip unnamed/empty scenarios
        if ($s.Scenario -eq '(unnamed)' -and $s.Recommended -eq 0) { continue }

        $gap = $s.Recommended - $s.Active
        $rate = $s.CompletionRate

        # Rule B: badge assignment based on completion rate (proportional to scenario size)
        # Rate thresholds: <15% → 🔴, 15-35% → 🟠, 35-60% → 🟡, ≥60% → ✅
        $badge = if ($rate -lt 15) { "🔴" }
                 elseif ($rate -lt 35) { "🟠" }
                 elseif ($rate -lt 60) { "🟡" }
                 else { "✅" }

        # Rule E: CompletedByUser split
        $stateDisplay = $s.State
        $isReviewed = $false
        if ($s.State -eq 'CompletedByUser') {
            if ($s.CompletionRate -ge 50) {
                $isReviewed = $true  # Goes to Reviewed section
            } else {
                $stateDisplay = "⚠️ Premature ($($s.CompletionRate)%)"
            }
        }

        # Key Tactic Gaps: parse TacticSummary, find tactics with <50% ratio, show top 3
        $keyTacticGaps = "—"
        if ($s.TacticSummary -and $s.TacticSummary -ne '' -and $s.TacticSummary -ne '(parse error)') {
            $tacticEntries = $s.TacticSummary -split ',\s*'
            $underserved = @()
            foreach ($entry in $tacticEntries) {
                if ($entry -match '^(\w+):(\d+)/(\d+)$') {
                    $tName = $Matches[1]
                    $tCurrent = [int]$Matches[2]
                    $tRecommended = [int]$Matches[3]
                    if ($tRecommended -gt 0 -and ($tCurrent / $tRecommended) -lt 0.5) {
                        $dispTName = if ($tacticDisplayNames.ContainsKey($tName)) { $tacticDisplayNames[$tName] } else { $tName }
                        $underserved += @{ Name = $dispTName; Ratio = $tCurrent / $tRecommended; Gap = $tRecommended - $tCurrent }
                    }
                }
            }
            if ($underserved.Count -gt 0) {
                $topGaps = @($underserved | Sort-Object { $_.Ratio } | Select-Object -First 3)
                $keyTacticGaps = ($topGaps | ForEach-Object { $_.Name }) -join ", "
            }
        }

        $rowData = @{
            Badge       = $badge
            Scenario    = $s.Scenario
            Active      = $s.Active
            Rec         = $s.Recommended
            Gap         = $gap
            Platform    = $s.Platform
            Sentinel    = $s.Sentinel
            SentinelGap = $s.SentinelGap
            State       = $stateDisplay
            KeyGaps     = $keyTacticGaps
            Rate        = $s.CompletionRate
        }

        if ($isReviewed) {
            [void]$prReviewedScenarios.Add($rowData)
        } else {
            [void]$prMainScenarios.Add($rowData)
        }
        $prScenarioCount++
    }

    # ─── Main Active Gaps Table (sorted by gap desc) ────────────────────
    [void]$prerenderedSections.AppendLine("<!-- Pre-rendered §4b tables. Copy VERBATIM. DO NOT recalculate badges, reorder rows, or modify values. -->")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("#### Active Gaps")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Priority | Scenario | Active | Rec. | Rate | Gap | Platform | Sentinel | Sentinel Gap | State | Key Tactic Gaps |")
    [void]$prerenderedSections.AppendLine("|----------|----------|--------|------|------|-----|----------|----------|--------------|-------|-----------------|")

    $sortedMain = @($prMainScenarios | Sort-Object { $_.Gap } -Descending)
    foreach ($r in $sortedMain) {
        [void]$prerenderedSections.AppendLine("| $($r.Badge) | $($r.Scenario) | $($r.Active) | $($r.Rec) | $($r.Rate)% | $($r.Gap) | $($r.Platform) | $($r.Sentinel) | $($r.SentinelGap) | $($r.State) | $($r.KeyGaps) |")
    }

    # ─── Reviewed & Addressed Table (if any CompletedByUser ≥50%) ────────
    if ($prReviewedScenarios.Count -gt 0) {
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("#### Reviewed & Addressed Scenarios")
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("| Scenario | Active/Rec. | Rate | Gap | Note |")
        [void]$prerenderedSections.AppendLine("|----------|-------------|------|-----|------|")

        $sortedReviewed = @($prReviewedScenarios | Sort-Object { $_.Rate } -Descending)
        foreach ($r in $sortedReviewed) {
            $note = if ($r.Rate -ge 80) { "Reviewed — near-complete" }
                    elseif ($r.Rate -ge 65) { "Reviewed — remaining gap likely platform-covered" }
                    else { "Reviewed — partial coverage accepted" }
            [void]$prerenderedSections.AppendLine("| $($r.Scenario) | $($r.Active)/$($r.Rec) | $($r.Rate)% | $($r.Gap) | $note |")
        }
    }
} else {
    [void]$prerenderedSections.AppendLine("<!-- NO_DATA: ThreatScenarios has no data. LLM should note SOC Optimization unavailability. -->")
}

Write-Host "   ✅ PRERENDERED §4b Threat Scenarios built ($prScenarioCount scenarios: $($prMainScenarios.Count) active, $($prReviewedScenarios.Count) reviewed)" -ForegroundColor Green

# ─── PRERENDERED.DataReadiness ───────────────────────────────────────────
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### DataReadiness")
[void]$prerenderedSections.AppendLine("<!-- Pre-rendered §5.5 tables. Copy VERBATIM. DO NOT recalculate values or modify badges. -->")

$prTotalChecked = $readyCount + $partialCount + $noDataCount + $tierBlockedCount
if ($prTotalChecked -gt 0) {
    # Summary table
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Status | Rules | Description |")
    [void]$prerenderedSections.AppendLine("|--------|-------|-------------|")
    [void]$prerenderedSections.AppendLine("| ✅ Ready | $readyCount | All referenced tables have active ingestion |")
    [void]$prerenderedSections.AppendLine("| ⚠️ Partial | $partialCount | Some tables have data, others do not (multi-table rules) |")
    [void]$prerenderedSections.AppendLine("| 🔴 No Data | $noDataCount | Primary table(s) have zero ingestion -- rule cannot fire |")
    [void]$prerenderedSections.AppendLine("| 🚫 Tier Blocked | $tierBlockedCount | Table on Basic/Data Lake tier -- analytics rules structurally cannot query |")
    [void]$prerenderedSections.AppendLine("| **Data Readiness** | **${readinessPct}%** | Ready / (Ready + Partial + NoData + TierBlocked) |")

    # Rules with Missing Data Sources (non-Ready rules)
    if ($nonReadyRules.Count -gt 0) {
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("#### Rules with Missing Data Sources")
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("| Rule Name | Tables | Status | Missing Tables | Available Volumes |")
        [void]$prerenderedSections.AppendLine("|-----------|--------|--------|----------------|-------------------|")
        foreach ($nr in $nonReadyRules) {
            $statusBadge = switch ($nr.Status) {
                "NoData"      { "🔴 NoData" }
                "TierBlocked" { "🚫 TierBlocked" }
                "Partial"     { "⚠️ Partial" }
                default       { $nr.Status }
            }
            [void]$prerenderedSections.AppendLine("| $($nr.RuleName) | $($nr.Tables) | $statusBadge | $($nr.MissingTables) | $($nr.Volumes) |")
        }
    }

    # Missing Tables Impact Summary
    if ($missingTablesSummary.Count -gt 0) {
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("#### Missing Tables -- Impact Summary")
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("| Table | Rules Affected |")
        [void]$prerenderedSections.AppendLine("|-------|----------------|")
        foreach ($entry in ($missingTablesSummary.GetEnumerator() | Sort-Object Value -Descending)) {
            [void]$prerenderedSections.AppendLine("| $($entry.Key) | $($entry.Value) |")
        }
    }

    # Tier-Blocked Tables
    if ($tierBlockedTablesSummary.Count -gt 0) {
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("#### Phantom Coverage -- Tier-Blocked Tables")
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("| Table | Tier | Rules Affected |")
        [void]$prerenderedSections.AppendLine("|-------|------|----------------|")
        foreach ($entry in ($tierBlockedTablesSummary.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending)) {
            [void]$prerenderedSections.AppendLine("| $($entry.Key) | $($entry.Value.Tier) | $($entry.Value.Count) |")
        }
    }
} else {
    [void]$prerenderedSections.AppendLine("<!-- NO_DATA: DataReadiness has no data. M7 may have failed or no enabled rules found. -->")
}

Write-Host "   ✅ PRERENDERED §5.5 Data Readiness built ($prTotalChecked rules checked: $readyCount ready, $partialCount partial, $noDataCount no data, $tierBlockedCount tier-blocked)" -ForegroundColor Green

# ─── PRERENDERED.ConnectorHealth ─────────────────────────────────────────
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### ConnectorHealth")
[void]$prerenderedSections.AppendLine("<!-- Pre-rendered §5.6 tables. Copy VERBATIM. DO NOT recalculate values or modify badges. -->")

if ($connectorHealth.Count -gt 0) {
    $prHealthy = 0; $prDegraded = 0; $prFailing = 0
    $prUnhealthy = [System.Collections.ArrayList]::new()
    foreach ($entry in $connectorHealth.GetEnumerator()) {
        if ($entry.Value.LastStatus -eq 'Failure') {
            $prFailing++
            [void]$prUnhealthy.Add(@{ Name=$entry.Key; LastStatus=$entry.Value.LastStatus; Success=$entry.Value.SuccessCount; Failure=$entry.Value.FailureCount; HealthPct=$entry.Value.HealthPct })
        } elseif ($entry.Value.HealthPct -lt 90) {
            $prDegraded++
            [void]$prUnhealthy.Add(@{ Name=$entry.Key; LastStatus=$entry.Value.LastStatus; Success=$entry.Value.SuccessCount; Failure=$entry.Value.FailureCount; HealthPct=$entry.Value.HealthPct })
        } else {
            $prHealthy++
        }
    }

    # Summary table
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Status | Connectors | Description |")
    [void]$prerenderedSections.AppendLine("|--------|------------|-------------|")
    [void]$prerenderedSections.AppendLine("| ✅ Healthy | $prHealthy | Last fetch succeeded, >90% success rate |")
    [void]$prerenderedSections.AppendLine("| ⚠️ Degraded | $prDegraded | Last fetch succeeded but <90% success rate (intermittent failures) |")
    [void]$prerenderedSections.AppendLine("| 🔴 Failing | $prFailing | Last fetch status is Failure |")

    # Detail table for unhealthy connectors
    if ($prUnhealthy.Count -gt 0) {
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("#### Connectors with Health Issues")
        [void]$prerenderedSections.AppendLine("")
        [void]$prerenderedSections.AppendLine("| Connector | Last Status | Success | Failure | Health % |")
        [void]$prerenderedSections.AppendLine("|-----------|-------------|---------|---------|----------|")
        foreach ($uh in ($prUnhealthy | Sort-Object { $_.HealthPct })) {
            [void]$prerenderedSections.AppendLine("| $($uh.Name) | $($uh.LastStatus) | $($uh.Success) | $($uh.Failure) | $($uh.HealthPct)% |")
        }
    }

    Write-Host "   ✅ PRERENDERED §5.6 Connector Health built ($($connectorHealth.Count) connectors: $prHealthy healthy, $prDegraded degraded, $prFailing failing)" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("<!-- NO_DATA: ConnectorHealth has no data. M8/SentinelHealth may not be enabled. -->")
    Write-Host "   ✅ PRERENDERED §5.6 Connector Health built (no M8 data)" -ForegroundColor Green
}

# ─── PRERENDERED.AlertFiring ─────────────────────────────────────────────
[void]$prerenderedSections.AppendLine("")
[void]$prerenderedSections.AppendLine("### AlertFiring")
[void]$prerenderedSections.AppendLine("<!-- Pre-rendered §5.2 table. Copy VERBATIM. DO NOT recalculate values or modify badges. -->")

if ($m4Data -is [array] -and $m4Data.Count -gt 0) {
    # Build table rows with [AR]/[CD] badges and MITRE cross-reference
    $prAlertRows = [System.Collections.ArrayList]::new()
    $prArCount = 0; $prCdCount = 0; $prUnmatchedCount = 0
    foreach ($alert in $m4Data) {
        $src = if ($alert.Source) { $alert.Source } else { 'AR' }
        $badge = "[$src]"
        if ($src -eq 'AR') { $prArCount++ } elseif ($src -eq 'CD') { $prCdCount++ }

        # Resolve tactics
        if ($src -eq 'AR' -and $allRuleTactics.ContainsKey($alert.RuleId) -and $allRuleTactics[$alert.RuleId].Count -gt 0) {
            $displayTactics = ($allRuleTactics[$alert.RuleId] | ForEach-Object {
                $_ -creplace '([a-z])([A-Z])', '$1 $2'
            }) -join ", "
        } elseif ($src -eq 'CD') {
            # CD: extract from SecurityAlert Tactics column
            $rawTactics = $alert.Tactics
            if ($rawTactics -is [string]) {
                try { $rawTactics = $rawTactics | ConvertFrom-Json -ErrorAction SilentlyContinue } catch { $rawTactics = @() }
            }
            $flatTactics = @()
            if ($rawTactics) {
                foreach ($item in $rawTactics) {
                    if ($item -is [array] -or ($item -is [System.Collections.IEnumerable] -and $item -isnot [string])) {
                        foreach ($sub in $item) { if ($sub -and $sub -ne '') { $flatTactics += $sub } }
                    } elseif ($item -and $item -ne '' -and $item -ne '[]') {
                        $flatTactics += $item
                    }
                }
            }
            $flatTactics = @($flatTactics | Select-Object -Unique)
            $displayTactics = if ($flatTactics.Count -gt 0) {
                ($flatTactics | ForEach-Object { $_ -creplace '([a-z])([A-Z])', '$1 $2' }) -join ", "
            } else { "—" }
        } else {
            $displayTactics = "—"
        }

        # Resolve techniques
        if ($src -eq 'AR' -and $allRuleTechniques.ContainsKey($alert.RuleId) -and $allRuleTechniques[$alert.RuleId].Count -gt 0) {
            $displayTechniques = $allRuleTechniques[$alert.RuleId] -join ", "
        } else {
            $displayTechniques = "—"
        }

        # Track unmatched AR rules (no MITRE cross-reference found in M1)
        if ($src -eq 'AR' -and $displayTactics -eq '—' -and $displayTechniques -eq '—') { $prUnmatchedCount++ }

        # Severity badge: show dominant severity
        $sevParts = @()
        if ([int]$alert.HighSev -gt 0) { $sevParts += "H:$($alert.HighSev)" }
        if ([int]$alert.MediumSev -gt 0) { $sevParts += "M:$($alert.MediumSev)" }
        if ([int]$alert.LowSev -gt 0) { $sevParts += "L:$($alert.LowSev)" }
        if ([int]$alert.InfoSev -gt 0) { $sevParts += "I:$($alert.InfoSev)" }
        $sevDisplay = if ($sevParts.Count -gt 0) { $sevParts -join " " } else { "—" }

        [void]$prAlertRows.Add(@{
            Badge = $badge
            Name = $alert.AlertName
            Tactics = $displayTactics
            Techniques = $displayTechniques
            Count = [int]$alert.AlertCount
            Severity = $sevDisplay
        })
    }

    # Render section title ("Top N" when results hit the take-50 cap, plain count otherwise)
    $m4Cap = 50
    $titlePrefix = if ($prAlertRows.Count -ge $m4Cap) { "Top $m4Cap" } else { "$($prAlertRows.Count)" }
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("SectionTitle: $titlePrefix Alert-Producing Rules")
    [void]$prerenderedSections.AppendLine("")
    [void]$prerenderedSections.AppendLine("| Alert | Tactics | Techniques | Alerts | Severity |")
    [void]$prerenderedSections.AppendLine("|-------|---------|------------|--------|----------|")
    foreach ($row in ($prAlertRows | Sort-Object { $_.Count } -Descending)) {
        $volBadge = if ($row.Count -ge 100) { "🔴 " } elseif ($row.Count -ge 20) { "🟠 " } else { "" }
        [void]$prerenderedSections.AppendLine("| $volBadge$($row.Badge) $($row.Name) | $($row.Tactics) | $($row.Techniques) | $($row.Count) | $($row.Severity) |")
    }

    # Summary line
    [void]$prerenderedSections.AppendLine("")
    $summaryParts = @()
    if ($prArCount -gt 0) { $summaryParts += "$prArCount AR" }
    if ($prCdCount -gt 0) { $summaryParts += "$prCdCount CD" }
    [void]$prerenderedSections.AppendLine("**Summary:** $($prAlertRows.Count) alert-producing rules ($($summaryParts -join ', ')) generated alerts in the ${Days}-day window.")
    if ($prUnmatchedCount -gt 0) {
        [void]$prerenderedSections.AppendLine("$prUnmatchedCount AR rule(s) fired alerts but could not be cross-referenced with the M1 rule inventory (rule may have been deleted or modified since alert generation).")
    }
    if ($prCdCount -gt 0) {
        [void]$prerenderedSections.AppendLine("CD = Custom Detection rules (identified by `AlertType == CustomDetection` in SecurityAlert). Tactic data from SecurityAlert Tactics column; technique-level detail not available.")
    }

    Write-Host "   ✅ PRERENDERED §5.2 Alert Firing built ($($prAlertRows.Count) rules: $prArCount AR, $prCdCount CD, $prUnmatchedCount unmatched)" -ForegroundColor Green
} else {
    [void]$prerenderedSections.AppendLine("<!-- NO_DATA: AlertFiring has no data. No SecurityAlert records in ${Days}d window. -->")
    Write-Host "   ✅ PRERENDERED §5.2 Alert Firing built (no M4 data)" -ForegroundColor Green
}

$prerenderedBlock = $prerenderedSections.ToString().TrimEnd()
Write-Host "   ✅ PRERENDERED blocks complete ($($tacticOrder.Count) tactics × 3 tables + incidents + scenarios + readiness + connectors + alert-firing)" -ForegroundColor Green
#endregion

#region ═══ Trim Redundant Scratchpad Sections ════════════════════════════════
# Sections now fully captured in PRERENDERED blocks — remove from raw phases
# to reduce scratchpad size and token pressure during LLM rendering.
# Computation variables are preserved (they feed PRERENDERED block builders).
function Remove-ScratchpadSection {
    param([string]$Block, [string]$SectionName)
    $lines = $Block -split "`n"
    $result = [System.Collections.ArrayList]::new()
    $skipping = $false
    foreach ($line in $lines) {
        if ($line.TrimEnd() -match "^### $([regex]::Escape($SectionName))$") {
            $skipping = $true; continue
        }
        if ($skipping -and $line -match '^#{2,3} ') { $skipping = $false }
        if (-not $skipping) { [void]$result.Add($line) }
    }
    return ($result -join "`n")
}

$trimmedSections = @()
# Phase 2: ThreatScenarios → PRERENDERED.ThreatScenarios
$phase2Block = Remove-ScratchpadSection $phase2Block 'ThreatScenarios'
$trimmedSections += 'ThreatScenarios'
# Phase 3: sections now in PRERENDERED.IncidentsByTactic / CombinedTacticCoverage / DataReadiness / ConnectorHealth / AlertFiring / ActiveVsTagged
foreach ($sect in @('IncidentsByTactic', 'PlatformTacticCoverage', 'DataReadiness_Summary', 'MissingTables', 'TierBlockedTables', 'ConnectorHealth_Summary', 'AlertFiring_MitreCorrelation', 'ActiveTacticCoverage')) {
    $phase3Block = Remove-ScratchpadSection $phase3Block $sect
    $trimmedSections += $sect
}
Write-Host "   ✅ Trimmed $($trimmedSections.Count) redundant sections from scratchpad: $($trimmedSections -join ', ')" -ForegroundColor DarkCyan
#endregion

#region ═══ Write Scratchpad ══════════════════════════════════════════════════
Write-Host "`n📝 Writing scratchpad..." -ForegroundColor Yellow

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$scratchpadPath = Join-Path $OutputDir "mitre_scratch_${timestamp}.md"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$scratchpad = @"
# SCRATCHPAD — MITRE ATT&CK Coverage Report
<!-- Auto-generated by Invoke-MitreScan.ps1. DO NOT edit manually. -->

## META
Workspace: $workspaceName
WorkspaceId: $workspaceId
Days: $Days
Generated: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
ATT&CK_Version: $($attackRef.version)
ATT&CK_Techniques: $($attackRef.totalTechniques)
ATT&CK_SubTechniques: $($attackRef.totalSubTechniques)
QueryCount: $($allQueries.Count)
ExecutionTime: ${totalQueryTime}s
Phases: $($phasesToRun -join ',')

## SCORE
MITRE_Score: $finalScore
Breadth: $breadthScore
Breadth_RuleOnly: $([math]::Round($ruleBreadth, 1))
Breadth_Combined: $([math]::Round($combinedBreadth, 1))
Breadth_Blend: 60/40
Balance: $balanceScore
Operational: $operationalScore
Tagging: $taggingScore
SOC_Alignment: $socAlignScore
Weights: breadth=$($weights.breadth),balance=$($weights.balance),operational=$($weights.operational),tagging=$($weights.tagging),socAlign=$($weights.socAlign)
Platform_Tier1: $($tier1Techniques.Count)
Platform_Tier2: $($tier2Techniques.Count)
Platform_Tier3: $($tier3Techniques.Count)
Platform_ActiveProducts: $($displayProducts.Count)
DataReadiness_Pct: $readinessPct
DataReadiness_Ready: $readyCount
DataReadiness_Partial: $partialCount
DataReadiness_NoData: $noDataCount
DataReadiness_TierBlocked: $tierBlockedCount
PhantomTechniques: $phantomTechCount
PhantomTechniqueList: $(($phantomTechniques | Sort-Object) -join ',')
TechCredit_Fired: $($creditStats.Fired)
TechCredit_Ready: $($creditStats.Ready)
TechCredit_Partial: $($creditStats.Partial)
TechCredit_NoData: $($creditStats.NoData)
TechCredit_TierBlocked: $($creditStats.TierBlocked)
TechCredit_Unknown: $($creditStats.Unknown)
TotalWeightedCredit: $([math]::Round($totalWeightedCredit, 2))
RuleBasedPlusPlatform_Coverage: $totalCombinedTechs / $totalFrameworkTechs ($overallCombinedPct%)
CTID_Version: $(if ($ctidRef) { $ctidRef.metadata.ctid_version } else { 'N/A' })

$phase1Block

$phase2Block

$phase3Block

$prerenderedBlock
"@

$scratchpad | Out-File -FilePath $scratchpadPath -Encoding utf8

$fileSize = [math]::Round((Get-Item $scratchpadPath).Length / 1024, 1)

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  ✅ Scratchpad written successfully" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  📄 Path: $scratchpadPath" -ForegroundColor White
Write-Host "  📏 Size: $fileSize KB" -ForegroundColor White
Write-Host "  ⏱️  Total time: ${totalQueryTime}s" -ForegroundColor White
Write-Host "  📊 MITRE Score: $finalScore / 100" -ForegroundColor White
Write-Host "  🎯 Technique Coverage: $totalCoveredTechs / $totalFrameworkTechs ($overallCoverage%)" -ForegroundColor White
Write-Host "  🛡️  Combined (Rule-Based+Platform): $totalCombinedTechs / $totalFrameworkTechs ($overallCombinedPct%)" -ForegroundColor White
Write-Host ""
#endregion
