<#
.SYNOPSIS
    Deploy custom detection rules to Microsoft Defender XDR via the Graph API.

.DESCRIPTION
    Reads a JSON manifest of detection rule definitions and creates them as
    custom detection rules using Invoke-MgGraphRequest (POST /beta/security/rules/detectionRules).

    Supports dry-run mode, duplicate checking (default: skip existing), and post-creation verification.
    Manifest supports dynamic alert titles ({{ColumnName}} syntax) and recommended actions.
    Response actions are always set to empty — automated response actions are prohibited.

.PARAMETER ManifestPath
    Path to a JSON file containing an array of detection rule definitions.

.PARAMETER DryRun
    List rules to deploy without creating them. Shows status (New/Exists), schedule, and severity for each rule.

.PARAMETER Force
    Deploy rules even if a rule with the same displayName already exists.
    Without -Force, existing rules are skipped automatically to prevent 409 errors.

.EXAMPLE
    .\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json -DryRun
    .\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json
    .\Deploy-CustomDetections.ps1 -ManifestPath .\temp\4799_4702.json -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$ManifestPath,

    [switch]$DryRun,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helpers ──────────────────────────────────────────────────────────────────

function Connect-GraphIfNeeded {
    try {
        $ctx = Get-MgContext
        if (-not $ctx) { throw "Not connected" }
        Write-Host "✅ Connected to Graph as $($ctx.Account)" -ForegroundColor Green
    }
    catch {
        Write-Host "🔐 Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes "CustomDetection.ReadWrite.All" -NoWelcome
        $ctx = Get-MgContext
        Write-Host "✅ Connected as $($ctx.Account)" -ForegroundColor Green
    }
}

function Get-ExistingRules {
    $response = Invoke-MgGraphRequest -Method GET `
        -Uri "/beta/security/rules/detectionRules" -OutputType PSObject
    return $response.value
}

function Build-RuleBody {
    param([PSCustomObject]$Rule)

    $impactedAssets = @()
    foreach ($asset in $Rule.impactedAssets) {
        $odataType = switch ($asset.type) {
            'device'  { "#microsoft.graph.security.impactedDeviceAsset" }
            'user'    { "#microsoft.graph.security.impactedUserAsset" }
            'mailbox' { "#microsoft.graph.security.impactedMailboxAsset" }
            default   { throw "Unknown asset type: $($asset.type)" }
        }
        $impactedAssets += @{
            "@odata.type" = $odataType
            identifier    = $asset.identifier
        }
    }

    # Alert title: use 'title' field if specified, fallback to displayName
    $alertTitle = if ($Rule.PSObject.Properties['title'] -and $Rule.title) {
        $Rule.title
    } else {
        $Rule.displayName
    }

    # Recommended actions: optional string field
    $recActions = if ($Rule.PSObject.Properties['recommendedActions'] -and $Rule.recommendedActions) {
        $Rule.recommendedActions
    } else {
        $null
    }

    # Response actions: ALWAYS empty — automated response actions are prohibited.
    # They must only be configured manually in the Defender portal after rule validation.
    # NOTE: Must be @(), not $null — $null serializes to "responseActions": null which
    # the API rejects with 400 Bad Request.
    $respActions = @()

    $body = @{
        displayName    = $Rule.displayName
        isEnabled      = $true
        queryCondition = @{
            queryText = $Rule.queryText
        }
        schedule = @{
            period = $Rule.schedule
        }
        detectionAction = @{
            alertTemplate = @{
                title              = $alertTitle
                description        = $Rule.description
                severity           = $Rule.severity
                category           = $Rule.category
                recommendedActions = $recActions
                mitreTechniques    = @($Rule.mitreTechniques)
                impactedAssets     = $impactedAssets
            }
            responseActions     = $respActions
        }
    }

    return $body | ConvertTo-Json -Depth 10
}

function Deploy-SingleRule {
    param(
        [string]$Body,
        [string]$DisplayName
    )

    try {
        $result = Invoke-MgGraphRequest -Method POST `
            -Uri "/beta/security/rules/detectionRules" `
            -Body $Body -ContentType "application/json" -OutputType PSObject
        return @{ Success = $true; Id = $result.id; Error = $null }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        # 409 Conflict may still create the rule (deletion propagation race)
        if ($statusCode -eq 409) {
            Write-Warning "⚠️  409 Conflict for '$DisplayName' — checking if rule was created despite error..."
            Start-Sleep -Seconds 5
            $existing = Get-ExistingRules | Where-Object { $_.displayName -eq $DisplayName }
            if ($existing) {
                return @{ Success = $true; Id = $existing.id; Error = "409 (rule created despite conflict)" }
            }
        }

        return @{ Success = $false; Id = $null; Error = $_.Exception.Message }
    }
}

# ── Main ─────────────────────────────────────────────────────────────────────

Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host   "║    Custom Detection Rule Deployment              ║" -ForegroundColor Cyan
Write-Host   "╚══════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Load manifest
$manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
Write-Host "📋 Loaded $($manifest.Count) rule(s) from manifest" -ForegroundColor White

if ($DryRun) {
    Write-Host "🔍 DRY RUN — listing rules to deploy (no queries executed, no rules created)`n" -ForegroundColor Yellow
}

# Connect to Graph
Connect-GraphIfNeeded

# Get existing rules for dedup
$existingRules = Get-ExistingRules
$existingNames = $existingRules | ForEach-Object { $_.displayName }
Write-Host "📊 Found $($existingRules.Count) existing rule(s) in tenant`n" -ForegroundColor White

# Process each rule
$results = @()
$index = 0

foreach ($rule in $manifest) {
    $index++
    $prefix = "[$index/$($manifest.Count)]"

    Write-Host "$prefix $($rule.displayName)" -ForegroundColor White

    # Duplicate check (default: skip existing; -Force overrides)
    if ($rule.displayName -in $existingNames) {
        if (-not $Force) {
            $existingId = ($existingRules | Where-Object { $_.displayName -eq $rule.displayName }).id
            Write-Host "   ⏭️  Already exists (ID: $existingId) — skipping (use -Force to override)" -ForegroundColor Yellow
            $results += @{ Name = $rule.displayName; Status = "Skipped"; Id = $existingId }
            continue
        }
        Write-Host "   ⚠️  Exists but -Force specified — attempting POST anyway" -ForegroundColor Yellow
    }

    if ($DryRun) {
        $status = if ($rule.displayName -in $existingNames) { "Exists" } else { "New" }
        Write-Host "   📝 $status — schedule: $($rule.schedule), severity: $($rule.severity)" -ForegroundColor Gray
        $results += @{ Name = $rule.displayName; Status = "Validated"; Id = $null }
        continue
    }

    # Build and deploy
    $body = Build-RuleBody -Rule $rule
    $deployResult = Deploy-SingleRule -Body $body -DisplayName $rule.displayName

    if ($deployResult.Success) {
        Write-Host "   ✅ Created (ID: $($deployResult.Id))" -ForegroundColor Green
        if ($deployResult.Error) {
            Write-Host "   ⚠️  Note: $($deployResult.Error)" -ForegroundColor Yellow
        }
        $results += @{ Name = $rule.displayName; Status = "Created"; Id = $deployResult.Id }
    }
    else {
        Write-Host "   ❌ Failed: $($deployResult.Error)" -ForegroundColor Red
        $results += @{ Name = $rule.displayName; Status = "Failed"; Id = $null }
    }
}

# Summary
Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host   "║    Deployment Summary                            ║" -ForegroundColor Cyan
Write-Host   "╚══════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

$created = @($results | Where-Object { $_.Status -eq 'Created' }).Count
$skipped = @($results | Where-Object { $_.Status -eq 'Skipped' }).Count
$failed  = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
$validated = @($results | Where-Object { $_.Status -eq 'Validated' }).Count

if ($DryRun) {
    Write-Host "   Validated: $validated" -ForegroundColor Green
}
else {
    Write-Host "   Created:  $created" -ForegroundColor Green
    Write-Host "   Skipped:  $skipped" -ForegroundColor Yellow
    Write-Host "   Failed:   $failed" -ForegroundColor Red
}

Write-Host ""

# Return results for pipeline use
return $results
