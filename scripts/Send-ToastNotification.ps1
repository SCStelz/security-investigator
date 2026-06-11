<#
.SYNOPSIS
    Sends a native Windows toast notification (no external modules required).

.DESCRIPTION
    Uses the built-in Windows.UI.Notifications WinRT API to display a toast.
    WinRT type projection only works under Windows PowerShell 5.1 (Desktop edition),
    NOT PowerShell 7+ (Core). When invoked from PowerShell 7 this script transparently
    re-launches itself via the bundled Windows PowerShell 5.1 host so callers do not
    have to care which edition they are running under.

    Toasts render only in an interactive, logged-on desktop session. In a true headless
    / service context no toast will appear (the script still exits 0 in that case unless
    the WinRT call itself throws). Focus Assist / Do Not Disturb can also suppress toasts.

.PARAMETER Title
    First line of the toast (bold).

.PARAMETER Body
    Second line of the toast (detail text).

.PARAMETER Severity
    Info | Warning | Error. Currently used only to prefix the title with an icon glyph;
    kept as a parameter so callers can express intent and future styling can hook in.

.EXAMPLE
    pwsh> .\scripts\Send-ToastNotification.ps1 -Title "MCP Health Check" -Body "All 5 servers PASS" -Severity Info

.EXAMPLE
    pwsh> .\scripts\Send-ToastNotification.ps1 -Title "MCP Health Check" -Body "2 servers need re-auth" -Severity Warning

.NOTES
    Sender shows as "Windows PowerShell" because we reuse the built-in PowerShell AUMID
    (a registered AppUserModelID is required for Windows to display the toast). Registering
    a custom branded AUMID is possible but intentionally out of scope here.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$Body,
    [ValidateSet('Info', 'Warning', 'Error')][string]$Severity = 'Info'
)

# WinRT toast projection requires Windows PowerShell 5.1 (Desktop). If we are running
# under PowerShell 7+ (Core), re-invoke this same script through powershell.exe and exit.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $ps51 = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $ps51)) {
        Write-Output "TOAST_FAILED: Windows PowerShell 5.1 not found at $ps51"
        exit 1
    }
    & $ps51 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Title $Title -Body $Body -Severity $Severity
    exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'

try {
    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime]

    $glyph = switch ($Severity) {
        'Warning' { [char]0x26A0 + ' ' }   # warning sign
        'Error'   { [char]0x274C + ' ' }   # cross mark
        default   { '' }
    }

    # XML-escape user-supplied text so titles/bodies with & < > " don't break the payload.
    $escTitle = [System.Security.SecurityElement]::Escape("$glyph$Title")
    $escBody = [System.Security.SecurityElement]::Escape($Body)

    $xmlText = "<toast><visual><binding template='ToastText02'><text id='1'>$escTitle</text><text id='2'>$escBody</text></binding></visual></toast>"

    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($xmlText)

    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    $aumid = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($aumid).Show($toast)

    Write-Output 'TOAST_SENT_OK'
}
catch {
    Write-Output "TOAST_FAILED: $($_.Exception.Message)"
    exit 1
}
