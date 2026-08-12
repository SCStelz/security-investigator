# macOS ClickFix — Cloaked Fingerprinting Gates Delivering AMOS/MacSync — Threat Hunts

**Created:** 2026-08-05  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceNetworkEvents, DeviceProcessEvents, DeviceFileEvents  
**Keywords:** macOS ClickFix, ClickFix, Atomic Stealer, AMOS, MacSync, fingerprinting gate, cloaked landing page, fake CAPTCHA, copy-paste lure, Terminal, curl pipe shell, osascript, AppleScript, do shell script, xattr, quarantine bypass, Gatekeeper bypass, chmod, base64 decode, keychain theft, infostealer, macOS stealer, file-word domain, /curl staging path, malvertising, SEO poisoning  
**MITRE:** T1189, T1204.004, T1059.004, T1059.002, T1105, T1140, T1553.001, T1555.001, T1071.001  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [From open lures to cloaked gates: How a macOS ClickFix campaign learned to hide (2026-08-05)](https://www.microsoft.com/en-us/security/blog/2026/08/05/macos-clickfix-campaign-learned-hide/)

---

## Threat Overview

Microsoft Threat Intelligence tracked a **macOS-focused ClickFix campaign** that evolved from open, obviously-malicious landing pages to **cloaked "fingerprinting gates"** — server-side checks (user-agent, platform, headless/automation heuristics, and geolocation) that only serve the malicious copy-paste lure to genuine macOS browser visitors and show benign content to scanners, sandboxes, and researchers. Victims are steered (via malvertising / SEO poisoning) to a page presenting a **fake verification / CAPTCHA** that instructs them to open **Terminal** and paste a pre-copied command.

The pasted command typically **`curl`s a stager** from an attacker-controlled host (using a **`/curl/<hex-id>` staging path** on domains following a **`file<word><word>` naming pattern**, e.g. `file...`, `...file...`), pipes it directly into a shell (`sh`/`zsh`/`bash`), or wraps the fetch in **`osascript` / AppleScript** (`do shell script`) to also raise native dialogs that reinforce the social-engineering flow. The downloaded payload is made executable and Gatekeeper/quarantine controls are stripped (**`xattr -c`** / `xattr -d com.apple.quarantine`, `chmod +x`), frequently via a **`base64`-decoded** second stage. The delivered malware is **MacSync** / **Atomic Stealer (AMOS)**, which harvests the login **keychain**, browser credentials, and crypto-wallet material.

### Hunting relevance & telemetry caveat

This campaign is **macOS endpoint execution** plus **network delivery**. The **network-delivery hunts (Queries 1–2) are OS-agnostic** — any browser or tool that resolves/contacts the front-end domains or the `/curl/<hex-id>` staging path is caught regardless of the endpoint OS, so they are the highest-value, environment-portable detections here. The **macOS execution hunts (Queries 3–5)** depend on **Defender for Endpoint macOS process telemetry** (`DeviceProcessEvents` from macOS agents). Environments without onboarded macOS devices will have no local telemetry to fire these on — they are provided as **ready-to-deploy hunts for macOS-enabled estates** and are marked `cd_ready: false` here because they cannot be fidelity-validated without macOS process telemetry (and, being built on ubiquitous Unix tooling, require per-environment tuning before promotion to a scheduled rule).

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [macOS ClickFix front-end / delivery domain sweep (direct IOC)](#query-1-macos-clickfix-front-end--delivery-domain-sweep-direct-ioc) | Investigation | `DeviceNetworkEvents` |
| 2 | [`file<word><word>` domain naming + `/curl/<hex-id>` staging-path he...](#query-2-filewordword-domain-naming--curlhex-id-staging-path-heuristic) | Investigation | `DeviceNetworkEvents` |
| 3 | [macOS Terminal `curl` piped directly into a shell](#query-3-macos-terminal-curl-piped-directly-into-a-shell) | Investigation | `DeviceInfo` + `DeviceProcessEvents` |
| 4 | [macOS `osascript` / AppleScript running a shell payload](#query-4-macos-osascript--applescript-running-a-shell-payload) | Investigation | `DeviceProcessEvents` |
| 5 | [macOS Gatekeeper / quarantine strip + make-executable on a dropped ...](#query-5-macos-gatekeeper--quarantine-strip--make-executable-on-a-dropped-payload) | Investigation | `DeviceProcessEvents` |


## IOC Reference

> Published indicators from the Microsoft Threat Intelligence article. IOCs rot — operators rotate infrastructure. Domains are defanged below; the queries use plain (de-fanged) forms. Refresh against current Microsoft Threat Intelligence before relying on the direct-match sweeps (Query 1).

### Front-end / delivery domains

| Domain | Type |
|---|---|
| applefilevault[.]com | Delivery / lure domain |
| apricotfilepoint[.]com | Delivery / lure domain |
| bananafastfile[.]com | Delivery / lure domain |
| cloudfilebridge[.]com | Delivery / lure domain |
| filecedarwallet[.]online | Delivery / lure domain |
| filecopperbasket[.]sbs | Delivery / lure domain |
| filecrimsonsignal[.]online | Delivery / lure domain |
| filemarblegarden[.]sbs | Delivery / lure domain |
| fileoceanhammer[.]sbs | Delivery / lure domain |
| filerubyfolder[.]sbs | Delivery / lure domain |
| filevelvettractor[.]sbs | Delivery / lure domain |
| lemonfilewave[.]com | Delivery / lure domain |
| limefilescope[.]com | Delivery / lure domain |
| mangocloudfile[.]com | Delivery / lure domain |
| orangesmartfile[.]com | Delivery / lure domain |
| syncdatavault[.]com | Delivery / lure domain |
| cloudsendhub[.]com | Delivery / lure domain |

### Behavioral / infrastructure patterns (from narrative — heuristics, not direct IOCs)

| Indicator | Type | Description |
|---|---|---|
| `file<word><word>` | Domain naming pattern | Front-end domains commonly concatenate `file` with mundane English words (colors, fruits, materials) |
| `/curl/<hex-id>` | URL staging path | Stager fetched from a `/curl/` path with a hex victim/campaign ID |
| `curl ... \| sh`/`zsh`/`bash` | Command pattern | Pasted Terminal command pipes a remote fetch straight into a shell |
| `osascript` / `do shell script` | Command pattern | AppleScript wrapper that runs the shell payload and renders native dialogs |
| `xattr -c` / `xattr -d com.apple.quarantine`, `chmod +x` | Command pattern | Gatekeeper/quarantine strip + make-executable on the dropped payload |

---

## Query 1: macOS ClickFix front-end / delivery domain sweep (direct IOC)

**Purpose:** Direct-match network sweep for the published front-end / delivery domains. OS-agnostic — fires on any endpoint that contacts the infrastructure, so it is portable to estates without macOS devices. A clean estate returns 0; any hit is a strong delivery-infrastructure contact indicator.  
**Severity:** High  
**MITRE:** T1189, T1204.004, T1071.001
<!-- cd-metadata
cd_ready: true
schedule: "NRT"
category: "InitialAccess"
title: "macOS ClickFix delivery domain contacted from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An endpoint contacted a known macOS ClickFix delivery/lure domain. Identify the initiating browser/process and user, pull the full URL (check for a /curl/<hex-id> staging path), determine whether a Terminal/osascript command was subsequently run (Queries 3-5), and triage the device for MacSync/AMOS stealer activity (keychain and browser-credential access). Refresh the domain list from current threat intelligence before relying on direct matches."
adaptation_notes: "Article-provided direct IOCs; high fidelity but IOCs rot as the actor rotates infrastructure. Keep the domain list current. OS-agnostic (network telemetry), so deployable regardless of macOS onboarding."
-->

```kql
let DeliveryDomains = dynamic([
  "applefilevault.com","apricotfilepoint.com","bananafastfile.com","cloudfilebridge.com",
  "filecedarwallet.online","filecopperbasket.sbs","filecrimsonsignal.online","filemarblegarden.sbs",
  "fileoceanhammer.sbs","filerubyfolder.sbs","filevelvettractor.sbs","lemonfilewave.com",
  "limefilescope.com","mangocloudfile.com","orangesmartfile.com","syncdatavault.com","cloudsendhub.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (DeliveryDomains)
| project Timestamp, DeviceName, DeviceId, ActionType, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Any match is a high-confidence delivery-infrastructure contact warranting immediate triage.

---

## Query 2: `file<word><word>` domain naming + `/curl/<hex-id>` staging-path heuristic

**Purpose:** Infrastructure-pattern companion to Query 1 that catches **rotated** domains the direct IOC list has not yet caught — hostnames matching the `file<word><word>` construction and/or URLs using the `/curl/<hex-id>` stager path. Heuristic and FP-prone (legitimate services use the word "file" in hostnames and `/curl/` in paths), so it is a **hunt**, not a scheduled rule.  
**Severity:** Medium  
**MITRE:** T1189, T1105
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "InitialAccess"
title: "Possible macOS ClickFix staging URL pattern on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "An endpoint contacted a URL matching the campaign's file<word><word> host or /curl/<hex-id> staging-path heuristic. Confirm the host is not a legitimate file-sharing/CDN service, then pivot to the initiating process and any subsequent Terminal/osascript execution."
adaptation_notes: "Heuristic regex over hostnames and paths; expected to match benign services that legitimately use 'file' in the hostname or '/curl/' in the path. Baseline and allowlist known-good domains before considering promotion. Do not deploy as-is."
-->

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl matches regex @"(?i)https?://[a-z0-9.-]*file[a-z]{4,}\.(com|sbs|online|xyz|net|shop|top)\b"
    or RemoteUrl matches regex @"(?i)/curl/[0-9a-f]{6,}\b"
| project Timestamp, DeviceName, DeviceId, RemoteUrl, RemoteIP,
    InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ReportId
| sort by Timestamp desc
```

**Expected results:** Low volume; requires triage. Treat matches as leads to validate against Query 1 infrastructure and downstream execution, not as confirmed detections.

---

## Query 3: macOS Terminal `curl` piped directly into a shell

**Purpose:** Detects the core ClickFix execution primitive — a `curl`/`wget` fetch piped straight into `sh`/`zsh`/`bash` (optionally wrapped in `eval`/`base64 -d`), the exact copy-paste command class the fake-CAPTCHA lure instructs the victim to run in Terminal.  
**Severity:** High  
**MITRE:** T1204.004, T1059.004, T1105, T1140
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "Execution"
title: "curl piped into shell (macOS ClickFix pattern) on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A remote-fetch-piped-to-shell command was observed. On a macOS host in the context of a browser/Terminal session this is a strong ClickFix execution indicator: identify the fetched URL, capture the downloaded stager, and triage for MacSync/AMOS (keychain/browser-credential theft, Query 5 quarantine strip)."
adaptation_notes: "Requires Defender for Endpoint macOS process telemetry (DeviceProcessEvents from macOS agents) — no macOS telemetry was available to fidelity-validate this hunt in the authoring environment. The pattern (curl|shell) is common in Linux/CI/admin automation, so it is FP-prone off-macOS; scope to macOS devices and baseline before promotion. Syntactically validated only."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
// Scope to macOS where telemetry exists; drop this line to hunt cross-OS (higher FP)
// | where DeviceName in (( DeviceInfo | where OSPlatform == "macOS" | distinct DeviceName ))
| where ProcessCommandLine has_any ("curl", "wget")
| where ProcessCommandLine matches regex @"(?i)(curl|wget)\b[^|]*\|\s*(sh|zsh|bash)\b"
| project Timestamp, DeviceName, DeviceId, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, ReportId
| sort by Timestamp desc
```

**Expected results:** In a macOS-onboarded estate, expect 0 from benign users; developer/admin automation may generate matches — baseline and scope to macOS. Any interactive-Terminal match following a browser session is high-signal.

---

## Query 4: macOS `osascript` / AppleScript running a shell payload

**Purpose:** Detects the AppleScript-wrapped variant where **`osascript`** executes `do shell script` (often to run the same remote fetch) and/or renders `display dialog`/`display notification` to reinforce the fake-verification social-engineering flow.  
**Severity:** High  
**MITRE:** T1204.004, T1059.002, T1059.004
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "Execution"
title: "osascript running shell payload (macOS ClickFix pattern) on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "osascript executed a shell command and/or raised native dialogs consistent with the ClickFix lure. Capture the AppleScript/shell content, identify the fetched stager, and triage the macOS host for stealer activity."
adaptation_notes: "Requires Defender for Endpoint macOS process telemetry — not fidelity-validated in the authoring environment (no macOS agents). osascript with 'do shell script' has legitimate admin/MDM uses; scope to macOS and baseline. Syntactically validated only."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "osascript" or ProcessCommandLine has "osascript"
| where ProcessCommandLine has_any ("do shell script", "display dialog", "display notification")
    or ProcessCommandLine has_any ("curl", "wget", "base64")
| project Timestamp, DeviceName, DeviceId, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 from typical end-users on a macOS estate; MDM/admin tooling may match `do shell script`. Interactive `osascript` fetching a remote payload is high-signal.

---

## Query 5: macOS Gatekeeper / quarantine strip + make-executable on a dropped payload

**Purpose:** Detects the post-download evasion step — **`xattr -c`** or **`xattr -d com.apple.quarantine`** (removing the quarantine attribute that triggers Gatekeeper) combined with or followed by **`chmod +x`** on the dropped stager, enabling silent execution.  
**Severity:** High  
**MITRE:** T1553.001, T1059.004, T1204.004
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "DefenseEvasion"
title: "Gatekeeper quarantine strip + chmod on payload (macOS) on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Quarantine-attribute removal (xattr -c / -d com.apple.quarantine) and/or chmod +x was observed, consistent with preparing a downloaded ClickFix stager for silent execution. Capture the target file path, correlate with the delivery/execution chain (Queries 1-4), and triage for MacSync/AMOS."
adaptation_notes: "Requires Defender for Endpoint macOS process telemetry — not fidelity-validated in the authoring environment. xattr/chmod have legitimate developer uses; require the quarantine/executable-prep combination and scope to macOS to reduce FPs. Syntactically validated only."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "xattr" and ProcessCommandLine has_any ("-c", "com.apple.quarantine"))
    or (FileName =~ "chmod" and ProcessCommandLine matches regex @"(?i)chmod\s+(\+x|[0-7]*[1357][0-7]*)\b")
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, ReportId
| sort by Timestamp desc
```

**Expected results:** Developer machines legitimately use `chmod +x`; the high-signal case is `xattr` quarantine removal immediately preceding `chmod +x` on a file dropped after a Query 1/2 network hit. Correlate across the chain rather than alerting on either verb alone.

---

## Hunting Workflow

1. **Start at the network layer (Queries 1–2, OS-agnostic).** Query 1 (direct IOCs) is the highest-fidelity, most portable detection and should be promoted to a scheduled/NRT rule with a maintained domain list. Query 2 surfaces rotated infrastructure for analyst review.
2. **Pivot to macOS execution (Queries 3–5)** for any device that hit the delivery infrastructure — reconstruct the `curl`→shell / `osascript` → quarantine-strip chain. These require macOS process telemetry.
3. **Confirm impact.** For confirmed execution, hunt MacSync/AMOS post-compromise behavior: login-keychain access, browser-credential store reads, and crypto-wallet file access.
4. **Refresh IOCs** from current Microsoft Threat Intelligence before relying on Query 1's direct matches — this campaign actively rotates front-end domains.
