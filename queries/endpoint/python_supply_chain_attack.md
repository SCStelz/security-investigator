# Python Supply Chain Attack Hunting — LiteLLM / PyPI Compromise

**Created:** 2026-03-25  
**Platform:** Both  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, ASimDnsActivityLogs, DeviceEvents, DeviceRegistryEvents, CloudAppEvents, DeviceTvmSoftwareInventory  
**Keywords:** litellm, pypi, pip install, supply chain, credential stealer, python package, site-packages, .pth file, secret exfiltration, environment variable harvesting, cloud credential theft, models.litellm.cloud, checkmarx.zone, trivy, CI/CD compromise, sysmon.py, node-setup, kubernetes lateral movement, fork bomb, uvx, MCP server, transitive dependency, TeamPCP, aquasecurtiy.org, GitHub Actions tag poisoning, mutable tags, startup folder, msbuild masquerade, wav steganography  
**MITRE:** T1195.002, T1059.006, T1027, T1555, T1552.001, T1041, T1071.001, T1547.001, T1547.004, T1082, T1083, T1005, T1543.002, T1610, T1552.007, T1499.004, T1036.005  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This hunting campaign targets TTPs from the **LiteLLM PyPI supply chain compromise** disclosed March 24, 2026:  
**[Security Update: Suspected Supply Chain Incident](https://docs.litellm.ai/blog/security-update-march-2026)**

LiteLLM was one of several downstream targets in a broader supply chain campaign attributed to threat actor **TeamPCP**. The campaign originated with the **Trivy compromise** (March 19, 2026), where attackers leveraged access from a prior, incompletely remediated incident to poison Trivy's binary releases, GitHub Actions (`trivy-action`, `setup-trivy`), and subsequently expanded to **Checkmarx KICS** and **LiteLLM**. All three campaigns share the same credential-stealing payload architecture (AES-256-CBC + RSA-4096 → `tpcp.tar.gz` exfil) and overlapping C2 infrastructure.

**Related intelligence:**
- **[Microsoft: Detecting, Investigating, and Defending Against the Trivy Supply Chain Compromise](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)** — Microsoft Defender coverage, Advanced Hunting queries, and mitigation guidance
- **[Aqua Security: Trivy Supply Chain Attack](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)** — Aqua's own post-mortem and remediation timeline

### Threat Summary

| Aspect | Detail |
|--------|--------|
| **Threat Actor** | **TeamPCP** — attributed by Microsoft Defender Security Research. Same actor behind Trivy (March 19) and Checkmarx KICS compromises |
| **Campaign Chain** | Trivy binary + GitHub Actions (March 19) → Checkmarx KICS → LiteLLM PyPI (March 24). Shared payload architecture and overlapping C2 infrastructure across all three |
| **Affected Packages** | `litellm==1.82.7`, `litellm==1.82.8` (removed from PyPI) |
| **Compromise Window** | March 24, 2026, 10:52–~12:00 UTC (v1.82.8 uploaded at 10:52, PyPI quarantined within ~46 minutes, 46,996 downloads) |
| **Downloads During Window** | 46,996 (32,464 for v1.82.8, 14,532 for v1.82.7) |
| **Dependent Packages** | 2,337 on PyPI — 88% had version specs allowing compromised versions |
| **Attack Vector** | Compromised maintainer PyPI account (via Checkmarx/Trivy CI/CD compromise chain). No GitHub tag for v1.82.7 or v1.82.8 — published directly to PyPI bypassing normal release process. Trivy was compromised via Git tag abuse: attackers force-pushed 76 of 77 tags in `trivy-action` and all 7 in `setup-trivy` to malicious commits, plus published infected binary v0.69.4 |
| **Patient Zero Infection Chain** | Cursor auto-update (10:59) → extension host restart → MCP server reconnection → `uvx futuresearch-mcp-legacy` → pulls `litellm==1.82.8` + 77 transitive deps (10:58) → `.pth` triggers on Python startup → fork bomb + credential theft |
| **Three-Stage Malware Architecture** | Stage 1: `litellm_init.pth` one-liner spawns child with base64 payload → Stage 2: RSA-4096 public key loader → Stage 3: `B64_SCRIPT` credential harvester → `run()` encrypts with AES+RSA and POSTs to C2 |
| **v1.82.8 Payload** | `litellm_init.pth` — .pth startup hook, runs on ANY Python interpreter start including `pip install` itself. Fork bomb bug: each `subprocess.Popen([sys.executable, ...])` child also triggers `.pth`, causing infinite recursion |
| **v1.82.7 Payload** | Injected in `proxy_server.py`, drops `p.py` — triggers only when `litellm.proxy` is imported (proxy servers, not SDK) |
| **C2 Domain (v1.82.8)** | `models.litellm[.]cloud` (NOT a legitimate BerriAI domain) |
| **C2 Domain (v1.82.7)** | `checkmarx[.]zone/raw` (typosquat of legitimate Checkmarx security vendor) |
| **Exfil Method** | AES-256-CBC encryption (random session key) + RSA-4096 public key wrapping → tar archive → POST to C2 |
| **Persistence (Linux)** | `~/.config/sysmon/sysmon.py` + `~/.config/systemd/user/sysmon.service` |
| **Persistence (Windows)** | `msbuild.exe` dropped in `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\` — masquerades as legitimate Microsoft Build Engine. Payload delivered via WAV steganography. See [startup_folder_persistence.md](startup_folder_persistence.md) for dedicated hunting queries |
| **K8s Lateral Movement** | Reads ALL cluster secrets, deploys privileged `alpine:latest` pods (`node-setup-*`) on every node in `kube-system` with host filesystem mount. **Note:** On macOS/non-pod hosts, K8s lateral movement likely fails — no service account token at `/var/run/secrets/`, and fork bomb may crash process before reaching K8s code path |
| **Credential Targets** | Env vars, SSH keys, AWS/GCP/Azure creds, K8s tokens/configs, DB passwords, git creds, Docker configs, npm/vault tokens, shell history, crypto wallets, SSL private keys, CI/CD files, IMDS metadata |
| **MCP Attack Surface** | Cursor/Claude Code MCP servers with unpinned litellm transitive deps pulled malicious version via `uvx` auto-download. **Re-infection risk:** Opening Cursor again re-triggers `uvx` which pulls from uv cache — must purge `~/.cache/uv` before restarting IDE |

### Patient-Zero Timeline (March 24, 2026 UTC)

Reconstructed from the [FutureSearch discovery transcript](https://futuresearch.ai/blog/litellm-attack-transcript/):

| Time (UTC) | Event |
|------------|-------|
| 10:52 | Poisoned `litellm==1.82.8` uploaded to PyPI — no corresponding GitHub tag (only v1.82.6 existed) |
| 10:58 | Cursor's `futuresearch-mcp-legacy` MCP server runs `uvx`, pulling litellm (14.9 MiB) + 77 transitive packages |
| 10:59 | Cursor auto-update triggers extension host restart → MCP servers reconnect → re-triggers package download |
| ~10:59–11:08 | `.pth` file executes on Python startup → fork bomb: 11,000+ Python processes spawn (each child triggers `.pth` again) |
| 11:07 | Malware attempts persistence: `~/.config/sysmon/sysmon.py` created (0 bytes — write interrupted) |
| 11:09 | Victim force-reboots — persistence only partially installed, malware partially neutralized |
| 11:13 | Investigation begins with Claude Code — initially diagnosed as runaway Claude Code loop |
| 11:40 | `litellm_init.pth` identified as malware (27 min after investigation start) |
| 11:58 | Confirmed still live on PyPI via isolated Docker container download |
| 12:02 | Disclosure blog post published |
| 12:10 | Victim opens Cursor again → malware re-triggers from uv cache (second infection) |

**Key forensic insight:** Claude Code initially misidentified the `exec(base64.b64decode(...))` pattern as normal tooling behavior — this is a legitimate pattern used by Python tools for shell escaping. It took deliberate human skepticism to push past the false-negative and discover the malware. AI-assisted security tooling should not dismiss base64-encoded Python execution without deeper inspection.

### MITRE ATT&CK Coverage

| Technique | ID | Relevance |
|-----------|----|-----------|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Malicious PyPI package upload |
| Command and Scripting Interpreter: Python | T1059.006 | Python payload execution via pip install |
| Obfuscated Files or Information | T1027 | Double base64-encoded payload, AES-256 + RSA-4096 encrypted exfil |
| Credentials from Password Stores | T1555 | Credential harvesting from config files |
| Unsecured Credentials: Credentials In Files | T1552.001 | SSH keys, cloud credential files, .env files, git creds, Docker configs |
| Unsecured Credentials: Container API | T1552.007 | K8s service account tokens, IMDS metadata endpoint queries |
| Exfiltration Over C2 Channel | T1041 | POST to models.litellm[.]cloud (v1.82.8) and checkmarx[.]zone (v1.82.7) |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS C2 communication |
| Boot or Logon Autostart Execution: .pth Startup | T1547.004 | `litellm_init.pth` runs Python code at interpreter startup |
| Create or Modify System Process: Systemd Service | T1543.002 | `~/.config/systemd/user/sysmon.service` persistence |
| Deploy Container | T1610 | Privileged `alpine:latest` pods (`node-setup-*`) on every K8s node |
| System Information Discovery | T1082 | Environment variable enumeration, hostname, whoami, uname |
| File and Directory Discovery | T1083 | Scanning for credential files (SSH, cloud configs, crypto wallets) |
| Data from Local System | T1005 | Collecting secrets from local filesystem |
| Boot or Logon Autostart Execution: Startup Folder | T1547.001 | `msbuild.exe` payload dropped in Windows Startup folder for login persistence. See [startup_folder_persistence.md](startup_folder_persistence.md) |
| Masquerading: Match Legitimate Name or Location | T1036.005 | Payload named `msbuild.exe` to impersonate Microsoft Build Engine |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | Fork bomb from .pth re-trigger bug (detection artifact) |

### IoCs

| Indicator | Type | Notes |
|-----------|------|-------|
| `models.litellm[.]cloud` | Domain | C2 exfiltration endpoint for v1.82.8 (NOT legitimate BerriAI) |
| `checkmarx[.]zone` | Domain | C2 exfiltration endpoint for v1.82.7 (typosquat of legitimate Checkmarx) |
| `litellm_init.pth` | Filename | Malicious .pth file in site-packages (v1.82.8), sha256=`ceNa7wMJnNHy1kRnNCcwJaFjWX3pORLfMh7xGL8TUjg` |
| `p.py` | Filename | Secondary script dropped by v1.82.7 payload |
| `~/.config/sysmon/sysmon.py` | File path | Persistent backdoor installed on compromised host |
| `~/.config/systemd/user/sysmon.service` | File path | Systemd persistence service for backdoor |
| `node-setup-*` | K8s pod name | Privileged pods deployed in `kube-system` for lateral movement |
| `litellm==1.82.7` | Package version | Compromised PyPI release (proxy_server.py payload) |
| `litellm==1.82.8` | Package version | Compromised PyPI release (.pth payload) |
| `tpcp.tar.gz` | Filename | Encrypted exfil archive created before POST to C2 |
| `scan.aquasecurtiy[.]org` | Domain | TeamPCP C2 for Trivy campaign (typosquat of "aquasecurity" — note deliberate misspelling) |
| `%AppData%\...\Startup\msbuild.exe` | File path | Masquerading payload in Windows Startup folder — NOT the legitimate MSBuild (`C:\Windows\Microsoft.NET\Framework\`) |
| `45.148.10.212` | IP | TeamPCP C2 IP address (Trivy campaign) |
| `plug-tab-protective-relay.trycloudflare.com` | Domain | TeamPCP C2 — Cloudflare Tunnel relay |
| `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io` | Domain | TeamPCP C2 — Internet Computer Protocol canister |
| `trivy==0.69.4` / `0.69.5` / `0.69.6` | Software version | Compromised Trivy binary releases (same campaign) |

### References

| Source | URL |
|--------|-----|
| BerriAI Official Disclosure | https://docs.litellm.ai/blog/security-update-march-2026 |
| FutureSearch — Initial Discovery | https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/ |
| FutureSearch — Post-Mortem | https://futuresearch.ai/blog/no-prompt-injection-required/ |
| FutureSearch — Blast Radius Analysis | https://futuresearch.ai/blog/litellm-hack-were-you-one-of-the-47000/ |
| FutureSearch — Discovery Transcript | https://futuresearch.ai/blog/litellm-attack-transcript/ |
| GitHub Issue #24512 | https://github.com/BerriAI/litellm/issues/24512 |
| Snyk Analysis | https://snyk.io/articles/poisoned-security-scanner-backdooring-litellm/ |
| Microsoft — Trivy Supply Chain Detection & Defense | https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/ |
| StepSecurity — Trivy Compromised a Second Time | https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release |

---

## Query Catalog

### Query 1 — Direct litellm Installation Detection (DeviceProcessEvents)

**Goal:** Detect any `pip install litellm` commands across the MDE fleet.  
**MITRE:** T1195.002, T1059.006

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "pip install litellm detected on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "Verify litellm version installed. If v1.82.7 or v1.82.8, treat as confirmed compromise. Isolate device, rotate all secrets, check for litellm_init.pth in site-packages."
adaptation_notes: "Already row-level. Add DeviceId + ReportId columns."
-->

```kql
// Detect pip install litellm commands — direct or as dependency
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "litellm"
    and (ProcessCommandLine has "pip install" 
         or ProcessCommandLine has "pip3 install"
         or ProcessCommandLine has "-m pip install")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    FileName,
    FolderPath
| order by Timestamp desc
```

---

### Query 2 — Broad pip/pip3 Install Activity Audit (DeviceProcessEvents)

**Goal:** Enumerate ALL pip install commands for supply chain exposure review. Useful to understand which devices run pip and what packages are being installed.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Audit/inventory query using summarize with make_set and dcount — not suitable for CD alerting."
-->

```kql
// Audit all pip install activity across fleet — useful for supply chain exposure assessment
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "pip install" 
    or ProcessCommandLine has "pip3 install"
    or ProcessCommandLine has "-m pip install"
| extend PackageRaw = extract(@"pip3?\s+install\s+(.+)", 1, ProcessCommandLine)
| extend Package = trim_start(@"[\s""]+", trim_end(@"[\s""]+", PackageRaw))
| summarize 
    InstallCount = count(),
    Devices = make_set(DeviceName, 20),
    Users = make_set(AccountName, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by Package
| order by InstallCount desc
```

---

### Query 3 — litellm File Artifacts on Disk (DeviceFileEvents)

**Goal:** Detect `litellm_init.pth` (the malicious .pth startup file from v1.82.8) and any litellm files in site-packages.  
**MITRE:** T1547.004, T1195.002

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "litellm file artifact detected on {{DeviceName}}: {{FileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Check if litellm_init.pth is present — this is the malicious .pth loader from v1.82.8. Isolate device, rotate all credentials, preserve artifacts for forensics."
adaptation_notes: "Already row-level with SHA256. Add DeviceId + ReportId columns."
-->

```kql
// Detect litellm files — especially litellm_init.pth (malicious .pth loader)
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName has "litellm" or FolderPath has "litellm"
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

### Query 4 — Malicious .pth File Detection (DeviceFileEvents)

**Goal:** Broader hunt for ANY suspicious `.pth` files in Python site-packages. The `.pth` file mechanism runs arbitrary Python at interpreter startup (T1547.004) and is increasingly abused in supply chain attacks.  
**MITRE:** T1547.004

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "Persistence"
title: "Suspicious .pth file in site-packages on {{DeviceName}}: {{FileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Inspect .pth file contents — .pth files execute arbitrary Python at interpreter startup. Verify the file is legitimate (expected package) or malicious (supply chain persistence)."
adaptation_notes: "Already row-level with allowlist exclusions. Add DeviceId + ReportId. 24H schedule suitable — .pth persistence is not time-critical."
-->

```kql
// Hunt for suspicious .pth files in Python site-packages
// .pth files execute Python code at interpreter startup — supply chain persistence mechanism
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".pth"
| where FolderPath has "site-packages" or FolderPath has "dist-packages"
// Exclude common legitimate .pth files
| where FileName !in~ (
    "easy-install.pth",
    "distutils-precedence.pth", 
    "setuptools.pth",
    "virtualenv.pth",
    "zope.pth",
    "_virtualenv.pth"
)
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    SHA256
| order by Timestamp desc
```

---

### Query 5 — C2 Domain Network Connections (DeviceNetworkEvents)

**Goal:** Detect outbound connections to the litellm C2 exfiltration domain `models.litellm[.]cloud`.  
**MITRE:** T1041, T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "0"
category: "Exfiltration"
title: "Outbound connection to litellm C2 domain from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "CRITICAL: This device connected to the litellm C2 exfiltration domain. Isolate immediately. Rotate ALL secrets. Check for litellm v1.82.7/1.82.8 installation. Preserve network and process artifacts."
adaptation_notes: "NRT-suitable — high-fidelity IoC match on known C2 domain. Remove let statements. Already row-level. Add DeviceId + ReportId."
-->

```kql
// Detect outbound connections to litellm C2 domain
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "models.litellm" 
    or RemoteUrl has "litellm.cloud"
    or RemoteUrl has "litellm"
| project 
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    ActionType,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 6 — C2 Domain DNS Resolution (ASIM DNS)

**Goal:** Detect DNS lookups for the litellm C2 domain `models.litellm[.]cloud` using ASIM-normalized DNS logs. This catches resolution attempts even if the HTTP connection was blocked.  
**MITRE:** T1041, T1071.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "DNS resolution of litellm C2 domain detected from {{SrcIpAddr}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "DNS lookup for litellm C2 domain detected — even if the HTTP connection was blocked, a compromised package attempted to resolve the C2. Identify the source device via SrcIpAddr, check for litellm installation, rotate secrets."
adaptation_notes: "Sentinel/LA table — use TimeGenerated. Dvc may serve as DeviceName proxy. No native ReportId — use EventUid as proxy. Verify Dvc populates as hostname."
-->

```kql
// Hunt for DNS resolution of litellm C2 domain via ASIM DNS logs
ASimDnsActivityLogs
| where TimeGenerated > ago(30d)
| where DnsQuery has "litellm"
| project 
    TimeGenerated,
    SrcIpAddr,
    DnsQuery,
    DnsQueryTypeName,
    DnsResponseName,
    DnsResponseCodeName,
    EventResult,
    Dvc,
    EventProduct
| order by TimeGenerated desc
```

---

### Query 7 — PyPI Download Activity on Compromise Date (ASIM DNS)

**Goal:** Identify any devices that resolved PyPI domains during the compromise window (March 24, 2026 10:39–16:00 UTC). These devices may have pulled the malicious package.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "One-time forensic query for a fixed time window (March 24 compromise). Not suitable for ongoing CD — hardcoded datetime range."
-->

```kql
// Identify devices resolving PyPI during the compromise window
ASimDnsActivityLogs
| where TimeGenerated between (datetime(2026-03-24T10:39:00Z) .. datetime(2026-03-24T16:00:00Z))
| where DnsQuery has "pypi.org" 
    or DnsQuery has "files.pythonhosted.org"
    or DnsQuery has "pythonhosted"
| project 
    TimeGenerated,
    SrcIpAddr,
    DnsQuery,
    DnsResponseName,
    DnsResponseCodeName,
    EventResult,
    Dvc
| order by TimeGenerated asc
```

---

### Query 8 — PyPI Download Activity Baseline (ASIM DNS)

**Goal:** Broader 30-day view of PyPI-related DNS lookups to understand which devices regularly pull Python packages. Useful for scoping supply chain exposure.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Baseline/inventory query using summarize — designed for exposure scoping, not alerting."
-->

```kql
// Baseline: which devices resolve PyPI domains (30-day lookback)
ASimDnsActivityLogs
| where TimeGenerated > ago(30d)
| where DnsQuery has "pypi.org" 
    or DnsQuery has "files.pythonhosted.org"
    or DnsQuery has "pythonhosted"
| summarize 
    QueryCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DnsQueries = make_set(DnsQuery, 10)
    by SrcIpAddr, Dvc
| order by QueryCount desc
```

---

### Query 9 — Python Process Spawning Suspicious Network Connections (DeviceNetworkEvents)

**Goal:** Detect Python processes making outbound connections to unusual domains — catches both litellm-specific and generic Python-based exfiltration.  
**MITRE:** T1041, T1071.001, T1059.006

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summarize aggregation by RemoteUrl/RemoteIP — designed for threat hunting review, not CD. High false-positive rate without tuning to specific environment."
-->

```kql
// Python processes making outbound connections — look for exfiltration patterns
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe", "python3.11.exe", "python3.12.exe", "python3.13.exe")
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
// Exclude common legitimate Python network targets
| where RemoteUrl !has "microsoft.com"
    and RemoteUrl !has "azure.com"
    and RemoteUrl !has "windows.net"
    and RemoteUrl !has "office.com"
    and RemoteUrl !has "github.com"
    and RemoteUrl !has "pypi.org"
    and RemoteUrl !has "pythonhosted.org"
    and RemoteUrl !has "googleapis.com"
| summarize 
    ConnectionCount = count(),
    Devices = make_set(DeviceName, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteUrl, RemoteIP
| order by ConnectionCount desc
| take 50
```

---

### Query 10 — Environment Variable Access by Python (DeviceProcessEvents)

**Goal:** Detect Python processes that enumerate environment variables — a key TTP of the litellm stealer payload. Looks for `os.environ`, `printenv`, `env`, and `set` commands spawned by Python.  
**MITRE:** T1082, T1552.001

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Python process spawned environment enumeration on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "Python spawned a child process that enumerates environment variables. This is a key TTP of credential-stealing packages (litellm, ultralytics, etc.). Investigate the parent Python script and check for recent pip installs."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. May need FP tuning for legitimate dev workflows."
-->

```kql
// Python spawning environment enumeration commands (credential harvesting indicator)
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe")
| where ProcessCommandLine has_any ("env", "set", "printenv", "Get-ChildItem Env:", "os.environ")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 11 — SSH Key and Cloud Credential File Access (DeviceFileEvents)

**Goal:** Detect Python processes reading SSH keys and cloud provider credential files — the litellm stealer specifically targets these.  
**MITRE:** T1552.001, T1005

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CredentialAccess"
title: "Python accessed credential file on {{DeviceName}}: {{FileName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Python process accessed sensitive credential files (SSH keys, cloud provider configs, .env files). Investigate the initiating Python script, check for recently installed packages, and verify whether access was legitimate (e.g., Ansible, Terraform) or malicious."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. May generate FPs from legitimate tools (Ansible, cloud SDKs, Terraform) — tune exclusions per environment."
-->

```kql
// Python process accessing SSH keys and cloud credential files
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe")
| where (
    // SSH keys
    FolderPath has ".ssh" and FileName in~ ("id_rsa", "id_ed25519", "id_ecdsa", "known_hosts", "authorized_keys", "config")
    )
    or (
    // AWS credentials
    FolderPath has ".aws" and FileName in~ ("credentials", "config")
    )
    or (
    // Azure credentials
    FolderPath has ".azure" and FileName in~ ("accessTokens.json", "azureProfile.json", "msal_token_cache.json")
    )
    or (
    // GCP credentials
    FolderPath has "gcloud" and FileName in~ ("credentials.db", "access_tokens.db", "application_default_credentials.json")
    )
    or (
    // Kubernetes tokens
    FolderPath has ".kube" and FileName in~ ("config")
    )
    or (
    // Generic env/secret files
    FileName in~ (".env", ".env.local", ".env.production", "secrets.json", "credentials.json")
    )
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 12 — Python Package Installation via CI/CD Agents (DeviceProcessEvents)

**Goal:** Detect pip install activity from CI/CD runners or automation accounts. These are high-risk because they often have unpinned dependencies and broad secret access.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "pip install from CI/CD context on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "pip install detected in a CI/CD or automation context. These environments typically have broad secret access and unpinned dependencies — high supply chain risk. Verify packages are pinned to safe versions and review the process tree."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. Tune AccountName has_any list for org-specific service accounts."
-->

```kql
// pip install from CI/CD or automation contexts
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "pip install" 
    or ProcessCommandLine has "pip3 install"
    or ProcessCommandLine has "-m pip install"
// Look for CI/CD indicators in the process tree
| where AccountName has_any ("runner", "agent", "build", "deploy", "service", "automation", "system")
    or InitiatingProcessCommandLine has_any ("actions-runner", "azagent", "vsts-agent", "jenkins", "gitlab-runner", "GitHub Actions")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

---

### Query 13 — Unpinned pip install Detection (DeviceProcessEvents)

**Goal:** Find pip install commands that DON'T pin a version — these would have pulled the latest (compromised) version during the window. `pip install litellm` without `==1.82.6` or similar is the exact attack vector.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: true
schedule: "24H"
category: "InitialAccess"
title: "Unpinned pip install detected on {{DeviceName}} by {{AccountName}}"
impactedAssets:
  - type: device
    identifier: deviceName
  - type: user
    identifier: accountName
recommendedActions: "A pip install command was executed without version pinning. This is the exact attack vector for PyPI supply chain compromises — unpinned installs pull the latest version, which may be malicious. Verify the package integrity and pin to a known-safe version."
adaptation_notes: "Already row-level. Add DeviceId + ReportId. 24H schedule — informational/posture detection, not urgent. May be noisy in dev environments — tune exclusions."
-->

```kql
// Detect unpinned pip installs (no version specifier) — highest supply chain risk
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "pip install" 
    or ProcessCommandLine has "pip3 install"
    or ProcessCommandLine has "-m pip install"
// Exclude requirements file installs (those may or may not be pinned, different risk)
| where ProcessCommandLine !has "-r " and ProcessCommandLine !has "--requirement"
// Look for installs without version pinning (no ==, >=, ~=, !=)
| where ProcessCommandLine !has "==" 
    and ProcessCommandLine !has ">=" 
    and ProcessCommandLine !has "~="
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessCommandLine,
    FileName
| order by Timestamp desc
```

---

### Query 14 — Post-Compromise Secret Exfiltration Pattern (DeviceNetworkEvents)

**Goal:** Detect the specific exfiltration pattern: Python process making an outbound POST with encrypted data. The litellm stealer encrypts harvested secrets and POSTs them to the C2.  
**MITRE:** T1041, T1027

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table join with let variable and time-window correlation (PipTime + 1h). Not suitable for NRT. Could be adapted for 1H schedule but join complexity and potential FP volume makes it better as a hunting query."
-->

```kql
// Python processes making outbound connections shortly after pip install
// Correlate: pip install → Python network activity within 1 hour
let pipInstalls = DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "pip install" or ProcessCommandLine has "pip3 install"
| project PipTime = Timestamp, DeviceName, AccountName, ProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe")
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| join kind=inner pipInstalls on DeviceName
| where Timestamp between (PipTime .. (PipTime + 1h))
| project 
    PipInstallTime = PipTime,
    NetworkTime = Timestamp,
    DeviceName,
    AccountName,
    PipCommand = ProcessCommandLine,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    InitiatingProcessCommandLine
| order by PipInstallTime desc
```

---

### Query 15 — Suspicious Domain Resolution After pip install (ASIM DNS + DeviceProcessEvents)

**Goal:** Cross-reference devices that ran pip install with DNS resolution of unusual domains shortly after. Catches C2 callbacks from compromised packages.  
**MITRE:** T1041, T1071.001, T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Cross-table join with let + summarize aggregation. Designed for hunting correlation, not CD alerting."
-->

```kql
// Step 1: Identify devices that ran pip install in last 30 days
let pipDevices = DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "pip install" or ProcessCommandLine has "pip3 install"
| distinct DeviceName;
// Step 2: Check DNS queries from those devices for suspicious domains
// (Adapt join if SrcIpAddr needs mapping through DeviceNetworkInfo)
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where DeviceName in (pipDevices)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "pythonw.exe")
// Look for non-standard domains that might be C2
| where RemoteUrl !has "microsoft.com"
    and RemoteUrl !has "windows.net"
    and RemoteUrl !has "azure.com"
    and RemoteUrl !has "github.com"
    and RemoteUrl !has "pypi.org"
    and RemoteUrl !has "pythonhosted.org"
    and RemoteUrl !has "office.com"
    and RemoteUrl !has "googleapis.com"
    and RemoteUrl !has "amazonaws.com"
| summarize 
    HitCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName, RemoteUrl, RemoteIP
| order by HitCount desc
| take 50
```

---

### Query 16 — Python Fleet Inventory (DeviceProcessEvents)

**Goal:** Understand the Python-capable attack surface — which devices have Python installed and actively run it. Essential for scoping supply chain exposure.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Fleet inventory query using summarize with make_set — designed for attack surface scoping, not alerting."
-->

```kql
// Python fleet inventory — which devices actively run Python
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("python.exe", "python3.exe", "pythonw.exe", "pip.exe", "pip3.exe")
| summarize 
    ProcessCount = count(),
    UniqueProcesses = make_set(FileName, 10),
    Users = make_set(AccountName, 10),
    LastSeen = max(Timestamp),
    FirstSeen = min(Timestamp)
    by DeviceName
| order by ProcessCount desc
```

---

### Query 17 — Docker Build with pip install During Compromise Window (DeviceProcessEvents)

**Goal:** Detect Docker builds that may have pulled the compromised package via `pip install litellm` inside a container build.  
**MITRE:** T1195.002

<!-- cd-metadata
cd_ready: false
adaptation_notes: "One-time forensic query for a fixed time window (March 24 compromise). Not suitable for ongoing CD — hardcoded datetime range."
-->

```kql
// Docker builds running pip install during the compromise window
DeviceProcessEvents
| where Timestamp between (datetime(2026-03-24T10:00:00Z) .. datetime(2026-03-25T00:00:00Z))
| where (InitiatingProcessFileName in~ ("dockerd", "docker.exe", "containerd", "buildkitd")
    or InitiatingProcessCommandLine has "docker build"
    or InitiatingProcessCommandLine has "docker-compose")
| where ProcessCommandLine has "pip install"
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 18 — Broad DNS Hunt for Newly Registered / Suspicious Domains from Python (ASIM DNS)

**Goal:** Find DNS queries for uncommon or recently-registered domains that originate from machines with Python activity. Useful for detecting C2 from ANY compromised Python package, not just litellm.  
**MITRE:** T1071.001, T1041

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Summarize aggregation with broad TLD-based hunting — high FP rate without environment-specific tuning. Better as periodic hunting query."
-->

```kql
// DNS queries from the DNS server — look for unusual .cloud TLDs and other suspicious patterns
// The litellm C2 used .cloud TLD which is commonly abused
ASimDnsActivityLogs
| where TimeGenerated > ago(7d)
| where DnsQuery has ".cloud" 
    or DnsQuery has ".top"
    or DnsQuery has ".xyz"
    or DnsQuery has ".icu"
    or DnsQuery has ".buzz"
    or DnsQuery has ".life"
| where DnsQuery !has "microsoft" 
    and DnsQuery !has "azure"
    and DnsQuery !has "windows"
    and DnsQuery !has "google"
    and DnsQuery !has "amazon"
    and DnsQuery !has "oracle"
    and DnsQuery !has "cloudflare"
    and DnsQuery !has "icloud"
    and DnsQuery !has "salesforce"
| summarize 
    QueryCount = count(),
    UniqueSources = dcount(SrcIpAddr),
    Sources = make_set(SrcIpAddr, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DnsQuery
| order by QueryCount desc
| take 100
```

---

### Query 19 — Second C2 Domain: checkmarx[.]zone DNS Lookups (ASIM DNS)

**Goal:** Detect DNS resolution of the v1.82.7 C2 domain `checkmarx.zone` — a typosquat of the legitimate security vendor Checkmarx. Any hit is high-fidelity.  
**MITRE:** T1071.001, T1041

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "Exfiltration"
title: "PyPI Supply Chain — checkmarx.zone C2 DNS Lookup"
description: "Detects DNS queries for the checkmarx.zone typosquat domain used as C2 by compromised litellm v1.82.7. Any resolution of this domain is a strong compromise indicator."
severity: "High"
impactedAssets: ["DeviceId"]
-->

```kql
// v1.82.7 C2 domain — typosquat of legitimate Checkmarx security vendor
ASimDnsActivityLogs
| where TimeGenerated > ago(30d)
| where DnsQuery has "checkmarx.zone"
| project 
    TimeGenerated,
    SrcIpAddr,
    SrcHostname,
    DnsQuery,
    DnsResponseName,
    EventResultDetails,
    DnsQueryType,
    EventResult
| order by TimeGenerated desc
```

---

### Query 20 — Second C2 Domain: checkmarx[.]zone Network Connections (DeviceNetworkEvents)

**Goal:** Detect direct network connections to the v1.82.7 C2 domain from endpoints. Covers cases where DNS resolution isn't logged but the connection is.  
**MITRE:** T1071.001, T1041

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "Exfiltration"
title: "PyPI Supply Chain — checkmarx.zone C2 Network Connection"
description: "Detects outbound network connections to checkmarx.zone, the C2 domain used by compromised litellm v1.82.7 to exfiltrate stolen credentials."
severity: "High"
impactedAssets: ["DeviceId"]
-->

```kql
// Outbound connections to v1.82.7 C2
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "checkmarx.zone" or RemoteUrl has "checkmarx[.]zone"
| project 
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
```

---

### Query 21 — Sysmon.py Persistence Backdoor File Creation (DeviceFileEvents)

**Goal:** Detect creation of the persistent backdoor file `sysmon.py` in `~/.config/sysmon/`. The malware installs this to maintain access after the initial package is removed.  
**MITRE:** T1547.004, T1543.002

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "Persistence"
title: "PyPI Supply Chain — sysmon.py Persistence Backdoor"
description: "Detects creation of sysmon.py in ~/.config/sysmon/ — a persistent backdoor installed by the compromised litellm package to survive package removal."
severity: "High"
impactedAssets: ["DeviceId"]
-->

```kql
// Persistent backdoor dropped by the malware
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has ".config/sysmon" 
    or FolderPath has ".config\\sysmon"
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 22 — Systemd User Service Persistence (DeviceFileEvents)

**Goal:** Detect creation of the systemd user service `sysmon.service` used for persistence. This ensures the backdoor restarts automatically.  
**MITRE:** T1543.002

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "Persistence"
title: "PyPI Supply Chain — Systemd User Service Persistence"
description: "Detects creation of sysmon.service in ~/.config/systemd/user/ — systemd persistence mechanism installed by compromised litellm to auto-restart the backdoor."
severity: "High"
impactedAssets: ["DeviceId"]
-->

```kql
// Systemd persistence for the backdoor
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath has ".config/systemd/user" or FolderPath has ".config\\systemd\\user")
    and FileName endswith ".service"
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 23 — Kubernetes Secret Enumeration and Lateral Movement (DeviceProcessEvents)

**Goal:** Detect kubectl commands used by the malware to enumerate secrets across all namespaces and deploy privileged pods. The attack creates `node-setup-*` pods in `kube-system` on every node with host filesystem mounts.  
**MITRE:** T1552.007, T1610

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "LateralMovement"
title: "PyPI Supply Chain — K8s Secret Theft and Privileged Pod Deployment"
description: "Detects kubectl commands for enumerating all secrets across namespaces or creating privileged pods (node-setup-*) — K8s lateral movement from the compromised litellm payload."
severity: "High"
impactedAssets: ["DeviceId"]
-->

```kql
// K8s lateral movement: secret theft + privileged pod creation
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("kubectl", "kubectl.exe")
| where ProcessCommandLine has_any (
    "get secrets --all-namespaces",
    "get secrets -A",
    "get secret --all-namespaces",
    "get secret -A",
    "node-setup",
    "create -f" // pod creation from manifest
    )
    or (ProcessCommandLine has "run" and ProcessCommandLine has "alpine" and ProcessCommandLine has "privileged")
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 24 — Fork Bomb Detection: Exponential Python Process Spawning (DeviceProcessEvents)

**Goal:** Detect the .pth file bug that causes exponential Python process spawning. The `litellm_init.pth` re-triggers on every Python startup including its own subprocess, creating a fork bomb. This is a high-confidence detection artifact — any device with 50+ Python processes in an hour is likely affected.  
**MITRE:** T1499.004, T1059.006

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "Execution"
title: "PyPI Supply Chain — Python Fork Bomb (.pth Re-trigger)"
description: "Detects exponential Python process spawning caused by the litellm_init.pth bug. The .pth file triggers on every Python startup including its own child, creating a visible fork bomb — 50+ processes/hour is abnormal."
severity: "High"
impactedAssets: ["DeviceId"]
-->

```kql
// Fork bomb from .pth re-trigger bug — extremely high Python process count
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("python.exe", "python3.exe", "python", "python3", "pythonw.exe")
| summarize 
    ProcessCount = count(),
    UniqueCommandLines = dcount(ProcessCommandLine),
    SampleCommands = make_set(ProcessCommandLine, 5),
    Users = make_set(AccountName, 5)
    by DeviceName, bin(Timestamp, 1h)
| where ProcessCount > 50
| order by ProcessCount desc
```

---

### Query 25 — MCP Server / uvx Transitive Dependency Pull (DeviceProcessEvents)

**Goal:** Detect `uvx` commands that may have pulled litellm as a transitive dependency. Cursor and Claude Code MCP servers using unpinned litellm deps auto-downloaded the compromised version via `uvx`.  
**MITRE:** T1195.002, T1059.006

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Hunting query for MCP/uvx vector — broad filter on uvx commands requires environment tuning. Not all uvx invocations are malicious."
-->

```kql
// MCP server / uvx transitive dependency pull
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("uvx", "uvx.exe", "uv", "uv.exe")
    or (ProcessCommandLine has "uvx" and ProcessCommandLine has_any ("litellm", "mcp"))
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 26 — Git Credential and Docker Config File Access by Python (DeviceFileEvents)

**Goal:** Detect Python processes reading git credentials (`.gitconfig`, `.git-credentials`) and Docker configs (`config.json` in docker/kaniko paths). These are high-value targets in the Stage 1 credential sweep.  
**MITRE:** T1552.001, T1005

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "CredentialAccess"
title: "PyPI Supply Chain — Git/Docker Credential Access by Python"
description: "Detects Python processes reading git credentials (.gitconfig, .git-credentials) or Docker configs — high-value targets in the litellm Stage 1 credential sweep."
severity: "Medium"
impactedAssets: ["DeviceId"]
-->

```kql
// Git credential and Docker config access by Python processes
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "python", "python3", "pythonw.exe")
| where (FileName in~ (".gitconfig", ".git-credentials", "credentials") 
        and FolderPath has_any ("home", "Users"))
    or (FileName =~ "config.json" 
        and FolderPath has_any (".docker", "kaniko"))
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 27 — IMDS Metadata Endpoint Access from Python (DeviceNetworkEvents)

**Goal:** Detect Python processes connecting to the cloud Instance Metadata Service (169.254.169.254). The malware queries IMDS to steal cloud instance credentials (AWS IAM role tokens, Azure managed identity tokens, GCP access tokens).  
**MITRE:** T1552.007, T1082

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "CredentialAccess"
title: "PyPI Supply Chain — IMDS Metadata Access from Python"
description: "Detects Python processes connecting to the cloud IMDS endpoint (169.254.169.254) to steal instance credentials — AWS IAM role tokens, Azure managed identity tokens, GCP access tokens."
severity: "Medium"
impactedAssets: ["DeviceId"]
-->

```kql
// Cloud IMDS metadata endpoint access from Python
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "169.254.169.254"
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "python", "python3", "pythonw.exe")
| project 
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
```

---

### Query 28 — v1.82.7-Specific: proxy_server.py Modification or p.py Drop (DeviceFileEvents)

**Goal:** Detect artifacts specific to v1.82.7: modification of `proxy_server.py` (where the payload was injected) or creation of `p.py` (the dropped secondary script). These are distinct from the v1.82.8 .pth attack.  
**MITRE:** T1195.002, T1059.006

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "Execution"
title: "PyPI Supply Chain — v1.82.7 proxy_server.py / p.py Artifacts"
description: "Detects v1.82.7-specific artifacts: modification of proxy_server.py (payload injection point) or creation of p.py (dropped secondary script). Distinct from the v1.82.8 .pth attack vector."
severity: "High"
impactedAssets: ["DeviceId"]
-->

```kql
// v1.82.7 specific artifacts
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName =~ "p.py" and FolderPath has_any ("litellm", "site-packages", "temp", "tmp"))
    or (FileName =~ "proxy_server.py" and FolderPath has "litellm" 
        and ActionType == "FileModified")
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 29 — Shell History and Package Manager Config Access by Python (DeviceFileEvents)

**Goal:** Detect Python processes accessing shell history files and package manager configs. The malware harvests `.bash_history`, `.zsh_history`, `.mysql_history`, `.psql_history`, `.npmrc`, `.vault-token`, `.netrc`, `.my.cnf`, `.pgpass`, and `.mongorc.js` for credentials and operational intelligence.  
**MITRE:** T1552.001, T1005, T1083

<!-- cd-metadata
cd_ready: true
schedule: "1h"
category: "CredentialAccess"
title: "PyPI Supply Chain — Shell History and Config Harvesting by Python"
description: "Detects Python processes reading shell history files (.bash_history, .zsh_history) and package manager configs (.npmrc, .vault-token, .pgpass) — credential and operational intelligence harvesting from the litellm payload."
severity: "Medium"
impactedAssets: ["DeviceId"]
-->

```kql
// Shell history and package manager config harvesting
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("python.exe", "python3.exe", "python", "python3", "pythonw.exe")
| where FileName in~ (
    ".bash_history", ".zsh_history", ".mysql_history", ".psql_history", ".rediscli_history",
    ".npmrc", ".vault-token", ".netrc", ".my.cnf", ".pgpass", ".mongorc.js"
    )
| project 
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Query 30 — TeamPCP Full Campaign C2 Infrastructure (DeviceNetworkEvents)

**Goal:** Detect network connections to ANY TeamPCP C2 infrastructure across the entire campaign — Trivy, Checkmarx KICS, and LiteLLM compromises. This is the broadest IoC sweep; covers domains and IPs from Microsoft's attribution analysis.  
**MITRE:** T1071.001, T1041, T1568  
**Source:** [Microsoft Defender — Trivy Supply Chain Detection](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)

```kql
// TeamPCP full campaign C2 infrastructure — all compromises
let TeamPCP_C2_Domains = dynamic([
    "models.litellm.cloud",                              // LiteLLM v1.82.8 C2
    "checkmarx.zone",                                     // LiteLLM v1.82.7 + Checkmarx KICS C2
    "scan.aquasecurtiy.org",                               // Trivy C2 (typosquat of aquasecurity)
    "plug-tab-protective-relay.trycloudflare.com",         // Trivy C2 — Cloudflare Tunnel
    "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"             // Trivy C2 — ICP canister
]);
let TeamPCP_C2_IPs = dynamic([
    "45.148.10.212"                                        // Trivy C2 IP
]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (TeamPCP_C2_Domains)
    or RemoteIP in (TeamPCP_C2_IPs)
| project
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ActionType
| order by Timestamp desc
```

---

### Query 31 — Compromised Trivy Versions in Software Inventory (DeviceTvmSoftwareInventory)

**Goal:** Identify devices with compromised Trivy binary versions (v0.69.4, v0.69.5, v0.69.6) installed. These versions were backdoored by TeamPCP with the same credential-stealing payload used in the LiteLLM compromise. Affected organizations should treat any device running these versions as potentially compromised.  
**MITRE:** T1195.001  
**Source:** [Microsoft Defender — Trivy Supply Chain Detection](https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/)

```kql
// Compromised Trivy versions in software inventory
DeviceTvmSoftwareInventory
| where SoftwareName has "trivy"
| where SoftwareVersion in ("0.69.4", "0.69.5", "0.69.6")
| project
    DeviceName,
    DeviceId,
    SoftwareName,
    SoftwareVersion,
    OSPlatform
| order by DeviceName asc
```

---

### Query 32 — TeamPCP DNS Lookups Across Full Campaign (DeviceEvents)

**Goal:** Detect DNS resolution attempts for all TeamPCP C2 domains. DNS queries may appear even when network connections are blocked by firewall/proxy, providing evidence of compromise even without successful C2 contact.  
**MITRE:** T1071.001, T1568

```kql
// TeamPCP campaign DNS lookups (all compromises)
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where AdditionalFields has_any (
    "models.litellm.cloud",
    "checkmarx.zone",
    "scan.aquasecurtiy.org",
    "plug-tab-protective-relay.trycloudflare.com",
    "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"
    )
| extend DnsQuery = tostring(parse_json(AdditionalFields).DnsQueryString)
| project
    Timestamp,
    DeviceName,
    DnsQuery,
    AdditionalFields
| order by Timestamp desc
```

---

## Triage Playbook

If any of the above queries return positive results:

### Immediate Actions (CRITICAL)

1. **Isolate affected device** via MDE device isolation
2. **Identify installed version**: On affected system run `pip show litellm` — if version is 1.82.7 or 1.82.8, treat as confirmed compromise
3. **Check for .pth file**: Search for `litellm_init.pth` in Python site-packages directories
4. **Check for persistence**: Look for `~/.config/sysmon/sysmon.py` and `~/.config/systemd/user/sysmon.service` (may be 0 bytes if write was interrupted)
5. **Purge package manager caches**: `rm -rf ~/.cache/uv` and `pip cache purge` — the compromised package persists in cache and **re-infects on next IDE/tool launch** (confirmed: patient zero was re-infected when reopening Cursor)
6. **Kill all Python processes** before further investigation: `killall python3` / `taskkill /IM python.exe /F` — the fork bomb may still be running
7. **Rotate ALL secrets** accessible from that device: API keys, SSH keys, cloud credentials, K8s tokens, DB passwords, environment variables, git creds, Docker registry tokens

### Investigation Steps

1. **Scope impact**: Run Query 2 to find all pip activity on the affected device
2. **Check C2 traffic**: Run Query 30 (full TeamPCP campaign sweep) first, then Queries 5 + 6 (v1.82.8 C2) AND Queries 19 + 20 (v1.82.7 C2) to confirm exfiltration attempts
3. **Persistence check**: Run Queries 21 + 22 to detect installed backdoors
4. **Fork bomb evidence**: Run Query 24 — if Python process counts spiked, device was affected by the .pth bug
5. **Credential file access**: Run Queries 11 + 26 + 29 to check what secrets were accessed
6. **K8s lateral movement**: If K8s environment, run Query 23 for secret enumeration and privileged pod deployment
7. **Cloud credential theft**: Run Query 27 for IMDS metadata access
8. **Timeline correlation**: Run Query 14 to trace pip install → network activity chain
9. **Lateral movement risk**: Check if stolen credentials were used elsewhere (pivot to user-investigation or authentication-tracing skills)
10. **Trivy exposure**: Run Query 31 to check if any devices have compromised Trivy versions (v0.69.4–v0.69.6) installed — same TeamPCP payload as LiteLLM

### Evidence Preservation

- Export `DeviceProcessEvents` for affected device/timeframe
- Capture DNS logs around the compromise window
- Preserve network connection logs showing C2 communication to `models.litellm[.]cloud`, `checkmarx[.]zone`, `scan.aquasecurtiy[.]org`, `plug-tab-protective-relay.trycloudflare.com`, and `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io`
- Check for persistence artifacts: `~/.config/sysmon/` directory, systemd user services
- If K8s: enumerate `node-setup-*` pods in `kube-system` namespace
- Document all rotated credentials and rotation timestamps

---

## Mitigations & Guidance

### 1. MCP Architecture: Vendor-Hosted vs Self-Built

The litellm attack directly illustrates the risk of self-hosted MCP servers with transitive Python dependencies. Cursor and Claude Code users running MCP servers via `uvx` with unpinned litellm deps auto-downloaded the compromised version — the MCP server itself became the attack vector.

| Risk | Self-Built MCP | Vendor-Hosted MCP |
|------|---------------|-------------------|
| PyPI supply chain | 🔴 Full exposure — you own the dependency tree | ✅ Not applicable — no user-managed Python |
| Dependency management | 🔴 Your team patches, pins, audits | ✅ Vendor owns patching and SBOMs |
| .pth startup hooks | 🔴 Python runtime risk on every install | ✅ No local Python interpreter needed |
| Credential exposure | 🔴 API keys, secrets in `.env` files and env vars — prime exfil targets | 🟢 OAuth / Entra ID auth — no stored credentials on disk |
| Patching cadence | 🟠 Depends on your CI/CD | ✅ Vendor SLA |
| Incident response | 🔴 Your team scopes and remediates | 🟢 Shared responsibility with vendor |
| Customizability | 🟢 Fully customizable | 🟡 Limited to vendor's API surface |

**Key point:** Microsoft-hosted MCP servers (Sentinel, Graph, Azure, KQL Search, Learn) have zero user-managed Python dependencies. You consume a service endpoint — Microsoft owns the supply chain. For most security tooling use cases, this eliminates an entire threat class without meaningful functionality loss.

**Authentication model:** Microsoft-hosted MCP servers authenticate via OAuth / Entra ID — there are no API keys, secrets, or tokens stored on disk. Compare this to self-built MCP servers that typically require stored credentials (API keys in `.env` files, service account JSON files, connection strings in environment variables) — exactly the artifacts this malware was designed to harvest. With OAuth, there is nothing for a credential stealer to exfiltrate from the local filesystem.

### 2. Dependency Pinning and Lock Files

88% of the 2,337 packages that depend on litellm had version specs that accepted the malicious release. CI/CD pipelines pulling `latest` got compromised within minutes.

**Mitigations:**
- **Pin exact versions**: `litellm==1.82.6` not `litellm>=1.80`
- **Use lock files** (`pip-compile`, `poetry.lock`, `uv.lock`) that capture the full dependency graph with hashes
- **Verify hashes**: `pip install --require-hashes -r requirements.txt`
- **Private PyPI mirrors** with approval gates (Azure Artifacts, Artifactory) — the 46-minute window between upload and quarantine is enough to poison a cache
- **Artifact signing**: PyPI now supports Sigstore attestations — verify them in pipelines

### 3. Python Runtime Hardening

The `.pth` file executes code on ANY Python interpreter startup — not just litellm imports. Most organizations don't monitor `site-packages` directories.

**Mitigations:**
- **Audit `.pth` files**: `find / -name "*.pth" -exec grep -l "import" {} \;` — legitimate `.pth` files rarely contain `import` statements
- **Set `PYTHONNOUSERSITE=1`** in production to prevent user site-packages from loading
- **Container isolation**: Run Python workloads in minimal containers (distroless/Alpine) with read-only filesystems — the malware writes to `~/.config/sysmon/` which fails on read-only
- **Monitor Python process counts**: The .pth fork bomb bug created hundreds of processes per minute (Query 24 detects this)

### 4. Credential Hygiene (Blast Radius Reduction)

Even if the malware executes, limit what it can steal:

| Mitigation | What It Prevents |
|------------|-----------------|
| **Managed identities** instead of stored credentials | Env var harvesting finds nothing — no `AWS_SECRET_ACCESS_KEY` on disk |
| **Workload Identity Federation** (Azure/AWS/GCP) | No long-lived tokens on disk to exfiltrate |
| **Secret managers** (Key Vault, AWS Secrets Manager) | Secrets fetched at runtime, never written to `.env` files |
| **Short-lived tokens** (< 1 hour) | Stolen tokens expire before attacker can use them |
| **K8s bound service account tokens** | Default tokens are cluster-wide — bound tokens scope to namespace/audience |
| **SSH certificate-based auth** | No `id_rsa` private key to steal — certs expire automatically |
| **Git Credential Manager** over `.git-credentials` | No plaintext credentials on disk |
| **Docker credential helpers** over `~/.docker/config.json` | No plaintext registry tokens |

**Principle:** *Assume the workstation will eventually be compromised. When the malware runs `cat ~/.aws/credentials`, does it find anything?*

### 5. CI/CD Pipeline Hardening

46,996 downloads in 46 minutes — most were automated pipelines, not humans.

- **Never `pip install` without a lock file** in production builds (Query 15 hunts for this)
- **Use `--no-deps`** when you control the dependency tree and install deps from your lock file
- **Separate build and runtime environments** — build containers should never have access to production secrets, K8s tokens, or cloud credentials
- **Network segmentation** — build environments should have restricted egress (allow PyPI/npm registries, deny everything else)
- **Ephemeral build agents** — destroy after each build, preventing persistence mechanisms from surviving

### 6. Detection Requirements

What to have in place BEFORE the next supply chain attack:

| Capability | Purpose | Coverage |
|------------|---------|----------|
| **MDE on developer workstations** | Process, file, network telemetry | Queries 1–29 in this pack |
| **DNS logging** (ASIM-normalized) | C2 domain resolution detection | Queries 6, 7, 8, 18, 19 |
| **Process command line auditing** | `pip install`, `uvx`, `kubectl` with full arguments | Queries 1, 2, 15, 23, 25 |
| **File integrity monitoring on `site-packages/`** | `.pth` file creation alerts | Queries 3, 4 |
| **Network monitoring for Python outbound** | Unusual POST destinations | Queries 5, 9, 20, 27 |
| **Container/K8s audit logging** | Privileged pod creation, secret enumeration | Query 23 |

### 7. The "46-Minute Window" Problem

The malicious version was live for 46 minutes before PyPI quarantined it. 46,996 downloads occurred. No scanner, advisory, or security tool caught it in time.

**Implications:**
- **Reactive security** (CVE scanning, advisory monitoring) is insufficient for supply chain attacks — the advisory comes *after* the damage
- **Proactive controls** (pinning, lock files, private mirrors, managed identities) are the only reliable preventive defense
- **Detection in depth** (this query pack) provides the forensic capability to scope impact after the fact
- **Vendor-hosted services** remove this entire attack class from your threat model for that component
