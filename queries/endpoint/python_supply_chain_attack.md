# Python Supply Chain Attack Hunting — LiteLLM / PyPI Compromise

**Created:** 2026-03-25  
**Platform:** Both  
**Tables:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, ASimDnsActivityLogs, DeviceEvents, DeviceRegistryEvents  
**Keywords:** litellm, pypi, pip install, supply chain, credential stealer, python package, site-packages, .pth file, secret exfiltration, environment variable harvesting, cloud credential theft, models.litellm.cloud, trivy, CI/CD compromise  
**MITRE:** T1195.002, T1059.006, T1027, T1555, T1552.001, T1041, T1071.001, T1547.004, T1082, T1083, T1005  
**Timeframe:** Last 30 days (configurable)

---

## Overview

This hunting campaign targets TTPs from the **LiteLLM PyPI supply chain compromise** disclosed March 24, 2026:  
**[Security Update: Suspected Supply Chain Incident](https://docs.litellm.ai/blog/security-update-march-2026)**

Related upstream compromise: **[Trivy Supply Chain Attack](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)**

### Threat Summary

| Aspect | Detail |
|--------|--------|
| **Affected Packages** | `litellm==1.82.7`, `litellm==1.82.8` (removed from PyPI) |
| **Compromise Window** | March 24, 2026, 10:39–16:00 UTC |
| **Attack Vector** | Compromised maintainer PyPI account (via Trivy CI/CD compromise) |
| **Payload** | Credential stealer in `proxy_server.py` + `litellm_init.pth` (v1.82.8) |
| **C2 Domain** | `models.litellm[.]cloud` (NOT a legitimate BerriAI domain) |
| **Exfil Method** | POST request with encrypted stolen data |
| **Targets** | Environment variables, SSH keys, AWS/GCP/Azure credentials, K8s tokens, DB passwords |

### MITRE ATT&CK Coverage

| Technique | ID | Relevance |
|-----------|----|-----------|
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Malicious PyPI package upload |
| Command and Scripting Interpreter: Python | T1059.006 | Python payload execution via pip install |
| Obfuscated Files or Information | T1027 | Encrypted exfiltration payload |
| Credentials from Password Stores | T1555 | Credential harvesting from config files |
| Unsecured Credentials: Credentials In Files | T1552.001 | SSH keys, cloud credential files, .env files |
| Exfiltration Over C2 Channel | T1041 | POST to models.litellm[.]cloud |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS C2 communication |
| Boot or Logon Autostart Execution: .pth Startup | T1547.004 | `litellm_init.pth` runs Python code at interpreter startup |
| System Information Discovery | T1082 | Environment variable enumeration |
| File and Directory Discovery | T1083 | Scanning for credential files (SSH, cloud configs) |
| Data from Local System | T1005 | Collecting secrets from local filesystem |

### IoCs

| Indicator | Type | Notes |
|-----------|------|-------|
| `models.litellm[.]cloud` | Domain | C2 exfiltration endpoint (NOT legitimate BerriAI) |
| `litellm_init.pth` | Filename | Malicious .pth file in site-packages (v1.82.8) |
| `litellm==1.82.7` | Package version | Compromised PyPI release |
| `litellm==1.82.8` | Package version | Compromised PyPI release |

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

## Triage Playbook

If any of the above queries return positive results:

### Immediate Actions (CRITICAL)

1. **Isolate affected device** via MDE device isolation
2. **Identify installed version**: On affected system run `pip show litellm` — if version is 1.82.7 or 1.82.8, treat as confirmed compromise
3. **Check for .pth file**: Search for `litellm_init.pth` in Python site-packages directories
4. **Rotate ALL secrets** accessible from that device: API keys, SSH keys, cloud credentials, K8s tokens, DB passwords, environment variables

### Investigation Steps

1. **Scope impact**: Run Query 2 to find all pip activity on the affected device
2. **Check C2 traffic**: Run Queries 5 + 6 to confirm exfiltration attempts
3. **Credential file access**: Run Query 11 to check what secrets were accessed
4. **Timeline correlation**: Run Query 14 to trace pip install → network activity chain
5. **Lateral movement risk**: Check if stolen credentials were used elsewhere (pivot to user-investigation or authentication-tracing skills)

### Evidence Preservation

- Export `DeviceProcessEvents` for affected device/timeframe
- Capture DNS logs around the compromise window
- Preserve network connection logs showing C2 communication
- Document all rotated credentials and rotation timestamps
