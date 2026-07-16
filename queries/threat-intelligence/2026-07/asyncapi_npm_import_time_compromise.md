# AsyncAPI npm Supply Chain Compromise — Import-Time Payload (Miasma) — Threat Hunts

**Created:** 2026-07-16  
**Platform:** Microsoft Defender XDR  
**Tables:** DeviceFileEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents  
**Keywords:** AsyncAPI, asyncapi/specs, asyncapi/generator, npm, supply chain, import-time execution, require-time, module load, ignore-scripts bypass, Miasma, M-RED-TEAM, miasma-monitor, sync.js, NodeJS masquerade directory, IPFS, IPFS CID, ipfs.io, detached node process, windowsHide, GitHub Actions, pull_request_target, pwn request, OIDC trusted publishing, npm-oidc-no-reply, provenance, credential harvesting, HKCU Run key, systemd user unit, second-stage payload, C2, decentralized fallback, Nostr, libp2p, BitTorrent DHT  
**MITRE:** T1195.002, T1059.007, T1027, T1140, T1105, T1036.005, T1547.001, T1543.002, T1546.004, T1071.001, T1573, T1552.001, T1552.005, T1074  
**Domains:** endpoint  
**Timeframe:** Last 30 days (configurable)  
**Source:** [Unpacking the AsyncAPI npm supply chain compromise and import-time payload delivery (2026-07-15)](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/)

---

## Threat Overview

On July 14, 2026, Microsoft Threat Intelligence identified a coordinated supply chain compromise of the **@asyncapi** npm organization. Five package versions across four package names (`@asyncapi/specs` 6.11.2-alpha.1 and 6.11.2, `@asyncapi/generator@3.3.1`, `@asyncapi/generator-components@0.7.1`, `@asyncapi/generator-helpers@1.1.1`) were republished within ~90 minutes, each carrying the same injected loader. The compromise originated from a GitHub Actions **pwn request** (`pull_request_target` in a docs-preview workflow) that exposed the `asyncapi-bot` PAT and allowed unauthorized pushes, which the project's legitimate **OIDC trusted-publishing** release workflows then distributed — producing poisoned packages with *valid* provenance attestations under the automated identity `npm-oidc-no-reply@github.com`.

Unlike the common `postinstall`-hook pattern, this campaign executes at **module-load (import/require) time**, so `npm install --ignore-scripts` does **not** neutralize it. On import, the injected loader spawns a hidden, detached `node` child that fetches a second stage (`sync.js`) from **IPFS** and writes it to an OS-specific "NodeJS" masquerade directory. `sync.js` (~8.2 MB) decrypts through three static-key crypto layers into the **Miasma** modular runtime (M-RED-TEAM v6.4, campaign `miasma-train-p1`) with active C2 (`85.137.53.71` ports 8080/8081/8091), platform persistence (Windows HKCU Run value `miasma-monitor`, Linux `miasma-monitor.service`, macOS shell-RC injection), and decentralized fallback channels (Nostr, Ethereum, BitTorrent DHT, libp2p, IPFS). Credential-harvesting, propagation, AI-poisoning, metamorphic, and evasion modules are implemented but disabled in the analyzed build.

### TTP Summary
| Capability | TTP |
|---|---|
| Poisoned npm packages distributed via trusted OIDC publishing | Supply Chain Compromise: Compromise Software Dependencies (T1195.002) |
| Injected loader runs at import/require time (no lifecycle hook) | JavaScript execution (T1059.007) |
| Heavily obfuscated loader; layered static-key decryption + `eval()` | Obfuscated Files/Info (T1027), Deobfuscate/Decode (T1140) |
| Hidden detached `node` child fetches second stage from IPFS | Ingress Tool Transfer (T1105) |
| `sync.js` written to OS-specific "NodeJS" masquerade directory | Masquerading: Match Legitimate Name/Location (T1036.005) |
| Windows HKCU Run value `miasma-monitor` persistence | Boot/Logon Autostart: Registry Run Keys (T1547.001) |
| Linux `miasma-monitor.service` systemd user unit | Create/Modify System Process: systemd Service (T1543.002) |
| macOS shell-RC injection (`.zshrc`/`.bashrc`/`.bash_profile`) | Event Triggered Execution: Unix Shell Config Mod (T1546.004) |
| Miasma C2 over IP:port + encrypted channels + P2P fallback | App-layer C2 (T1071.001), Encrypted Channel (T1573) |
| Credential harvest of env vars / secret files (disabled in build) | Credentials in Files (T1552.001), Cloud Instance Metadata / creds (T1552.005) |
| Staged local drop of encrypted second-stage bundle | Data Staged: Local Data Staging (T1074.001) |

### ⚠️ Hunt Pitfalls
| Pitfall | Mitigation |
|---|---|
| `node`/`node.exe` and dependency resolution are ubiquitous on developer & CI hosts | Anchor on campaign artifacts (`sync.js` under a `NodeJS` dir, the IPFS CID, `.miasma`, `miasma-monitor`) or pair a behavioral hit with a network/persistence hit; treat generic node activity alone as low-signal |
| `--ignore-scripts` gives false assurance | This payload triggers on **import**, not install — do not treat an install-time scanner or `--ignore-scripts` as coverage; hunt import-time execution and the dropped artifacts |
| Published IOCs (hashes, C2 IP, IPFS CID) rot after disclosure | Treat direct-match sweeps as point-in-time; refresh from current Microsoft TI / VirusTotal and re-run in Sentinel Data Lake (>30d) for retrospective coverage beyond the 30-day AH window |
| Bare `ipfs.io` traffic is legitimate (docs/gateways) | Anchor the network hunt on the **specific IPFS CID**; a bare `ipfs.io` filter alone produces benign hits (documentation/gateway browsing) and should be a hunting signal only, not an alert |
| Obfuscator `_0x` variable prefixes are generic | The exact loader variable name is sample-specific and obfuscators reuse `_0x`; combine `node -e` obfuscated-loader hunting with the masquerade dir / IPFS CID rather than alerting on `_0x` alone |
| Second-stage `sync.js` SHA rotates as the actor rebuilds | Pair the hash sweep with the behavioral drop (filename `sync.js` in a `NodeJS` masquerade path) so detection survives payload rebuilds |
| `node.lock` is a generic filename | Scope the runtime-artifact hunt to the `.miasma` path, not `node.lock` alone |

---

## Quick Reference — Query Index

| # | Query | Use Case | Key Table |
|---|-------|----------|-----------|
| 1 | [Poisoned @asyncapi tarball / injected-file / sync.js hash sweep](#query-1-poisoned-asyncapi-tarball--injected-file--syncjs-hash-sweep) | Investigation | `DeviceFileEvents` |
| 2 | [Poisoned @asyncapi package version present in npm/Yarn caches](#query-2-poisoned-asyncapi-package-version-present-in-npmyarn-caches) | Investigation | `DeviceFileEvents` |
| 3 | [sync.js dropped under a "NodeJS" masquerade directory](#query-3-syncjs-dropped-under-a-nodejs-masquerade-directory) | Investigation | `DeviceFileEvents` |
| 4 | [IPFS second-stage retrieval (specific CID)](#query-4-ipfs-second-stage-retrieval-specific-cid) | Investigation | `DeviceNetworkEvents` |
| 5 | [Miasma C2 — 85.137.53.71 on ports 8080/8081/8091](#query-5-miasma-c2--851375371-on-ports-808080818091) | Investigation | `DeviceNetworkEvents` |
| 6 | [Detached node child spawned from a NodeJS masquerade directory](#query-6-detached-node-child-spawned-from-a-nodejs-masquerade-directory) | Investigation | `DeviceProcessEvents` |
| 7 | [Obfuscated `node -e` import-time loader (hunt heuristic)](#query-7-obfuscated-node--e-import-time-loader-hunt-heuristic) | Investigation | `DeviceProcessEvents` |
| 8 | [Windows HKCU Run-key persistence (`miasma-monitor`)](#query-8-windows-hkcu-run-key-persistence-miasma-monitor) | Investigation | `DeviceRegistryEvents` |
| 9 | [Miasma runtime / cross-platform persistence artifacts on disk](#query-9-miasma-runtime--cross-platform-persistence-artifacts-on-disk) | Investigation | `DeviceFileEvents` |


## IOC Reference

> All indicators below are transcribed verbatim from the article's *Indicators of compromise* section. **IOCs rot** — operators rotate infrastructure and rebuild payloads after disclosure. Refresh from current Microsoft TI before relying on direct-match hunts, and run IOC sweeps in Sentinel Data Lake (>30d) for retrospective coverage beyond the 30-day Advanced Hunting window.

**Poisoned package tarballs (SHA-256)**

| Package | Version | Injected file | Tarball SHA-256 |
|---|---|---|---|
| `@asyncapi/specs` | 6.11.2-alpha.1 | `index.js` | `d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7` |
| `@asyncapi/specs` | 6.11.2 | `index.js` | `9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b` |
| `@asyncapi/generator` | 3.3.1 | `lib/templates/config/validator.js` | `bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4` |
| `@asyncapi/generator-components` | 0.7.1 | `lib/utils/ErrorHandling.js` | `082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab` |
| `@asyncapi/generator-helpers` | 1.1.1 | `src/utils.js` | `34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1` |

**Injected-file / second-stage SHA-256**

| Indicator | Description |
|---|---|
| `b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a` | `@asyncapi/generator` `lib/templates/config/validator.js` (injected) |
| `b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292` | `@asyncapi/generator-components` `lib/utils/ErrorHandling.js` (injected) |
| `8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c` | `@asyncapi/specs` `index.js` (alpha AND stable — identical) |
| `6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71` | `@asyncapi/generator-helpers` `src/utils.js` (injected) |
| `24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168` | Wrapper `sync.js` (generator-family IPFS object) |

**Network / delivery indicators**

| Indicator | Type | Description |
|---|---|---|
| `85.137.53.71:8080` | IP:port | Central C2 |
| `85.137.53.71:8081` | IP:port | Upload service |
| `85.137.53.71:8091` | IP:port | Management configuration |
| `Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | IPFS CID | `specs` second-stage object |
| `QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9` | IPFS CID | `generator-family` second-stage object (narrative; not in IOC table) |
| `hxxps://ipfs[.]io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf` | IPFS URL | Second-stage retrieval |
| `npm-oidc-no-reply@github.com` | Publisher identity | OIDC trusted-publishing actor used for poisoned releases |
| `rentry.co/elzotebo999` | URL | First-stage MDX retrieval in the pwn-request PR (narrative; not in IOC table) |
| `/api/v1/beacon`, `/api/v1/file-result`, `/api/v1/file-content/<cid>` | HTTP paths | Miasma C2 request paths |
| `_miasma._tcp` | mDNS service | Local discovery |

**Host / persistence artifacts**

| Indicator | Type | Description |
|---|---|---|
| `%LOCALAPPDATA%\NodeJS\sync.js` | File path | Windows second-stage drop |
| `~/.local/share/NodeJS/sync.js` | File path | Linux second-stage drop |
| `~/Library/Application Support/NodeJS/sync.js` | File path | macOS second-stage drop |
| `~/.config/NodeJS/sync.js` | File path | Fallback drop |
| `~/.config/.miasma/run/node.lock` | File path | Runtime lock file |
| `miasma-monitor` | Registry value (HKCU Run) | Windows persistence value name |
| `miasma-monitor.service` | systemd user unit | Linux persistence |
| `M-RED-TEAM v6.4` / `miasma-train-p1` / `miasma-test-org` | Runtime identifiers | Recovered from `sync.js` |

---

## Query 1: Poisoned @asyncapi tarball / injected-file / sync.js hash sweep

**Purpose:** Direct SHA-256 sweep for the five poisoned tarballs, the four injected source files, and the `sync.js` wrapper across endpoint file telemetry (incl. npm/Yarn caches). A clean estate returns 0; any hit identifies a host that pulled or stored a compromised artifact.  
**Severity:** High  
**MITRE:** T1195.002, T1105
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "AsyncAPI-compromise file hash observed on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A published AsyncAPI-compromise artifact (poisoned tarball, injected source file, or sync.js) was written on this host. Identify the initiating process and folder (npm/Yarn cache vs. runtime drop), purge npm/Yarn caches, remove the affected versions, hunt for the detached node spawn (Query 6) and IPFS retrieval (Query 4), and rotate credentials accessible from the host. IOCs rot — confirm against current Microsoft TI."
adaptation_notes: "Row-level hash match; already CD-shaped. sync.js SHA rotates as the actor rebuilds — pair with Query 3 (behavioral drop) for durable coverage."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in (
    "d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7",
    "9b2e65db653ca8575c9b10eefb9a80c6006404812c2ec212bf5675e3c690233b",
    "bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4",
    "082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab",
    "34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1",
    "b9993a8ad0518849416798cf29668256ccb96598fc4423501ccab5312812653a",
    "b270bdf8e2274ea1af0a6eed74d8f10e5fe61012d6cc226a43cc7cc7fd9f6292",
    "8351d251cf0b5a0bd82242deaa0a14e3e1394418d55c0f4259dac4303b79fc0c",
    "6e78713b75bd34828d49896176627f7face7aa9036cd874f2e02d9f23a9a9c71",
    "24b9ee242f21a73b55f7bb3297eafb33c60840907386b542ed79fc6b72365168")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment (post-disclosure hashes). Any match warrants immediate triage.

---

## Query 2: Poisoned @asyncapi package version present in npm/Yarn caches

**Purpose:** Hash-independent fallback that finds the specific compromised package/version tarball filenames in dependency caches — useful when the actor rebuilds `sync.js` (rotating hashes) but the pinned poisoned *versions* remain the exposure. A clean, up-to-date estate returns 0.  
**Severity:** High  
**MITRE:** T1195.002
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "InitialAccess"
title: "Poisoned @asyncapi package version in cache on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A pinned poisoned @asyncapi version tarball was observed in an npm/Yarn cache. Purge npm/Yarn caches, rebuild from a known-good baseline (specs 6.11.1, generator 3.3.0, generator-components 0.7.0, generator-helpers 1.1.0), and review dependency trees/lockfiles for transitive references."
adaptation_notes: "Version-pinned filename match; low FP. Broaden or narrow the cache-path anchors to match local package-manager layout. Retire once fixed versions are fully rolled out."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("asyncapi", ".npm", "yarn", "node_modules")
| where FileName has_any (
    "specs-6.11.2.tgz", "specs-6.11.2-alpha.1.tgz",
    "generator-3.3.1.tgz", "generator-components-0.7.1.tgz", "generator-helpers-1.1.1.tgz")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
    InitiatingProcessFileName, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 expected once fixed versions are pinned. A hit means a build/dev host still resolved a compromised version.

---

## Query 3: sync.js dropped under a "NodeJS" masquerade directory

**Purpose:** Behavioral detection of the second-stage drop — a file named `sync.js` written into an OS-specific `NodeJS` masquerade directory (`%LOCALAPPDATA%\NodeJS`, `~/.local/share/NodeJS`, `~/Library/Application Support/NodeJS`, `~/.config/NodeJS`). Survives payload rebuilds because it keys on filename + location, not hash.  
**Severity:** High  
**MITRE:** T1036.005, T1105, T1074.001
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "sync.js written to NodeJS masquerade directory on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A file named sync.js was written into a NodeJS masquerade directory consistent with the AsyncAPI/Miasma second stage. Isolate the host, capture the file, hunt for the detached node spawn (Query 6), IPFS retrieval (Query 4), C2 (Query 5), and persistence (Query 8/9), and rotate credentials from the host."
adaptation_notes: "Filename+path behavioral anchor; hash-independent. Legitimate software rarely writes sync.js into these exact user-profile NodeJS paths, so FP rate is low; confirm no in-house tool uses this layout before promoting."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "sync.js"
| where FolderPath contains_cs "NodeJS"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. A hit is a high-confidence second-stage-drop indicator.

---

## Query 4: IPFS second-stage retrieval (specific CID)

**Purpose:** Outbound retrieval of the second stage from IPFS keyed on the **specific published CID**. Anchoring on the CID (not bare `ipfs.io`) keeps this high-fidelity; the article's bare-gateway pattern is retained only as a hunting signal.  
**Severity:** High  
**MITRE:** T1105, T1071.001
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "IPFS retrieval of AsyncAPI second-stage CID from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Device retrieved the published AsyncAPI second-stage IPFS CID. Isolate, identify the initiating process (expect a detached node child), and hunt for the sync.js drop (Query 3), C2 (Query 5), and persistence (Query 8/9). Consider blocking public IPFS gateways at the perimeter if IPFS is not required for business."
adaptation_notes: "CID-specific match is high fidelity and CD-ready. Do NOT promote a bare ipfs.io filter — benign public IPFS gateway/documentation browsing generates FPs; keep that as a hunt-only signal."
-->

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf"
    or RemoteUrl has "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 expected. A hit is a high-confidence second-stage fetch. (A broader `RemoteUrl has "ipfs.io"` sweep is useful for hunting but is noisy — treat bare-gateway hits as leads, not alerts.)

---

## Query 5: Miasma C2 — 85.137.53.71 on ports 8080/8081/8091

**Purpose:** Direct network IOC sweep for the Miasma C2/upload/management endpoints. Mirrors the article's remediation guidance to block these ports.  
**Severity:** High  
**MITRE:** T1071.001, T1573
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "CommandAndControl"
title: "Connection to Miasma C2 (85.137.53.71) from {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Device contacted the published Miasma C2 infrastructure. Isolate, identify the initiating process, hunt the full chain (Queries 1/3/4/6/8/9), and rotate credentials accessible from the host. IOCs rot — confirm against current Microsoft TI and block 85.137.53.71:8080/8081/8091 at the perimeter."
adaptation_notes: "Row-level IP:port match; CD-ready. Refresh the IP as infrastructure rotates. Ports are informative but the IP alone is sufficient to alert."
-->

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "85.137.53.71"
| where RemotePort in (8080, 8081, 8091)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 expected (post-disclosure infrastructure). A hit is a high-confidence compromise indicator.

---

## Query 6: Detached node child spawned from a NodeJS masquerade directory

**Purpose:** Behavioral detection of Stage 1 — a `node` process (child of `node`) referencing `sync.js`, the IPFS CID, a `NodeJS` masquerade path, or `.miasma`. Catches the hidden detached child (`spawn('node', ..., {detached:true, windowsHide:true})`) even when hashes rotate.  
**Severity:** High  
**MITRE:** T1059.007, T1105, T1036.005
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Execution"
title: "Detached node child referencing AsyncAPI/Miasma artifact on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A node process referenced a campaign artifact (sync.js in a NodeJS dir, the IPFS CID, or .miasma). Isolate the host, capture the sync.js file, and hunt for the IPFS retrieval (Query 4), C2 (Query 5), and persistence (Query 8/9)."
adaptation_notes: "Artifact-anchored process hunt; low FP because it requires the campaign strings, not generic node activity. Add the masquerade-path condition if node-spawns-node is common in local CI."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node", "node.exe") or InitiatingProcessFileName in~ ("node", "node.exe")
| where ProcessCommandLine has_any (
    "sync.js",
    "Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf",
    "QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9",
    ".miasma", "miasma-monitor")
    or (ProcessCommandLine has_cs "NodeJS" and ProcessCommandLine has "sync.js")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. Any match warrants immediate triage.

---

## Query 7: Obfuscated `node -e` import-time loader (hunt heuristic)

**Purpose:** Hunting heuristic for an inline `node -e` invocation carrying an obfuscated loader (article observed `node -e "const _0x..."`). Obfuscator `_0x` prefixes are generic, so this is a **hunt-only** heuristic to be corroborated, not a standalone alert.  
**Severity:** Medium  
**MITRE:** T1059.007, T1027
<!-- cd-metadata
cd_ready: false
schedule: "1H"
category: "Execution"
title: "Obfuscated inline node -e loader on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "Review the inline node -e command line for an obfuscated loader and correlate with the campaign chain (Queries 3/4/5/6). Confirm whether the host resolved a poisoned @asyncapi version."
adaptation_notes: "NOT CD-ready. The `_0x` obfuscator prefix is generic (minified/obfuscated tooling reuses it) and the exact variable name is sample-specific — expect FPs. Promote only after pairing with a masquerade-dir, IPFS-CID, or C2 hit, or narrowing to the confirmed loader signature. Hunt-only."
-->

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node", "node.exe")
| where ProcessCommandLine has "-e"
| where ProcessCommandLine has_cs "const _0x"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessFolderPath, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in this environment during testing. In estates with heavy obfuscated-JS tooling this can be noisy — corroborate every hit with another query in this campaign before escalating.

---

## Query 8: Windows HKCU Run-key persistence (`miasma-monitor`)

**Purpose:** Detects the Miasma Windows persistence — an HKCU `...\CurrentVersion\Run` value named `miasma-monitor`, or a Run value whose data references `sync.js`/`NodeJS`. High fidelity on the named value.  
**Severity:** High  
**MITRE:** T1547.001
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Miasma Run-key persistence (miasma-monitor) on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A Run-key persistence value consistent with Miasma was set. Isolate the host, remove the persistence, capture sync.js and the NodeJS masquerade directory, and hunt the full chain (Queries 1/3/4/5/6/9). Rotate credentials accessible from the host."
adaptation_notes: "Named value `miasma-monitor` is high fidelity and CD-ready. The sync.js/NodeJS data-based branch is broader; keep it but expect it to be the tunable part if a local tool legitimately references a NodeJS path in a Run value."
-->

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueName =~ "miasma-monitor"
    or RegistryValueData has_cs "sync.js"
    or RegistryValueData has_cs "NodeJS"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. A hit on the named value is a high-confidence persistence indicator.

---

## Query 9: Miasma runtime / cross-platform persistence artifacts on disk

**Purpose:** Sweeps for Miasma runtime and persistence artifacts on disk — the `.miasma` runtime path / lock file, the Linux `miasma-monitor.service` unit, and `sync.js` in an OS-specific NodeJS masquerade path. Complements the Windows Run-key hunt with Linux/macOS coverage.  
**Severity:** High  
**MITRE:** T1543.002, T1036.005, T1074.001
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Miasma runtime/persistence artifact on disk on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: deviceName
recommendedActions: "A Miasma runtime/persistence artifact was written (.miasma runtime path, miasma-monitor.service, or sync.js in a NodeJS masquerade dir). Isolate the host, remove persistence, capture artifacts, and hunt the full chain (Queries 1/3/4/5/6/8). Rotate credentials from the host."
adaptation_notes: "Scoped to the `.miasma` path and the named systemd unit for fidelity — `node.lock` alone is generic and deliberately excluded as a standalone anchor. CD-ready."
-->

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_cs ".miasma"
    or FileName =~ "miasma-monitor.service"
    or (FileName =~ "sync.js" and (
        FolderPath has ".local/share/NodeJS"
        or FolderPath has "Application Support/NodeJS"
        or FolderPath has ".config/NodeJS"
        or FolderPath contains_cs @"\NodeJS\"))
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceId, ReportId
| sort by Timestamp desc
```

**Expected results:** 0 in an unaffected environment. A hit indicates Miasma runtime staging or cross-platform persistence.

---

## General Tuning Notes

1. **IOC refresh.** The tarball/injected-file/`sync.js` hashes (Queries 1/3), the IPFS CIDs (Queries 4/6), and the C2 IP (Query 5) are point-in-time. Operators rotate infrastructure and rebuild payloads after disclosure — refresh from current Microsoft TI / VirusTotal and re-run direct-match sweeps in Sentinel Data Lake (>30d) for retrospective coverage beyond the 30-day Advanced Hunting window.
2. **Prefer behavioral over hash where possible.** Queries 3 (sync.js in NodeJS dir), 6 (detached node child), 8 (`miasma-monitor` Run value), and 9 (`.miasma` artifacts) key on filenames, paths, and named artifacts rather than hashes, so they survive payload rebuilds. Pair a behavioral hit with a hash/network hit to raise confidence.
3. **`--ignore-scripts` is not coverage.** This campaign executes at import/require time, not via a lifecycle hook. Do not treat install-time scanners or `--ignore-scripts` as mitigation; hunt the import-time execution and dropped artifacts.
4. **IPFS anchoring.** Anchor the network hunt on the specific IPFS CID (Query 4). A bare `ipfs.io` filter is legitimate-traffic-heavy (documentation/gateway browsing) and should be a hunting lead only — never a standalone alert.
5. **Obfuscated-loader heuristic (Query 7) is hunt-only.** The `_0x` obfuscator prefix is generic; corroborate any hit with a masquerade-dir, IPFS-CID, or C2 hit before escalating. Left `cd_ready: false` deliberately.
6. **Generic filenames.** `node.lock` is generic and deliberately scoped to the `.miasma` path in Query 9. `sync.js` is only meaningful inside a NodeJS masquerade dir — never alert on `sync.js` alone.
7. **CD-readiness summary.** Queries 1, 2, 3, 4, 5, 6, 8, 9 are `cd_ready: true` (high-fidelity IOC or campaign-specific behavioral anchors); Query 7 is `cd_ready: false` (generic obfuscator heuristic, hunt-only). Add `DeviceId`/`ReportId` are already projected for custom-detection entity mapping.
8. **Telemetry gaps.** macOS shell-RC persistence (`.zshrc`/`.bashrc`/`.bash_profile` injection) and the decentralized fallback channels (Nostr, Ethereum, BitTorrent DHT, libp2p) are not reliably captured by the endpoint tables here — treat their absence as a coverage limitation, not an all-clear.

---

## References

- Microsoft Threat Intelligence — [Unpacking the AsyncAPI npm supply chain compromise and import-time payload delivery](https://www.microsoft.com/en-us/security/blog/2026/07/15/unpacking-asyncapi-npm-supply-chain-compromise-import-time-payload-delivery/)
- MITRE ATT&CK — [T1195.002 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/002/)
- MITRE ATT&CK — [T1036.005 Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- MITRE ATT&CK — [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- Companion files: [`queries/threat-intelligence/2026-06/mastra_npm_supply_chain.md`](../2026-06/mastra_npm_supply_chain.md), [`queries/threat-intelligence/2026-05/npm_dependency_confusion.md`](../2026-05/npm_dependency_confusion.md), [`queries/threat-intelligence/2026-03/npm_supply_chain_attack.md`](../2026-03/npm_supply_chain_attack.md)
