# Network Anomaly Detection Using series_decompose_anomalies()

**Created:** 2026-01-15  
**Platform:** Microsoft Sentinel  
**Tables:** DeviceNetworkEvents  
**Keywords:** anomaly detection, series_decompose_anomalies, time series, baseline deviation, rare IP, honeypot, reconnaissance, scanning, botnet  
**MITRE:** T1046, T1595, TA0043  
**Timeframe:** Last 7 days (configurable)

---

## Overview

This collection contains production-ready KQL queries using the `series_decompose_anomalies()` function to detect anomalous network connection patterns. The function decomposes time series data into seasonal, trend, and residual components, then identifies outliers using Tukey's fence test.

**Key Concepts:**
- **Baseline Period:** Historical data used to establish "normal" patterns
- **Anomaly Score:** Deviation from expected behavior (higher = more anomalous)
- **Threshold:** Controls sensitivity (1.5 = mild anomalies, 3.0 = strong anomalies)
- **Seasonality:** Automatic detection of recurring patterns (-1 = auto-detect)

**When to Use:**
- Detecting rare or first-time external IP connections
- Honeypot attack analysis (identifying coordinated botnets)
- Finding reconnaissance scanning activity
- Baseline deviation detection for security monitoring

---

## Query 1: Least Common External IPs (7-Day Analysis)

**Purpose:** Identify external IP addresses with anomalously low connection counts - potential reconnaissance scans, first-time attackers, or novel threat actors.

**Why 7 Days?**
- 24-hour window catches CDN rotation noise (legitimate services rotating IPs)
- 7-day window reveals true anomalies vs. normal rotation patterns
- Captures longer-term attack campaigns and intermittent threats

**Parameters:**
- **Timeframe:** 1-hour bins for connection counting
- **Lookback:** 7 days (168 hours)
- **Threshold:** 1.5 (recommended - balances sensitivity vs. noise)
- **Seasonality:** Auto-detect (-1)
- **Trend:** Average ('avg')

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Time-series anomaly detection using series_decompose_anomalies() with make-series. Produces statistical baselines, not row-level events. CD requires event-driven queries."
-->
```kql
// Query 1: Least Common External IPs Using Anomaly Detection (7 days)
// Detects rare/first-time IPs that may indicate reconnaissance or attacks
let Timeframe = 1h;
let Lookback = 7d;
let AnomalyThreshold = 1.5;
DeviceNetworkEvents
| where TimeGenerated > ago(Lookback)
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by RemoteIP, bin(TimeGenerated, Timeframe)
| make-series ConnectionSeries = sum(ConnectionCount) default=0 
    on TimeGenerated 
    from ago(Lookback) to now() step Timeframe 
    by RemoteIP
| extend (AnomalyFlags, AnomalyScore, ExpectedValue) = series_decompose_anomalies(ConnectionSeries, AnomalyThreshold, -1, 'avg')
| mv-expand 
    TimeGenerated to typeof(datetime), 
    ConnectionSeries to typeof(long), 
    AnomalyFlags to typeof(int), 
    AnomalyScore to typeof(double), 
    ExpectedValue to typeof(double)
| where AnomalyFlags != 0  // Only anomalies
| summarize 
    TotalConnections = sum(ConnectionSeries),
    MaxAnomalyScore = max(AnomalyScore),
    MinAnomalyScore = min(AnomalyScore),
    AnomalousHours = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP
| order by TotalConnections asc, MaxAnomalyScore desc
| take 50
```

**Expected Results:**
- **RemoteIP:** External IP address flagged as anomalous
- **TotalConnections:** Total connections over 7 days (lower = more suspicious)
- **MaxAnomalyScore:** Peak deviation from expected (higher = more anomalous)
- **AnomalousHours:** Number of hours this IP triggered anomaly detection
- **FirstSeen / LastSeen:** Time window of activity

**Interpreting Anomaly Scores:**
- **0-2:** Mild deviation, possibly legitimate but uncommon
- **2-5:** Moderate anomaly, warrants investigation
- **5-10:** Strong anomaly, likely reconnaissance or attack
- **10+:** Extreme anomaly, investigate immediately

**Common False Positives:**
- CDN rotation (Microsoft, Akamai, Fastly IPs appearing "new")
- Azure cloud services (Windows Defender telemetry, Windows Update)
- VPN gateway connections (intermittent corporate VPN usage)

**Filtering Out Known Good Traffic:**
```kql
// Add after initial where clause to reduce noise:
| where RemoteUrl !has "wd.microsoft.com"  // Windows Defender
| where RemoteUrl !has "windowsupdate.com"  // Windows Update
| where RemoteUrl !has "azure.com"  // Azure services
```

---

## Query 2: Device-Specific Anomaly Detection (Honeypot Mode)

**Purpose:** Analyze anomalous network patterns for a specific device - ideal for honeypot analysis or targeted investigation of compromised machines.

**Use Case:**
- Honeypot server attack analysis
- Investigating a specific compromised device
- Baseline comparison for a single endpoint

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Parameter-dependent (let TargetDevice) + time-series anomaly detection with make-series/series_decompose_anomalies(). Investigation query for specific device analysis."
-->
```kql
// Query 2: Device-Specific IP Anomaly Detection
// Replace <DEVICE_NAME> with your target device (case-insensitive)
let TargetDevice = "<DEVICE_NAME>";
let Timeframe = 1h;
let Lookback = 7d;
let AnomalyThreshold = 1.5;
DeviceNetworkEvents
| where TimeGenerated > ago(Lookback)
| where DeviceName =~ TargetDevice
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by RemoteIP, bin(TimeGenerated, Timeframe)
| make-series ConnectionSeries = sum(ConnectionCount) default=0 
    on TimeGenerated 
    from ago(Lookback) to now() step Timeframe 
    by RemoteIP
| extend (AnomalyFlags, AnomalyScore, ExpectedValue) = series_decompose_anomalies(ConnectionSeries, AnomalyThreshold, -1, 'avg')
| mv-expand 
    TimeGenerated to typeof(datetime), 
    ConnectionSeries to typeof(long), 
    AnomalyFlags to typeof(int), 
    AnomalyScore to typeof(double), 
    ExpectedValue to typeof(double)
| where AnomalyFlags != 0
| summarize 
    TotalConnections = sum(ConnectionSeries),
    MaxAnomalyScore = max(AnomalyScore),
    AnomalousHours = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP
| order by TotalConnections asc, MaxAnomalyScore desc
| take 50
```

**Honeypot Analysis Tips:**
- Run on isolated honeypot devices to capture pure attacker traffic
- Compare against production devices to identify attack-specific IPs
- Enrich all detected IPs with threat intelligence (AbuseIPDB, ipinfo.io)
- Low connection count (1-5) with high anomaly score = reconnaissance scan

---

## Query 3: Threshold Sensitivity Analysis

**Purpose:** Test multiple anomaly thresholds simultaneously to understand detection sensitivity in your environment.

**Thresholds Explained:**
- **1.0:** Most sensitive (catches more anomalies, more false positives)
- **1.5:** Recommended default (balanced sensitivity)
- **2.0:** Moderate strictness
- **2.5:** Stricter detection
- **3.0:** Most strict (only strong anomalies, fewer false positives)

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Calibration/tuning tool — tests 5 anomaly thresholds simultaneously on the same dataset. Not a detection query; used to establish optimal threshold for the environment."
-->
```kql
// Query 3: Threshold Sensitivity Comparison
// Tests 5 thresholds simultaneously to help tune detection
let Timeframe = 1h;
let Lookback = 7d;
DeviceNetworkEvents
| where TimeGenerated > ago(Lookback)
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by RemoteIP, bin(TimeGenerated, Timeframe)
| make-series ConnectionSeries = sum(ConnectionCount) default=0 
    on TimeGenerated 
    from ago(Lookback) to now() step Timeframe 
    by RemoteIP
// Apply multiple thresholds
| extend Flags_1_0 = series_decompose_anomalies(ConnectionSeries, 1.0, -1, 'avg')
| extend Flags_1_5 = series_decompose_anomalies(ConnectionSeries, 1.5, -1, 'avg')
| extend Flags_2_0 = series_decompose_anomalies(ConnectionSeries, 2.0, -1, 'avg')
| extend Flags_2_5 = series_decompose_anomalies(ConnectionSeries, 2.5, -1, 'avg')
| extend Flags_3_0 = series_decompose_anomalies(ConnectionSeries, 3.0, -1, 'avg')
// Extract anomaly flags (first element of tuple)
| extend 
    AnomalyFlags_1_0 = Flags_1_0[0],
    AnomalyFlags_1_5 = Flags_1_5[0],
    AnomalyFlags_2_0 = Flags_2_0[0],
    AnomalyFlags_2_5 = Flags_2_5[0],
    AnomalyFlags_3_0 = Flags_3_0[0]
// Count anomalies per threshold
| extend
    Anomalies_1_0 = array_length(set_difference(dynamic_to_json(AnomalyFlags_1_0), dynamic_to_json(dynamic([0])))),
    Anomalies_1_5 = array_length(set_difference(dynamic_to_json(AnomalyFlags_1_5), dynamic_to_json(dynamic([0])))),
    Anomalies_2_0 = array_length(set_difference(dynamic_to_json(AnomalyFlags_2_0), dynamic_to_json(dynamic([0])))),
    Anomalies_2_5 = array_length(set_difference(dynamic_to_json(AnomalyFlags_2_5), dynamic_to_json(dynamic([0])))),
    Anomalies_3_0 = array_length(set_difference(dynamic_to_json(AnomalyFlags_3_0), dynamic_to_json(dynamic([0]))))
| summarize 
    TotalIPs = count(),
    Detected_1_0 = countif(Anomalies_1_0 > 0),
    Detected_1_5 = countif(Anomalies_1_5 > 0),
    Detected_2_0 = countif(Anomalies_2_0 > 0),
    Detected_2_5 = countif(Anomalies_2_5 > 0),
    Detected_3_0 = countif(Anomalies_3_0 > 0)
| extend
    Rate_1_0 = round(100.0 * Detected_1_0 / TotalIPs, 2),
    Rate_1_5 = round(100.0 * Detected_1_5 / TotalIPs, 2),
    Rate_2_0 = round(100.0 * Detected_2_0 / TotalIPs, 2),
    Rate_2_5 = round(100.0 * Detected_2_5 / TotalIPs, 2),
    Rate_3_0 = round(100.0 * Detected_3_0 / TotalIPs, 2)
```

**Expected Results Table:**
| Threshold | Description | Typical Detection Rate |
|-----------|-------------|------------------------|
| 1.0 | Most sensitive | 30-50% of unique IPs |
| 1.5 | Balanced (recommended) | 15-30% of unique IPs |
| 2.0 | Moderate | 5-15% of unique IPs |
| 2.5 | Strict | 2-8% of unique IPs |
| 3.0 | Very strict | 1-5% of unique IPs |

---

## Query 4: Attack Intensity Timeline (15-Minute Bins)

**Purpose:** Visualize attack patterns over time with intensity classifications - ideal for understanding attack campaigns, identifying burst patterns, and correlating with other events.

**Parameters:**
- Requires specific date range (modify `start` and `end` variables)
- Optional device filter for targeted analysis
- 15-minute bins for granular visibility

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Aggregation/visualization query — summarizes connection counts into 15-minute bins with intensity classification. Reporting/timeline tool, not event-driven detection."
-->
```kql
// Query 4: Attack Intensity Timeline Visualization
// Modify start/end dates and optionally uncomment device filter
let start = ago(48h);  // Or: datetime(2026-01-08)
let end = now();       // Or: datetime(2026-01-10)
// let TargetDevice = "<DEVICE_NAME>";  // Uncomment for device-specific
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
// | where DeviceName =~ TargetDevice  // Uncomment for device-specific
| where RemoteIPType == "Public"
| summarize 
    ConnectionCount = count(),
    UniqueIPs = dcount(RemoteIP),
    TopPorts = make_set(RemotePort, 10),
    TopIPs = make_set(RemoteIP, 10)
    by bin(TimeGenerated, 15m)
| extend 
    IntensityLevel = case(
        ConnectionCount >= 1000, "🔴 Extreme",
        ConnectionCount >= 500, "🟠 High",
        ConnectionCount >= 100, "🟡 Medium",
        ConnectionCount >= 10, "🟢 Low",
        "⚪ Minimal"
    )
| project 
    TimeWindow = TimeGenerated,
    Connections = ConnectionCount,
    UniqueAttackers = UniqueIPs,
    IntensityLevel,
    TopPorts,
    SampleIPs = TopIPs
| order by TimeWindow asc
```

**Intensity Level Thresholds:**
- **🔴 Extreme (1000+):** Major attack campaign, DDoS, or coordinated botnet
- **🟠 High (500-999):** Significant scanning activity or targeted attack
- **🟡 Medium (100-499):** Active reconnaissance or distributed scanning
- **🟢 Low (10-99):** Normal background scanning or legitimate traffic spikes
- **⚪ Minimal (1-9):** Baseline traffic, likely legitimate

**Attack Pattern Indicators:**
- Sharp burst followed by sustained low activity = Initial discovery/reconnaissance
- Consistent high volume = Sustained attack campaign
- Multiple bursts = Coordinated waves (common in botnet attacks)
- High unique IP count with low connections each = Distributed scanning botnet

---

## Query 5: Score Distribution Analysis (Percentiles)

**Purpose:** Understand your environment's anomaly score distribution to calibrate thresholds appropriately.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical distribution analysis — computes percentiles of anomaly scores across all IPs. Calibration tool for threshold tuning, not detection."
-->
```kql
// Query 5: Anomaly Score Distribution Analysis
let Timeframe = 1h;
let Lookback = 7d;
let AnomalyThreshold = 1.5;
DeviceNetworkEvents
| where TimeGenerated > ago(Lookback)
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by RemoteIP, bin(TimeGenerated, Timeframe)
| make-series ConnectionSeries = sum(ConnectionCount) default=0 
    on TimeGenerated 
    from ago(Lookback) to now() step Timeframe 
    by RemoteIP
| extend (AnomalyFlags, AnomalyScore, ExpectedValue) = series_decompose_anomalies(ConnectionSeries, AnomalyThreshold, -1, 'avg')
| mv-expand AnomalyScore to typeof(double)
| summarize 
    TotalDataPoints = count(),
    AvgScore = round(avg(AnomalyScore), 2),
    P10 = round(percentile(AnomalyScore, 10), 2),
    P25 = round(percentile(AnomalyScore, 25), 2),
    P50 = round(percentile(AnomalyScore, 50), 2),
    P75 = round(percentile(AnomalyScore, 75), 2),
    P90 = round(percentile(AnomalyScore, 90), 2),
    P95 = round(percentile(AnomalyScore, 95), 2),
    P99 = round(percentile(AnomalyScore, 99), 2),
    MaxScore = round(max(AnomalyScore), 2),
    MinScore = round(min(AnomalyScore), 2)
```

**Interpreting Distribution:**
- **P50 near 0:** Most traffic is predictable (healthy baseline)
- **P90 > 3:** Significant outliers exist (investigate top 10%)
- **P99 > 10:** Extreme anomalies present (likely attacks)
- **Large gap between P95 and Max:** Few extreme outliers (targeted investigation)

**Healthy Production Environment Baseline:**
```
P50: 0.0, P75: 0.0, P90: 0.0, P95: 0.0, P99: 3.5, Max: 140
```
This indicates 99% of traffic is perfectly predictable with rare extreme outliers.

**Honeypot/Attacked Environment:**
```
P50: 7.0, P75: 7.0, P90: 7.0, P95: 7.0, P99: 7.0, Max: 7.2
```
This indicates nearly ALL traffic is anomalous (attack traffic only).

---

## Query 6: Extreme Outlier Detection

**Purpose:** Identify IPs with extremely high or low anomaly scores that warrant immediate investigation.

<!-- cd-metadata
cd_ready: false
adaptation_notes: "Time-series outlier detection using make-series/series_decompose_anomalies() with extreme score thresholds (>100 / <-50). Hunting query for extreme deviations, not CD-compatible due to make-series."
-->
```kql
// Query 6: Extreme Outliers (MaxScore > 100 or MinScore < -50)
let Timeframe = 1h;
let Lookback = 7d;
let AnomalyThreshold = 1.5;
DeviceNetworkEvents
| where TimeGenerated > ago(Lookback)
| where RemoteIPType == "Public"
| summarize ConnectionCount = count() by RemoteIP, bin(TimeGenerated, Timeframe)
| make-series ConnectionSeries = sum(ConnectionCount) default=0 
    on TimeGenerated 
    from ago(Lookback) to now() step Timeframe 
    by RemoteIP
| extend (AnomalyFlags, AnomalyScore, ExpectedValue) = series_decompose_anomalies(ConnectionSeries, AnomalyThreshold, -1, 'avg')
| mv-expand 
    TimeGenerated to typeof(datetime),
    AnomalyScore to typeof(double),
    ConnectionSeries to typeof(long)
| summarize 
    MaxScore = max(AnomalyScore),
    MinScore = min(AnomalyScore),
    TotalConnections = sum(ConnectionSeries),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP
| where MaxScore > 100 or MinScore < -50  // Extreme thresholds
| order by MaxScore desc
```

**What Extreme Scores Mean:**
- **Very High Positive (100+):** Sudden burst of activity that's dramatically different from baseline
- **Very Negative (<-50):** Expected activity suddenly disappeared (could indicate blocking or IP rotation)

**Common Causes of Extreme Outliers:**
1. **Azure/Cloud Infrastructure:** Intermittent cloud service connections (Windows Defender, Azure VPN)
2. **IPv6 Link-Local Addresses:** Configuration issues if fe80:: addresses appear in public traffic
3. **Software Updates:** Bulk update downloads causing connection bursts
4. **Attack Bursts:** Short coordinated attack campaigns

---

## Platform Notes

### Microsoft Sentinel vs. Defender XDR Advanced Hunting

**Column Name Differences:**
| Sentinel | Defender XDR |
|----------|--------------|
| `TimeGenerated` | `Timestamp` |
| Both use `RemoteIP`, `DeviceName`, `RemoteIPType` |

**Query Adjustment:**
- For Sentinel: Use `TimeGenerated`
- For Defender XDR: Replace with `Timestamp`

### Best Practices

1. **Start with 7-day lookback** - 24 hours catches too much CDN rotation noise
2. **Use threshold 1.5 initially** - Adjust based on your environment's score distribution
3. **Always enrich anomalous IPs** - Use AbuseIPDB, ipinfo.io, or similar services
4. **Filter known-good traffic** - Add exclusions for Windows Defender, Azure services
5. **Compare honeypot vs. production** - Honeypot traffic should have dramatically different score distributions

### Common Exclusion Filters

```kql
// Add these filters to reduce false positives:
| where RemoteUrl !has "wd.microsoft.com"        // Windows Defender
| where RemoteUrl !has "windowsupdate.com"       // Windows Update  
| where RemoteUrl !has "microsoft.com"           // Microsoft services
| where RemoteIP !startswith "fe80:"             // IPv6 link-local
| where RemoteIP !startswith "169.254."          // APIPA addresses
```

---

## IP Enrichment Workflow

After identifying anomalous IPs, enrich them with threat intelligence:

**Recommended Services:**
- **AbuseIPDB:** Crowdsourced abuse reports and confidence scores
- **ipinfo.io:** Geolocation, ASN, VPN/proxy/hosting detection
- **vpnapi.io:** VPN, proxy, Tor, relay detection

**Key Enrichment Fields:**
- **Abuse Score:** 0-100% (higher = more malicious)
- **Report Count:** Number of abuse reports
- **ISP/Org:** Hosting provider or ISP name
- **Country:** Geographic origin
- **VPN/Proxy Flags:** Detection of anonymization services

**Triage Priority:**
1. **High Priority:** Abuse score >50%, multiple reports, hosting/VPN provider
2. **Medium Priority:** Abuse score 10-50%, single reports, unusual countries
3. **Low Priority:** Abuse score <10%, no reports, known CDN/cloud providers

---

## Reference

**Function Documentation:**
- [series_decompose_anomalies() - Microsoft Learn](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/series-decompose-anomaliesfunction)

**Related Tables:**
- `DeviceNetworkEvents` - Network connection telemetry
- `DeviceLogonEvents` - Authentication attempts (correlate with network anomalies)
- `DeviceProcessEvents` - Process execution (identify malicious processes after network compromise)

**Threshold Selection Guide:**
| Environment Type | Recommended Threshold |
|-----------------|----------------------|
| High-security (SOC monitoring) | 1.0-1.5 |
| Standard production | 1.5-2.0 |
| Noisy environments | 2.0-2.5 |
| Alert-only (minimal noise) | 2.5-3.0 |
