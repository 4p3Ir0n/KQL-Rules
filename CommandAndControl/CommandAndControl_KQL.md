# Command and Control KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Command and Control** tactic.

Primary ATT&CK techniques covered here include:

- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1095** - Non-Application Layer Protocol
- **T1219** - Remote Access Software
- **T1572** - Protocol Tunneling
- **T1105** - Ingress Tool Transfer

> These queries are written primarily for **Microsoft Defender XDR / Advanced Hunting**.
> Tune for sanctioned remote support tools, software updaters, backup agents, CDNs, and known business SaaS destinations.

---

## 1) Possible HTTP/S beaconing to external IPs

**ATT&CK:** T1071.001  
**Severity:** High  
**Purpose:** Hunt for repeated outbound web connections to the same external IP and port that may indicate beaconing.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (80, 443, 8080, 8443)
| where RemoteIPType !in~ ("Private")
| summarize ConnectionCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where ConnectionCount between (20 .. 500)
| project DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, ConnectionCount, FirstSeen, LastSeen
| order by ConnectionCount desc
```

---

## 2) Repeated low-volume outbound connections from a single process

**ATT&CK:** T1071.001  
**Severity:** Medium  
**Purpose:** Detect long-running periodic outbound connections that may represent C2 heartbeat traffic.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType !in~ ("Private")
| summarize ConnectionCount=count(), DistinctUrls=dcount(RemoteUrl), DistinctIPs=dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, 1h)
| where ConnectionCount > 15 and DistinctUrls <= 5 and DistinctIPs <= 5
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ConnectionCount, DistinctUrls, DistinctIPs
| order by Timestamp desc
```

---

## 3) Known remote access tooling execution

**ATT&CK:** T1219  
**Severity:** High  
**Purpose:** Detect commercial remote access tools commonly abused for C2 and hands-on-keyboard activity.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ (
    "anydesk.exe","teamviewer.exe","screenconnect.clientservice.exe",
    "rustdesk.exe","netsupport.exe","litemanager.exe","logmein.exe","splashtop-streamer.exe"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 4) Remote access tool network activity

**ATT&CK:** T1219  
**Severity:** High  
**Purpose:** Detect outbound network connections initiated by common remote access tools.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ (
    "anydesk.exe","teamviewer.exe","screenconnect.clientservice.exe",
    "rustdesk.exe","netsupport.exe","litemanager.exe","logmein.exe"
)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## 5) Suspicious outbound connections on uncommon C2 ports

**ATT&CK:** T1095  
**Severity:** High  
**Purpose:** Detect outbound traffic to uncommon ports often used by malware and C2 frameworks.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (4444, 4445, 1234, 1337, 31337, 8888, 9999, 6666, 6667, 7777)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## 6) DNS tunneling or abnormally long DNS queries

**ATT&CK:** T1572  
**Severity:** High  
**Purpose:** Detect long or suspiciously structured DNS queries that may indicate tunneling.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "DnsQueryResponse"
| extend QueryLength = strlen(RemoteUrl)
| where QueryLength > 60
| where RemoteUrl matches regex @"[a-z0-9]{20,}\.[a-z]{2,10}$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteUrl, QueryLength, RemoteIP
| order by Timestamp desc
```

---

## 7) PowerShell download cradle followed by outbound network activity

**ATT&CK:** T1105, T1071.001  
**Severity:** High  
**Purpose:** Correlate suspicious PowerShell execution with near-term outbound connectivity.

```kusto
let SuspiciousPS =
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("DownloadString","DownloadFile","Net.WebClient","Invoke-WebRequest","iwr ","wget ","curl ")
| project DeviceId, DeviceName, AccountName, ProcTime=Timestamp, FileName, ProcessCommandLine;
DeviceNetworkEvents
| join kind=inner SuspiciousPS on DeviceId
| where Timestamp between (ProcTime .. ProcTime + 30m)
| where RemoteIPType !in~ ("Private")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## 8) Mshta, rundll32, or regsvr32 making external connections

**ATT&CK:** T1218, T1071.001  
**Severity:** High  
**Purpose:** Detect LOLBins making outbound connections, often indicative of staged payload retrieval or active C2.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe")
| where RemoteIPType !in~ ("Private")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## 9) Rare external domains contacted by script interpreters

**ATT&CK:** T1071.001  
**Severity:** Medium  
**Purpose:** Hunt for script interpreters and shells contacting uncommon external destinations.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
| where RemoteIPType !in~ ("Private")
| summarize ConnectionCount=count() by DeviceName, InitiatingProcessFileName, RemoteUrl
| where ConnectionCount < 5
| project DeviceName, InitiatingProcessFileName, RemoteUrl, ConnectionCount
| order by ConnectionCount asc
```

---

## 10) Suspicious cloud-storage or paste-site outbound traffic

**ATT&CK:** T1071.001, T1105  
**Severity:** Medium  
**Purpose:** Detect connections to common attacker staging or dead-drop services.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any (
    "pastebin","gist.githubusercontent.com","raw.githubusercontent.com",
    "transfer.sh","anonfiles","mega.nz","dropbox","mediafire","discordapp","telegram"
)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

---

## 11) BITSAdmin or certutil with external network destinations

**ATT&CK:** T1105  
**Severity:** Medium  
**Purpose:** Detect native tools often abused to establish foothold or retrieve payloads from attacker infrastructure.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ("http","https","/transfer"))
    or (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("http","https","-urlcache"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 12) Multiple endpoints contacting the same suspicious external IP

**ATT&CK:** T1071.001  
**Severity:** High  
**Purpose:** Detect possible shared C2 infrastructure across multiple hosts.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType !in~ ("Private")
| summarize HostCount=dcount(DeviceName), Hosts=make_set(DeviceName, 20), Processes=make_set(InitiatingProcessFileName, 20) by RemoteIP, RemotePort
| where HostCount >= 3
| project RemoteIP, RemotePort, HostCount, Hosts, Processes
| order by HostCount desc
```

## 13) Dead-drop resolver: non-browser process fetching C2 config from public profiles

**ATT&CK:** T1102.001  
**Severity:** High  
**Purpose:** Vidar and similar stealers retrieve their C2 address from attacker-controlled Steam Community profiles and Telegram channel descriptions. Detects a non-browser, non-client process fetching these dead-drop resolvers — a durable TTP independent of rotating C2 IPs.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any ("steamcommunity.com","t.me","telegra.ph","api.telegram.org","mastodon.social") or RemoteUrl endswith "telegram.org"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","msedgewebview2.exe","steam.exe","steamwebhelper.exe","Telegram.exe","outlook.exe","olk.exe","teams.exe","ms-teams.exe","slack.exe")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteUrl, RemoteIP, RemotePort, ReportId
```

**Tuning notes:**
- Exclude enterprise proxy/inspection agents and any sanctioned chat integrations by process name.
- Highest confidence when InitiatingProcessFolderPath is under Temp/AppData/ProgramData or the process is unsigned; add that filter if a security or monitoring tool generates volume.
