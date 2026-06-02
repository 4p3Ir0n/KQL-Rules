# Lateral Movement KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Lateral Movement** tactic.

Primary ATT&CK techniques covered here include:

- **T1021.001** - Remote Desktop Protocol
- **T1021.002** - SMB/Windows Admin Shares
- **T1021.006** - WinRM
- **T1570** - Lateral Tool Transfer
- **T1569.002** - Service Execution
- **T1047** - Windows Management Instrumentation
- **T1078** - Valid Accounts

> These queries are written for **Microsoft Defender XDR / Advanced Hunting** and, where noted, **Microsoft Sentinel / Windows Security Events**.
> Tune for jump boxes, SCCM, Intune scripts, remote support tooling, vulnerability scanners, and approved administration hosts.

---

## 1) Remote Desktop logons to endpoints

**ATT&CK:** T1021.001, T1078  
**Severity:** High  
**Purpose:** Detect Remote Desktop logons that may indicate lateral movement or unauthorized remote access.

```kusto
DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType =~ "RemoteInteractive"
| where ActionType =~ "LogonSuccess"
| project Timestamp, DeviceName, AccountName, RemoteIP, Protocol, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 2) RDP logons using service-like or privileged accounts

**ATT&CK:** T1021.001, T1078  
**Severity:** High  
**Purpose:** Hunt for interactive RDP by accounts that typically should not log on interactively.

```kusto
DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType =~ "RemoteInteractive"
| where ActionType =~ "LogonSuccess"
| where AccountName has_any ("svc","admin","backup","sql","oracle")
| project Timestamp, DeviceName, AccountName, RemoteIP, Protocol
| order by Timestamp desc
```

**Tuning notes:**
- Adjust matching to your actual service-account naming conventions.
- Exclude jump hosts if they generate expected interactive admin activity.

---

## 3) New or rare RDP source IPs per account/device

**ATT&CK:** T1021.001, T1078  
**Severity:** High  
**Purpose:** Identify first-seen or rare RDP origins for a given user and endpoint.

```kusto
let Lookback = 30d;
let RecentWindow = 1d;
let Historical =
DeviceLogonEvents
| where Timestamp between (ago(Lookback) .. ago(RecentWindow))
| where LogonType =~ "RemoteInteractive"
| where ActionType =~ "LogonSuccess"
| distinct DeviceName, AccountName, RemoteIP;
DeviceLogonEvents
| where Timestamp >= ago(RecentWindow)
| where LogonType =~ "RemoteInteractive"
| where ActionType =~ "LogonSuccess"
| where isnotempty(RemoteIP)
| join kind=leftanti Historical on DeviceName, AccountName, RemoteIP
| project Timestamp, DeviceName, AccountName, RemoteIP, Protocol, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 4) SMB admin share file creation

**ATT&CK:** T1570, T1021.002  
**Severity:** High  
**Purpose:** Detect file drops to administrative shares commonly used before remote execution.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath startswith @"\\ADMIN$"
    or FolderPath startswith @"\\C$"
    or FolderPath startswith @"\\IPC$"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

---

## 5) Administrative share copy of suspicious payload types

**ATT&CK:** T1570  
**Severity:** High  
**Purpose:** Detect likely tool transfer over SMB admin shares using executable or script payloads.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath startswith @"\\ADMIN$"
    or FolderPath startswith @"\\C$"
| where FileName endswith ".exe"
    or FileName endswith ".dll"
    or FileName endswith ".ps1"
    or FileName endswith ".bat"
    or FileName endswith ".cmd"
    or FileName endswith ".vbs"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

---

## 6) PsExec or PaExec execution

**ATT&CK:** T1569.002, T1021.002  
**Severity:** High  
**Purpose:** Detect PsExec-style remote execution tooling and command-line usage.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("psexec.exe","paexec.exe")
    or ProcessCommandLine has_any ("psexec","paexec","\\\\","-s","accepteula")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 7) PsExec service artifact creation

**ATT&CK:** T1569.002  
**Severity:** High  
**Purpose:** Hunt for service names and artifacts commonly associated with PsExec execution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("PSEXESVC","PsExecSvc")
    or FileName in~ ("PSEXESVC.exe","PsExecSvc.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

---

## 8) WMIC remote process creation

**ATT&CK:** T1047  
**Severity:** High  
**Purpose:** Detect WMI used to start processes on remote systems.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has "process call create"
    or ProcessCommandLine has "/node:"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 9) WinRM / PowerShell remoting network activity

**ATT&CK:** T1021.006  
**Severity:** High  
**Purpose:** Detect remote management connections over WinRM.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (5985, 5986)
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

---

## 10) PowerShell remoting command-line indicators

**ATT&CK:** T1021.006  
**Severity:** High  
**Purpose:** Detect `Enter-PSSession`, `Invoke-Command`, or remote execution via PowerShell.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Enter-PSSession","Invoke-Command","-ComputerName","New-PSSession")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 11) Remote service creation through sc.exe

**ATT&CK:** T1569.002  
**Severity:** High  
**Purpose:** Detect remote service manipulation used for lateral execution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any ("\\\\"," create "," start "," config ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 12) Remote scheduled task creation

**ATT&CK:** T1053.005, T1021  
**Severity:** High  
**Purpose:** Detect task creation against remote systems.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("/s "," /ru ","powershell","cmd","wscript","mshta")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 13) Lateral movement tool set detection

**ATT&CK:** T1021, T1570, T1569.002  
**Severity:** Medium  
**Purpose:** Hunt for common remote administration and lateral movement tools.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "psexec.exe","paexec.exe","wmic.exe","winrs.exe","mstsc.exe",
    "anydesk.exe","teamviewer.exe","screenconnect.clientservice.exe","rustdesk.exe"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 14) Remote command shells spawned from admin tools

**ATT&CK:** T1021, T1569.002  
**Severity:** High  
**Purpose:** Detect remote management utilities spawning shells or script interpreters.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("psexec.exe","paexec.exe","wmic.exe","winrs.exe","mstsc.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 15) Security Event RDP success from non-private IPs

**ATT&CK:** T1021.001, T1078  
**Severity:** High  
**Purpose:** Sentinel/Windows event view of RDP logons from public IP space.

```kusto
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| where LogonType == 10
| where TargetUserName !endswith "$"
| where IpAddress !startswith "10."
    and IpAddress !startswith "192.168."
    and IpAddress !startswith "172."
| project TimeGenerated, Computer, TargetUserName, IpAddress, WorkstationName
| order by TimeGenerated desc
```

---

## 16) Failed-then-successful RDP authentication sequence

**ATT&CK:** T1078, T1110, T1021.001  
**Severity:** High  
**Purpose:** Detect multiple failed remote interactive logons followed by a success from the same IP.

```kusto
let Failed =
DeviceLogonEvents
| where Timestamp >= ago(1d)
| where LogonType =~ "RemoteInteractive"
| where ActionType !~ "LogonSuccess"
| summarize FailedCount=count(), LastFailure=max(Timestamp) by DeviceName, AccountName, RemoteIP;
let Success =
DeviceLogonEvents
| where Timestamp >= ago(1d)
| where LogonType =~ "RemoteInteractive"
| where ActionType =~ "LogonSuccess"
| summarize SuccessTime=min(Timestamp) by DeviceName, AccountName, RemoteIP;
Failed
| where FailedCount >= 5
| join kind=inner Success on DeviceName, AccountName, RemoteIP
| where SuccessTime between (LastFailure .. LastFailure + 1h)
| project DeviceName, AccountName, RemoteIP, FailedCount, LastFailure, SuccessTime
| order by SuccessTime desc
```
