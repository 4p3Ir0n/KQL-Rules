# Discovery KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Discovery** tactic.

Primary ATT&CK techniques covered here include:

- **T1087** - Account Discovery
- **T1082** - System Information Discovery
- **T1083** - File and Directory Discovery
- **T1046** - Network Service Discovery
- **T1016** - System Network Configuration Discovery
- **T1033** - System Owner/User Discovery
- **T1069** - Permission Groups Discovery

> These queries are written primarily for **Microsoft Defender XDR / Advanced Hunting**.
> Tune for IT admin scripts, login scripts, inventory tools, vulnerability scanners, and approved management platforms.

---

## 1) whoami, net user, nltest, dsquery, and WMIC account discovery

**ATT&CK:** T1087, T1033  
**Severity:** Medium  
**Purpose:** Detect common account and identity discovery commands.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("whoami.exe","net.exe","net1.exe","nltest.exe","dsquery.exe","wmic.exe")
| where ProcessCommandLine has_any (
    "whoami","net user","net group","net localgroup",
    "nltest /domain_trusts","nltest /dclist","dsquery user","wmic useraccount"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 2) Burst of host discovery commands within 5 minutes

**ATT&CK:** T1082, T1016  
**Severity:** Medium  
**Purpose:** Detect a cluster of reconnaissance commands executed in a short time window.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ (
    "systeminfo.exe","ipconfig.exe","hostname.exe","net.exe",
    "arp.exe","route.exe","netstat.exe","tasklist.exe","quser.exe","qwinsta.exe"
)
| summarize Commands=make_set(FileName), Count=count() by DeviceName, AccountName, bin(Timestamp, 5m)
| where Count >= 4
| project Timestamp, DeviceName, AccountName, Commands, Count
| order by Timestamp desc
```

---

## 3) Directory enumeration of user and root folders

**ATT&CK:** T1083  
**Severity:** Low  
**Purpose:** Detect enumeration of sensitive directories using cmd or PowerShell.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "dir C:\\Users","dir C:\\","tree /f",
    "Get-ChildItem","gci C:\\","ls C:\\","Get-ChildItem C:\\Users"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 4) Port scan or large network sweep behavior

**ATT&CK:** T1046  
**Severity:** High  
**Purpose:** Detect a single device reaching many ports or IPs in a short interval.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionAttempted"
| summarize DistinctPorts=dcount(RemotePort), DistinctIPs=dcount(RemoteIP) by DeviceName, AccountName, bin(Timestamp, 5m)
| where DistinctPorts > 50 or DistinctIPs > 30
| project Timestamp, DeviceName, AccountName, DistinctPorts, DistinctIPs
| order by Timestamp desc
```

**Tuning notes:**
- Exclude sanctioned scanners and asset discovery platforms.

---

## 5) Network configuration discovery commands

**ATT&CK:** T1016  
**Severity:** Medium  
**Purpose:** Detect commands used to enumerate IP config, routing, DNS, and shares.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("ipconfig.exe","route.exe","arp.exe","net.exe","netsh.exe","nslookup.exe")
| where ProcessCommandLine has_any (
    "/all","print","arp -a","net view","net use","show config","show dns","nslookup"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 6) AD and privilege group discovery

**ATT&CK:** T1069, T1087  
**Severity:** Medium  
**Purpose:** Detect enumeration of groups, admins, and domain trusts.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("net.exe","net1.exe","whoami.exe","dsquery.exe","nltest.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "net group","net localgroup administrators","whoami /groups",
    "Domain Admins","Enterprise Admins","Schema Admins",
    "Get-ADGroup","Get-ADUser","Get-DomainGroup","Get-NetGroup"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 7) Recon toolkit detection: BloodHound, SharpHound, PowerView

**ATT&CK:** T1087, T1069, T1018  
**Severity:** Medium  
**Purpose:** Detect common AD recon tooling used by attackers.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("SharpHound.exe","BloodHound.exe","PowerView.ps1","AdRecon.ps1")
    or ProcessCommandLine has_any (
        "Invoke-BloodHound","Get-NetUser","Get-NetGroupMember",
        "Invoke-ACLScanner","Get-DomainUser","Find-LocalAdminAccess",
        "Get-DomainTrust","Get-NetComputer"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 8) Remote session and logged-on user discovery

**ATT&CK:** T1033  
**Severity:** Low  
**Purpose:** Detect commands used to enumerate logged-in users and active sessions.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("quser.exe","qwinsta.exe","query.exe","whoami.exe")
| where ProcessCommandLine has_any ("quser","qwinsta","query user","whoami")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 9) Share and domain discovery using net view / net use

**ATT&CK:** T1135, T1018  
**Severity:** Medium  
**Purpose:** Detect discovery of file shares and neighboring systems.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("net.exe","net1.exe")
| where ProcessCommandLine has_any ("net view","net use","net share","net session")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 10) Discovery commands launched from suspicious parents

**ATT&CK:** T1082, T1087, T1016  
**Severity:** Medium  
**Purpose:** Hunt for discovery commands launched from Office, script hosts, or unusual parents.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("whoami.exe","systeminfo.exe","ipconfig.exe","nltest.exe","net.exe","net1.exe","arp.exe","route.exe")
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 11) PowerShell-based discovery framework usage

**ATT&CK:** T1082, T1087, T1069  
**Severity:** Medium  
**Purpose:** Detect PowerShell-based host/domain discovery frameworks.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "Get-ADComputer","Get-ADUser","Get-ADGroup","Get-NetUser",
    "Get-NetComputer","Get-NetLocalGroup","Get-DomainController",
    "Get-DomainTrust","Invoke-ShareFinder","Invoke-UserHunter"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 12) nmap or masscan execution

**ATT&CK:** T1046  
**Severity:** High  
**Purpose:** Detect explicit network scanning tool execution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("nmap.exe","masscan.exe","naabu.exe","rustscan.exe")
    or ProcessCommandLine has_any ("-sS","-sT","-Pn","masscan","nmap ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
