# Credential Access KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Credential Access** tactic.

Primary ATT&CK techniques covered here include:

- **T1003.001** - LSASS Memory
- **T1003** - OS Credential Dumping
- **T1555** - Credentials from Password Stores
- **T1110.003** - Password Spraying
- **T1558.003** - Kerberoasting
- **T1552** - Unsecured Credentials

> These queries are written for **Microsoft Defender XDR / Advanced Hunting** and, where noted, **Microsoft Sentinel / Windows Security Events**.
> Tune aggressively for administrators, red team exercises, break-glass accounts, password vault tooling, and approved forensic workflows.

---

## 1) Mimikatz, ProcDump, or LSASS-targeting command lines

**ATT&CK:** T1003.001, T1003  
**Severity:** Critical  
**Purpose:** Detect common credential dumping tooling and command-line indicators including `mimikatz`, `sekurlsa`, `lsadump`, and ProcDump targeting LSASS.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "mimikatz.exe")
    or ProcessCommandLine has_any (
        "sekurlsa","lsadump","privilege::debug",
        "token::elevate","kerberos::list","Invoke-Mimikatz"
    )
    or (FileName =~ "procdump.exe" and ProcessCommandLine has "lsass")
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs.dll")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Tuning notes:**
- Some IR or memory-acquisition tools may look similar.
- Consider allowlisting authorized forensic hosts.

---

## 2) Suspicious access to LSASS via process or handle indicators

**ATT&CK:** T1003.001  
**Severity:** High  
**Purpose:** Hunt for suspicious API or sensor events associated with credential dumping against LSASS.

```kusto
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType in~ ("OpenProcessApiCall","ReadProcessMemoryApiCall","CreateRemoteThreadApiCall")
| where AdditionalFields has_any ("lsass.exe","LSASS")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
```

**Tuning notes:**
- Field population can vary by sensor version and licensing.
- Best used as a hunt query if your environment has sparse API telemetry.

---

## 3) Task Manager, ProcDump, or comsvcs abuse targeting LSASS

**ATT&CK:** T1003.001  
**Severity:** High  
**Purpose:** Detect native or dual-use binaries being leveraged to dump LSASS memory.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "procdump.exe" and ProcessCommandLine has "lsass")
    or (FileName =~ "taskmgr.exe" and ProcessCommandLine has "lsass")
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has_all ("comsvcs.dll","MiniDump"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 4) Browser credential store access by non-browser processes

**ATT&CK:** T1555  
**Severity:** High  
**Purpose:** Detect suspicious access to browser credential databases and login data files by non-browser processes.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName in~ ("Login Data","Cookies","Web Data","key4.db","logins.json")
| where InitiatingProcessFileName !in~ (
    "chrome.exe","msedge.exe","firefox.exe","iexplore.exe",
    "explorer.exe","MicrosoftEdgeUpdate.exe"
)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Tuning notes:**
- Password managers, backup agents, and browser enterprise tooling may access these files legitimately.

---

## 5) Browser credential theft tooling or suspicious sqlite copying

**ATT&CK:** T1555  
**Severity:** Medium  
**Purpose:** Hunt for common post-exploitation attempts to copy browser credential databases from user profiles.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "Login Data","Cookies","Web Data","key4.db","logins.json",
    "\\AppData\\Local\\Google\\Chrome\\User Data",
    "\\AppData\\Local\\Microsoft\\Edge\\User Data",
    "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 6) Password spraying against many accounts from one IP

**ATT&CK:** T1110.003  
**Severity:** High  
**Purpose:** Detect a likely password spray where a single source IP fails authentication against many accounts in a short period.

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize
    FailedCount = count(),
    Accounts = make_set(TargetUserName)
  by IpAddress, bin(TimeGenerated, 10m)
| where FailedCount > 20 and array_length(Accounts) > 5
| project TimeGenerated, IpAddress, FailedCount, Accounts
| order by TimeGenerated desc
```

**Tuning notes:**
- This requires Windows Security Events in Sentinel/Log Analytics.
- Tune thresholds to your auth volume and MFA posture.

---

## 7) Successful sign-in after password spray pattern

**ATT&CK:** T1110.003, T1078  
**Severity:** Critical  
**Purpose:** Correlate failed spray-like behavior followed by a success from the same IP.

```kusto
let Failed =
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize FailedCount=count(), Accounts=make_set(TargetUserName) by IpAddress, bin(TimeGenerated, 10m);
let Success =
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| summarize SuccessAccounts=make_set(TargetUserName), SuccessCount=count() by IpAddress, bin(TimeGenerated, 10m);
Failed
| where FailedCount > 20 and array_length(Accounts) > 5
| join kind=inner Success on IpAddress
| project TimeGenerated, IpAddress, FailedCount, Accounts, SuccessAccounts, SuccessCount
| order by TimeGenerated desc
```

---

## 8) Kerberoasting: RC4-encrypted TGS requests spike

**ATT&CK:** T1558.003  
**Severity:** Critical  
**Purpose:** Detect spikes in service ticket requests using RC4 encryption for non-machine accounts, indicative of Kerberoasting preparation.

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !has "$"
| summarize
    RequestCount = count(),
    Services = make_set(ServiceName)
  by Account, ClientAddress, bin(TimeGenerated, 10m)
| where RequestCount > 5
| project TimeGenerated, Account, ClientAddress, RequestCount, Services
| order by TimeGenerated desc
```

**Tuning notes:**
- Some older environments still legitimately use RC4 for certain services.
- Baseline service-account behavior before turning into a high-confidence analytic.

---

## 9) Rubeus, Kerbrute, or Kerberoast command-line indicators

**ATT&CK:** T1558.003  
**Severity:** High  
**Purpose:** Detect offensive tooling and command lines associated with Kerberoasting or Kerberos abuse.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("Rubeus.exe","Kerbrute.exe")
    or ProcessCommandLine has_any (
        "kerberoast","asreproast","/nowrap","/ticket","dump /service",
        "asktgt","s4u","tgtdeleg"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 10) Registry or file artifacts containing plaintext credentials

**ATT&CK:** T1552  
**Severity:** Medium  
**Purpose:** Hunt for scripts and command lines that may expose embedded credentials or passwords.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("password=","passwd=","pwd=","/p:","-p ","ConvertTo-SecureString","cmdkey")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Tuning notes:**
- This can be noisy in admin-heavy environments.
- Consider filtering known installers and deployment tooling.

---

## 11) Cmdkey usage storing or listing credentials

**ATT&CK:** T1555, T1552  
**Severity:** Medium  
**Purpose:** Detect `cmdkey.exe` usage to add, list, or manage stored credentials.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "cmdkey.exe"
| where ProcessCommandLine has_any ("/add:","/list","/generic:","/pass:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 12) Suspicious access to SAM, SECURITY, or SYSTEM hives

**ATT&CK:** T1003.002, T1003.003  
**Severity:** High  
**Purpose:** Detect attempts to access or copy local registry hives commonly used for offline credential dumping.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName in~ ("SAM","SECURITY","SYSTEM")
| where FolderPath has "\\System32\\config\\"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 13) Reg save or esentutl hive export commands

**ATT&CK:** T1003.002, T1003.003  
**Severity:** High  
**Purpose:** Detect command-line export of sensitive registry hives for offline cracking or analysis.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "reg.exe" and ProcessCommandLine has_any ("save HKLM\\SAM","save HKLM\\SYSTEM","save HKLM\\SECURITY"))
    or (FileName =~ "esentutl.exe" and ProcessCommandLine has_any ("ntds.dit","/y","/vss"))
    or (FileName =~ "ntdsutil.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 14) PowerShell credential theft or vault enumeration keywords

**ATT&CK:** T1555, T1003  
**Severity:** High  
**Purpose:** Detect PowerShell content suggestive of credential theft, vault extraction, or dumping.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "Invoke-Mimikatz","Get-Credential","CredEnumerate","VaultCmd",
    "Get-VaultCredential","sekurlsa","lsadump","dumpcred","token::elevate"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 15) VaultCmd usage to enumerate Windows Credential Manager

**ATT&CK:** T1555  
**Severity:** Medium  
**Purpose:** Detect `vaultcmd.exe` usage that may indicate credential store enumeration.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "vaultcmd.exe"
| where ProcessCommandLine has_any ("/list","/listschema","Windows Credentials","Web Credentials")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 16) Offensive credential-access tooling set

**ATT&CK:** T1003, T1558, T1555  
**Severity:** Medium  
**Purpose:** Hunt for known tools associated with credential dumping, roasting, and secrets extraction.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "mimikatz.exe","Rubeus.exe","Kerbrute.exe","secretsdump.py",
    "LaZagne.exe","procdump.exe","SharpKatz.exe"
)
    or ProcessCommandLine has_any (
        "Invoke-Mimikatz","Invoke-Kerberoast","sekurlsa","lsadump",
        "dumpcred","asktgt","kerberoast","asreproast"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## Recommended correlations

High-confidence investigations should correlate:
- LSASS-targeting process events + file creation of dump artifacts
- Kerberoast activity + unusual service ticket volume + Rubeus execution
- browser credential DB access + outbound archive creation or exfiltration
- spray failures + subsequent successful logon + lateral movement signals
