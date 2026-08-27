# Defense Evasion KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Defense Evasion** tactic.

Primary ATT&CK techniques covered here include:

- **T1070.001** - Clear Windows Event Logs
- **T1562.001** - Impair Defenses
- **T1027** - Obfuscated Files or Information
- **T1036** - Masquerading
- **T1218** - System Binary Proxy Execution
- **T1222** - File and Directory Permissions Modification

> These queries are written for **Microsoft Defender XDR / Advanced Hunting** and, where noted, **Microsoft Sentinel / Windows Event Logs**.
> Tune for security tooling, software packaging, golden-image changes, and legitimate troubleshooting activity.

---

## 1) Event log clearing activity

**ATT&CK:** T1070.001  
**Severity:** Medium  
**Purpose:** Detect anti-forensics behavior through log clearing.

```kusto
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (1102, 104)
| project TimeGenerated, Computer, Activity, Account
| union (
    DeviceEvents
    | where Timestamp > ago(1d)
    | where ActionType == "ClearWindowsEventLogs"
    | project Timestamp, DeviceName, AccountName, AdditionalFields
)
```

---

## 2) Defender, AV, or Firewall tampering via PowerShell

**ATT&CK:** T1562.001  
**Severity:** High  
**Purpose:** Detect attempts to disable or weaken Defender and local firewall settings.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "Set-MpPreference","DisableRealtimeMonitoring","DisableBehaviorMonitoring",
    "DisableIOAVProtection","DisableIntrusionPreventionSystem",
    "Add-MpPreference -ExclusionPath","Add-MpPreference -ExclusionProcess",
    "netsh advfirewall set allprofiles state off"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 3) Exclusion-path or exclusion-process tampering

**ATT&CK:** T1562.001  
**Severity:** High  
**Purpose:** Detect security product exclusion additions that may hide malware.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Add-MpPreference -ExclusionPath","Add-MpPreference -ExclusionProcess","Set-MpPreference")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 4) AMSI bypass or reflection-based PowerShell content

**ATT&CK:** T1027, T1562.001  
**Severity:** High  
**Purpose:** Detect common obfuscation and AMSI bypass patterns.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "AmsiUtils","amsiInitFailed","FromBase64String","Reflection.Assembly",
    "System.Management.Automation.Amsi","IEX(","Invoke-Expression"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 5) PowerShell script block obfuscation indicators

**ATT&CK:** T1027  
**Severity:** Medium  
**Purpose:** Hunt script block content for obfuscation and dynamic loading. Requires PowerShell logging.

```kusto
Event
| where TimeGenerated > ago(1d)
| where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
| where RenderedDescription has_any (
    "FromBase64String","Invoke-Expression","IEX",
    "Net.WebClient","DownloadString","Reflection.Assembly","[System.Convert]",
    "AmsiUtils","amsiInitFailed"
)
| project TimeGenerated, Computer, RenderedDescription
| order by TimeGenerated desc
```

---

## 6) Masquerading with renamed or odd binary locations

**ATT&CK:** T1036  
**Severity:** Medium  
**Purpose:** Detect suspicious filenames or system-like names executing from user-writable paths.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FolderPath has_any ("\\Users\\","\\AppData\\","\\Temp\\","\\ProgramData\\")
| where FileName in~ ("svchost.exe","lsass.exe","csrss.exe","explorer.exe","services.exe","winlogon.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 7) Certutil, InstallUtil, Regsvr32, or Mshta proxy execution

**ATT&CK:** T1218  
**Severity:** High  
**Purpose:** Detect common LOLBins used to proxy malicious execution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-urlcache","http","https"))
    or (FileName =~ "InstallUtil.exe" and ProcessCommandLine has_any ("/U","\\Users\\","\\Temp\\"))
    or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("scrobj.dll","/i:http","/i:https",".sct"))
    or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http://","https://",".hta","javascript:"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 8) Wevtutil log clearing or disabling

**ATT&CK:** T1070.001  
**Severity:** Medium  
**Purpose:** Detect direct `wevtutil` usage to clear logs.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any (" cl "," clear-log "," sl "," set-log ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 9) File permission changes using icacls or attrib

**ATT&CK:** T1222  
**Severity:** Medium  
**Purpose:** Detect permission or attribute changes that may hide or protect malicious files.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("icacls.exe","attrib.exe")
| where ProcessCommandLine has_any ("/grant","/deny","+h","+s","+r","/inheritance")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 10) Security tool process termination or tampering indicators

**ATT&CK:** T1562.001  
**Severity:** High  
**Purpose:** Hunt for attempts to kill or tamper with EDR/AV-related processes.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("taskkill.exe","wmic.exe","net.exe","sc.exe")
| where ProcessCommandLine has_any (
    "MsMpEng","Sense","WinDefend","WdNisSvc","SecurityHealthService",
    "taskkill /f"," stop "," delete "
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 11) Hidden or suspicious file creation in temp and user paths

**ATT&CK:** T1027, T1036  
**Severity:** Medium  
**Purpose:** Detect staging of suspicious scripts and binaries in writable locations.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath has_any ("\\Temp\\","\\AppData\\","\\Users\\Public\\","\\ProgramData\\")
| where FileName endswith ".exe"
    or FileName endswith ".dll"
    or FileName endswith ".ps1"
    or FileName endswith ".vbs"
    or FileName endswith ".js"
    or FileName endswith ".hta"
| where ActionType in~ ("FileCreated","FileRenamed","FileModified")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 12) Encoded PowerShell launched from Office or script parents

**ATT&CK:** T1027, T1566, T1204  
**Severity:** High  
**Purpose:** Detect obfuscated PowerShell with suspicious parent processes.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String","IEX(")
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","wscript.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## 13) Linux shell history destruction or Atuin history tampering

**ATT&CK:** T1070.003  
**Severity:** Medium  
**Purpose:** Detects attackers disabling or wiping shell history (including the Atuin SQLite history store), a common anti-forensics step after interactive Linux access.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("history -c","history -d","history -w /dev/null","unset HISTFILE","HISTFILE=/dev/null","HISTFILE=\"\"","HISTSIZE=0","HISTFILESIZE=0","set +o history","export HISTCONTROL=ignorespace",".bash_history",".zsh_history",".sh_history","atuin history prune","atuin history delete","atuin store purge",".local/share/atuin/history.db")
| where FileName in~ ("bash","sh","zsh","dash","ksh","atuin","rm","shred","truncate","ln","unlink","sqlite3")
| project Timestamp, DeviceName, DeviceId, AccountName, ProcessCommandLine, FileName, FolderPath, ProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ReportId
```

**Tuning notes:**
- Some hardening/imaging scripts and dotfile managers legitimately touch HISTFILE settings — allowlist by InitiatingProcessCommandLine (e.g. ansible, cloud-init, packer) or by device group for build hosts.
- Correlate with preceding SSH logons in DeviceLogonEvents to prioritise sessions from unusual source IPs.
