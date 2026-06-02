# Persistence KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Persistence** tactic.

Primary ATT&CK techniques covered here include:

- **T1547.001** - Registry Run Keys / Startup Folder
- **T1543.003** - Windows Service
- **T1053.005** - Scheduled Task
- **T1546.003** - WMI Event Subscription
- **T1098** - Account Manipulation
- **T1136** - Create Account

> These queries are written primarily for **Microsoft Defender XDR / Advanced Hunting**.
> Tune for approved software deployment, endpoint management, gold-image setup activity, and sanctioned administration.

---

## 1) Registry Run key or RunOnce persistence added

**ATT&CK:** T1547.001  
**Severity:** High  
**Purpose:** Detect writes to common autorun registry keys used by malware for startup persistence.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 2) Startup folder persistence via file creation

**ATT&CK:** T1547.001  
**Severity:** High  
**Purpose:** Detect executables, scripts, and shortcuts added to Startup folders.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath has_any (
    "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
)
| where ActionType in~ ("FileCreated","FileRenamed","FileModified")
| where FileName endswith ".lnk"
    or FileName endswith ".exe"
    or FileName endswith ".bat"
    or FileName endswith ".cmd"
    or FileName endswith ".ps1"
    or FileName endswith ".vbs"
    or FileName endswith ".js"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 3) Suspicious service creation via sc.exe

**ATT&CK:** T1543.003  
**Severity:** High  
**Purpose:** Detect creation of Windows services pointing to suspicious paths or interpreters.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has "create"
| where ProcessCommandLine has_any (
    "\\Temp\\","\\AppData\\","\\Users\\Public\\","\\ProgramData\\",
    "powershell","cmd.exe","wscript","cscript","mshta","rundll32"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 4) Service registry persistence written directly

**ATT&CK:** T1543.003  
**Severity:** High  
**Purpose:** Detect service image path modification or direct service registry changes.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"SYSTEM\CurrentControlSet\Services"
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 5) Scheduled task creation with suspicious payload

**ATT&CK:** T1053.005  
**Severity:** High  
**Purpose:** Detect `schtasks.exe` creating tasks that launch scripts, encoders, or binaries from writable locations.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any (
    "powershell","pwsh","cmd","wscript","cscript","mshta",
    "\\Temp\\","\\AppData\\","\\ProgramData\\","-enc","IEX",".js",".vbs",".ps1"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 6) WMI permanent event subscription creation

**ATT&CK:** T1546.003  
**Severity:** High  
**Purpose:** Detect permanent WMI subscription creation used for stealthy persistence.

```kusto
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in~ ("WmiEventFilterToPermanentSubscriptionBinding","WmiPermanentSubscriptionCreation")
| project Timestamp, DeviceName, AccountName, ActionType, AdditionalFields, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 7) Local administrators group modified with net.exe

**ATT&CK:** T1098  
**Severity:** High  
**Purpose:** Detect `net localgroup administrators /add` often used to retain privileged access.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("net.exe","net1.exe")
| where ProcessCommandLine has "localgroup"
    and ProcessCommandLine has "administrators"
    and ProcessCommandLine has "/add"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 8) User account creation from command-line utilities

**ATT&CK:** T1136  
**Severity:** High  
**Purpose:** Detect local account creation from built-in utilities.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("net.exe","net1.exe")
| where ProcessCommandLine has " user "
    and ProcessCommandLine has "/add"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 9) Startup persistence via shortcut plus writable-path target

**ATT&CK:** T1547.001  
**Severity:** Medium  
**Purpose:** Hunt for shortcut-based persistence that points to user-writable or suspicious directories.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath has_any (
    "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
)
| where FileName endswith ".lnk"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 10) Suspicious service binary execution from ProgramData or Temp

**ATT&CK:** T1543.003  
**Severity:** High  
**Purpose:** Detect service-like binaries launched from directories commonly abused by malware.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "services.exe"
| where FolderPath has_any ("\\ProgramData\\","\\Temp\\","\\Users\\Public\\","\\AppData\\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 11) Registry Run key set to script interpreter or LOLBin

**ATT&CK:** T1547.001  
**Severity:** High  
**Purpose:** Detect autoruns launching common interpreters or LOLBins instead of standard applications.

```kusto
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
| where RegistryValueData has_any ("powershell","pwsh","cmd.exe","wscript","cscript","mshta","rundll32","regsvr32")
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 12) Scheduled task XML or schtasks activity from temp paths

**ATT&CK:** T1053.005  
**Severity:** Medium  
**Purpose:** Hunt for task creation where artifacts are staged from temp or user-controlled directories.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("\\Temp\\","\\AppData\\","\\Users\\Public\\",".xml")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
