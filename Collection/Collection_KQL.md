# Collection KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Collection** tactic.

Primary ATT&CK techniques covered here include:

- **T1114.001** - Local Email Collection
- **T1056.001** - Keylogging
- **T1560.001** - Archive Collected Data
- **T1005** - Data from Local System
- **T1113** - Screen Capture
- **T1115** - Clipboard Data

> These queries are written primarily for **Microsoft Defender XDR / Advanced Hunting**.
> Tune for backup agents, DLP tools, eDiscovery, approved admin scripts, and user support tooling.

---

## 1) Outlook PST/OST access by non-Outlook processes

**ATT&CK:** T1114.001  
**Severity:** High  
**Purpose:** Detect processes other than Outlook interacting with mailbox storage files.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName endswith ".pst" or FileName endswith ".ost"
| where InitiatingProcessFileName !in~ ("OUTLOOK.EXE","MicrosoftEdgeUpdate.exe","explorer.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

---

## 2) PowerShell clipboard or key-reading activity

**ATT&CK:** T1056.001, T1115  
**Severity:** High  
**Purpose:** Detect PowerShell using clipboard access or keyboard APIs.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "Get-Clipboard","[Console]::ReadKey","GetAsyncKeyState",
    "SetWindowsHookEx","[System.Windows.Forms.Clipboard]"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 3) Archive creation of user data with 7zip, RAR, or zip tools

**ATT&CK:** T1560.001  
**Severity:** High  
**Purpose:** Detect compression of commonly targeted user directories or password-protected archives.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("7z.exe","7za.exe","rar.exe","winrar.exe","zip.exe","tar.exe")
| where ProcessCommandLine has_any (
    "\\Desktop\\","\\Documents\\","\\Users\\","C:\\Users",
    "password","pass","-p"," -hp"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 4) Access to sensitive document types by unusual processes

**ATT&CK:** T1005  
**Severity:** Medium  
**Purpose:** Hunt for processes reading or modifying documents and archives outside typical user apps.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName endswith ".docx"
    or FileName endswith ".xlsx"
    or FileName endswith ".pptx"
    or FileName endswith ".pdf"
    or FileName endswith ".zip"
    or FileName endswith ".7z"
| where InitiatingProcessFileName !in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","AcroRd32.exe","explorer.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 5) Screen capture utility execution

**ATT&CK:** T1113  
**Severity:** Medium  
**Purpose:** Detect tools or command lines associated with screenshot collection.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("nircmd.exe","psr.exe","snippingtool.exe")
    or ProcessCommandLine has_any ("screenshot","screenCapture","CaptureScreen","SaveScreenshot")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 6) PowerShell collection from desktop, docs, and downloads

**ATT&CK:** T1005  
**Severity:** Medium  
**Purpose:** Detect scripted aggregation of user data from common high-value locations.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "Get-ChildItem","Copy-Item","Compress-Archive","Move-Item",
    "\\Desktop\\","\\Documents\\","\\Downloads\\","\\OneDrive\\"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 7) Bulk file access across user profile paths

**ATT&CK:** T1005  
**Severity:** High  
**Purpose:** Detect a process touching many files in user directories over a short period.

```kusto
DeviceFileEvents
| where Timestamp > ago(1h)
| where FolderPath has_any ("\\Desktop\\","\\Documents\\","\\Downloads\\","\\Pictures\\","\\OneDrive\\")
| summarize FileOps=count(), DistinctPaths=dcount(FolderPath) by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 10m)
| where FileOps > 100 and DistinctPaths >= 5
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileOps, DistinctPaths
| order by FileOps desc
```

---

## 8) Staging archives in temp or public directories

**ATT&CK:** T1560.001  
**Severity:** Medium  
**Purpose:** Detect archive creation in staging locations frequently used before exfiltration.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("\\Temp\\","\\Users\\Public\\","\\ProgramData\\")
| where FileName endswith ".zip"
    or FileName endswith ".7z"
    or FileName endswith ".rar"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 9) Cmd or PowerShell copying mail, docs, or browser data

**ATT&CK:** T1005, T1114.001, T1555  
**Severity:** Medium  
**Purpose:** Detect command-line collection of email stores, documents, or browser data.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","robocopy.exe","xcopy.exe")
| where ProcessCommandLine has_any (
    ".pst",".ost","Login Data","Cookies","logins.json",
    "\\Documents\\","\\Desktop\\","\\Downloads\\","robocopy","xcopy"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 10) Collection tooling keywords in process command lines

**ATT&CK:** T1005, T1560.001, T1113  
**Severity:** Medium  
**Purpose:** Detect offensive collection tools and modules.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("nircmd.exe","psr.exe","7z.exe","rar.exe","winrar.exe")
    or ProcessCommandLine has_any (
        "Invoke-ClipboardMonitor","Get-Clipboard","SharpClipHistory",
        "Invoke-ScreenCapture","Out-Minidump","Compress-Archive"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```
