# Impact KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Impact** tactic.

Primary ATT&CK techniques covered here include:

- **T1490** - Inhibit System Recovery
- **T1486** - Data Encrypted for Impact
- **T1489** - Service Stop
- **T1499** - Endpoint Denial of Service
- **T1561** - Disk Wipe / Disk Structure Wipe

> These queries are written primarily for **Microsoft Defender XDR / Advanced Hunting**.
> Tune for backup operations, legitimate admin recovery work, software upgrades, and approved maintenance windows.

---

## 1) Shadow copy deletion and recovery inhibition

**ATT&CK:** T1490  
**Severity:** Critical  
**Purpose:** Detect classic ransomware precursor behavior disabling recovery options.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no","bootstatuspolicy ignoreallfailures"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete catalog")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 2) Backup service or security service stopping

**ATT&CK:** T1489, T1490  
**Severity:** High  
**Purpose:** Detect stopping of services often targeted by ransomware prior to encryption.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("net.exe","sc.exe","taskkill.exe")
| where ProcessCommandLine has_any (
    " stop "," delete ","VSS","SQL","MSSQL","Backup","veeam","wbengine",
    "WinDefend","Sense","Sophos","CrowdStrike","Acronis"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 3) Mass file rename or extension change burst

**ATT&CK:** T1486  
**Severity:** Critical  
**Purpose:** Detect a rapid volume of file rename/modify operations suggestive of encryption activity.

```kusto
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileRenamed","FileModified")
| summarize FileCount=count(), Extensions=make_set(tostring(extract(@"\.([^.]+)$", 1, FileName)), 50) by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 5m)
| where FileCount > 200
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileCount, Extensions
| order by Timestamp desc
```

---

## 4) Creation of ransom-note style files

**ATT&CK:** T1486  
**Severity:** High  
**Purpose:** Detect common ransom note naming patterns dropped across hosts.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FileName has_any ("README","RECOVER","DECRYPT","HOW_TO_RESTORE","RANSOM","HELP")
    or FileName endswith ".txt"
    or FileName endswith ".html"
| where FolderPath has_any ("\\Desktop\\","\\Users\\","\\ProgramData\\")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

**Tuning notes:**
- This is broad by design; consider narrowing with stronger naming patterns in production.

---

## 5) Rapid child process spawning from a single parent

**ATT&CK:** T1499  
**Severity:** High  
**Purpose:** Detect process storms associated with DoS, miners, worms, or destructive tooling.

```kusto
DeviceProcessEvents
| where Timestamp > ago(10m)
| summarize ChildCount=count() by InitiatingProcessFileName, InitiatingProcessId, DeviceName, bin(Timestamp, 1m)
| where ChildCount > 100
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessId, ChildCount
| order by ChildCount desc
```

---

## 6) Cipher or built-in encryption utilities used recursively

**ATT&CK:** T1486  
**Severity:** High  
**Purpose:** Detect use of built-in or common encryption/compression utilities against user data.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("cipher.exe","7z.exe","7za.exe","winrar.exe","rar.exe")
| where ProcessCommandLine has_any ("\\Users\\","\\Documents\\","\\Desktop\\"," -p"," password"," encrypt")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 7) Destructive disk or partition tooling

**ATT&CK:** T1561  
**Severity:** Critical  
**Purpose:** Detect utilities that may wipe or alter partitions and disk structures.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("diskpart.exe","format.com","format.exe","bcdboot.exe")
| where ProcessCommandLine has_any ("clean","delete partition","format ","/fs:","/q")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 8) Deletion of backups, archives, or shadow artifacts

**ATT&CK:** T1490  
**Severity:** High  
**Purpose:** Detect removal of backup-related files and recovery artifacts.

```kusto
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in~ ("FileDeleted","FileRenamed")
| where FolderPath has_any ("WindowsImageBackup","Backup","Veeam","Acronis","System Volume Information")
    or FileName has_any (".vhd",".vhdx",".bkf",".wbcat",".zip",".7z")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 9) Multiple high-value user directories touched by one process

**ATT&CK:** T1486  
**Severity:** High  
**Purpose:** Hunt for a single process touching many user data locations in a short time.

```kusto
DeviceFileEvents
| where Timestamp > ago(1h)
| where FolderPath has_any ("\\Desktop\\","\\Documents\\","\\Downloads\\","\\Pictures\\","\\OneDrive\\")
| summarize TouchedPaths=dcount(FolderPath), FileOps=count() by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 10m)
| where TouchedPaths >= 10 and FileOps > 100
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, TouchedPaths, FileOps
| order by FileOps desc
```

---

## 10) Recovery inhibition plus mass file operations correlation

**ATT&CK:** T1490, T1486  
**Severity:** Critical  
**Purpose:** Correlate ransomware precursor activity with subsequent large-scale file modifications.

```kusto
let RecoveryInhibit =
DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no","bootstatuspolicy ignoreallfailures"))
| project DeviceId, DeviceName, RecoveryTime=Timestamp, AccountName, FileName, ProcessCommandLine;
let FileBurst =
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed","FileModified")
| summarize FileCount=count() by DeviceId, DeviceName, bin(Timestamp, 15m), InitiatingProcessFileName;
RecoveryInhibit
| join kind=inner FileBurst on DeviceId, DeviceName
| where Timestamp between (RecoveryTime .. RecoveryTime + 2h)
| where FileCount > 200
| project DeviceName, AccountName, RecoveryTime, FileName, ProcessCommandLine, Timestamp, InitiatingProcessFileName, FileCount
| order by RecoveryTime desc
```

---

## 11) Stopping databases or mail services before encryption

**ATT&CK:** T1489  
**Severity:** High  
**Purpose:** Detect attempts to stop enterprise applications commonly targeted by ransomware.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("net.exe","sc.exe","taskkill.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "exchange","sql","mssql","oracle","veeam","backup","tomcat","iisadmin","vmms","dfsr"
)
| where ProcessCommandLine has_any ("stop","kill","terminate","disable")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 12) Suspicious file extension proliferation by one process

**ATT&CK:** T1486  
**Severity:** High  
**Purpose:** Detect one process introducing many new uncommon extensions quickly.

```kusto
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| extend Ext = tostring(extract(@"\.([^.]+)$", 1, FileName))
| summarize ExtCount=dcount(Ext), FileCount=count(), Extensions=make_set(Ext, 50) by DeviceName, InitiatingProcessFileName, AccountName, bin(Timestamp, 10m)
| where ExtCount >= 10 and FileCount > 100
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ExtCount, FileCount, Extensions
| order by FileCount desc
```
