# Execution KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Execution** tactic.

Primary ATT&CK techniques covered here include:

- **T1059.001** - PowerShell
- **T1059.003** - Windows Command Shell
- **T1047** - Windows Management Instrumentation
- **T1218.011** - Rundll32
- **T1218.005** - Mshta
- **T1105** - Ingress Tool Transfer
- **T1218** - System Binary Proxy Execution
- **T1204** - User Execution

> These queries are written primarily for **Microsoft Defender XDR / Advanced Hunting**.
> Tune allowlists for sanctioned automation, software deployment tools, and administrative scripts.

---

## 1) Encoded or obfuscated PowerShell execution

**ATT&CK:** T1059.001  
**Severity:** High  
**Purpose:** Detect base64-encoded PowerShell, download cradles, IEX, hidden windows, and other common post-compromise execution patterns.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "-enc","-encodedcommand","FromBase64String","IEX(","Invoke-Expression",
    "DownloadString","DownloadFile","Net.WebClient","WebRequest",
    "Reflection.Assembly","-nop","-w hidden","-windowstyle hidden"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Tuning notes:**
- Exclude known administrative automation and EDR test harnesses.
- Consider adding filters for signed scripts or known software deployment systems.

---

## 2) PowerShell launched from Office, browser, or Outlook parents

**ATT&CK:** T1059.001, T1204  
**Severity:** High  
**Purpose:** Detect suspicious PowerShell execution chains commonly associated with phishing or user-driven initial execution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE","chrome.exe","msedge.exe","firefox.exe","explorer.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by Timestamp desc
```

---

## 3) Suspicious cmd.exe administrative and reconnaissance chains

**ATT&CK:** T1059.003  
**Severity:** Medium  
**Purpose:** Catch `cmd.exe` execution invoking utilities commonly used for post-exploitation, staging, or admin abuse.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_any (
    "net user","net localgroup","sc create","sc start",
    "reg add","wmic process call","whoami","systeminfo","tasklist",
    "nltest","quser","qwinsta","ipconfig","route print"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 4) WMIC remote process creation

**ATT&CK:** T1047  
**Severity:** High  
**Purpose:** Detect WMIC being used to create processes remotely or execute commands through WMI.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has "process call create"
    or ProcessCommandLine has "/node:"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**Tuning notes:**
- SCCM and other enterprise tooling may generate WMIC usage in older environments.

---

## 5) Rundll32 suspicious DLL or script-style execution

**ATT&CK:** T1218.011  
**Severity:** High  
**Purpose:** Detect `rundll32.exe` abuse from temp/user-writable paths or JavaScript-style command lines.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any (
    "\\AppData\\","\\Temp\\","\\ProgramData\\",
    "javascript:","advpack.dll","ieadvpack.dll","setupapi.dll"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| order by Timestamp desc
```

---

## 6) Mshta suspicious execution from user or internet delivery paths

**ATT&CK:** T1218.005  
**Severity:** High  
**Purpose:** Detect `mshta.exe` abuse used for payload launch, phishing, or proxy execution.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://","https://",".hta","javascript:","vbscript:","\\Downloads\\","\\Temp\\","\\AppData\\")
    or InitiatingProcessFileName in~ ("OUTLOOK.EXE","WINWORD.EXE","EXCEL.EXE","chrome.exe","msedge.exe","firefox.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 7) Regsvr32 remote scriptlet or suspicious COM script execution

**ATT&CK:** T1218.010  
**Severity:** High  
**Purpose:** Detect `regsvr32.exe` abuse including Squiblydoo-style remote scriptlet retrieval.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("scrobj.dll","/i:http","/i:https",".sct","javascript:")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 8) InstallUtil suspicious proxy execution

**ATT&CK:** T1218.004  
**Severity:** High  
**Purpose:** Detect `InstallUtil.exe` launching or registering non-standard payloads from writable locations.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "InstallUtil.exe"
| where ProcessCommandLine has_any ("\\Users\\","\\AppData\\","\\Temp\\","/logfile=","/U")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 9) Csc.exe or MsBuild suspicious compilation from user-writable paths

**ATT&CK:** T1127, T1027  
**Severity:** Medium  
**Purpose:** Hunt for attacker-on-host compilation and proxy execution via developer tooling.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("csc.exe","msbuild.exe")
| where ProcessCommandLine has_any ("\\Users\\","\\AppData\\","\\Temp\\",".csproj",".sln",".cs",".xml")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 10) Certutil, BITS, curl, or wget used as download cradles

**ATT&CK:** T1105  
**Severity:** Medium  
**Purpose:** Detect native or commonly present tools used to fetch payloads from external locations.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-urlcache","http","https","-decode","-encode"))
    or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ("/transfer","http","https","ftp"))
    or (FileName =~ "curl.exe" and ProcessCommandLine has_any ("-o","--output","http","https"))
    or (FileName =~ "wget.exe" and ProcessCommandLine has_any ("http","https"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 11) Script host execution of VBS, JS, or JSE from user paths

**ATT&CK:** T1059.005, T1204  
**Severity:** High  
**Purpose:** Detect Windows Script Host execution of common malicious script formats from downloads or temp paths.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (".vbs",".vbe",".js",".jse",".wsf","\\Downloads\\","\\Temp\\","\\AppData\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 12) Explorer spawning suspicious script interpreters and LOLBins

**ATT&CK:** T1204, T1218  
**Severity:** Medium  
**Purpose:** Hunt for user-driven execution from Explorer into common malicious interpreters and proxy binaries.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","regsvr32.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 13) Suspicious execution from AppData, Temp, or ProgramData

**ATT&CK:** T1204, T1105  
**Severity:** High  
**Purpose:** Detect payload execution from common attacker staging locations.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FolderPath has_any ("\\AppData\\","\\Temp\\","\\ProgramData\\")
| where FileName endswith ".exe"
    or FileName in~ ("rundll32.exe","regsvr32.exe","powershell.exe","pwsh.exe","cmd.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 14) Office spawning LOLBins or interpreters

**ATT&CK:** T1204, T1059, T1218  
**Severity:** High  
**Purpose:** Detect suspicious Office child-process behavior associated with malware delivery and macro abuse.

```kusto
let OfficeParents = dynamic(["WINWORD.EXE","EXCEL.EXE","POWERPNT.EXE","OUTLOOK.EXE"]);
let SuspiciousChildren = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe"]);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ (OfficeParents)
| where FileName in~ (SuspiciousChildren)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## 15) PowerShell downloading from paste sites or raw code repositories

**ATT&CK:** T1059.001, T1105  
**Severity:** High  
**Purpose:** Detect PowerShell retrieving content from common attacker staging and payload hosting services.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "pastebin","gist.githubusercontent.com","raw.githubusercontent.com",
    "paste.ee","hastebin","transfer.sh","anonfiles"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 16) Parent-child anomaly: svchost, Outlook, or Word spawning shells

**ATT&CK:** T1059, T1204  
**Severity:** Medium  
**Purpose:** Hunt for suspicious non-standard parent-child execution chains.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessFileName =~ "svchost.exe" and FileName in~ ("powershell.exe","cmd.exe","net.exe"))
    or (InitiatingProcessFileName =~ "winword.exe" and FileName =~ "powershell.exe")
    or (InitiatingProcessFileName =~ "outlook.exe" and FileName in~ ("powershell.exe","cmd.exe","mshta.exe"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp desc
```
