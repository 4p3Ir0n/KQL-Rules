# Exfiltration KQL Detections

This file contains KQL detections aligned to the **MITRE ATT&CK Exfiltration** tactic.

Primary ATT&CK techniques covered here include:

- **T1041** - Exfiltration Over C2 Channel
- **T1048** - Exfiltration Over Alternative Protocol
- **T1567** - Exfiltration to Cloud Storage
- **T1020** - Automated Exfiltration

> These queries are written primarily for **Microsoft Defender XDR / Advanced Hunting**.
> Tune for backup software, sanctioned cloud sync tools, developer workflows, and approved large-file transfer services.

---

## 1) Large outbound transfer to external IPs over HTTP/S

**ATT&CK:** T1041  
**Severity:** High  
**Purpose:** Detect unusually large outbound transfers to external destinations.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (80, 443)
| where RemoteIPType !in~ ("Private")
| summarize TotalBytes=sum(SentBytes) by DeviceName, RemoteIP, AccountName, bin(Timestamp, 1h)
| where TotalBytes > 100000000
| project Timestamp, DeviceName, AccountName, RemoteIP, TotalBytes
| order by TotalBytes desc
```

---

## 2) FTP, SCP, or SFTP outbound connections

**ATT&CK:** T1048  
**Severity:** High  
**Purpose:** Detect outbound alternative-protocol transfers from endpoints not expected to use them.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (21, 22, 989, 990)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType !in~ ("Private")
| where InitiatingProcessFileName !in~ ("sshd.exe","sftp-server.exe")
| project Timestamp, DeviceName, AccountName, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 3) Cloud storage exfiltration destinations

**ATT&CK:** T1567  
**Severity:** High  
**Purpose:** Detect outbound traffic to common cloud storage and file-sharing providers.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any (
    "dropbox","mega.nz","box.com","drive.google.com","docs.google.com",
    "onedrive","sharepoint","mediafire","wetransfer","transfer.sh"
)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

---

## 4) Rclone or Mega client execution

**ATT&CK:** T1567, T1020  
**Severity:** High  
**Purpose:** Detect common exfiltration tooling used for scripted data transfer.

```kusto
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("rclone.exe","megacmd.exe","mega-sync.exe","azcopy.exe")
    or ProcessCommandLine has_any ("rclone","mega.nz","megacmd","azcopy copy","azcopy sync")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

## 5) Archive creation followed by outbound network transfer

**ATT&CK:** T1560.001, T1041  
**Severity:** High  
**Purpose:** Correlate local archive staging with subsequent outbound network activity.

```kusto
let Archives =
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| project DeviceId, DeviceName, ArchiveTime=Timestamp, FileName, FolderPath, InitiatingProcessFileName;
DeviceNetworkEvents
| join kind=inner Archives on DeviceId, DeviceName
| where Timestamp between (ArchiveTime .. ArchiveTime + 2h)
| where RemoteIPType !in~ ("Private")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

---

## 6) Browser or script process uploading shortly after compression

**ATT&CK:** T1041, T1567  
**Severity:** Medium  
**Purpose:** Detect suspicious upload chains using browser or script interpreters.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("7z.exe","winrar.exe","rar.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("Compress-Archive",".zip",".7z",".rar")
| project DeviceId, DeviceName, ProcTime=Timestamp, AccountName, FileName, ProcessCommandLine;
DeviceNetworkEvents
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName in~ ("chrome.exe","msedge.exe","firefox.exe","powershell.exe","pwsh.exe","rclone.exe")
    | project DeviceId, DeviceName, NetProcTime=Timestamp, NetProc=FileName, NetCmd=ProcessCommandLine
) on DeviceId, DeviceName
| where NetProcTime between (ProcTime .. ProcTime + 2h)
| project DeviceName, AccountName, ProcTime, FileName, ProcessCommandLine, NetProcTime, NetProc, NetCmd
| order by NetProcTime desc
```

---

## 7) Automated repeated outbound transfers by one process

**ATT&CK:** T1020  
**Severity:** Medium  
**Purpose:** Detect a process sending data repeatedly over time to external infrastructure.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType !in~ ("Private")
| summarize Connections=count(), DistinctIPs=dcount(RemoteIP), BytesSent=sum(SentBytes) by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, 1h)
| where Connections > 20 and BytesSent > 50000000
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, Connections, DistinctIPs, BytesSent
| order by BytesSent desc
```

---

## 8) Unusual outbound transfers by LOLBins

**ATT&CK:** T1041  
**Severity:** High  
**Purpose:** Detect native binaries making suspicious outbound connections.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("certutil.exe","bitsadmin.exe","mshta.exe","rundll32.exe","regsvr32.exe","powershell.exe","pwsh.exe")
| where RemoteIPType !in~ ("Private")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl, SentBytes
| order by Timestamp desc
```

---

## 9) Public file-sharing destination plus archive tooling

**ATT&CK:** T1567, T1041  
**Severity:** High  
**Purpose:** Detect likely exfil chains involving staging plus transfer to public file-sharing services.

```kusto
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any ("wetransfer","mega.nz","dropbox","mediafire","transfer.sh","anonfiles")
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName in~ ("7z.exe","rar.exe","winrar.exe","rclone.exe","powershell.exe","pwsh.exe")
    | project DeviceId, DeviceName, ProcTime=Timestamp, FileName, ProcessCommandLine
) on DeviceName
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, ProcTime, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

## 10) External upload utilities or scripted transfer commands

**ATT&CK:** T1048, T1567  
**Severity:** Medium  
**Purpose:** Detect command-line usage of common upload tools and protocols.

```kusto
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("curl.exe","wget.exe","powershell.exe","pwsh.exe","scp.exe","pscp.exe","ftp.exe","sftp.exe")
| where ProcessCommandLine has_any (
    "ftp://","sftp://","scp ","pscp ","curl -T","Invoke-WebRequest","Invoke-RestMethod",
    "transfer.sh","dropbox","mega.nz","webdav"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```
