# KQL Rules across MITRE ATT&CK tactics

This repository contains practical Kusto Query Language (KQL) detections aligned to MITRE ATT&CK tactics and techniques, with emphasis on process-level detections and Microsoft Defender XDR / Advanced Hunting telemetry.

## Coverage

The initial content includes detections for:

- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

## Telemetry assumptions

These rules primarily use common Microsoft Defender Advanced Hunting tables, including:

- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceFileEvents`
- `DeviceRegistryEvents`
- `DeviceLogonEvents`
- `DeviceImageLoadEvents`
- `DeviceEvents`
-
Rules may need tuning for your environment, allowlists, and naming conventions.

## Repository structure

- `InitialAccess/` - RDP, phishing execution, removable media, public-facing exploitation indicators
- `Execution/` - PowerShell, encoded commands, LOLBins, suspicious script hosts
- `Persistence/` - Run keys, services, scheduled tasks, startup folder, WMI
- `PrivilegeEscalation/` - token abuse, admin group changes, elevated tool execution
- `DefenseEvasion/` - AMSI bypass, clearing logs, tampering, masquerading
- `CredentialAccess/` - Mimikatz, LSASS targeting, browser credential theft indicators
- `Discovery/` - whoami, net, nltest, systeminfo, AD and host reconnaissance
- `LateralMovement/` - PsExec, WMI, WinRM, RDP, remote service creation
- `Collection/` - archive staging, screenshotting, file aggregation, clipboard abuse indicators
- `CommandAndControl/` - beaconing, suspicious outbound connections, remote admin tooling, DNS tunneling indicators
- `Exfiltration/` - archive movement, cloud exfil patterns, unusual outbound transfers
- `Impact/` - ransomware precursors, shadow copy deletion, backup tampering, service stopping

## Notes

- Each rule file includes a detection name, MITRE mapping, rationale, tuning notes, and KQL.
- Queries are intended as starting points for hunts or scheduled detections.
- False-positive reduction has been added where broadly safe, but environment-specific tuning is still required.
