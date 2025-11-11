# 🕵️‍♂️ The Tech Support Trap: A Fake Support Session Turned Intrusion

## Overview
This report documents a simulated intrusion chain uncovered during a threat hunt. The investigation revealed an operator masquerading as an IT technician who executed a malicious PowerShell script (`SupportTool.ps1`) to gain initial access, perform reconnaissance, stage exfiltration, and establish persistence under the guise of legitimate support activity. The sequence demonstrates how social engineering and technical execution can blend to create convincing yet harmful activity.

---

## Full Report

During the threat hunt, an unfamiliar script named SupportTool.ps1 was observed in the user’s Downloads folder. This initial execution suggested the operator might have been masquerading as IT diagnostics, attempting to appear legitimate while gaining initial access. The script execution was captured in the DeviceProcessEvents table by filtering for files in the Downloads folder with names resembling support or help tools.

```kql
let start_time = datetime(2025-10-01T00:00:00Z);
let end_time   = datetime(2025-10-15T23:59:59Z);
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where (FolderPath has @"\Downloads\" or ProcessCommandLine has @"\Downloads\")
  and (FileName matches regex @"(?i).*(desk|help|support|tool).*\.(exe|scr|bat|ps1|vbs|msi)$"
       or ProcessCommandLine matches regex @"(?i).*(desk|help|support|tool).*")
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by DeviceName, TimeGenerated desc
```
<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot1.png">

---

Following the initial execution, there were signs of potential defense evasion. Abnormal process command lines indicated that the operator may have attempted to disable or bypass security tools to reduce visibility before continuing operations. This activity was identified by reviewing process events for unexpected PowerShell or command-line executions that deviated from normal patterns.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-10-09T13:13:12.5263837Z');
DeviceFileEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| sort by TimeGenerated desc 
| where RequestAccountName == "g4bri3lintern"
```
<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot2.png">

---

Shortly thereafter, evidence of quick data probing appeared. Commands interacting with the clipboard, such as PowerShell clipboard commands, suggested that the operator was checking for sensitive information readily available in the user’s environment. This low-profile reconnaissance was detected by querying process events for clipboard-related commands.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-10-09T13:13:12.5263837Z');
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_cs "clip" 
      or ProcessCommandLine has_cs "Get-Clipboard"
      or ProcessCommandLine has_cs "Set-Clipboard"
      or ProcessCommandLine has_cs "Out-Clipboard"
      or ProcessCommandLine has_cs "Get-Clipboard -"
| extend ProbeIndicator = iif(ProcessCommandLine has_cs "clip","clip.exe", "powershell-clipboard")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessId, InitiatingProcessId, ProcessCommandLine, ProbeIndicator
| order by Timestamp desc
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot3.png">

---

The attacker then expanded reconnaissance to gain a broader understanding of the host environment. A SensitiveFileRead action was observed, indicating that they were sampling important files and understanding the system context. 

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-10-09T13:13:12.5263837Z');
DeviceEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where ActionType has_any("SensitiveFileRead","ScheduledTaskCreated","wmi","browser")
```
<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot4.png">

---

I then discovered  when the last recon attempt was made on the machine using ‘qwinsta’ which is a built-in windows utility which enumerates user sessions on the local machine or a remote RD Session Host.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-11-09T13:13:12.5263837Z');
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_cs "query session" or ProcessCommandLine has_cs "qwinsta"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName, FileName, FolderPath, ProcessCommandLine, ReportId
| sort by TimeGenerated desc
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot5.png">

---

After searching through the Proc events logs I discovered more evidence of enumeration, more specifically on the filesystem. The highlight command checks how much disk space is available and helps identify mapped drives.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-11-09T13:13:12.5263837Z');
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| sort by TimeGenerated desc
| project ProcessCommandLine, InitiatingProcessFileName, FileName, FolderPath
| distinct ProcessCommandLine, InitiatingProcessFileName, FileName, FolderPath
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot6.png">

---

Once the local environment was scoped, the operator probed network connectivity. Outbound connections made through PowerShell to multiple websites over ports 80 and 443 suggested attempts to verify egress capabilities and ensure the host could communicate externally. DeviceNetworkEvents confirmed these connections, showing successful tests of the host’s network posture.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-11-09T13:13:12.5263837Z');
DeviceNetworkEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountDomain == "gab-intern-vm"
//| distinct InitiatingProcessCommandLine
| where InitiatingProcessFileName has_any ("powershell") 
| project ActionType, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessRemoteSessionDeviceName
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot7.png">

---

I then searched for any attempts to detect interactive or active user sessions on the host in the device proc events table using a list of built in windows command line tools that could be used to to detect interactive or active user sessions. I discovered a ‘query session’ was initiated which is used to list local/remote user sessions.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-11-09T13:13:12.5263837Z');
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| sort by TimeGenerated desc
| where ProcessCommandLine has_any ("query session","quser","qwinsta","query user","whoami","wmic computersystem get username","tasklist /v","net session","wevtutil")
| project ProcessCommandLine, InitiatingProcessParentFileName, FileName, FolderPath, InitiatingProcessUniqueId
//| distinct ProcessCommandLine, InitiatingProcessParentFileName, FileName, FolderPath
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot8.png">

---

I also looked for processes that would indicate enumeration of running applications and services that would inform risk and opportunity. (This is common for attackers trying to escalate privileges on a system)

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-10-09T13:13:12.5263837Z');
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessCommandLine has_any ("netstat","ipconfig","displaydns", "tasklist")
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot9.png">

---

Following process enumeration, the operator mapped privileges by running whoami /groups. This command revealed the user’s group memberships and access rights, providing insight into what actions could be performed and what defenses could be bypassed. Capturing privilege information is a common step before attempting escalation or data collection.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-10-09T13:13:12.5263837Z');
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where ProcessCommandLine contains "who"
| project TimeGenerated, ProcessCommandLine 
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot10.png">

---

With host and identity context understood, the attacker validated outbound connectivity while likely capturing evidence. Successful connections to www.msftconnecttest.com indicated egress checks, and the timing suggested potential screen capture or other evidence-gathering activities during the same period.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-11-09T13:13:12.5263837Z');
DeviceNetworkEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountDomain == "gab-intern-vm"
//| distinct InitiatingProcessCommandLine
| where InitiatingProcessFileName has_any ("powershell") 
| order by TimeGenerated desc
| project TimeGenerated, ActionType, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessRemoteSessionDeviceName
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot11.png">

---

The operator then began staging collected data. A PowerShell instance was used to bundle key artifacts into a file named ReconArtifacts.zip, consolidating information for potential exfiltration. File events confirmed the creation and modification of this archive on the host.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-11-09T13:13:12.5263837Z');
DeviceFileEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| order by TimeGenerated desc
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
 ```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot12.png">

---

Exfiltration was subsequently tested. Outbound HTTP requests to httpbin.org likely simulated the upload of the staged archive. DeviceNetworkEvents confirmed these connections, demonstrating that the operator was validating the ability to transfer data externally.

```kql
let end_time   = todatetime('2025-11-09T13:13:12.5263837Z');
DeviceNetworkEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountDomain == "gab-intern-vm"
//| distinct InitiatingProcessCommandLine
| where InitiatingProcessFileName has_any ("powershell") 
| order by TimeGenerated desc
| project TimeGenerated, ActionType, InitiatingProcessParentFileName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessRemoteSessionDeviceName
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot13.png">

---

Persistence measures were established next. A scheduled task named \SupportToolUpdater was created to trigger on logon, ensuring that the malicious script could execute in future sessions. This persistence mechanism was identified in DeviceEvents and indicated an effort to maintain access over time.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-10-09T13:13:12.5263837Z');
DeviceEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where ActionType has_any("SensitiveFileRead","ScheduledTaskCreated","wmi","browser")
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot14.png">

---

In addition to scheduled task persistence, the operator likely implemented a secondary fallback using a registry Run key named RemoteAssistUpdater. While registry events were not available for direct confirmation, the pattern aligns with common redundant persistence strategies observed in similar scenarios.

---

Finally, the attacker attempted to manipulate narrative control on the host. Helpdesk-like chat logs were dropped, possibly to justify the suspicious activity and mask their true intent. File creation events confirmed the presence of these logs, providing context for how the operator sought to influence the perception of their actions.

```kql
let start_time = todatetime('2025-10-09T12:22:27.6588913Z');
let end_time   = todatetime('2025-11-09T13:13:12.5263837Z');
DeviceFileEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == "gab-intern-vm"
| where ActionType == "FileCreated" and InitiatingProcessAccountName == "g4bri3lintern"
| distinct FileName
```

<img width="1212" alt="image" src="https://github.com/dmarrero98/threat-hunt-scenario-TechSupportTrap/blob/main/screenshots/screenshot15.png">

---

## Summary
Overall, the attack followed a methodical sequence: initial execution under disguise, probing and reconnaissance, staging and testing exfiltration, and finally securing persistence while leaving misleading artifacts. The activity touched on multiple MITRE ATT&CK techniques, including user execution, defense evasion, credential and session discovery, process and file enumeration, data staging, exfiltration, and persistence through scheduled tasks and registry keys. The findings highlight a well-structured attack lifecycle with clear attention to operational security and redundancy.





















