# TryHackMe — Conti Ransomware (Splunk Investigation)

**Room:** https://tryhackme.com/room/contiransomwarehgh
**Date:** 2026-08-20
**Category:** SOC / Threat Hunting / DFIR
**Tool:** Splunk (Search & Reporting)

## Scenario
An on-prem Microsoft Exchange server was hit with Conti ransomware. Employees couldn't log into Outlook, the admin was locked out of the Exchange Admin Center, and `readme.txt` ransom notes appeared on the server. Task: reconstruct the attack from Sysmon + IIS logs in Splunk.

## Access
- **Splunk URL:** `http://MACHINE_IP:8000` (IP changes each deploy)
- **Index:** `main`
- **Sysmon sourcetype:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- Set time range to **All time** for every search.

## Key Sysmon event codes used
- **11** = FileCreate (file written/overwritten)
- **1** = ProcessCreate (includes CommandLine + Hashes)
- **8** = CreateRemoteThread (process injection / migration)
- IIS logs (`sourcetype=iis`) = initial web-based access

## Investigation steps and findings

**1. Location of the ransomware** → `C:\Users\Administrator\Documents\cmd.exe`
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
```
*Reasoning:* ransomware floods FileCreate events. `cmd.exe` living in `\Documents\` (not System32) is a renamed dropper.

**2. Sysmon event ID for file creation** → `11`

**3. MD5 hash of the ransomware** → `290C7DFB01E50CEA9E19DA81A781AF2C`
```
index=main EventCode=1 Image="*Documents\\cmd.exe"
```
*Reasoning:* ProcessCreate events carry a `Hashes` field; read the MD5 off the execution event (drop into VirusTotal to confirm Conti).

**4. File saved to multiple folders** → `readme.txt`
*Reasoning:* same EventCode=11 results — one filename repeats across many directories = ransom note dropped per encrypted folder.

**5. Command to add a new user** → `net user /add securityninja hardToHack123$`
```
index=main EventCode=1 "net user"
```
*Reasoning:* attacker persistence via rogue local account; full command in `CommandLine`.

**6. Migrated + original process image (Event Code 8)** →
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,C:\Windows\System32\wbem\unsecapp.exe`
```
index=main EventCode=8
```
*Reasoning:* CreateRemoteThread = process injection/migration. `unsecapp.exe` → `powershell.exe` = attacker moving foothold to blend in.

**7. Process image for retrieving hashes** → `C:\Windows\System32\lsass.exe`
*Reasoning:* LSASS holds credentials in memory; dumping it = credential theft.

**8. Web shell deployed** → `i3gfPctK1c2x.aspx`
```
index=main sourcetype=iis cs_method=POST | search *.aspx
```
*Reasoning:* initial access. Random-named `.aspx` in the Exchange web dir = planted web shell for RCE.

**9. Command line that executed the web shell** →
```
attrib.exe -r \\win-aoqkg2as2q7.bellybear.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\i3gfPctK1c2x.aspx
```
*Reasoning:* confirms web shell path inside `...\owa\auth\` and that it was actively used.

**10. Three CVEs leveraged** → `CVE-2020-0796, CVE-2018-13374, CVE-2018-13379`
*Reasoning:* 2021 Exchange compromise via web shell in `owa\auth\` (ProxyShell-style chain); last two are the Fortinet VPN flaws Conti affiliates used for entry per the leaked Conti playbook.

## Kill chain summary
Exploit Exchange → drop `.aspx` web shell (**initial access**) → add rogue user (**persistence**) → inject/migrate processes (**defense evasion**) → dump LSASS (**credential access**) → drop & run `cmd.exe` ransomware → write `readme.txt` notes everywhere (**impact**).

## Takeaway
Investigation method = pivot across Sysmon event codes (11 → 1 → 8) to rebuild host activity, then use IIS logs to find root cause (initial access). Narrate incidents in ATT&CK order: initial access → persistence → priv/credential access → impact.
