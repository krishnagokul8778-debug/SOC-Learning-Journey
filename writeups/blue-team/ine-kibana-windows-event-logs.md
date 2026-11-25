# INE Lab — Kibana: Windows Event Logs I

- **Type:** Log Analysis — Windows Event Logs (Kibana + Elasticsearch)
- **Log source:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- **Date:** 2026-08-14
- **Platform:** INE (AttackDefense lab)
- **Result:** all 5 questions solved

## Method

Sysmon process-creation events are ingested into Elasticsearch and browsed in Kibana
Discover. Every question is answered by filtering the `EventData.CommandLine` field with a
KQL query and reading the matching command line. Data timeframe is Jul 19, 2019 (~20:11–20:43).

## Investigation steps and findings

### Q1 — Scheduled task set to run daily; password of the user running it
- **Finding:** `At0micStrong`
- **Filter:** `EventData.CommandLine : "schtasks"` (4 hits)
- **Evidence:**
  ```
  SCHTASKS /Create /S localhost /RU DOMAIN\user /RP At0micStrong /TN ' Atomic 'task /TR C:\windows\system32\cmd.exe /SC daily /ST 20:10
  ```
- `/SC daily` = daily schedule; `/RP <password>` = run-as password.

### Q2 — .txt file securely deleted with sdelete; full path
- **Finding:** `C:\some\file.txt`
- **Filter:** `EventData.CommandLine : sdelete*` (1 hit)
- **Evidence:**
  ```
  C:\Windows\system32\cmd.exe /c 'sdelete.exe C:\some\file.txt'
  ```

### Q3 — `net use` to remote share as Administrator; password
- **Finding:** `P@ssw0rd1`
- **Filter:** `EventData.CommandLine : "net use"` (3 hits)
- **Evidence:**
  ```
  cmd.exe /c net use \\Target\C$ P@ssw0rd1 /u:DOMAIN\Administrator
  ```

### Q4 — Ping sweep attack; target subnet (CIDR)
- **Finding:** `192.168.1.0/24`
- **Filter:** `EventData.CommandLine : "ping"` (255 hits)
- **Evidence:**
  ```
  for /l %%i in (1,1,254) do ping -n 1 -w 100 192.168.1.%%i
  ```
- Loop pings 192.168.1.1–254 → subnet 192.168.1.0/24.

### Q5 — Bitsadmin download; full path of downloaded file
- **Finding:** `C:\Windows\Temp\bitsadmin_flag.ps1`
- **Filter:** `EventData.CommandLine : bitsadmin*` (12 hits)
- **Evidence:**
  ```
  bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\Windows\Temp\bitsadmin_flag.ps1
  ```

## Notes / MITRE ATT&CK mapping
- T1053.005 Scheduled Task (schtasks)
- T1070.004 File Deletion (sdelete)
- T1021.002 SMB/Admin Shares (net use)
- T1018 Remote System Discovery (ping sweep)
- T1197 BITS Jobs (bitsadmin download)
