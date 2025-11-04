# 🔍 ForenSynth AI — DFIR Summary (Two-Pass)

- Generated: 2025-11-02T20:34:09.437010+00:00
- Micro model: `gpt-5-mini`
- Final model: `gpt-5`
- Chunks: 25

---

## Final Executive Report

Executive DFIR Report — Consolidated From Micro-Summaries

1) Executive Summary
- What we’re seeing: A multi-week, campaign-level intrusion pattern across 2025-10-05 through 2025-11-02 characterized by heavy, obfuscated PowerShell execution; repeated persistence (Scheduled Tasks and Registry Run keys/autoruns); living-off-the-land (regsvr32, rundll32, WMIC, BITS/bitsadmin); log tampering; discovery; lateral tooling; and account manipulation.
- Scale and duration: Activity spans at least 28 days with recurring bursts on 2025-10-05–07, 10-10–10-16, 10-22–10-28, and 11-02. Conservatively, hundreds (≥300) of encoded/non-interactive PowerShell executions across ≥15 distinct bursts, ≥20 Scheduled Task creations, ≈15–20 autorun/Run key modifications, ≥10 log-clearing attempts, ≥10 WMIC remote process creations, and ≥12 SMB share mounts. At least 3 new local accounts and multiple group privilege modifications observed.
- Likely objectives: Establish persistent access, automate post-exploitation, escalate/maintain privileges, move laterally, and impede detection via obfuscation and log tampering. Repeated payload staging via BITS/bitsadmin and executable drops suggests tooling refresh.
- Current risk posture: High. Indicators span multiple MITRE ATT&CK phases with confirmed persistence and defense evasion. Log manipulation and new accounts materially increase blast radius and dwell time. Treat as ongoing multi-host compromise until proven otherwise.
- Immediate action required: Isolate impacted hosts; collect volatile and disk evidence before remediation; remove persistence; disable/rotate impacted accounts; enterprise-wide hunt for encoded PS, Set-Alias/IEX patterns, BITS artifacts, Run keys, schtasks, regsvr32/rundll32 and WMIC usage.

2) Observed Activity (grouped)
Execution and Automation (dominant)
- Encoded/non-interactive PowerShell (T1059.001): ≥300 executions across repeated bursts.
  - Early: 2025-10-05 20:27–21:28 (~26 events); 2025-10-06 16:41 (~10).
  - Mid: 2025-10-07 16:47–18:15 (multiple bursts, ~26–28 events).
  - 2025-10-10 evening waves: 22:49–23:23 (multiple clusters of 20–28 events each).
  - Subsequent clusters: 2025-10-11–13 (~22+); 2025-10-13–15 (~25 per day); 2025-10-15 (~24); 2025-10-23–10-24 (~25–30 total); 2025-10-25 multiple clusters (≥29 per cluster); 2025-10-26–10-28 (≥20); 2025-11-02 (≥22).
- PowerShell obfuscation/aliasing/IEX (T1027/T1027.009): Set-Alias and token obfuscation snippets recur (e.g., alias sets gcim/rcim/rcie/gcms; IEX obfuscation like (&("{0}{1}" -f "Get-","Date")) and Write-Output trick). EventID 4104 confirms script block logging on some hosts.

Persistence and Privilege Maintenance
- Scheduled Tasks (T1053.005): ≥20 creations across 2025-10-05→11-02; notable timestamps include 2025-10-05 20:26/22:42/23:28/23:56; 2025-10-06 16:15; 2025-10-07 16:04/16:08; 2025-10-10 22:50/22:53/23:02/23:06/23:18/23:22; 2025-10-11 23:23 and 2025-10-13 16:12; 2025-10-15 17:57 and 2025-10-16 00:13; 2025-10-22 23:57 and 2025-10-24 15:28/15:53; 2025-10-25 13:23; 2025-11-02 14:06.
- Registry autoruns/Run keys (T1547.001): ≈15–20 modifications, including CurrentVersion autorun and PowerShell Run entries (e.g., 2025-10-05 20:24x3; 2025-10-13 23:05; 2025-10-14 02:06; 2025-10-24 15:52/15:54; 2025-10-25 00:08/13:39/16:27; 2025-10-26 00:07; 2025-10-28 16:28; 2025-11-02 14:07).
- Services/other persistence: ≥5 rare service installations (2025-10-05 19:38/20:12; 2025-10-05 22:21/23:46) and COM search-order hijack (2025-10-06 01:10). Elevated SYSTEM shell spawns (2025-10-06 16:23; 2025-10-07 16:10).

Defense Evasion and Tooling Abuse
- Event log clearing/config changes (T1070.001/T1562.002): ≥10 occurrences across 2025-10-10, 10-11, 10-14, 10-24, 10-25, 10-26, 11-02; string “clearkali” noted 2025-10-26.
- Signed binary/LOLBIN abuse (T1218.*): regsvr32 (many events across 10-10→10-28), rundll32 (frequent, including uncommon DLL extension), WMIC process create (≥10 events), cmd output redirection/shell spawn.
- Process injection (T1055): Remote thread creation in shell app on multiple days (e.g., 2025-10-23 00:00:24; 2025-10-25 16:23:15).
- Godmode Sigma detection and privilege/config manipulation observed (2025-10-07 16:08; 2025-10-13 22:33).

Discovery and Lateral Movement
- Discovery: Local account enumeration, hostnames, Get-Process/System info observed repeatedly across clusters (dozens of events).
- SMB/Windows share mounts via net.exe (T1021.002): ≥12 mounts across 10-10, 10-13, 10-14, 10-15, 10-24, 10-25.
- BITS/bitsadmin staging (T1197/T1105): BITS or bitsadmin downloads to suspicious folders (2025-10-23 00:03; 2025-10-26 00:07).
- Account manipulation: New local users via net.exe (≥3) and security-enabled global group membership additions (≥2) on 2025-10-07 and 2025-10-05.

Staging/Resource Development
- Executable created by executable (T1587.001): ≥9 events with dense cluster 2025-10-07 16:06–16:07 and earlier 2025-10-05 21:52/22:42.
- AppCompat “new app” (2025-10-06 17:20) suggesting staged payload or execution chain.

Data gaps
- Most detections lack hostnames, usernames, command lines, file paths, hashes, network endpoints; comprehensive evidence collection is required to derive concrete IOCs and blast radius.

3) Key TTPs/Techniques (MITRE ATT&CK)
- Execution: T1059.001 PowerShell (encoded/non-interactive, IEX), T1059.005 Windows cmd/shell
- Persistence: T1053.005 Scheduled Task, T1547.001 Registry Run Keys/Startup, T1543.003 Create/Modify System Process (services), T1546.015 COM Hijacking
- Privilege/Account: T1136.001 Create local accounts, T1098 Account manipulation; elevated shells
- Defense Evasion: T1070.001 Clear Windows Event Logs, T1562.002 Impair defenses, T1027/T1027.009 Obfuscated/aliased scripts, T1218.010 regsvr32, T1218.011 rundll32, T1036.003 Masquerading, T1055 Process injection
- Discovery: T1087.001 Account discovery, T1082 System info, T1057 Process discovery
- Lateral Movement/Remote Execution: T1021.002 SMB/Windows shares, T1047 WMI (WMIC), T1197/T1105 BITS/bitsadmin
- Staging/Resource Dev: T1587.001 Payload creation/drop; AppCompat abuse

4) Risk Assessment
- Severity: High. Multiple concurrent TTPs across the kill chain, proven persistence, account manipulation, and recurrent log tampering indicate entrenched access and an ability to re-establish footholds.
- Likelihood of multi-host compromise: High. Temporal breadth and repeated clusters imply propagation or repeated re-entry, likely across more than one endpoint.
- Business impact: Elevated risk of data access/exfiltration (not yet evidenced), credential theft/reuse, service disruption, and loss of forensic visibility due to log tampering.
- Dwell time: ~28+ days (2025-10-05 to 2025-11-02) with periodic reactivation.
- Confidence: High for compromise; specific scope attribution is limited by missing host/account/command-line details. Note: a subset of PowerShell snippets resemble simulation text; treat all activity as hostile until verified and segmented to sanctioned test environments.

5) Actionable Recommendations (prioritized) 
High Priority (immediate containment and evidence; quick wins included)
- Isolate and preserve
  - Isolate endpoints exhibiting encoded/non-interactive PowerShell plus persistence changes (quick win).
  - Acquire memory, full EDR telemetry, and Windows Event Logs (Security, Sysmon, PowerShell 4104/Operational, TaskScheduler, Microsoft-Windows-Bits-Client) before changes (quick win).
- Disable adversary persistence and access
  - Enumerate and disable/remove malicious Scheduled Tasks; export XML before removal (quick win).
  - Export and revert unauthorized Run/autorun keys; capture full key/value data (quick win).
  - Disable or delete newly created local accounts; remove unauthorized group memberships; force password resets of affected users/admins (quick win).
- Block active TTPs
  - Temporarily block encoded PowerShell (-EncodedCommand), enforce AMSI and Script Block Logging; move high-risk hosts to Constrained Language Mode.
  - Contain LOLBIN abuse: block/alert regsvr32/rundll32/wmic/schtasks invoked by non-standard parents via EDR; restrict BITS/bitsadmin job creation.
- Enterprise hunt
  - Search for recurring indicators: Set-Alias patterns, IEX obfuscation, encoded PowerShell strings, “clearkali,” BITS job artifacts, identical Run key values/paths, remote thread injection events, net.exe share mounts.
- Credential containment
  - Reset credentials used on affected systems (local admins, service accounts, interactive users). Invalidate cached tokens and enforce MFA where possible.

Medium Priority (eradication, scoping, and hardening)
- Scope and IOC derivation
  - Decode captured PowerShell commands; extract payload paths, C2, and secondary IOCs; analyze downloaded binaries in sandbox.
  - Correlate WMIC, schtasks, regsvr32/rundll32 invocation trees and SMB session logs to map lateral movement and affected hosts.
- Logging and prevention uplift
  - Ensure Sysmon (proc/create, file/create, network/connect), detailed 4688 with command line, PowerShell 4104+transcription are enabled and retained.
  - Implement AppLocker/WDAC rules to restrict LOLBINs and PowerShell to approved scenarios; enforce LAPS and remove shared local admin credentials.
- Network controls
  - Tighten SMB and admin share access; segment management networks; apply egress filtering for suspicious destinations; monitor DNS/HTTP(S) for beaconing from affected hosts.

Low Priority (strategic improvements and validation)
- Validate and segregate any sanctioned simulation/test activity; whitelisting and separate logging for red team/dev labs to avoid alert confusion.
- Patch hygiene and baseline controls review; ensure service install auditing, COM/AppCompat abuse detections, and tamper protection are in place.
- Conduct tabletop and remediation readiness exercises based on this campaign’s playbook.

Quick wins summary
- Isolate affected hosts now.
- Disable new local accounts and revert unauthorized group additions.
- Export and remove malicious Scheduled Tasks and Run keys.
- Enable/verify PowerShell Script Block Logging and AMSI; block -EncodedCommand.
- EDR rule: flag Set-Alias/IEX obfuscation, regsvr32/rundll32/wmic/schtasks spawned by PowerShell or untrusted parents.
- Hunt for “clearkali,” BITS jobs, and identical encoded PS across the estate.

---

## Micro Cluster Summaries

## Micro 1: Cluster Summary

Executive bullets
- PowerShell execution spike: ~26 PowerShell events (non-interactive + Base64/encoded) between 2025-10-05T20:27:13 and 2025-10-05T21:28:45 UTC with a dense burst at 21:28:14–21:28:45 — indicative of scripted payload execution/automation (high priority).
- Persistence chain observed: registry autorun modifications at 2025-10-05T20:24:51–20:24:54 (3 events) and a Scheduled Task created at 2025-10-05T20:26:11 — likely used to maintain execution across reboots/sessions.
- Service-based persistence/privilege escalation: three "Rare Service Installations" at 2025-10-05T19:38:30, 19:38:37 and 20:12:14 — inspect service names and binary paths immediately.
- Account/group change: Security-enabled global group membership added at 2025-10-05T19:33:52 (EventID 4728) — potential unauthorized privilege elevation/persistence.
- Session/logoff anomalies: five user logoff events (EventID 4634/4647) at 19:34:41, 19:34:43, 19:47:54, 20:17:09 and 20:22:18 — may indicate script-driven session cleanup or lateral activity.
- Timeline summary + immediate recommendations (prioritized by risk & effort):
  1) Isolate affected host(s) now (High risk, Low effort).
  2) Collect volatile artifacts (PowerShell command lines, parent PIDs, task XML, registry keys, service binary paths, security event logs) before remediation (High risk, Medium effort).
  3) After collection, disable/remove scheduled task, revert autorun registry entries, and stop/remove suspicious services (High risk, Higher effort).
  4) Audit and remediate group membership changes and rotate potentially exposed credentials (High risk, Higher effort).

Key TTPs
- T1059.001 PowerShell (execution) — ~26 detections, many non-interactive + Base64 encoded commands.
- T1027 Obfuscated/encoded payloads (PowerShell Base64 patterns; defense-evasion).
- T1053.005 Scheduled Task/AT (scheduled task created at 2025-10-05T20:26:11).
- T1547.001 Registry autoruns (CurrentVersion / CurrentControlSet autorun key modifications at 20:24:51–20:24:54).
- T1543.003 Windows Service (rare service installations at 19:38:30/19:38:37/20:12:14).
- T1098 Account Manipulation (member added to global security group, 2025-10-05T19:33:52).
- T1531 (tagged with logoff events) — session/logoff impacts observed.

Notable IOCs (if any)
- No network addresses, file hashes, or account names provided in detections (no direct IOCs listed).
- Artifact locations/timestamps to collect as IOCs:
  - PowerShell commandlines and decoded payloads for events between 2025-10-05T20:27:13 and 2025-10-05T21:28:45.
  - Scheduled Task created at 2025-10-05T20:26:11 — collect task name and XML.
  - Registry autorun keys modified at 2025-10-05T20:24:51–20:24:54 — collect full key paths and new values.
  - Services installed at 2025-10-05T19:38:30, 19:38:37, 20:12:14 — collect service names, binary paths, creators.
  - EventIDs to review: 4728 (group add), 4634/4647 (logoff), 1 (PowerShell), 11 (Scheduled Task file creation), 13 (AppCompat/registry).

## Micro 2: Cluster Summary

Executive bullets
- PowerShell campaign: >=15 non-interactive / encoded PowerShell executions detected. Initial cluster 2025-10-05T21:28:45–21:28:47 (3 events); major spike 2025-10-06T16:41:07–16:41:48 (~10 events). (EventID 1; execution T1059.001)
- Scheduled-task persistence: 6 scheduled-task creation events — 2025-10-05T22:42:46, 2025-10-05T23:28:08, 2025-10-05T23:56:40 (×2), 2025-10-06T16:15:00, 2025-10-07T16:04:43. (EventID 11; T1053.005)
- Payload staging / binary drops: 9 "creation of an executable by an executable" events — 2025-10-05T21:52:11, 2025-10-05T22:42:51 and a dense cluster 2025-10-07T16:06:52–16:07:43. (EventID 11; T1587.001)
- Persistence & privilege escalation signs: 2 rare service installations (2025-10-05T22:21:42 & 2025-10-05T23:46:37), service terminated with error (2025-10-05T22:24:23), COM search-order hijack (2025-10-06T01:10:19), AppCompat new app (2025-10-06T17:20:42) and elevated system shell spawn (2025-10-06T16:23:20).
- Immediate high-priority triage (low effort): isolate affected host(s); collect PowerShell command lines, scheduled task XMLs, service install records, new executables and their parent process trees; capture memory + Windows event logs for 2025-10-05 → 2025-10-07; block PowerShell -EncodedCommand and restrict egress for suspect hosts.

Key TTPs (MITRE)
- T1059.001 — PowerShell: encoded/non-interactive executions observed (execution / defense evasion).
- T1053.005 — Scheduled Task/Job: multiple scheduled-task creations for persistence/privilege escalation.
- T1543.003 — Create or Modify System Process (Service): rare service installs indicating persistence/privilege escalation.
- T1546.015 — COM Search Order Hijacking: potential persistence via COM hijack (event 2025-10-06T01:10:19).
- T1587.001 & T1204.002 — Resource development / User execution: executable creation events (payload staging) and AppCompat new app (possible user-executed or user-triggered component).

Notable IOCs (if any)
- No file paths, hashes, IPs, or hostnames supplied in alerts. Key timestamps & counts to prioritize collection:
  - PS encoded spikes: 2025-10-05T21:28:45–21:28:47 (3); 2025-10-06T16:41:07–16:41:48 (~10).
  - Scheduled tasks: 2025-10-05T22:42:46; 2025-10-05T23:28:08; 2025-10-05T23:56:40 (×2); 2025-10-06T16:15:00; 2025-10-07T16:04:43.
  - Executable creation cluster: 2025-10-05T21:52:11, 2025-10-05T22:42:51, and 2025-10-07T16:06:52–16:07:43 (≈7 events).
  - Other notable times: service installs 2025-10-05T22:21:42 & 2025-10-05T23:46:37; COM hijack 2025-10-06T01:10:19; elevated shell 2025-10-06T16:23:20.

## Micro 3: Cluster Summary

Executive bullets
- Massive scripted activity: ~17 suspicious Base64-encoded PowerShell executions and ~9 non-interactive PowerShell process spawns observed between 2025-10-07T16:47:38 and 2025-10-07T17:06:33 (repeated bursts at ~16:47–16:48, ~16:52, ~16:59, final at 17:06:33).
- Account persistence: 2 New User Created via net.exe at 2025-10-07T16:47:38 and a Member added to a Security‑Enabled Global Group (EventID 4728) at 2025-10-07T16:47:38 — same-second sequence.
- Discovery/lateral tooling: 4 net.exe executions (timestamps ~2025-10-07T16:52:13 and 16:59:02) and Local Accounts Discovery events at 16:52:12, 16:52:32, 16:59:01.
- Early persistence/resource prep: Executable created by another executable at 2025-10-07T16:08:04 and Scheduled Task created at 2025-10-07T16:08:10.
- Privilege/defense-evasion: Elevated system shell spawned at 2025-10-07T16:10:46 and a “Godmode” Sigma detection at 2025-10-07T16:08:17 (indicative of privilege/configuration manipulation).
- Overall timeline: initial file/executable & scheduled-task activity ~16:08 → elevated shell ~16:10 → rapid account creation and heavy encoded PowerShell + discovery/lateral commands from ~16:47 onward.

Key TTPs (MITRE)
- Command and scripting: T1059 (T1059.001 PowerShell) — repeated Base64/encoded PowerShell execution and non-interactive shells.
- Persistence / Scheduled Task: T1053.005 — Scheduled task created at 2025-10-07T16:08:10.
- Account manipulation / persistence: T1136.001 (local account creation) and group modification T1098 (member added to global group) at 2025-10-07T16:47:38.
- Resource/tool development & delivery: T1587.001 (creation of executable by executable) and discovery T1087.001 / T1007 / T1049 (local account and service discovery via net.exe).

Notable IOCs (if any)
- Observable actions (no file hashes/IPs provided): repeated Base64-encoded PowerShell command execution (multiple timestamps listed above); multiple net.exe executions (~16:52:13, ~16:59:02); new local accounts and global-group membership at 2025-10-07T16:47:38; scheduled task created at 2025-10-07T16:08:10; executable-by-executable creation at 2025-10-07T16:08:04.
- Data gaps: logs contain no usernames, hostnames, file paths, command strings, file hashes or network IOCs — escalate collection/forensic capture (process command lines, parent PIDs, file artifacts, event log full details, endpoint network connections).

## Micro 4: Cluster Summary

• Executive bullets
- Time window: 2025-10-07T17:08:15 → 2025-10-07T18:15:40 UTC; activity clustered around 17:11–17:20 and 18:08–18:15.  
- PowerShell mass activity: 14 Suspicious "PowerShell with Base64" events and 14 Non‑interactive PowerShell spawns (first PS non‑interactive 2025-10-07T17:08:15; last base64 PS 2025-10-07T18:15:40).  
- Net.exe usage: 5 Net.EXE executions (pairs at 17:11:12 and 17:20:15; additional at 18:08:39) used for discovery/management.  
- Account reconnaissance: 4 Local Accounts Discovery events plus Whoami and Hostname executions (reconnaissance confirmed at 17:11, 17:20, 18:08–18:14).  
- Persistence/lateral signals: New local user created via Net.EXE at 2025-10-07T18:08:39.593150Z (Net.EXE + account creation + SMB/discovery tags present).

• Key TTPs
- T1059.001 — PowerShell (non‑interactive execution, encoded/base64 scripts) — execution and potential post‑exploitation scripting.  
- T1087.001 / T1033 — Local account discovery / user enumeration (Whoami, hostname, local account queries).  
- T1136.001 — Create local account (New User Created via Net.EXE at 2025-10-07T18:08:39).  
- T1021.002 / T1049 — SMB/remote service discovery and network discovery (Net.EXE used for discovery and potential lateral movement).

• Notable IOCs (if any)
- New local user creation: Net.EXE created account at 2025-10-07T18:08:39.593150Z (username not provided in alerts).  
- Net.EXE executions: 2025-10-07T17:11:12.123029, 17:11:12.134105, 17:20:15.006571, 17:20:15.018066, 18:08:39.615360.  
- PowerShell Base64 / non‑interactive bursts: 14 base64 execs + 14 non‑interactive spawns between 2025-10-07T17:08:15 and 2025-10-07T18:15:40 (no hashes or remote IPs provided).

Prioritized recommended actions (risk/effort — keep short)
- High risk / Low effort: Isolate affected hosts with repeated PS & Net.EXE activity; collect volatile artifacts (process command lines, parent PID, PowerShell decoded payloads) and disable newly created local account.  
- High risk / Medium effort: Hunt for same PowerShell Base64 payloads and Net.EXE usage across environment (EDR, SIEM) and block encoded PowerShell execution policy where appropriate.  
- Medium risk / Low effort: Review local and domain authentication logs for lateral movement around listed timestamps; change/rotate credentials for impacted machines.

## Micro 5: Cluster Summary

Executive bullets
- Repeated scripted execution: 11 non-interactive PowerShell spawns and 10 suspicious PowerShell runs with Base64 between 2025-10-07T18:15:46 and 2025-10-09T22:54:45 — high likelihood of automated malicious payload execution.
- Payload drop / setup activity: 5 "Creation of an executable by an executable" events clustered 2025-10-09T22:52:06–22:53:09 plus 3 AppCompat "New Application" entries (last at 2025-10-09T22:53:24) and a Godmode Sigma hit — indicates installation/registration of new binaries.
- Privilege/persistence indicators: Elevated system shell spawned at 2025-10-09T22:55:04 (privilege escalation/defense-evasion) and Scheduled Task created (file creation) at 2025-10-10T16:32:34 (persistence).
- Discovery behavior: Local account discovery observed twice (2025-10-07T18:16:03, 2025-10-09T22:54:35) and hostname query at 2025-10-08T15:10:12 — attacker reconnaissance attempts.
- Ancillary signals: Three Windows Update Error events (2025-10-07–10-09) and two user logoff events — may indicate attempted covert activity or service interference.

Key TTPs (MITRE)
- T1059.001 — PowerShell: automated, non-interactive and Base64-encoded executions (11 / 10 occurrences).
- T1587.001 & T1587 (resource-development) — Creation of executables by executables (5 events) and resource/setup activity.
- T1053.005 — Scheduled Task persistence (created 2025-10-10T16:32:34); T1059 (elevated shells) observed at 2025-10-09T22:55:04.
- T1033 / T1087.001 / T1082 — Account and host discovery (local accounts, hostname).

Notable IOCs (if any)
- PowerShell (Base64 / non-interactive) cluster: 2025-10-07T18:15:46 → 2025-10-09T22:54:45 (11 non-interactive, 10 Base64 executions).
- Executable creation cluster: 2025-10-09T22:52:06 → 2025-10-09T22:53:09 (5 CREATE_BY_EXEC events); AppCompat new app + Godmode detection at 2025-10-09T22:53:24.
- Privilege/persistence timestamps: elevated shell 2025-10-09T22:55:04; scheduled task created 2025-10-10T16:32:34; local account discovery 2025-10-07T18:16:03 & 2025-10-09T22:54:35.

Prioritized recommendations (risk → effort)
- High risk / low effort: Isolate affected host(s) observed 2025-10-09T22:50–22:58 and collect full memory + EDR telemetry for 22:50–23:00 window.
- High risk / medium effort: Hunt for and quarantine created executables (5 events) and disable/remove scheduled task; gather file hashes and block on prevention controls.
- Medium risk / low effort: Export PowerShell command lines/decoded Base64 for analysis; add detections to block similar PS command patterns.
- Medium risk / medium effort: Review privileged accounts and local account changes; reset credentials if lateral movement/persistence confirmed.

## Micro 6: Cluster Summary

Executive bullets
- Timeline summary: two distinct activity clusters — early lateral/coverup at ~2025-10-10T16:38–17:42Z and a concentrated execution+injection burst at ~2025-10-10T22:02–22:06Z.
- Early cluster (16:38–17:42Z): 2 user logoffs (16:38:36, 17:12:56) and concurrent lateral/discovery + event-log modification indicators — 3 suspicious EventLog clearing/config changes (17:40:08, 17:41:26, 17:42:07), 2 cmd.exe output redirects (17:40:32, 17:42:17), and 2 net.exe Windows share mounts (17:40:32, 17:42:17) — suggests lateral access and defense-evasion attempts.
- Execution burst (22:02:52–22:06:19Z): >= ~20 PowerShell encoded/base64 / non-interactive executions and related suspicious child-process events (multiple timestamps between 22:02:52 and 22:06:13) — rapid scripted execution and discovery (hostname observed at 22:02:55).
- Follow-on post-execution signs of injection/LOLBIN use: regsvr32 anomaly (22:03:04), remote thread created in Shell Application (22:05:09), suspicious rundll32 activity (22:06:16), and shell/scripting processes spawning suspicious programs (22:06:19) — indicates process injection and use of built-in binaries for defense evasion.

Key TTPs (MITRE)
- Execution via PowerShell: T1059.001 — encoded/base64 & non-interactive PowerShell spawn, multiple events (>= ~20) 2025-10-10T22:02:52–22:06:13Z.
- Lateral movement & discovery: T1021.002 (SMB/Windows share via net.exe), T1082 (System discovery — hostname exec at 22:02:55).
- Defense evasion / log tampering & disabling: T1070.001 (Clear Windows Event Logs), T1562.002 (Impeding/modify defenses); LOLBINs and service registration abuse: T1218.010 (regsvr32), T1218.011 (rundll32); process injection: T1055 (remote thread creation).

Notable IOCs (if any)
- Processes / binaries observed: PowerShell (encoded/non-interactive) — clustered 22:02:52–22:06:13Z (>= ~20 events); regsvr32.exe (22:03:04); rundll32.exe (22:06:16); net.exe mounts (17:40:32, 17:42:17); cmd.exe output redirects (17:40:32, 17:42:17); Shell Application remote thread (22:05:09).
- Event counts/timestamps: EventLog clearing x3 (17:40:08, 17:41:26, 17:42:07); net.exe mounts x2 (17:40:32, 17:42:17); logoffs x2 (16:38:36, 17:12:56); PowerShell sequence >= ~20 events (22:02:52–22:06:13).
- No network IPs, file hashes, or full command-lines provided in these detections — collect command-line strings, parent PID, source/target hostnames and network endpoints for IOC enrichment.

Prioritized recommended actions (by risk → effort)
- High risk / low effort: Isolate affected host(s) seen in the 22:02–22:06Z burst; preserve volatile data (memory/process list), collect full PowerShell command lines, parent PIDs, and relevant Windows event logs immediately.
- High risk / medium effort: Revoke/rotate credentials for accounts active during 16:38–17:42Z and 22:02–22:06Z; block SMB lateral paths used (source → targets) and restrict net.exe usage via AppLocker/WDAC where feasible.
- Medium risk / medium effort: Hunt across environment for matching encoded PowerShell commands, regsvr32/rundll32 anomalies, and evidence of remote thread/process injection (T1055); pivot from collected command-lines to identify additional compromised hosts.
- Low risk / higher effort: If compromise confirmed, plan remediation (full forensic imaging and rebuild) and review/strengthen logging/alerting for encoded PowerShell, event-log clears, and LOLBIN abuse.

## Micro 7: Cluster Summary

Executive bullets
- Two rapid, repeated attack bursts: 2025-10-10T22:49:59–22:50:19 UTC and 2025-10-10T22:53:39–22:53:48 UTC.  
- PowerShell-heavy activity: 26 PowerShell events (encoded/base64/non-interactive/child spawns) across the two bursts (~13 events per burst). (EventID 1 tags: attack.execution, T1059.001)  
- Encoded/Base64 PS usage repeated (multiple -EncodedCommand occurrences) — strong sign of scripted/obfuscated payload execution. (timestamps above)  
- Defense-evasion / signed-binary proxy use: Regsvr32 anomalies observed twice (22:50:11, 22:53:47). (attack.t1218.010)  
- Remote/local execution/persistence primitives: WMIC process creation (EventID 4688) seen twice (22:50:11, 22:53:47); Scheduled Task creation via schtasks.exe seen twice (22:50:18, 22:53:48).  
- Lateral-movement/discovery behaviors: net.exe share mount at 22:50:19 (attack.t1021.002) and hostname/CMD discovery indicators (CMD redirect and hostname calls at 22:50:02/22:50:19/22:53:41).  

Key TTPs (MITRE)
- T1059.001 — PowerShell execution (encoded, non-interactive, child processes) — primary vector (26 events).  
- T1218 / T1218.010 — Signed binary proxy execution via regsvr32 (2 events) and other system binaries.  
- T1047 — Windows Management Instrumentation / WMIC process creation (2 events).  
- T1053.005 — Scheduled Task creation via schtasks (2 events).  
- T1021.002 — SMB / Windows admin shares (net.exe mount).  
- T1082 — System information discovery (hostname, CMD output redirect).

Notable IOCs (if any)
- No explicit IPs, domain names, file hashes or user accounts provided in alerts.  
- Process/command IOCs observed: repeated powershell.exe with -EncodedCommand / base64 and non-interactive flags; regsvr32 anomalous invocation; wmic.exe process creation (EventID 4688); schtasks.exe creating scheduled tasks; net.exe mounting a share; CMD output redirect usage.  
- Key timestamps for triage/correlation: 2025-10-10T22:49:59–22:50:19 UTC and 2025-10-10T22:53:39–22:53:48 UTC.

## Micro 8: Cluster Summary

Executive bullets
- High-volume encoded PowerShell activity (~28 encoded/Non‑interactive PowerShell events) in two quick bursts: 2025-10-10T22:55:12–22:55:27 UTC and 2025-10-10T23:02:47–23:02:51 UTC — strong execution + obfuscation signal (multiple Base64/encoded command detections).
- Persistence/privilege/tool usage: Scheduled task creation via schtasks at 2025-10-10T22:55:27 UTC; WMIC process creation observed at 2025-10-10T22:55:26 and 2025-10-10T23:02:51; Regsvr32 anomalies at 22:55:26 and 23:02:51 — indicates attempts at persistence and defense‑evasion.
- Lateral movement and discovery: net.exe Windows share mounts at 2025-10-10T22:53:49 and 22:55:28; CMD shell output redirection and hostname queries at ~22:53:49, 22:55:16, 22:55:28, 23:02:48 — potential remote share access/credential use and environment reconnaissance.
- Windows shell/scripting processes repeatedly spawned suspicious programs (events clustered ~22:55:26–27 and 23:02:51) consistent with orchestrated post‑compromise activity across standard system binaries.

Key TTPs
- Execution / Obfuscated commands: T1059.001 (PowerShell — encoded/Base64), T1059.* (scripting interpreters), frequent non‑interactive child processes.
- Lateral movement & discovery: T1021.002 (SMB/Windows admin shares via net.exe), T1082 (System Information Discovery — hostname/OS queries).
- Persistence & defense evasion: T1053.005 (Scheduled Task via schtasks), T1218.010 (regsvr32 abuse), T1047 (WMI/wmic), overall use of signed system utilities (living-off-the‑land).

Notable IOCs (if any)
- Process names repeatedly observed: powershell.exe (encoded/Base64, non‑interactive), net.exe (share mounts) — 2 mount events (22:53:49, 22:55:28), cmd.exe (output redirect) — 2 events (22:53:49, 22:55:28), schtasks.exe (task creation 22:55:27), wmic.exe (process create at 22:55:26 & 23:02:51), regsvr32.exe anomalies (22:55:26 & 23:02:51).
- No IP addresses, hostnames, or file hashes supplied in detections; relevant artifacts to collect: full PowerShell command lines (decoded), scheduled task XML, process trees/parent PIDs, SMB session/auth logs, and EDR telemetry for the timestamped bursts.

Prioritized recommendations (by risk & effort)
- Immediate (High risk, low effort): Identify and isolate affected endpoint(s) showing the two PowerShell bursts; preserve volatile data (memory, running processes, process tree, PowerShell command logs) and pull full EDR/Windows event logs for the timestamps.
- Contain & investigate (High risk, medium effort): Terminate malicious processes if active, export and disable suspicious scheduled tasks, collect schtasks XML and WMIC command lines, review authentication logs for lateral logins to SMB shares, and hunt for same encoded PowerShell patterns enterprise‑wide.
- Remediate & prevent (Medium risk, higher effort): Restrict/whitelist regsvr32/wmic/schtasks usage via AppLocker or WDAC where possible, enforce/enable PowerShell logging (Module, Script_Block, Transcription) and block encoded command usage, rotate any exposed credentials and tighten SMB share permissions.

## Micro 9: Cluster Summary

Executive bullets
- Summary: 40 related events on 2025-10-10 between 2025-10-10T23:02:54 and 2025-10-10T23:15:19; activity clustered at ~23:02:54, ~23:06:33–23:06:46 and ~23:15:14–23:15:19.
- PowerShell mass execution: ~27 PowerShell events (encoded/base64, non-interactive, child processes) in two bursts (~13 events at 23:06:33–23:06:42; ~14 events at 23:15:14–23:15:19) — high-likelihood of scripted/automated post‑exploitation.
- Persistence & scheduled tasks: schtasks.exe used to create scheduled tasks (2 events: 23:02:54, 23:06:46) — probable persistence (also flagged privilege escalation).
- Defense-evasion / signed-binary abuse: regsvr32 anomalies (2 events: 23:06:42, 23:15:19) and multiple detections of Windows shell/scripting spawning suspicious programs (3 events) indicating proxy execution.
- Lateral movement & discovery: net.exe used to mount shares twice (23:02:54, 23:06:46) and hostname/system-info discovery (t1082) observed twice; cmd output redirection seen twice — likely credential or data collection attempts.
- Other notable execution methods: WMIC-created process at 23:06:42 (1 event) and CMD output redirect & shell spawning (multiple events) — several native utilities used for execution/triage evasion.

Key TTPs
- Execution / scripting: PowerShell encoded execution (T1059.001), CMD/shell scripting (T1059.005); WMI execution (T1047).
- Persistence / scheduled task: Scheduled Task via schtasks.exe (T1053.005).
- Defense evasion / signed‑binary proxy: regsvr32 and other t1218 family (T1218, T1218.010).
- Lateral movement / SMB: Windows share mount via net.exe (T1021.002).
- Discovery: System information / hostname enumeration (T1082).

Notable IOCs (artifacts observed)
- Executables/flags: powershell (encoded/base64, non-interactive) — ~27 events (23:06:33–23:06:42; 23:15:14–23:15:19); schtasks.exe (2 events: 23:02:54, 23:06:46); regsvr32 (2 events: 23:06:42, 23:15:19); net.exe (share mounts x2); wmic.exe (1 event at 23:06:42); cmd.exe output redirection (2 events); generic shell/scripting spawn events (3).
- No external IPs, hostnames, file hashes or accounts provided in detections — collect process command-lines, parent PIDs, and logon/account context immediately.

Prioritized recommendations (by risk & effort)
- High risk / low effort: Isolate the affected host(s) immediately; collect volatile artifacts (ps lists, netsessions, open SMB connections, running processes, command lines, scheduled tasks, Windows Event logs for 4688/4689/4702) and preserve disk image.
- High risk / medium effort: Hunt for lateral movement — check SMB mounts, account authentication logs, recent remote logons, and other hosts with same schtasks/encoded PowerShell indicators; block identified accounts/credentials.
- Medium risk / low effort: Extract full PowerShell command-lines (decode Base64), regsvr32 command arguments, and WMIC command strings to identify payloads or C2 indicators.
- Medium risk / medium effort: Revoke/rotate credentials used on the host(s), reset privileged accounts if evidence of compromise; deploy or tighten logging/EDR policies to capture scripted/encoded PowerShell and parent-child process chains.

## Micro 10: Cluster Summary

Executive bullets
- Summary: 40 detections between 2025-10-10T23:15:19Z and 2025-10-10T23:23:03Z showing coordinated activity: heavy encoded/non-interactive PowerShell, scheduled task creation, WMIC process launches, regsvr32 anomaly, and SMB share mounts.
- Volume by category: ~25 PowerShell-related events (encoded/-EncodedCommand/non-interactive), 4 Windows shell/scripting spawn alerts, 2 WMIC process-creates, 2 schtasks-created, 2 net.exe (share mount) events, 2 cmd output-redirects, 1 regsvr32 anomaly, 2 hostname discovery events.
- Timeline clusters: initial staging at 23:15:19–23:15:22 (WMIC, schtasks, net use, cmd redirect); heavy execution/persistence at 23:18:22–23:18:43 (bulk encoded PS, regsvr32, schtasks, WMIC); repeat execution at 23:22:54–23:23:03 (more encoded PS).
- Likely intent: remote code execution + defense evasion (encoded PowerShell, regsvr32), persistence (Scheduled Task), lateral movement (SMB share mounts), and discovery (hostname/system enumeration).
- Triage priority: treat as active compromise — encoded PowerShell + scheduled tasks + regsvr32 indicate immediate containment required.
- Immediate actions (high risk / low effort): isolate affected host(s); collect volatile evidence (memory, running processes, scheduled tasks, event logs 4688/Windows PowerShell/commandline); list mounted shares and active sessions; snapshot/kill suspicious processes; block regsvr32/wmic/schtasks invocation patterns and base64 PowerShell in EDR.

Key TTPs
- Execution via obfuscated PowerShell: T1059.001 (PowerShell) — ~25 events showing -EncodedCommand / non-interactive instances.
- Signed-binary / native utility misuse: T1218 / T1218.010 (regsvr32) and T1218 (WMIC/schtasks usage via cmd/WMIC) — WMIC (2), schtasks (2), regsvr32 (1).
- Persistence & privilege escalation: T1053.005 (Scheduled Task) — 2 scheduled-task creation events.
- Lateral movement & discovery: T1021.002 (SMB/Windows admin share mounts via net.exe) and T1082 (System/hostname discovery) — net use (2), hostname queries (2).

Notable IOCs (if any)
- Suspicious binaries invoked (counts): powershell.exe (~25 encoded/non-interactive launches), wmic.exe (2 process-creates), schtasks.exe (2 task creations), regsvr32.exe (1 anomaly), net.exe (2 share mounts), cmd.exe (2 output redirects).
- No file hashes, IPs, usernames, or file paths provided in detections — collect command lines, task names, scheduled task XML, process commandlines, and EDR telemetry for precise IOCs.

## Micro 11: Cluster Summary

Executive bullets
- High-volume PowerShell execution: ~22 encoded / non-interactive PowerShell events detected across 2025-10-10 → 2025-10-13. Major clusters: 2025-10-11T21:54:21–21:54:39 (≈14 events) and 2025-10-13T22:24:10–22:24:14 (≈6 events); additional hits at 2025-10-10T23:23:04 and 2025-10-13T21:47:22.
- Persistence activity: Scheduled task creation observed 2025-10-10T23:23:10 and 2025-10-13T16:12:38 (file creation). New Run key added 2025-10-11T21:55:13 pointing to a suspicious folder.
- Lateral/remote actions: WMIC spawned suspicious processes at 2025-10-10T23:23:04 and 2025-10-11T21:54:37; net.exe mounted a Windows share at 2025-10-10T23:23:16 — consistent with lateral movement attempts.
- Defense-evasion & tampering: regsvr32 / rundll32 invocations at 2025-10-10T23:23:04 and 2025-10-11T21:54:36; event log clearing/config change at 2025-10-11T21:54:16; CMD stream redirection at 2025-10-11T21:45:15 and 2025-10-10T23:23:16. Encoded PowerShell + non-interactive shells indicate obfuscation.
- Immediate prioritized recommendations (risk ↓ / effort ↑):
  1) High risk / low effort: isolate affected host(s) showing clustered PowerShell + schtasks + Run key activity; preserve volatile data (command lines, process trees, scheduled task XML, registry hives, eventlog backups).
  2) Medium risk / low‑medium effort: search SIEM/EDR for the listed timestamps, duplicate PowerShell base64 patterns, regsvr32/rundll32, WMIC spawns and schedule creation across estate; block or quarantine matching binaries/processes.
  3) Medium risk / medium effort: disable/limit regsvr32/rundll32 and restrict PowerShell (ConstrainedLanguage, module logging, script block logging); remove suspicious scheduled tasks and Run key after collection.
  4) High effort / high risk: credential reset and lateral containment if WMIC/SMB mounts show account misuse; full host forensic triage if persistence confirmed.

Key TTPs (MITRE IDs)
- Execution: PowerShell (T1059.001), Windows command/shell (T1059.005), WMIC remote execution (T1047).
- Persistence: Scheduled Tasks (T1053.005), Registry Run Keys (T1547.001).
- Defense evasion / tampering: Regsvr32 (T1218.010), Rundll32 (T1218.011), Encoded/obfuscated commands & stream redirection (T1564.004), Event Log Clearing (T1070.001 / T1562.002).
- Lateral movement / discovery: SMB/Windows share mount (T1021.002), Local accounts discovery (T1087.001 / T1033), System information discovery (T1082).

Notable IOCs (if any)
- Artifacts & timestamps to collect immediately: Run key added 2025-10-11T21:55:13 (points to suspicious folder); Scheduled tasks created 2025-10-10T23:23:10 and 2025-10-13T16:12:38; WMIC process creations 2025-10-10T23:23:04 & 2025-10-11T21:54:37; regsvr32/rundll32 executions 2025-10-10T23:23:04 & 2025-10-11T21:54:36; net.exe share mount 2025-10-10T23:23:16; event log clearing 2025-10-11T21:54:16; ~22 encoded PowerShell events clustered 2025-10-11T21:54 and 2025-10-13T22:24.
- NOTE: detections contain no explicit IPs, file hashes, usernames or full file paths — collect process command-lines, scheduled-task XML, registry values and EDR network artifacts to extract concrete IOCs.

## Micro 12: Cluster Summary

Executive bullets
- Large, coordinated PowerShell activity: ≳20 non-interactive / encoded-PS events (NonInteractive, -EncodedCommand, encoded patterns, suspicious child processes) in three bursts — 2025-10-13T22:24:14–22:24:30, 22:30:41–22:30:47, 22:33:43–22:33:44.
- Scripting/native tool abuse + persistence: multiple Windows shell/scripting processes spawning suspicious programs (events at 22:24:22–24, 22:30:43–44, 22:33:44), Regsvr32 and Rundll32 anomalies (~22:24:20–21), Suspicious Schtasks types at 22:24:20 and 22:30:42, and a new RUN registry key created at 22:24:30.
- Defense-evasion/discovery indicators: Event log clearing/config change at 22:33:43 (clear or config change) and CMD shell output redirect at 22:30:47 — suggests active cover-up and discovery of system info.

Key TTPs
- T1059.001 — PowerShell: widespread non-interactive and Base64/EncodedCommand executions (primary vector).
- T1059.005 / T1218 (T1218.010 regsvr32, T1218.011 rundll32) — Windows cmd/scripting + signed binary abuse to execute payloads.
- T1053.005 / T1547.001 — Scheduled task anomalies and Registry Run key persistence created.
- T1070.001 / T1562.002 / T1082 — Event log clearing/alteration (defense evasion) and discovery (CMD output redirect / system/info enumeration).

Notable IOCs (if any)
- Processes/tools observed: PowerShell (NonInteractive, -EncodedCommand), regsvr32, rundll32, schtasks, cmd.exe.
- Encoded PowerShell payloads: repeated Base64/EncodedCommand usage across the three bursts (timestamps above) — immediate decode of captured command lines recommended.
- Persistence / timeline points: New RUN registry key at 2025-10-13T22:24:30; Suspicious schtasks at 2025-10-13T22:24:20 and 22:30:42; Event-log clearing at 2025-10-13T22:33:43.

Prioritized recommendations (by risk & effort)
- Immediate / High risk, Low–Med effort: Isolate affected host(s); collect volatile artifacts now (full memory capture, PowerShell command-line history, all relevant EVTX, Scheduled Tasks export, registry hives for Run keys, running processes); stop/disable suspicious scheduled tasks and remove the new RUN key.
- Medium / Lower immediacy: Decode all captured EncodedCommand payloads, hunt across estate for identical encoded patterns / command-lines / timestamps, search for additional persistence and C2 indicators; increase script-execution logging and block or constrain regsvr32/rundll32 where feasible.

## Micro 13: Cluster Summary

Executive bullets
- Rapid, repeated PowerShell use: >=25 PowerShell-related events (including ~11 explicit "Base64" executions) in three bursts on 2025-10-13 at ~22:33:51–22:33:56Z, ~22:52:29–22:52:52Z, and ~23:05:35–23:05:43Z — consistent with scripted/automated execution.
- Persistence/scheduler activity: schtasks.exe used to create tasks (2025-10-13T22:33:44Z) and suspicious schtasks schedule types observed (22:52:48Z); Registry Run key added pointing to a suspicious folder at 2025-10-13T22:52:53Z.
- Living-off-the-land and management tools observed: wmic.exe spawned a process at 22:33:48Z; suspicious rundll32 activity at 22:33:45Z and 23:05:42Z — possible proxy execution.
- Defense evasion: Event log clearing/configuration change at 2025-10-13T22:52:29Z and multiple signs of encoded/obfuscated PowerShell use — indicates active log tampering and evasion.
- Scope/visibility note: ~40 detections total; Godmode Sigma rule fired at 22:33:56Z. No file hashes, hostnames, users or network IOCs included in the provided alerts — further collection required before full attribution.

Key TTPs (MITRE)
- Execution: T1059.001 PowerShell (encoded/non-interactive), T1059.005 Windows shell/scripting.
- Persistence / Scheduling: T1053.005 Scheduled Task (schtasks), T1547.001 Registry Run Keys.
- Lateral/Management / Proxy execution: T1047 WMI (wmic), T1218 / T1218.011 Signed-binary proxy execution (rundll32).
- Defense evasion / log manipulation: T1070.001 Clear Windows Event Logs; T1562.002 (tagged in alerts).

Notable IOCs (if any)
- Processes/artifacts and timestamps: schtasks.exe creation (2025-10-13T22:33:44Z); schtasks schedule types (22:52:48Z); powershell.exe (>=25 encoded/non-interactive events between 22:33–23:05Z); wmic.exe new-process (22:33:48Z); rundll32.exe suspicious calls (22:33:45Z, 23:05:42Z); Registry Run key pointing to suspicious folder (22:52:53Z); Godmode indicator (22:33:56Z).
- Missing: no hashes, hostnames, user accounts, command-line strings or network IOCs in the provided data — treat as high-priority collection tasks.

Prioritized recommendations (risk vs effort)
- Immediate / High risk, Low effort: Isolate affected host(s) and snapshot volatile data now (PowerShell logs/commandlines, Sysmon/4688 process events, Task Scheduler XML, HKLM/HKCU Run keys, Windows Event Log, running process list, memory dump).
- Short term / Medium effort: Preserve evidence (disk image, memory), export scheduled task definitions, capture the exact PowerShell Base64 strings and decode for payload/IOC extraction; collect process parent/child chains and user context.
- Hunt / Medium effort: Search environment for identical encoded PowerShell strings, same Run key target, schtasks/wmic/rundll32 activity and lateral artifacts; prioritize endpoints with matching indicators.
- Remediate / Lower immediacy (after collection): Disable/remove malicious scheduled task and Run key, clean impacted hosts, tighten EDR/IDS rules to block encoded PowerShell and monitor/deny proxy-execution via rundll32/wmic; rotate creds if lateral movement suspected.

## Micro 14: Cluster Summary

Executive bullets
- Large concentrated burst of obfuscated PowerShell activity (~25 PowerShell-related events) between 2025-10-13T23:05:44 and 2025-10-15T17:56:21, peak 2025-10-14T02:04:58–02:06:03 UTC (many Base64/encoded cmdlines, non-interactive ps spawns).
- Persistence changes: CurrentVersion autorun key modified at 2025-10-13T23:05:45.787518 and PowerShell run-key written at 2025-10-14T02:06:03.830076 (EventID 13).
- Defense-evasion: Event log clearing/config change at 2025-10-14T02:04:58.100501 plus regsvr32/rundll32 anomalies 02:05:17–02:05:53 indicating log tampering and LOLBIN abuse.
- Execution + lateral movement: Windows scripting spawned suspicious programs repeatedly (02:05:15–02:06:00) and net.exe performed a Windows share mount at 2025-10-14T02:05:21.814781 (possible lateral access).
- Scope unclear (no host/user identifiers provided); last related PS seen 2025-10-15T17:56:21 and a user logoff at 2025-10-15T17:50:04 — treat as active compromise until host-level triage completes.

Key TTPs
- T1059.001 (PowerShell): widespread encoded/Base64 and non-interactive PowerShell execution — primary execution vector (~25 events).
- T1547.001 (Registry Run Keys/Startup Folder): Registry autorun/Run key modifications observed (EventID 13).
- T1070.001 / T1562.002 / T1218.* (Defense evasion & LOLBIN misuse): Eventlog clearing (T1070.001), regsvr32/rundll32 anomalies and Windows scripting (T1218.010/011, T1059.005) used for evasion/abuse.

Notable IOCs (if any)
- Registry changes: CurrentVersion autorun mod 2025-10-13T23:05:45.787518; PowerShell in Run keys 2025-10-14T02:06:03.830076 (EventID 13).
- Eventlog clearing/config change timestamp: 2025-10-14T02:04:58.100501 (investigate gap prior to PS burst).
- Lateral movement artifact: net.exe share mount at 2025-10-14T02:05:21.814781; multiple process creation events with Base64-encoded PS — decode payloads to extract C2 domains/IPs and file paths.

Prioritized recommendations (risk / effort)
- High risk / moderate effort: Immediately isolate affected host(s), collect volatile data (memory, running processes, parent/child process trees at the noted timestamps), and capture disk image; block identified outbound endpoints and disable execution of encoded PowerShell via GPO/AMSI where possible.
- Medium risk / low–moderate effort: Hunt environment for the above timestamps, registry Run/CurrentVersion modifications, and net.exe share mounts; decode Base64 payloads from logs to identify binaries/C2 and remove/revert autorun entries.
- Low risk / low effort: Rotate credentials used on implicated hosts, enable enhanced logging (Process Creation with commandline, Sysmon), and monitor for reoccurrence.

## Micro 15: Cluster Summary

Executive bullets
- Large burst of encoded PowerShell activity: ~24 PowerShell-related detections (encoded/base64, non-interactive spawns, child-process anomalies) between 2025-10-15T17:56:30 and 2025-10-15T18:01:21 — high likelihood of scripted remote execution (see t1059.001).
- Host discovery observed: hostname queries and CMD output redirect at 2025-10-15T17:56:25 / 17:57:21 / 17:58:03 (attack.discovery, t1082) — attacker likely enumerating environment.
- Persistence attempts: Scheduled Task creation via schtasks.exe at 2025-10-15T17:57:34 and a FileCreation record for a Scheduled Task at 2025-10-16T00:13:21 (attack.persistence, t1053.005).
- Lateral/movement staging: Windows share mount via net.exe at 2025-10-15T17:58:04 and process creation via wmic.exe at 2025-10-15T17:57:32 (attack.t1021.002, t1047) — potential SMB/remote execution attempts.
- Living-off-the-land / defense-evasion tooling: Regsvr32 anomaly at 2025-10-15T17:57:31 and multiple Windows shell/scripting processes spawning suspicious programs around 17:57:33–17:57:34 (t1218.010, t1218, t1059.005).
- Impact/other: Windows Update error at 2025-10-15T18:02:06 (t1584) and user logoff at 2025-10-16T00:33:42 — may indicate disruption or cleanup activity.

Key TTPs
- Execution: PowerShell encoded/commandline execution (T1059.001) — repeated non-interactive launches and encoded payloads.
- Persistence & Privilege: Scheduled Task creation (T1053.005) and possible privilege escalation behavior (schtasks, task file creation).
- Lateral/Discovery/Defense evasion: SMB share mounting (T1021.002), WMI execution (T1047), Regsvr32 living-off-the-land (T1218.010), host discovery (T1082).

Notable IOCs (processes/timestamps)
- Process names observed: powershell.exe (encoded/base64), regsvr32.exe (2025-10-15T17:57:31), wmic.exe (2025-10-15T17:57:32), net.exe (share mount 2025-10-15T17:58:04), schtasks.exe (task creation 2025-10-15T17:57:34), cmd.exe (output redirect 2025-10-15T17:58:03).
- Counts/timing: ~24 PowerShell-related detections clustered 2025-10-15T17:56:30–18:01:21; scheduled task events at 2025-10-15T17:57:34 and 2025-10-16T00:13:21.
- No external IPs, file hashes, or filenames provided in detections — collect process command lines, task names, created files, and any network endpoints immediately.

Prioritized recommendations (by risk then effort)
- Immediate / high risk, low effort: Isolate affected host(s); capture volatile artifacts (memory, running processes, network connections) and collect Event Logs for 2025-10-15 17:50–18:10 and 2025-10-16 00:00–00:40.
- High risk, moderate effort: Extract full PowerShell commandlines/decoded payloads, scheduled task definitions, and regsvr32/WMI command arguments for IOC/hunting and detonation analysis.
- Medium risk, low effort: Block/monitor execution of encoded PowerShell (-EncodedCommand) and disable regsvr32 usage via AppLocker/WDAC where feasible; tighten logging for Process Creation and PowerShell Module Logging.
- Low effort maintenance: Audit recent lateral authentication and SMB accesses from the host(s) seen on 2025-10-15T17:57–17:58; rotate any exposed credentials if found.

## Micro 16: Cluster Summary

Executive bullets
- Two multi-event suspicious activity clusters:
  - Cluster A (2025-10-23 00:00–00:04 UTC): ~20+ PowerShell encoded / non-interactive spawns (Base64 patterns), remote thread creation (00:00:24), BITS file download to a suspicious folder (00:03:05), new RUN key (00:03:40), local account enumeration (00:03:42 & 00:03:45), scheduled-task creation just prior (2025-10-22 23:57:49). Indicators show execution → persistence → discovery.
  - Cluster B (2025-10-24 15:28–15:52 UTC): scheduled task created (15:28:05), user logoff (15:50:54), eventlog clearing/config change (15:52:07), then ~5–7 encoded/non-interactive PowerShell events around 15:52.
- Behavioral summary: repeated encoded PowerShell (non-interactive) used to spawn/shell to other binaries, BITS used to fetch payload, registry RUN key and scheduled tasks created for persistence, event log manipulation for defense evasion, and local account discovery — consistent with a post‑compromise automation chain.

Key TTPs (MITRE)
- Command and scripting interpreter — PowerShell (T1059.001): repeated Base64/encoded executions and non-interactive spawns (multiple timestamps in both clusters).
- Scheduled tasks (T1053.005) and Registry Run Keys (T1547.001): scheduled task events 2025-10-22T23:57:49 & 2025-10-24T15:28:05; RUN key created 2025-10-23T00:03:40.
- BITS file transfer (T1197) and binary proxy execution (T1218 / T1036.003): BITS download to suspicious folder (2025-10-23T00:03:05); multiple shell/scripting spawns pointing to suspicious programs.
- Process injection / remote thread (T1055): Remote thread created in shell app (2025-10-23T00:00:24).
- Event log clearing / tampering (T1070.001 / T1562.002): Suspicious eventlog clearing/config change (2025-10-24T15:52:07).
- Account discovery (T1087.001) and potential impact-related actions (T1531): Local accounts enumeration (2025-10-23T00:03:42 & 00:03:45); user logoffs at both clusters.

Notable IOCs (if any)
- Scheduled Task creations: 2025-10-22T23:57:49.537016Z and 2025-10-24T15:28:05.753110Z (EventID 11).
- Registry RUN key created: 2025-10-23T00:03:40.649638Z (EventID 13) — points to suspicious folder (no path provided).
- BITS download to suspicious target folder: 2025-10-23T00:03:05.052482Z (EventID 1).
- Event log clearing/config change: 2025-10-24T15:52:07.605471Z (EventID 1).
- No file hashes, IPs, or command-line strings supplied in detections — capture endpoints for these artifacts immediately.

Prioritized recommendations (risk → effort)
- High risk / Low effort: Isolate affected hosts from network, collect volatile artifacts (Process listings, PowerShell command lines, parent/child PIDs, scheduled task XML, RUN key values, BITS job list, Windows Event Log segments) and preserve disk images. (Immediate)
- High risk / Medium effort: Hunt for matching Base64 PowerShell, scheduled tasks, RUN keys, BITS jobs, and event-log tamper on other hosts (central EDR/Log search across past 48–72 hrs); look for lateral movement indicators and reaped credentials.
- Medium risk / Higher effort: Reconstruct decoded PowerShell payload(s), analyze downloaded files (sandbox + static), rotate high‑privilege credentials if discovery indicates account compromise, and remediate persistence (remove tasks/registry entries) after containment.

## Micro 17: Cluster Summary

Executive bullets
- Mass encoded/non-interactive PowerShell activity: ~26 EventID 1 alerts (base64/encoded/non-interactive/child-process patterns) between 2025-10-24T15:52:21 and 2025-10-24T15:55:52 — likely scripted remote code execution.
- Shell/scripting spawning suspicious programs + schtasks: 4 Windows shell/scripting spawn events and a scheduled-task creation at 2025-10-24T15:53:42 — indicates persistence + execution staging.
- Registry persistence evidence: 2 RUN key modifications referencing PowerShell/suspicious folder at 15:52:33 and 15:53:57 (EventID 13).
- Discovery activity: Local account enumeration seen 5 times (15:52:33–15:53:59) and hostname/system info query at 15:52:22 — likely internal reconnaissance.

Key TTPs
- T1059.001 PowerShell (encoded/obfuscated, non-interactive, child processes) and T1059.005 command shell usage — primary execution vector.
- T1218 family (signed-binary proxy execution): regsvr32 T1218.010 (2 anomalies) and rundll32 T1218.011 (1 event) — defense evasion/living-off-the-land.
- Persistence & scheduling + discovery: T1547.001 Registry Run Keys (2 events), T1053.005 Schtasks (1 event), T1087.001 Local Account Discovery, T1082/T1033 system/hostname discovery.

Notable IOCs (if any)
- PowerShell: ~26 encoded/Non‑interactive exec events, first 2025-10-24T15:52:21, last 15:55:52 (EventID 1).
- Registry RUN keys: new RUN key -> suspicious folder at 2025-10-24T15:52:33; PowerShell in Run keys at 2025-10-24T15:53:57 (EventID 13).
- Proxy/signed-binary events: rundll32 at 2025-10-24T15:52:27; regsvr32 anomalies at 15:52:27 and 15:53:42; schtasks creation at 15:53:42.

Prioritized recommendations (ranked by risk and effort)
- Immediate (High risk, low effort): Isolate affected host(s); collect live artifacts (process list, full command lines, PowerShell transcription/Module logs, Sysmon/Event logs covering 15:52–15:56, registry Run keys, scheduled tasks); block encoded PowerShell via policy and prevent regsvr32/rundll32 use with AppLocker/EDR if possible.
- Investigation & remediation (High risk, medium effort): Remove unauthorized Run keys and scheduled tasks, perform credential/ lateral-movement hunt tied to those timestamps, reset impacted privileged credentials, scan environment for same indicators/patterns, enable/strengthen PowerShell logging and EDR prevention rules.

## Micro 18: Cluster Summary

• Executive bullets
- Two concentrated bursts of scripted activity: many encoded/non-interactive PowerShell executions in ~15:55:54–15:56:10 and ~16:08:07–16:08:21 (≈20–25 PS encoded/base64 events total).
- Repeated use of signed-binary proxy techniques: rundll32 and regsvr32 observed spawning unusual/unknown DLLs and child processes (multiple events across both bursts).
- Additional attacker behaviors consistent with lateral/automation: a single suspicious schtasks entry (15:56:02.513618), a new Run key pointing to a suspicious folder (15:56:10.163065), and a WMIC-created process (16:08:18.319585).
- Discovery activity concurrent with execution: local account enumeration (15:56:10.231815) and hostname retrieval (16:08:10.978166).
- Triage priority (high risk / low effort first): isolate affected host(s), capture memory/process tree and PowerShell command lines, export Run key + scheduled task details, collect relevant event logs and parent/child PIDs for triage.

• Key TTPs (MITRE)
- T1059.001 — PowerShell execution: encoded/base64 and non-interactive PS processes (primary mechanism; ~20–25 events).
- T1218 family — Signed binary proxy execution: rundll32 (t1218.011; uncommon DLL ext seen) and regsvr32 (t1218.010) used to execute payloads.
- T1053.005 — Scheduled Task (Schtasks) used for persistence/automation (15:56:02.513618).
- T1547.001 — Registry Run Keys for persistence (Run key created at 15:56:10.163065).
- T1047/T1082/T1087.001/T1033 — WMIC (t1047) process creation and discovery (hostname, local accounts).

• Notable IOCs (if any)
- Timestamps of high-value artifacts to collect: PS encoded commands around 15:55:54–15:56:10 and 16:08:07–16:08:21 (capture full cmdlines to decode).
- Persistence indicator: Run key created 2025-10-24T15:56:10.163065+00:00 (points to suspicious folder — export registry value and target path).
- Proxy binaries/processes observed: regsvr32 (15:56:07.615159; 16:08:19.321209), rundll32 (15:56:01.947046; 16:08:18.126408), wmic (16:08:18.319585), schtasks (15:56:02.513618). No file hashes, filenames, network IOCs or URLs provided — collect command lines, parent PIDs, executable paths, and any associated DLL names.

## Micro 19: Cluster Summary

Executive bullets
- Two concentrated bursts of encoded/non-interactive PowerShell abuse: ~14 PowerShell events between 2025-10-24T16:08:22–16:09:30 and ~15 between 2025-10-25T00:08:19–00:08:39 (total ~29 PS-related detections: encoded/Base64, encoded-command patterns, non-interactive PS spawns, PS child-processes).
- Signed-binary proxy / script host misuse and process creation around the first burst: wmic.exe spawned (2025-10-24T16:09:22), regsvr32 anomaly (2025-10-24T16:09:23), Windows shell/scripting spawning suspicious programs (2025-10-24T16:09:25 and 2025-10-25T00:08:35/00:08:38).
- Evidence of process injection/remote-thread activity: Remote thread created in shell application (2025-10-24T18:27:10; EventID 8 → t1055). Suspicious rundll32 activity recorded (2025-10-25T00:08:36; EventID 4688).
- Possible discovery/cleanup activity: CMD output redirect and user logoff at 2025-10-25T00:06:22; hostname queried/executed at 2025-10-25T00:08:28. Godmode Sigma rule fired at 2025-10-24T16:08:24 (context required).

Key TTPs (MITRE)
- T1059.001 — PowerShell: repeated encoded/non-interactive PowerShell execution and child spawns (~29 events across two bursts).
- T1218 / T1218.010 / T1218.011 — Signed binary proxy execution: regsvr32, rundll32, other scripting hosts observed.
- T1047 — WMI execution: new process created via wmic.exe (2025-10-24T16:09:22).
- T1055 — Process injection: remote thread created in shell application (2025-10-24T18:27:10).
- T1082 — System/host discovery: hostname execution detected (2025-10-25T00:08:28).
- T1531 (tagged) — Impact/cleanup indicators: user logoff at 2025-10-25T00:06:22; CMD output redirect.

Notable IOCs (if any)
- Processes/programs of interest: wmic.exe spawn (2025-10-24T16:09:22), regsvr32 anomaly (2025-10-24T16:09:23), rundll32 activity (2025-10-25T00:08:36), repeated non-interactive PowerShell invocations (timestamps above).
- Behavior IOCs: encoded/Base64 PowerShell command lines and encoded command patterns (two concentrated bursts); Windows shell/scripting spawning suspicious programs (16:09:25; 00:08:35/00:08:38); CMD output redirected (00:06:22).
- No network/URL/IP or file-hash IOCs provided in the detections; collect artifacts for enrichment.

Prioritized recommendations (by risk then effort)
- High risk / moderate effort: Isolate affected endpoints (those with PS encoded runs, wmic/regsvr32/rundll32 activity), preserve memory, PowerShell logs (ModuleLogging/ScriptBlockLogging), Sysmon/Windows event logs, and relevant process trees and command lines.
- High impact / moderate effort: Extract full decoded PowerShell script content (from ScriptBlock/AMSI logs or collected memory) and search enterprise for same command hashes/strings and arrival times.
- Medium risk / low effort: Hunt for lateral movement indicators (recent logons, remote execution events), enumerate scheduled tasks, services, Run keys, and open network connections on affected hosts.
- Medium-high impact / higher effort: Enforce/enable PowerShell logging policies, restrict regsvr32/wmic/rundll32 via AppLocker/WDAC or block execution from user-writable locations; apply least-privilege and credential hygiene reviews.

## Micro 20: Cluster Summary

Executive bullets
- Two activity clusters: 2025-10-25T00:08:39–00:08:41 (3 detections) and a large burst 2025-10-25T13:23:23–13:39:32 (≈37 detections), concentrated 2025-10-25T13:38:48–13:39:32.
- Heavy scripted execution: extensive encoded/BASE64 and non-interactive PowerShell activity during the 13:38–13:39 window (≥20 PowerShell-related detections, including ≥6 explicit "Base64" executions and multiple encoded-pattern detections).
- Persistence/privilege-elevation indicators: Scheduled Task created at 2025-10-25T13:23:23; Suspicious Registry Run Keys flagged at 2025-10-25T00:08:41 and 2025-10-25T13:39:01.
- Living-off-the-land / defense-evasion: regsvr32 anomaly (2025-10-25T13:38:55), rundll32 anomalies (2025-10-25T13:39:30–13:39:31), WMIC-launched process (2025-10-25T13:38:57), and Windows shell/scripting processes spawning suspicious programs.
- Discovery activity: Local account enumeration events at 2025-10-25T00:08:41, 13:39:02 and 13:39:05; suspicious hostname command at 2025-10-25T13:39:29.
- Recommended triage (prioritized by risk / effort): High risk/low effort — isolate affected host(s) seen in these logs; collect full PowerShell command-lines/-decoded payloads, scheduled task definition, and Run key values; perform EDR/AV scan and volatile memory capture. Medium effort — hunt for lateral movement (WMIC, scheduled tasks, remote rundll32), review event timelines and credential use, reset compromised accounts if confirmed. Low effort — block/disable encoded PowerShell execution and suspicious LOBT tools via app control.

Key TTPs
- T1059.001 (PowerShell execution) — dominant (≥20 detections: encoded/BASE64 + non-interactive spawns).
- T1547.001 (Registry Run Keys / Startup) — 2 detections (00:08:41, 13:39:01).
- T1053.005 (Scheduled Task) — task created 2025-10-25T13:23:23 (persistence/exec).
- Living-off-the-land / defense-evasion family — T1218.010 (regsvr32), T1218.011 (rundll32), T1047 (WMIC), T1059.005 (cmd/Windows shell spawning other programs); Discovery: T1033 / T1087.001 (local accounts), T1082 (hostname/system info).

Notable IOCs (if any)
- Notable timestamps/artifacts to collect: ScheduledTask created 2025-10-25T13:23:23.632989Z; Registry RunKey alerts 2025-10-25T00:08:41.759212Z and 2025-10-25T13:39:01.993162Z; regsvr32 anomaly 2025-10-25T13:38:55.596113Z; WMIC new-process 2025-10-25T13:38:57.066740Z; rundll32 anomalies 2025-10-25T13:39:30–13:39:31.
- No network addresses, file hashes, full command-lines or registry key names provided in the detection list — collect those artifacts immediately to create actionable IOCs.

## Micro 21: Cluster Summary

Executive bullets
- Multiple PowerShell execution patterns: 20+ non-interactive/EncodedCommand PowerShell events between 2025-10-25T13:39:33 and 2025-10-25T16:23:03 (EventID 1 & 4104) — repeated base64/encoded invocations and child-process spawning.
- Registry persistence activity: CurrentVersion autorun modified at 2025-10-25T13:39:35 (EventID 13) and new RUN key pointing to suspicious folder at 2025-10-25T16:08:42 (EventID 13).
- Defense-evasion via tampering and LOLBins: Eventlog clearing/config change at 2025-10-25T16:08:20 (EventID 1); suspicious use of regsvr32, rundll32, wmic, schtasks around 2025-10-25T16:08:29–16:08:30 (EventID 1).
- Discovery activity observed: multiple Get-Process (EventID 4104) and local accounts discovery at 2025-10-25T16:08:42 and 16:21:16 indicating host/process and account enumeration.
- Possible benign/test activity: 4104 snippets include “Simulates PowerShell EncodedCommand executions” and Write-Host text — investigate to confirm whether this is development/simulation vs. adversary reuse of same commands.

Key TTPs (MITRE)
- T1059.001 PowerShell — frequent non-interactive / base64 EncodedCommand executions (multiple EventID 1 & 4104).
- T1218 (LOLBins) — regsvr32, rundll32 used for potential defense-evasion or payload execution.
- T1047 Windows Management Instrumentation — wmic used to create processes.
- T1053.005 Scheduled Task — suspicious schtasks scheduling activity.
- T1547.001 Registry Run Keys/Startup Folder — autorun and RUN key modifications.
- T1070.001 / T1562.002 Defense Evasion — event log clearing / log configuration changes.
- T1057 / T1082 / T1087.001 Discovery — Get-Process, system and local account enumeration.

Notable IOCs (if any)
- Process names observed: powershell.exe (non-interactive, -EncodedCommand patterns), regsvr32.exe, rundll32.exe, wmic.exe, schtasks.exe, cmd.exe.
- Timestamps for rapid sequence activity: bulk of suspicious activity 2025-10-25T16:08:20 → 2025-10-25T16:23:03; earlier cluster at 2025-10-25T13:39:33 → 13:39:36. No external IPs/hashes provided in detections — collect richer telemetry.

Prioritized recommendations (by risk then effort)
- High risk / low effort: Isolate affected host(s) observed in the timestamp ranges; preserve memory, PowerShell transcription/ScriptBlock logs, Sysmon, Security Event logs and the registry hives (ntuser/system/software); export EDR/host logs for those times.
- High risk / medium effort: Hunt enterprise-wide for the EncodedCommand pattern, modified Run keys, EventID 1102/clear/log-config changes, and same LOLBin usage; identify source/entry (RDP, email, SSM, remote admin).
- Medium risk / medium effort: If compromise confirmed, rotate credentials for local/admin accounts discovered, disable scheduled malicious tasks and remove RUN entries, and apply containment (block offending binaries or restrict via AppLocker/WDAC).
- Low risk / low effort: Verify whether detected PowerShell snippets are legitimate simulation/test activity (contact dev/ops), and if so, enforce separation/whitelisting for test hosts and enable enhanced PowerShell logging and transcript retention.

## Micro 22: Cluster Summary

Executive bullets
- Large burst of PowerShell execution: ~29 PowerShell-related events (encoded/base64/encoded-command/non-interactive/IEX) between 2025-10-25T16:23:05Z and 2025-10-25T16:27:40Z (EventID 1 / 4104 flagged repeatedly).
- Multiple non-interactive/encoded invocations and IEX usage indicating scripted payload execution and in-memory activity (repeated "Suspicious Execution of Powershell with Base64", "Suspicious Encoded PowerShell Command Line", "IEX" snippets).
- Clear obfuscation attempts: 4 Set-Alias definitions at 2025-10-25T16:27:05.834… and two token-obfuscation snippets (e.g. (&("{0}{1}" -f "Get-","Date") and IEX '$x="W`ri`te-Output"; & ($x) ...').
- Process injection observed: Remote thread created in Shell application at 2025-10-25T16:23:15 (EventID 8) — likely T1055-style injection.
- Post-exploitation activity: Registry autorun modified at 2025-10-25T16:27:16 (EventID 13, persistence), and Windows share mount via net.exe at 2025-10-25T16:27:16 (lateral movement); rundll32/regsvr32 spawned ~16:27:13 (LOLBIN abuse).

Key TTPs
- T1059.001 — PowerShell execution (encoded/base64, non-interactive, IEX); ~29 detections (16:23:05–16:27:40).
- T1027 / T1027.009 — Obfuscation (Set-Alias aliasing, PowerShell token obfuscation; multiple 4104 snippets).
- T1055, T1547.001, T1021.002, T1218.010/011, T1057 — Process injection, registry autorun persistence, SMB share mount/lateral movement, regsvr32/rundll32 LOLBINs, process discovery (Get-Process).

Notable IOCs (if any)
- Command snippets / aliases:
  - Set-Alias definitions at 2025-10-25T16:27:05.834: ncim->New-CimInstance, gcai->Get-CimAssociatedInstance, rcms->Remove-cimSession, gcls->Get-CimClass.
  - Token obfuscation: (&("{0}{1}" -f "Get-","Date")) and IEX '$x="W`ri`te-Output"; & ($x) "Suspicious-But-Benign"'.
  - IEX 'Get-Process | Select-Object -First 3' (process discovery).
- High-value event timestamps for follow-up: Remote thread creation 2025-10-25T16:23:15 (EventID 8); Registry autorun modification 2025-10-25T16:27:16 (EventID 13); net.exe SMB mount 2025-10-25T16:27:16.

Recommendations (prioritized by risk → effort)
- (High risk / Low effort) Immediately isolate affected host(s), preserve logs (Sysmon/PowerShell/Windows Event), capture memory and process dumps for the timeline 16:23:05–16:27:40Z; block further PowerShell encoded execution and disable inbound SMB where inappropriate.
- (Medium risk / Medium effort) Hunt for and remove persistence (CurrentVersion autorun keys, regsvr32/rundll32 registrations), audit SMB mounts and account usage, reset any credentials used, and tune detections to flag Set-Alias patterns, token obfuscation, and IEX usage.

## Micro 23: Cluster Summary

• Executive bullets
- Burst of obfuscated PowerShell activity (13+ encoded/base64/encoded-pattern detections) between 2025-10-25T16:27:41–2025-10-25T16:28:31; repeated non-interactive PowerShell spawns also observed (16:27:43, 16:27:50, 16:28:29).
- Token/alias obfuscation observed: multiple PowerShell token mangling and IEX usage (W`ri`te-Output; IEX '(&("{0}{1}" -f "Get-","Date"))') and 8 Set-Alias entries targeting CIM cmdlets (two bursts at 16:27:42 and 16:28:31) — indicates defense evasion and script hiding.
- Living-off-the-land and proxy execution: 3 Windows shell/scripting → suspicious program spawns (16:27:46–16:28:39) and 2 rundll32 events with uncommon DLL extension (16:27:47, 16:28:32) — possible payload execution pivot.
- Persistence and tampering: CurrentVersion autorun key modified at 2025-10-25T16:27:53 and eventlog clearing/config change at 2025-10-25T16:28:25 — escalation of persistence + defense evasion.
- Immediate prioritized actions (by risk/effort): 1) Isolate affected host(s) now (High risk, low effort). 2) Acquire volatile evidence (memory), PowerShell logs/transcripts, registry (autorun) and eventlog files; capture process tree and network connections (High risk, medium effort). 3) Full disk image, credential resets, hunt for lateral movement and remove persistence (High risk, higher effort).

• Key TTPs
- Execution: PowerShell (T1059.001) — encoded/Base64 invocations, IEX usage, non-interactive PS.
- Defense Evasion: Obfuscated files/strings / token obfuscation (T1027 / T1027.009), signed-binary proxy execution (rundll32) (T1218.011), Clear Windows Event Logs (T1070.001).
- Persistence: Registry Run Keys / CurrentVersion autoruns (T1547.001).
- Discovery: Process discovery (Get-Process) (T1057) and system information discovery via CMD output redirection (T1082).

• Notable IOCs (snippets / counts / timestamps)
- Obfuscated snippets: $x="W`ri`te-Output"; & ($x) "Suspicious-But-Benign" (16:27:40.966523 and 16:28:28.222630); IEX '(&("{0}{1}" -f "Get-","Date"))' (16:28:26.949431).
- Set-Alias entries (8 total) creating aliases for CIM cmdlets — examples: gcim, rcim, rcie, gcms, scim, icim, ncms, ncso (16:27:42.675115–16:28:31.007305).
- Persistence / tamper timestamps: CurrentVersion autorun modification (2025-10-25T16:27:53.056165); Eventlog clearing/config change (2025-10-25T16:28:25.028467); Rundll32 suspicious executions (2025-10-25T16:27:47.450091, 2025-10-25T16:28:32.694861).

## Micro 24: Cluster Summary

• Executive bullets
- Repeated PowerShell execution and obfuscation (~20 events) from 2025-10-25T16:28 → 2025-10-28T16:29; spikes at 2025-10-26T00:06–00:08 and 2025-10-28T16:27–16:29 — includes encoded/base64 commands, aliasing, token obfuscation, and multiple non-interactive PowerShell spawns (EventID 1 / 4104).
- Persistence artifacts created: CurrentVersion autorun modified (2025-10-25T16:28:43) and New RUN key pointing to suspicious folder (2025-10-26T00:07:52); Scheduled Task created (2025-10-26T00:01:04).
- Discovery and reconnaissance: File/directory discovery scripts observed (2025-10-25T16:46:17 & 16:46:20), Local Accounts discovery (2025-10-26T00:07:52), suspicious Get‑WmiObject usage (2025-10-26T03:17:07).
- Defense‑evasion/log tampering: Eventlog clearing/config changes detected (2025-10-26T00:07:23; 2025-10-26T03:27:03 — snippet “clearkali”).
- Living‑off‑the‑land downloads/execution: bitsadmin file download to suspicious folder (2025-10-26T00:07:44); rundll32 execution with uncommon DLL extension (2025-10-26T00:07:43–00:07:44); multiple Windows shell/scripting processes spawning suspicious programs (10-25 & 10-26 timestamps).

• Key TTPs
- Execution/scripting: T1059.001 (PowerShell), T1059.005 (cmd), T1218.* (rundll32; T1218.011 observed).
- Persistence & lateral: T1547.001 (Registry Run keys), T1053.005 (Scheduled Task), T1197/T1036.003 (bitsadmin download / possible masquerading).
- Defense evasion & discovery: T1070.001 (Clear logs), T1562.002 (log/config tampering), T1027 (obfuscation — aliasing, token obfuscation), T1083/T1082/T1087.001 (file/host/local account discovery), T1546 (WMI use).

• Notable IOCs (if any)
- Registry/startup: CurrentVersion autorun modification (2025-10-25T16:28:43); New RUN key to suspicious folder (2025-10-26T00:07:52); Scheduled Task created 2025-10-26T00:01:04.
- Execution/download artifacts & strings: bitsadmin download to suspicious target folder (2025-10-26T00:07:44); rundll32 with uncommon DLL ext (2025-10-26T00:07:43–00:07:44); log‑clear string "clearkali" (2025-10-26T03:27:03); PowerShell snippets: token obfuscation "Suspicious-But-Benign" and multiple Set‑Alias entries (2025-10-26T00:07:36 & 2025-10-28T16:29:31).

• Prioritized recommendations (by risk & effort)
- Immediate — High risk / Low‑Medium effort: Isolate affected hosts (those with PS non‑interactive + registry/task changes + bitsadmin activity). Collect volatile evidence: PowerShell event logs (4104), process creation logs, scheduled tasks, Run keys, downloaded files; take forensic images before remediation.
- Short term containment/hunt — High risk / Medium effort: Disable/remove suspicious Run keys and scheduled tasks; quarantine/delete downloaded payloads; reset/revoke local and privileged credentials seen in discovery; search estate for matching IOCs/PowerShell encoded patterns, "clearkali", bitsadmin target path, and alias patterns; block bitsadmin/rundll32 misuse via EDR/AV/prevention rules.

## Micro 25: Cluster Summary

• Executive bullets
- Two focused attack clusters: 2025-10-28 16:29:35–16:29:53 (17 events: mass PowerShell encoded/non-interactive invocations, IEX obfuscation, Set‑Alias, wmic/rundll32 spawns, cmd redirect) and 2025-11-02 14:06:22–14:09:17 (22 events: scheduled task creation, autorun registry modifications, event-log clearing, repeated PowerShell encoded/non-interactive + Set‑Alias obfuscation).
- Repeated encoded/Base64 and non-interactive PowerShell executions across both clusters (multiple EventID 1 and 4104 entries) — likely scripted remote/automated execution (T1059.001).
- PowerShell obfuscation observed: IEX token obfuscation variants and alias creation (Set-Alias gcim/rcim/rcie/gcms) consistent with defense‑evasion (T1027 / T1027.009).
- Persistence and privilege techniques: Scheduled task created (2025-11-02T14:06:22; EventID 11, T1053.005) and Autorun key modifications at 2025-11-02T14:07:17 & 14:07:43 (EventID 13, T1547.001).
- Defense-evasion and cover-up: Event log clearing/config change at 2025-11-02T14:09:04 (T1070.001 / T1562.002); command-stream/cmd output redirection also present.
- Lateral/legacy tool usage and risky process spawning: wmic.exe new-process at 2025-10-28T16:29:45 (T1047), rundll32 suspicious activity 16:29:47 (T1218.011), and Windows shell scripting spawning suspicious programs 16:29:48 (T1059.005/T1218).

• Key TTPs
- Execution: PowerShell encoded/non-interactive (T1059.001) — multiple encoded command detections and EventID 4104 script block logs.
- Obfuscation/Defense Evasion: PowerShell token obfuscation and alias use (T1027, T1027.009); eventlog clearing/config changes (T1070.001, T1562.002).
- Persistence/Privilege Escalation & Abuse of Legitimate Tools: Scheduled Task creation (T1053.005), Registry Autoruns (T1547.001), WMIC and Rundll32 abuse (T1047, T1218.011).

• Notable IOCs (if any)
- PowerShell snippets: IEX '(&("{0}{1}" -f "Get-","Date"))' (2025-10-28T16:29:42) and IEX '$x="W`ri`te-Output"; & ($x) "Suspicious-But-Benign"' (2025-11-02T14:09:09).
- Alias artifacts: Set-Alias names gcim, rcim, rcie, gcms (observed 2025-10-28T16:29:53 and 2025-11-02T14:09:12); process names wmic.exe, rundll32.exe; Scheduled Task created 2025-11-02T14:06:22; Registry keys modified: HKLM\...\CurrentVersion and HKLM\...\CurrentControlSet autorun keys (timestamps above).
- No external network IPs, domain names, file hashes or decoded payloads provided in current detections — decode Base64/script blocks and capture task/registry values and parent PIDs ASAP.

• Prioritized recommendations (risk ↓ / effort ↑)
- High risk / Low effort: Immediately collect and preserve volatile artifacts for affected hosts — full PowerShell command lines and decoded scriptblocks, Task XML, modified registry autorun values, process parent IDs, Windows event logs (Security, System, PowerShell) for 2025-10-28 and 2025-11-02 timeframes.
- High risk / Medium effort: Quarantine affected endpoints, block flagged processes (wmic.exe/rundll32 invoked by non-standard parents) and disable suspicious scheduled task; enable/force PowerShell script block logging and transcription if not already.
- Medium risk / Low effort: Hunt for matching Set-Alias strings and IEX patterns across estate; search EDR for other occurrences of Base64/encoded PowerShell around these timestamps.
- Medium risk / Medium effort: Restore/validate event log integrity, review and roll back unauthorized autorun registry entries, and investigate possible lateral movement from these hosts.