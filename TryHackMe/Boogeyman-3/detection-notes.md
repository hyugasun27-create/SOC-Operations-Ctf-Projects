# Boogeyman 3 — SOC Detection and Response Notes

## Detection opportunities

| Behaviour | Telemetry / fields | Hunting idea |
|---|---|---|
| HTA launched by a user-facing process | Sysmon Event ID 1; `process.name`, `process.parent.name`, `process.command_line` | Find `mshta.exe` with an HTA path, especially from mounted media or user-writable directories |
| Suspicious process ancestry | Sysmon Event ID 1; Process GUID and Parent Process GUID | Correlate `mshta.exe` spawning script hosts or LOLBins |
| DLL proxy execution | Sysmon Event ID 1 | Review `rundll32.exe` command lines referencing unusual DLL-like files in user-writable paths |
| Scheduled task persistence | Security 4698; Task Scheduler Operational; Sysmon process events | Review task creation and task actions launching binaries or DLLs from temporary directories |
| UAC bypass using fodhelper | Sysmon Event ID 1; registry telemetry | Alert when `fodhelper.exe` spawns PowerShell, cmd.exe or unexpected child processes; correlate relevant per-user registry changes |
| Concealed PowerShell | Sysmon Event ID 1; PowerShell 4104 where enabled | Review `-WindowStyle Hidden`, `-NonInteractive`, `-EncodedCommand` / `-enc`, and registry-backed command retrieval |
| Credential dumping | Sysmon, EDR, LSASS access telemetry | Hunt for Mimikatz indicators, suspicious LSASS access and unusual process handles |
| Pass-the-hash | Security logon events, EDR, authentication telemetry | Correlate NTLM logons, source host, account, logon type and unusual remote access |
| Remote share access | SMB client/server logs, Security events | Review unusual share enumeration and reads of administrative scripts |
| PowerShell Remoting | WinRM Operational, Sysmon Event ID 1 | Correlate remote logons and `wsmprovhost.exe` process activity across hosts |
| DCSync | Domain Controller Security events, directory replication auditing | Alert on replication rights usage by non-DC systems or unexpected accounts |
| Ransomware staging | Sysmon Event ID 1, PowerShell logs, proxy/DNS telemetry | Detect script-driven executable downloads following credential-access activity |

## Example Kibana KQL starting points

These are starting points for hunting, not complete production detections. Adjust field names and time windows to the dataset.

### Initial HTA execution

```kql
host.hostname: "WKSTN-0051" and event.code: 1 and process.name: "mshta.exe"
```

### Process activity involving the initial PID

```kql
host.hostname: "WKSTN-0051" and process.parent.pid: 6392
```

Use the time window and Process GUID fields to avoid false joins caused by PID reuse.

### UAC-bypass-related process

```kql
host.hostname: "WKSTN-0051" and event.code: 1 and process.name: "fodhelper.exe"
```

### Hidden or encoded PowerShell

```kql
host.hostname: "WKSTN-0051" and event.code: 1 and process.name: "powershell.exe" and process.command_line: (*-enc* or *-EncodedCommand* or *-WindowStyle* or *-W Hidden*)
```

### Scheduled-task-related command lines

```kql
host.hostname: "WKSTN-0051" and event.code: 1 and process.command_line: (*Register-ScheduledTask* or *New-ScheduledTask*)
```

## SOC response checklist

- [ ] Validate alert context, timestamp, host and user.
- [ ] Preserve original event records and relevant endpoint/network telemetry.
- [ ] Reconstruct process ancestry using GUIDs and timestamps.
- [ ] Determine whether credential material was accessed or reused.
- [ ] Scope remote logons, SMB access and WinRM sessions to other endpoints.
- [ ] Escalate suspected DCSync activity to domain administrators / Incident Response.
- [ ] Coordinate credential resets and privileged-secret rotation.
- [ ] Contain endpoints and block validated indicators under approved procedures.
- [ ] Document evidence gaps and avoid claiming ransomware execution without proof.

## Analyst caution

A legitimate Windows binary can be abused. Base the conclusion on process ancestry, command-line arguments, registry activity, user context, host role and correlated network/authentication telemetry. Do not infer compromise from a filename alone.
