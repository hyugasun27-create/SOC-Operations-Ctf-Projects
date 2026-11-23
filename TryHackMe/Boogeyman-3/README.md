# TryHackMe — Boogeyman 3
## SOC L1 Multi-Stage Intrusion, Credential Access and Lateral Movement Investigation

**Platform:** TryHackMe  
**Investigation type:** Phishing-led endpoint compromise, HTA execution, persistence, UAC bypass, credential dumping, lateral movement, DCSync, and ransomware staging  
**Role perspective:** SOC Analyst Level 1  
**Environment:** Authorized TryHackMe lab; Elastic/Kibana and Sysmon telemetry  
**Status:** Completed training-room investigation with external walkthrough/reference assistance  
**Documentation approach:** Findings directly reviewed in Kibana are distinguished from details taken from the external reference. This is a learning case study, not a claim of a wholly independent investigation.

> **Transparency note:** I used a published walkthrough as a reference while completing this room. I independently reviewed selected first-host Sysmon process-creation events in Kibana, including the initial HTA execution and the `fodhelper.exe` → PowerShell chain. Some later-stage answers and attack-chain details were cross-checked against the walkthrough and were not independently revalidated from raw telemetry for this portfolio report. I have marked those limitations rather than presenting all findings as independently verified.

## 1. Executive Summary

This case study examines a multi-stage intrusion against Quick Logistics LLC. The initial activity involved a suspicious ISO/HTA attachment opened by CEO Evan Hutchinson on workstation `WKSTN-0051`. Sysmon process-creation telemetry showed `mshta.exe` executing `D:\\ProjectFinancialSummary_Q3.pdf.hta` (PID 6392). Subsequent events showed the malicious chain invoking `rundll32.exe`, creating a scheduled task named `Review`, and launching the Windows utility `fodhelper.exe` before hidden PowerShell execution.

The wider attack chain, as documented in the referenced walkthrough, included Mimikatz credential dumping, reuse of credentials to access a remote file share, retrieval of a PowerShell automation script, lateral movement to `WKSTN-1327`, further credential dumping, a DCSync attempt against a domain account, and an attempted ransomware download.

**SOC assessment:** The reported activity is consistent with a high-severity, multi-host compromise involving privilege escalation, credential access, lateral movement, and attempted domain credential replication. In a production environment, this would require immediate escalation to Incident Response and identity/domain administrators.

## 2. Investigation Objectives

- Identify the initial payload execution and reconstruct its process ancestry.
- Review persistence and privilege-escalation activity.
- Identify credential-access tooling and credential-reuse behaviour.
- Trace remote-share access and lateral movement.
- Review second-host credential access and reported DCSync activity.
- Identify the ransomware download attempt.
- Separate directly reviewed telemetry from reference-assisted findings.

## 3. Environment and Evidence Sources

| Source | Use in this case |
|---|---|
| TryHackMe Boogeyman 3 Elastic/Kibana dataset | Search and review preloaded endpoint telemetry |
| Sysmon Event ID 1 / Process Create | Process creation, command lines, parent process and process GUID correlation |
| Sysmon network telemetry | Review network connections where available |
| Published walkthrough by Mobius | Reference used to cross-check later-stage room findings; not a substitute for raw evidence |
| Analyst notes from the lab | Record queries, timestamps, process IDs and observations |

The lab data was preloaded into Elastic; no local log-file upload was required for the Discover investigation.

## 4. Initial Access and Stage-One Execution

The initial suspicious process event was observed on `WKSTN-0051`:

| Field | Observed value |
|---|---|
| Timestamp | 2023-08-29 23:51:15.856 |
| Host | `WKSTN-0051` |
| User | `QUICKLOGISTICS\\evan.hutchinson` |
| Process | `mshta.exe` |
| PID | `6392` |
| Executable | `C:\\Windows\\SysWOW64\\mshta.exe` |
| Command-line target | `D:\\ProjectFinancialSummary_Q3.pdf.hta` |
| Parent process | `explorer.exe` |
| Parent PID | `2940` |
| Event | Sysmon Event ID 1 — Process Create |

The filename resembles a PDF, but the actual extension is `.hta`. This mismatch is a useful triage clue. `mshta.exe` is a legitimate Windows utility that can execute HTML Applications and is frequently abused as a living-off-the-land binary.

## 5. Payload Execution and Persistence

The reviewed process events and PowerShell command showed the following activity:

- `rundll32.exe` was used to execute `D:\\review.dat,DllRegisterServer`.
- A PowerShell command created a scheduled task named `Review`.
- The task action referenced `rundll32.exe` and a copy of `review.dat` in the user's temporary directory.
- The task trigger was configured to run daily at 06:00.

The observed scheduled-task command is evidence of a persistence mechanism. The exact task XML was not separately extracted for this report.

## 6. UAC Bypass and Hidden PowerShell

At approximately 23:54:49 on August 29, Sysmon Event ID 1 records showed:

| Timestamp | Process | PID | Parent process | Parent PID |
|---|---|---:|---|---:|
| 23:54:49.213 | `fodhelper.exe` | 5180 | `rundll32.exe` | 4672 |
| 23:54:49.444 | `powershell.exe` | 7116 | `fodhelper.exe` | 5180 |

The PowerShell command used `-NoP`, `-NonI`, `-W Hidden`, and `-enc`. It read a value from the current user's `HKCU:\\Software\\Microsoft\\Windows Update` registry path and passed that value to a second encoded PowerShell invocation.

This behaviour is consistent with abuse of the auto-elevated `fodhelper.exe` binary for UAC bypass, followed by concealed PowerShell execution. The process ancestry and command line are directly supported by the events reviewed in Kibana.

## 7. Credential Access and Lateral Movement

The remaining stages below were cross-checked against the external walkthrough and are recorded as **reference-assisted findings**, not as independently revalidated raw event evidence in this report.

The referenced attack chain reports:

1. The attacker downloaded Mimikatz from its public GitHub release location and used it for credential dumping.
2. A local account named `itadmin` was used in a pass-the-hash attempt to access another machine.
3. The attacker accessed `IT_Automation.ps1` from a remote share.
4. The script contained a further domain credential pair, which was used for remote execution against `WKSTN-1327`.
5. The second host's process ancestry included `wsmprovhost.exe`, consistent with PowerShell Remoting.
6. Further credential dumping on the second host targeted the local `administrator` account.
7. A DCSync attempt against the domain controller targeted the additional account `backupda`, alongside the administrator account.

**Credential handling:** Plaintext passwords and complete credential hashes are intentionally omitted from this public portfolio. They are not needed to demonstrate the investigation method and should not be copied into public reports.

## 8. Ransomware Staging

The walkthrough reports a PowerShell `Invoke-WebRequest` command attempting to retrieve a file named `ransomboogey.exe` from an external host.

The URL is defanged in the IOC register. This report describes a download attempt; it does not claim that ransomware execution or successful encryption was independently verified.

## 9. High-Level Attack Timeline

| Time / stage | Activity | Evidence confidence |
|---|---|---|
| Aug 29, 23:51:15 | `mshta.exe` executes the HTA attachment on `WKSTN-0051` | Directly reviewed in Kibana |
| Shortly after initial execution | `rundll32.exe` executes `review.dat`; scheduled task `Review` is created | Directly reviewed in lab notes/events |
| Aug 29, 23:54:49 | `fodhelper.exe` launches hidden PowerShell | Directly reviewed in Kibana |
| Later stage | Mimikatz download and credential dumping | Walkthrough-assisted; not independently revalidated here |
| Later stage | Remote share access and retrieval of `IT_Automation.ps1` | Walkthrough-assisted |
| Later stage | Lateral movement to `WKSTN-1327` via PowerShell Remoting | Walkthrough-assisted |
| Later stage | Further credential dumping and DCSync attempt targeting `backupda` | Walkthrough-assisted |
| Final stage | Ransomware binary download attempt | Walkthrough-assisted; execution not established |

The table is a reconstructed sequence, not a complete event-by-event forensic timeline. Exact timestamps for later stages should be added only after reviewing the corresponding raw events.

## 10. Indicators and Artefacts

See [iocs.md](./iocs.md) for the public-safe indicator register. Credential values and live executable download links are intentionally excluded.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Case behaviour |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Suspicious attachment delivered to the CEO |
| Execution | Mshta | T1218.005 | HTA executed through `mshta.exe` |
| Execution | PowerShell | T1059.001 | Hidden and encoded PowerShell execution |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | Task named `Review` |
| Privilege Escalation | Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | `fodhelper.exe` abuse |
| Defense Evasion | System Binary Proxy Execution | T1218 | Abuse of trusted Windows binaries; sub-technique depends on exact binary behaviour |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Mimikatz credential-dumping activity reported by reference |
| Lateral Movement | Use Alternate Authentication Material: Pass the Hash | T1550.002 | NTLM hash-based authentication reported by reference |
| Discovery | Network Share Discovery | T1135 | Enumeration of accessible shares |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | PowerShell Remoting / `wsmprovhost.exe` |
| Credential Access | OS Credential Dumping: DCSync | T1003.006 | DCSync attempt against a domain account |
| Command and Control | Ingress Tool Transfer | T1105 | Download of tools and attempted ransomware retrieval |

Mappings are analytical and should be validated against the original telemetry before being used as production detection labels. The report does not claim successful ransomware execution.

## 12. SOC L1 Assessment and Escalation

- **Classification:** Multi-stage malware / endpoint compromise with credential access and lateral movement
- **Suggested severity:** Critical or High, based on the organisation's incident severity matrix
- **Escalation:** Immediate escalation to SOC L2 / Incident Response, identity team and domain administrators
- **Rationale:** The observed first-host chain includes suspicious HTA execution, DLL proxy execution, persistence and UAC-bypass behaviour. The reference-assisted later stages describe credential dumping, remote access, DCSync and attempted ransomware staging.

### Recommended response priorities

1. Isolate affected endpoints using approved incident-response procedures.
2. Preserve Sysmon, Security, PowerShell, WinRM and network telemetry before remediation.
3. Identify all systems that received remote logons or PowerShell Remoting sessions from the compromised hosts.
4. Reset exposed credentials and rotate affected privileged/service-account secrets using a coordinated identity-response plan.
5. Review domain replication permissions and investigate the DCSync attempt with domain-controller security logs.
6. Hunt for the task name, process ancestry, suspicious command-line patterns, tool artefacts and defanged indicators in the report.
7. Block validated indicators and restrict unnecessary remote administration paths.
8. Rebuild affected endpoints only after evidence preservation and eradication validation.

## 13. Detection Opportunities

- Alert on Office/Explorer-launched `mshta.exe` executing an HTA from mounted media or user-writable paths.
- Correlate `mshta.exe` → `rundll32.exe` / `powershell.exe` process ancestry.
- Detect scheduled-task creation where the action launches `rundll32.exe` against unusual files in user-writable directories.
- Alert on `fodhelper.exe` spawning PowerShell or other unexpected child processes.
- Monitor hidden, non-interactive and encoded PowerShell command lines, with script-block logging enabled.
- Detect Mimikatz indicators and suspicious access to LSASS, using endpoint controls and telemetry.
- Monitor remote share access followed by PowerShell Remoting to a new host.
- Alert on DCSync-like directory replication requests from systems or accounts that are not approved for that role.
- Monitor unusual external downloads of executable files after credential-access activity.

Detection rules should be tuned to the organisation's baseline and tested against false positives.

## 14. Lessons Learned and Evidence Limitations

### Lessons learned

- A misleading filename can hide an executable HTA extension; inspect the full path and extension.
- Parent-child process relationships are valuable, but correlate using Process GUIDs and timestamps because PIDs can be reused.
- A trusted Windows binary is not automatically benign; its parent, child, command line, user context and registry activity matter.
- Credential dumping and lateral movement must be correlated across endpoints, identity events, shares and remote-management telemetry.
- A DCSync attempt is a domain-level escalation signal and requires immediate specialist review.
- Reports should distinguish observed evidence, analytical interpretation and facts sourced from a reference.

### Evidence limitations

- Only selected first-host process-creation events were directly reviewed and retained in the conversation notes.
- Later-stage credential, share, second-host, DCSync and ransomware findings were cross-checked against a published walkthrough, not independently reconstructed from raw telemetry for this report.
- Exact later-stage event timestamps, Process GUIDs, logon IDs and full event records are not retained here.
- Credential hashes and plaintext passwords are deliberately excluded.
- A ransomware download attempt is documented; successful execution or encryption is not established.

## 15. References

- [TryHackMe — Boogeyman 3](https://tryhackme.com/room/boogeyman3)
- [Mobius — Boogeyman 3 walkthrough (Medium)](https://medium.com/@vivinnathlingam2/boogeyman-3-98f490bac264)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Microsoft Sysmon documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon)

**Disclaimer:** Educational case study based on an authorized TryHackMe environment. Findings from the external walkthrough are explicitly identified as reference-assisted. No live malware, plaintext passwords or complete credential hashes are included.
