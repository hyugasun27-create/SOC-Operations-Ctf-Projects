# Operation Tempest — SOC Investigation Case Report

> **Platform:** TryHackMe  
> **Investigation type:** Phishing-led endpoint compromise and network investigation  
> **Role perspective:** SOC Analyst Level 1  
> **Status:** Completed  
> **Environment:** Authorized, simulated training environment

## 1. Executive Summary

This investigation examined a Windows workstation affected by a phishing-led attack chain. The analysis combined endpoint event logs and network traffic to identify the initial malicious document, exploitation activity, persistence artefacts, and command-and-control (C2) communication.

The investigation identified a malicious document named `free_magicules.doc`, associated with Microsoft Word process ID `496`. The activity was linked to **CVE-2022-30190 (Follina)**. A Startup-folder shortcut named `update.lnk` and an archive named `update.zip` were also identified. Network analysis identified HTTP C2 activity associated with `resolve.cyber:80`.

This report records the findings established during the lab. Exact event timestamps, file hashes, destination IP addresses, and some execution details are not included because they were not confirmed in the available investigation notes.

## 2. Investigation Objectives

- Review endpoint and Windows event evidence for suspicious execution.
- Identify the phishing-related document and exploitation activity.
- Locate persistence artefacts.
- Review network traffic for C2 communication.
- Record defensible findings and recommend appropriate response actions.

## 3. Evidence Sources

| Evidence | Purpose |
|---|---|
| `sysmon.evtx` | Endpoint process and system activity |
| `windows.evtx` | Windows event evidence |
| `capture.pcapng` | Network traffic and suspected C2 activity |

## 4. Tools and Techniques

- **PowerShell / Windows Event Log analysis:** Review event records and process activity.
- **Sysmon logs:** Investigate process and endpoint events.
- **Wireshark:** Inspect packet capture and HTTP traffic.
- **Event correlation:** Relate endpoint artefacts to network observations.

The investigation used a correlation-based approach: suspicious endpoint activity was reviewed alongside network evidence rather than treating individual events as proof in isolation.

## 5. Key Findings

### Finding 1 — Malicious document

- **File:** `free_magicules.doc`
- **Related process:** `WINWORD.EXE`
- **Process ID observed:** `496`

The document was identified as part of the phishing-led activity investigated in the room.

### Finding 2 — Exploitation activity

The activity was associated with **CVE-2022-30190**, commonly known as **Follina**, a Microsoft Support Diagnostic Tool (MSDT) vulnerability that can be abused through specially crafted Office documents.

The finding connects the malicious Office document to the exploitation stage of the incident. The report does not claim a specific payload command or successful execution detail beyond what was established in the investigation.

### Finding 3 — Startup persistence artefact

A shortcut named `update.lnk` was identified in the Windows Startup folder:

```text
C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk
```

A Startup-folder shortcut can be used to launch a program or command when a user logs on. Its presence is consistent with a persistence mechanism and should be treated as suspicious in the context of this incident.

### Finding 4 — Downloaded archive

The archive `update.zip` was identified during the investigation. It was associated with the suspicious activity, but the available notes do not establish a verified file hash or the complete contents of the archive.

### Finding 5 — Command-and-control communication

Network analysis identified HTTP C2 activity associated with:

| Field | Finding |
|---|---|
| Hostname | `resolve.cyber` |
| Port | `80` |
| Protocol | HTTP |
| DNS resolution | A DNS resolution failure was observed during analysis |

The hostname and port are recorded as the lab finding. A DNS resolution failure does not, by itself, disprove the observed C2 indicator; it means the hostname did not resolve successfully during that particular lookup.

## 6. Attack Progression

The evidence supports the following high-level progression:

1. A phishing-related Office document, `free_magicules.doc`, was involved in the initial compromise.
2. The document activity was associated with the Follina vulnerability (CVE-2022-30190).
3. The investigation identified `update.zip` as a downloaded archive.
4. A suspicious shortcut, `update.lnk`, was found in the user's Startup folder, indicating a persistence concern.
5. Network analysis identified HTTP C2 activity associated with `resolve.cyber:80`.

**Timeline limitation:** Exact timestamps and a fully ordered event timeline were not retained in the available notes. The sequence above is a high-level reconstruction, not a timestamp-verified chronology.

## 7. MITRE ATT&CK Mapping

The following mappings are based on the observed behaviour and should be treated as analytical classifications:

| Tactic | Technique | ID | Basis |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Malicious Office document delivered through phishing activity |
| Execution | Exploitation for Client Execution | T1203 | Activity associated with CVE-2022-30190 / Follina |
| Persistence | Boot or Logon Autostart Execution: Startup Folder | T1547.001 | Shortcut identified in the user's Startup folder |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP C2 activity associated with `resolve.cyber:80` |

These mappings describe the behaviour indicated by the available evidence; they are not a substitute for a complete forensic timeline.

## 8. Indicators and Artefacts

| Type | Indicator / Artefact | Context |
|---|---|---|
| File | `free_magicules.doc` | Malicious Office document |
| Process | `WINWORD.EXE` (PID `496`) | Process associated with document activity |
| Vulnerability | `CVE-2022-30190` | Follina |
| File | `update.zip` | Archive identified during investigation |
| Persistence artefact | `update.lnk` | Startup-folder shortcut |
| File path | `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk` | Startup location |
| Network hostname | `resolve.cyber` | C2 hostname identified in network analysis |
| Network port / protocol | `80 / HTTP` | C2 communication |

No file hashes or destination IP addresses are published in this report because verified values were not available in the investigation notes.

## 9. SOC Analyst Assessment

From a SOC L1 perspective, the combination of a suspicious Office document, activity associated with a known Office exploitation vulnerability, a Startup-folder shortcut, and HTTP C2 traffic warrants escalation as a suspected endpoint compromise.

A suitable alert disposition would be:

- **Classification:** Suspected malware / endpoint compromise
- **Priority:** High, pending organisational severity matrix
- **Escalation:** Incident Response / SOC L2
- **Reason:** Multiple related endpoint and network indicators suggest execution, persistence, and external communication.

## 10. Recommended Response Actions

In a real enterprise environment, the SOC should follow approved incident-response procedures:

1. Isolate the affected endpoint from the network where authorised.
2. Preserve relevant endpoint, Windows, and network evidence.
3. Escalate the incident with the observed artefacts and event context.
4. Review the Startup folder and identify the target of `update.lnk` without executing it.
5. Investigate `update.zip` in a controlled malware-analysis environment.
6. Hunt across the environment for the document name, shortcut name, hostname, and related process activity.
7. Block confirmed malicious indicators through approved security controls.
8. Reset potentially exposed credentials after assessing scope and following incident-response policy.
9. Validate eradication and monitor for recurrence before restoring normal connectivity.

## 11. Lessons Learned

- Correlating endpoint logs with packet captures provides stronger investigative context than relying on a single alert.
- Office documents can be an initial vector for exploitation and should be investigated carefully.
- Startup-folder artefacts are important persistence leads.
- DNS lookup failure should be recorded accurately and should not automatically invalidate other network evidence.
- A professional case report should distinguish confirmed observations from assumptions and unresolved details.

## 12. Conclusion

The Operation Tempest investigation identified a phishing-related malicious Office document, activity associated with Follina (CVE-2022-30190), a suspicious Startup-folder shortcut, a downloaded archive, and HTTP C2 activity associated with `resolve.cyber:80`.

The findings demonstrate practical SOC L1 investigation skills across endpoint event analysis, vulnerability context, persistence identification, network traffic analysis, evidence correlation, ATT&CK mapping, and escalation recommendations.

## 13. Disclaimer

This investigation was completed in the authorized TryHackMe training environment. The report is for educational and portfolio purposes only. No live malware, credentials, or executable payloads are included.
