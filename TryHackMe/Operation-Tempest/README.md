# Operation Tempest — SOC Investigation Case Report

> **Platform:** TryHackMe  
> **Investigation type:** Phishing-led endpoint compromise and network investigation  
> **Role perspective:** SOC Analyst Level 1  
> **Status:** Completed — portfolio case study  
> **Environment:** Authorized, simulated training environment

## 1. Executive Summary

This investigation examined a Windows workstation affected by a phishing-led attack chain. Endpoint event evidence and network traffic were reviewed to identify the suspicious document, exploitation context, persistence artefacts, and possible command-and-control (C2) communication.

The investigation identified a document named `free_magicules.doc`, activity involving `WINWORD.EXE` (PID `496`), and activity associated with **CVE-2022-30190 (Follina)**. A Startup-folder shortcut named `update.lnk` and an archive named `update.zip` were also identified. Network analysis identified HTTP activity associated with `resolve.cyber:80`.

The available investigation notes do not contain verified timestamps for every event, file hashes, destination IP addresses, or the complete target of the shortcut. These gaps are explicitly retained rather than filled with assumptions.

## 2. Investigation Scope and Objectives

- Review endpoint and Windows event evidence for suspicious activity.
- Identify the phishing-related document and exploitation context.
- Locate possible persistence artefacts.
- Review network traffic for HTTP communication associated with the incident.
- Correlate endpoint and network observations.
- Produce a defensible SOC L1 assessment and escalation recommendation.

**Scope note:** This is a training-lab investigation, not a claim of a complete enterprise forensic examination.

## 3. Evidence Sources

| Evidence source | Intended use |
|---|---|
| `sysmon.evtx` | Review process and endpoint activity |
| `windows.evtx` | Review relevant Windows event records |
| `capture.pcapng` | Inspect network traffic and HTTP activity |

The source filenames are recorded from the investigation materials. Individual event record IDs, packet numbers, timestamps, and cryptographic hashes were not retained in the notes available for this report.

## 4. Tools and Investigation Approach

- **Windows Event Viewer / PowerShell:** Review Windows event records.
- **Sysmon event data:** Examine process and endpoint activity.
- **Wireshark:** Inspect packet capture contents and HTTP traffic.
- **Event correlation:** Compare endpoint observations with network findings.

### Analyst workflow

1. Identify suspicious document and process activity in endpoint evidence.
2. Assess the document activity against the known Follina vulnerability context.
3. Review identified files and Startup-folder artefacts as possible execution or persistence leads.
4. Inspect the packet capture for related HTTP communication.
5. Correlate findings and separate direct observations from analytical interpretation.
6. Assess severity and recommend escalation.

This workflow describes the investigation approach. It does not imply that every artefact was independently validated through a separate forensic acquisition.

## 5. Key Findings

### Finding 1 — Phishing-related document

- **File:** `free_magicules.doc`
- **Related process:** `WINWORD.EXE`
- **Process ID observed:** `496`

The document was identified as part of the phishing-related activity investigated in the room. The process association provides endpoint context but, by itself, does not establish every subsequent execution action.

### Finding 2 — Follina exploitation context

The activity was associated with **CVE-2022-30190**, commonly known as **Follina**, a vulnerability involving the Microsoft Support Diagnostic Tool (MSDT) that can be abused through specially crafted Office documents.

The available investigation notes support associating the malicious Office document with the Follina stage. They do not preserve a complete payload command or sufficient event detail to independently reconstruct every execution step.

### Finding 3 — Startup persistence artefact

A shortcut named `update.lnk` was identified in the Windows Startup folder:

```text
C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk
```

A Startup-folder shortcut can launch a program or command at user logon. Its presence is a persistence lead and is suspicious in the context of the other findings. The shortcut's target and arguments are not included because they were not preserved in the available notes.

### Finding 4 — Archive

- **File:** `update.zip`

The archive was identified during the investigation and associated with the suspicious activity. Its verified hash and complete contents are not available in the retained notes; therefore, no payload identity is asserted here.

### Finding 5 — HTTP communication

Network analysis identified HTTP activity associated with the following indicator:

| Field | Observation |
|---|---|
| Hostname | `resolve.cyber` |
| Port | `80` |
| Protocol | HTTP |
| DNS lookup | A resolution failure was observed during analysis |

The hostname and port are recorded as lab findings. A DNS lookup failure during one analysis attempt does not, by itself, disprove the observed network indicator. The destination IP and packet-level timestamps were not retained.

## 6. Reconstructed Attack Progression

The available findings support this high-level sequence:

1. A phishing-related Office document, `free_magicules.doc`, was involved in the initial compromise.
2. The document activity was associated with Follina (CVE-2022-30190).
3. The archive `update.zip` was identified during the investigation.
4. The Startup-folder shortcut `update.lnk` was identified as a possible persistence mechanism.
5. HTTP activity associated with `resolve.cyber:80` was identified in network analysis.

**Timeline qualification:** This is a high-level analytical reconstruction, not a timestamp-verified chronology. The exact ordering and timing of individual actions should be validated against original event records and packet timestamps before being treated as a forensic timeline.

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence basis |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Phishing-related malicious Office document |
| Execution | Exploitation for Client Execution | T1203 | Activity associated with CVE-2022-30190 / Follina |
| Persistence | Boot or Logon Autostart Execution: Startup Folder | T1547.001 | Shortcut identified in the user's Startup folder |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP activity associated with `resolve.cyber:80` |

These are behaviour-based analytical mappings. They should be revisited if additional evidence changes the understanding of the execution chain or network activity.

## 8. Indicator and Artefact Register

| Type | Indicator / artefact | Context | Validation status |
|---|---|---|---|
| File | `free_magicules.doc` | Phishing-related Office document | Identified in lab investigation |
| Process | `WINWORD.EXE` — PID `496` | Associated with document activity | Observed in investigation notes |
| Vulnerability | `CVE-2022-30190` | Follina context | Associated with document activity |
| File | `update.zip` | Archive identified during investigation | Identified; contents/hash not retained |
| File | `update.lnk` | Startup-folder shortcut | Identified; target not retained |
| Path | `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk` | Startup location | Path recorded |
| Hostname | `resolve.cyber` | HTTP communication indicator | Identified in network analysis |
| Port / protocol | `80 / HTTP` | Network communication | Identified in network analysis |

**IOC handling:** The hostname is a lab indicator, not a verified current threat-intelligence verdict. Validate indicators in context before using them for production blocking or threat attribution.

## 9. Evidence Gaps and Validation Needed

The following details were not present in the investigation notes retained for this report:

| Evidence gap | Why it matters | Recommended validation |
|---|---|---|
| Exact event timestamps | Establishes a defensible event sequence | Re-open original EVTX records and record event time and EventRecordID |
| Process command line and parent process | Clarifies execution chain | Review relevant Sysmon process-creation events |
| Shortcut target and arguments | Confirms what would launch at logon | Inspect `update.lnk` metadata in a safe analysis environment |
| Archive contents and SHA-256 | Supports file identification and correlation | Hash and inspect the archive in an isolated lab |
| HTTP packet number, URI, headers, and destination IP | Makes the network finding independently reproducible | Revisit the PCAP and record packet/frame references |
| Supporting screenshots | Allows a reviewer to verify key observations quickly | Capture sanitized screenshots of the relevant log and packet views |

No missing value has been estimated or fabricated. These are limitations of the retained report evidence, not proof that the underlying lab did not contain the information.

## 10. SOC L1 Assessment and Escalation

From a SOC L1 perspective, the combination of a suspicious Office document, activity associated with a known Office-document exploitation vulnerability, a Startup-folder shortcut, and related HTTP network activity warrants escalation as a suspected endpoint compromise.

- **Classification:** Suspected malware / endpoint compromise
- **Suggested priority:** High, subject to the organisation's severity matrix
- **Escalation:** SOC L2 / Incident Response
- **Rationale:** Multiple endpoint and network observations are consistent with a compromise involving execution, a possible persistence mechanism, and external communication.

The analyst should preserve the distinction between observed facts, contextual interpretation, and unverified hypotheses when escalating.

## 11. Recommended Response Actions

In a real enterprise environment, follow approved incident-response procedures:

1. Isolate the affected endpoint where authorised and operationally appropriate.
2. Preserve relevant endpoint, Windows, and network evidence before remediation.
3. Escalate with event context, timestamps, host details, and the observed artefacts.
4. Inspect the Startup shortcut's target and arguments without executing it.
5. Investigate the archive in a controlled malware-analysis environment.
6. Hunt for the document name, shortcut name, hostname, and related process activity across the environment.
7. Validate indicators before blocking them through approved security controls.
8. Assess possible credential exposure and follow the organisation's credential-reset policy.
9. Confirm eradication and monitor for recurrence before restoring normal connectivity.

## 12. Lessons Learned

- Correlating endpoint logs with packet captures provides stronger context than relying on a single event.
- Office documents can be an initial vector for exploitation and require careful investigation.
- Startup-folder artefacts are useful persistence leads, but their targets should be verified.
- A DNS lookup failure should be documented precisely and should not automatically invalidate other network observations.
- A professional SOC report must distinguish evidence, interpretation, confidence, and unresolved questions.
- A timeline is only as reliable as its source timestamps and event references.

## 13. Conclusion

The Operation Tempest investigation identified a phishing-related Office document, activity associated with Follina (CVE-2022-30190), a suspicious Startup-folder shortcut, an archive, and HTTP activity associated with `resolve.cyber:80`.

The case demonstrates SOC L1 investigation practices across endpoint event review, vulnerability context, persistence analysis, network traffic inspection, evidence correlation, ATT&CK mapping, and escalation recommendations. The report also records evidence limitations transparently so that conclusions are not overstated.

## 14. Disclaimer

This case study is based on an authorized TryHackMe training environment and is published for educational and portfolio purposes. It is not a real-world incident attribution or a complete forensic report. No live malware, credentials, or executable payloads are included.
