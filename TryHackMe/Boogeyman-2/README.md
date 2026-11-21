# TryHackMe — Boogeyman 2
## SOC L1 Incident Response Investigation

**Status:** In progress  
**Role:** SOC Analyst L1 aspirant  
**Platform:** TryHackMe  
**Scenario:** Phishing-led compromise of a workstation belonging to Maxine, a Human Resources Specialist at Quick Logistics LLC.

> This is a training-lab investigation. The report is being built from evidence and validated findings. No answer values are guessed. The initial Boogeyman 1 room was completed separately using a walkthrough; this Boogeyman 2 case is intended as an independent investigation.

## Executive Summary

The scenario describes a malicious resume delivered to an employee through email. The investigation focuses on identifying the phishing message and attachment, reconstructing macro and payload execution, examining process ancestry and memory artifacts, identifying command-and-control (C2) activity, and documenting scheduled-task persistence.

**Current disposition:** Suspected endpoint compromise. Severity, scope, and final impact are pending evidence validation.

## Investigation Objectives

1. Identify the phishing sender, recipient, attachment name, and attachment MD5.
2. Determine the stage-two payload URL and execution details.
3. Reconstruct process name, image path, PID, and parent PID.
4. Identify the URL used to retrieve the malicious binary.
5. Identify the C2 process, executable path, destination IP, and port.
6. Validate the malicious attachment's full path from the memory dump.
7. Recover the complete scheduled-task command used for persistence.
8. Build a defensible timeline, IOC register, and incident assessment.

## Evidence Sources

| Artifact | Investigation use | Status |
|---|---|---|
| Phishing email | Sender, recipient, attachment and delivery context | Pending |
| Malicious Office document | Macro and stage-two URL analysis | Pending |
| Memory dump | Process tree, command lines, file paths, network connections | Pending |
| Network / endpoint logs, if supplied | Download and C2 correlation | Pending |

Record filenames, acquisition details, timestamps, and SHA-256 hashes in [evidence-log.md](evidence-log.md). Preserve original artifacts and analyze copies.

## Attack-Chain Reconstruction

The following is the working investigation sequence, not a statement that every stage has already been proven:

1. Phishing email delivered
2. Malicious document opened
3. Macro executed
4. Stage-two payload downloaded and executed
5. Malicious binary retrieved and launched
6. C2 connection established
7. Scheduled task created for persistence

Every stage must be supported by an artifact, timestamp, and observable evidence.

## Findings Register

| # | Investigation question | Validated finding |
|---:|---|---|
| 1 | Phishing sender email | Pending |
| 2 | Victim employee email | Pending |
| 3 | Malicious attachment name | Pending |
| 4 | Attachment MD5 | Pending |
| 5 | Stage-two payload download URL | Pending |
| 6 | Process that executed stage two | Pending |
| 7 | Stage-two payload full path | Pending |
| 8 | Stage-two process PID | Pending |
| 9 | Stage-two parent PID | Pending |
| 10 | Malicious binary download URL | Pending |
| 11 | PID of process used for C2 | Pending |
| 12 | Full path of C2 process | Pending |
| 13 | C2 destination IP and port | Pending |
| 14 | Attachment full path from memory | Pending |
| 15 | Full scheduled-task persistence command | Pending |

Do not replace “Pending” until the value has been checked against the source evidence. Add a short evidence reference and analysis note for each completed item.

## Timeline

See [timeline.md](timeline.md). Preserve the original timestamp and timezone from each artifact.

## Indicators of Compromise

See [iocs.md](iocs.md). Include only validated indicators. Defang URLs and IP addresses in the public report where appropriate.

## MITRE ATT&CK Mapping

Potential techniques to assess. Include them in the final mapping only when the artifacts support them:

- [T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [T1204.002 — Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [T1059.005 — Visual Basic](https://attack.mitre.org/techniques/T1059/005/)
- [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/)

## SOC L1 Assessment

The completed report will document:
- Alert classification and severity rationale
- Affected user and endpoint scope supported by evidence
- Confirmed attacker actions versus hypotheses
- Process ancestry and suspicious execution chain
- C2 and persistence assessment
- Containment, eradication, recovery, and escalation recommendations

## Limitations

This case is based on a simulated training environment and the artifacts provided by the room. Any unavailable evidence or unobservable activity will be documented as a limitation, not treated as proof that an event did not occur.

## Safe Handling and Publication

- Do not execute suspicious documents or payloads.
- Preserve originals and analyze working copies.
- Calculate and record hashes before analysis.
- Do not publish malware samples, memory dumps, credentials, tokens, or private data.
- Publish sanitized evidence excerpts and screenshots only where permitted.

## References

- [TryHackMe — Boogeyman 2](https://tryhackme.com/room/boogeyman2)
- [MITRE ATT&CK](https://attack.mitre.org/)

**Disclaimer:** Educational incident-response case study conducted in an authorized TryHackMe lab.
