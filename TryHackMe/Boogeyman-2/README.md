# TryHackMe — Boogeyman 2
## SOC L1 Phishing, Malware, Memory Forensics and C2 Investigation

**Platform:** TryHackMe  
**Investigation type:** Phishing, malicious Office macro, staged payload delivery, Windows memory forensics, C2 analysis, and scheduled-task persistence  
**Role perspective:** SOC Analyst Level 1  
**Status:** Completed training-room investigation  
**Environment:** Authorized TryHackMe lab  
**Documentation note:** This report was prepared from the investigation outputs retained during the exercise, with guided assistance and reference material used to validate selected findings. It is a learning case study, not a claim of a wholly unaided forensic examination.

## 1. Executive Summary

This case investigated a phishing email sent to a Quick Logistics employee, Maxine Beck. The message contained a malicious Word document. Static macro analysis identified a staged download-and-execution chain: the macro retrieved a file named `update.png`, saved the response as `C:\ProgramData\update.js`, and launched it with Windows Script Host. Memory analysis showed the resulting process chain leading to `updater.exe`, which initiated repeated TCP connections to `128.199.95.189:8080`.

The investigation also identified a scheduled-task artefact named `Updater` and the malicious executable at `C:\Windows\Tasks\updater.exe`. The task file was located in the memory scan, but its XML action was not successfully extracted during this investigation. Therefore, the executable path is recorded as an observed process/host-application path, not as a fully recovered task XML command line.

**SOC assessment:** Phishing-led Windows endpoint compromise with staged payload execution, external C2 communication, and evidence of scheduled-task persistence. In a real environment, this would warrant prompt escalation to Incident Response.

## 2. Investigation Scope

- Review the phishing email and identify its sender, recipient, and attachment.
- Inspect the Word document's macro without executing it.
- Reconstruct the process ancestry from the memory image.
- Identify the stage-one and stage-two payload download indicators.
- Identify the process responsible for C2 and its remote endpoint.
- Locate persistence artefacts and record evidence limitations.
- Produce an evidence-based SOC L1 report.

## 3. Evidence Sources and Tools

| Source / tool | Purpose |
|---|---|
| `Resume - Application for Junior IT Analyst Role.eml` | Email metadata and attachment identification |
| `Resume_WesleyTaylor.doc` | Static macro inspection |
| `WKSTN-2961.raw` | Windows memory image |
| `olevba` | Extract and review Office VBA macro |
| Volatility 3 | Process tree, command lines, file objects, network sockets, and memory analysis |
| `strings` | Search extracted process memory and memory image for readable strings |

No live payload was downloaded or executed as part of this write-up.

## 4. Phishing Email

| Field | Observed value |
|---|---|
| Sender | `westaylor23@outlook.com` |
| Recipient | `maxine.beck@quicklogisticsorg.onmicrosoft.com` |
| Subject | `Resume - Application for Junior IT Analyst Role` |
| Date | `Sun, 20 Aug 2023 18:19:20 +0000` |
| Attachment | `Resume_WesleyTaylor.doc` |
| Message-ID | `478f3a30-7dad-42ae-a40e-08dba1a9fbcc` |

### Attachment hash

| Algorithm | Value |
|---|---|
| MD5 | `52c4384a0b9e248b95804352ebec6c5b` |
| SHA-256 | `4db25ee3c46be38aa219fe2192711af65d55d5d7e25a889bb9990beb19f9b8b0` |

## 5. Malicious Macro and Staged Payload Delivery

Static macro analysis identified an `AutoOpen()` routine. The macro used `Microsoft.XMLHTTP` to retrieve a remote response and `ADODB.Stream` to save it as `C:\ProgramData\update.js`, then launched the script using `wscript.exe`.

### Stage 1 — Script retrieval

Observed URL (defanged for safe publication):

```text
hxxps://files[.]boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update[.]png
```

The `.png` extension should not be treated as proof that the downloaded content was an image. In the macro, the response body was saved with a `.js` filename and executed as a script.

### Stage 2 — Binary retrieval

The stage-two binary download URL identified during the room was:

```text
hxxps://files[.]boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update[.]exe
```

### Script destination and execution

| Item | Finding |
|---|---|
| Script path | `C:\ProgramData\update.js` |
| Script host | `wscript.exe` |
| Script process PID | `4260` |
| Parent PID | `1124` |

The process command line recorded by Volatility was:

```text
wscript.exe C:\ProgramData\update.js
```

## 6. Process Ancestry

The Volatility process tree showed the following chain:

```text
OUTLOOK.EXE (PID 1440)
└── WINWORD.EXE (PID 1124)
    ├── WINWORD.EXE (PID 4336, exited)
    └── wscript.exe (PID 4260)
        └── updater.exe (PID 6216)
            └── conhost.exe (PID 4464)
```

The Word process command line referenced the attachment in the Outlook cache:

```text
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```

The process tree supports the relationship between the opened document, Windows Script Host, and the subsequently executed updater process.

## 7. Command-and-Control Analysis

Volatility's `windows.netscan` output showed repeated TCP connections owned by PID `6216` (`updater.exe`) to the same remote endpoint.

| Field | Observation |
|---|---|
| Process | `updater.exe` |
| PID | `6216` |
| Local IP | `10.10.49.181` |
| Remote IP | `128.199.95.189` |
| Remote port | `8080` |
| Protocol | TCP |
| Socket state in captured output | CLOSED |
| Observed connection times | 2023-08-21 14:14:13 to 14:16:11 |

**C2 endpoint:** `128.199.95.189:8080`

The repeated connections from the same process to the same remote IP and port support identifying this endpoint as the C2 destination in the context of this lab. The `CLOSED` state reflects the socket state at memory capture; it does not negate the recorded connection artefacts.

## 8. Persistence Investigation

The memory file scan identified the scheduled-task file:

```text
\Windows\System32\Tasks\Updater
```

The associated executable was identified at:

```text
C:\Windows\Tasks\updater.exe
```

The process memory strings also contained the host application path:

```text
Host Application: C:\Windows\Tasks\updater.exe
Process ID: 6216
```

**Evidence limitation:** The task file was located by `windows.filescan`, but the attempted `windows.dumpfiles` extraction returned no dumped file. Registry hive recovery also encountered parsing errors. Consequently, the task XML's exact `<Command>` and `<Arguments>` values were not independently recovered in the retained evidence. The executable path above is supported by process-memory evidence, but should not be misrepresented as a fully extracted scheduled-task action.

## 9. High-Level Attack Timeline

This sequence is reconstructed from the available email, macro, process, and network evidence. It is not a complete timestamped event timeline.

1. Maxine Beck received an email containing a Word document presented as a job application.
2. The document's `AutoOpen()` macro retrieved the stage-one response from the attacker-controlled host.
3. The macro saved the response as `C:\ProgramData\update.js`.
4. The macro launched the script using `wscript.exe` (PID 4260).
5. The process chain showed execution of `updater.exe` (PID 6216).
6. The updater process initiated repeated TCP connections to `128.199.95.189:8080`.
7. A scheduled-task file named `Updater` and the updater executable path were identified as persistence-related artefacts.

## 10. Indicator Register

| Type | Indicator | Context |
|---|---|---|
| Email | `westaylor23@outlook.com` | Sender |
| Email | `maxine.beck@quicklogisticsorg.onmicrosoft.com` | Recipient |
| File | `Resume_WesleyTaylor.doc` | Malicious Word attachment |
| SHA-256 | `4db25ee3c46be38aa219fe2192711af65d55d5d7e25a889bb9990beb19f9b8b0` | Attachment hash |
| URL | `hxxps://files[.]boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update[.]png` | Stage-one retrieval |
| URL | `hxxps://files[.]boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update[.]exe` | Stage-two binary retrieval |
| File | `C:\ProgramData\update.js` | Downloaded script destination |
| Process | `wscript.exe` — PID 4260 | Executes stage-two script |
| Process | `updater.exe` — PID 6216 | Malicious process associated with C2 |
| File | `C:\Windows\Tasks\updater.exe` | Updater executable path |
| Task | `\Windows\System32\Tasks\Updater` | Scheduled-task artefact |
| IP:Port | `128.199.95.189:8080` | C2 endpoint |

These are lab indicators. Validate them against current telemetry and threat intelligence before using them in production controls.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Case evidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Email carrying a malicious Word document |
| Execution | User Execution: Malicious File | T1204.002 | User-opened document in the phishing chain |
| Execution | Visual Basic | T1059.005 | VBA macro execution |
| Execution | JavaScript | T1059.007 | Downloaded `update.js` executed by Windows Script Host |
| Command and Control | Ingress Tool Transfer | T1105 | Staged retrieval of script and binary |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTP(S) payload retrieval |
| Command and Control | Non-Application Layer Protocol | T1095 | TCP connection to the C2 endpoint; validate exact protocol semantics with additional network evidence |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | `Updater` task artefact identified |

ATT&CK mappings are analytical classifications based on the observed lab behaviours. They do not establish attribution to a real-world threat actor.

## 12. SOC L1 Assessment and Escalation

- **Classification:** Phishing-led malware / endpoint compromise
- **Suggested priority:** High, subject to the organisation's severity matrix
- **Escalation:** SOC L2 / Incident Response
- **Rationale:** A malicious Office macro, staged script and binary execution, suspicious process ancestry, repeated external TCP connections, and a scheduled-task artefact were identified.

A SOC L1 analyst should preserve the original email, attachment, memory image, process details, and network evidence; record exact timestamps and source references; and escalate according to the organisation's incident-response process.

## 13. Recommended Response Actions

1. Isolate the affected endpoint in accordance with approved procedures.
2. Preserve the email, attachment, memory image, relevant event logs, and network telemetry.
3. Hunt for the attachment hash, file paths, process names, domain, and C2 IP across other endpoints.
4. Review scheduled tasks and other persistence mechanisms on affected systems.
5. Block confirmed indicators through approved controls after validation.
6. Assess credential exposure and follow the organisation's credential-reset and secrets-rotation procedures.
7. Rebuild or restore the endpoint only after evidence preservation and eradication validation.

## 14. Evidence Gaps and Lessons Learned

### Evidence gaps

- The scheduled-task XML was not successfully extracted; the exact task action and arguments remain unverified in this report.
- A complete packet capture and packet-level references were not retained.
- The stage-two binary's cryptographic hash was not recorded.
- The C2 protocol and application-layer contents were not independently decoded.
- A fully timestamped attack timeline was not retained.

### Lessons learned

- A file extension is not proof of file content; inspect how the macro handles the downloaded response.
- Process ancestry helps connect document execution to later payload activity.
- Correlating process IDs with network sockets can identify which process initiated suspicious connections.
- Persistence findings should be validated from the task definition or equivalent authoritative artefact, not inferred solely from a filename.
- Reports should clearly separate confirmed observations from unresolved details.

## 15. Conclusion

The Boogeyman 2 investigation demonstrates a phishing-led compromise involving a malicious Word macro, staged payload retrieval, Windows Script Host execution, a follow-on updater process, C2 communication, and a scheduled-task persistence artefact.

The case provided practical SOC L1 experience in email triage, static macro analysis, Volatility process and network analysis, process-tree correlation, IOC documentation, ATT&CK mapping, and evidence-aware escalation.

## References

- [TryHackMe — Boogeyman 2](https://tryhackme.com/room/boogeyman2)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)

**Disclaimer:** Educational case study based on an authorized TryHackMe training environment. No live malware, credentials, or executable payloads are included.
