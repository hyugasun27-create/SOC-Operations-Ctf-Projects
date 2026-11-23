# Boogeyman 3 — Evidence Log

This file records the evidence retained for the portfolio report. It distinguishes directly reviewed Kibana events from walkthrough-assisted findings.

## E-01 — Initial HTA execution

- **Source:** Elastic / Sysmon Operational
- **Event ID:** 1 — Process Create
- **Timestamp:** 2023-08-29 23:51:15.856
- **Host:** WKSTN-0051
- **User:** QUICKLOGISTICS\\evan.hutchinson
- **Image:** `C:\\Windows\\SysWOW64\\mshta.exe`
- **PID:** 6392
- **Command line:** `mshta.exe D:\\ProjectFinancialSummary_Q3.pdf.hta`
- **Parent:** `explorer.exe`, PID 2940
- **Assessment:** A file presented with a PDF-like name was executed as an HTA through mshta.exe. This is suspicious in the context of the incident.
- **Confidence:** Directly reviewed in Kibana.

## E-02 — Scheduled task creation and payload execution

- **Source:** Elastic / Sysmon process-creation events and analyst notes
- **Processes observed:** `rundll32.exe` PID 3680; `powershell.exe` PID 6204
- **Command behaviour:** `rundll32.exe` executed `D:\\review.dat,DllRegisterServer`; PowerShell used ScheduledTasks cmdlets to register a task named `Review`.
- **Task configuration visible in command:** Daily trigger at 06:00; action references `rundll32.exe` and `review.dat,DllRegisterServer`.
- **Assessment:** Consistent with DLL proxy execution and scheduled-task persistence.
- **Confidence:** Directly reviewed in lab events/notes; exact task XML not retained.

## E-03 — UAC-bypass-related process chain

### Event A

- **Timestamp:** 2023-08-29 23:54:49.213
- **Event ID:** Sysmon 1 — Process Create
- **Image:** `C:\\Windows\\System32\\fodhelper.exe`
- **PID:** 5180
- **Parent image:** `C:\\Windows\\System32\\rundll32.exe`
- **Parent PID:** 4672
- **Process GUID:** `{6682e687-8549-64ee-ff01-000000001200}`

### Event B

- **Timestamp:** 2023-08-29 23:54:49.444
- **Event ID:** Sysmon 1 — Process Create
- **Image:** `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
- **PID:** 7116
- **Parent image:** `C:\\Windows\\System32\\fodhelper.exe`
- **Parent PID:** 5180
- **Command-line characteristics:** `-NoP -NonI -W Hidden`; reads a value from `HKCU:\\Software\\Microsoft\\Windows Update`; invokes a second PowerShell process with `-enc`.
- **Assessment:** Consistent with fodhelper UAC-bypass abuse followed by hidden PowerShell execution.
- **Confidence:** Directly reviewed in Kibana.

## E-04 — Credential dumping and lateral movement

- **Source:** Published Medium walkthrough by Mobius, used as an external reference.
- **Reported activity:** Mimikatz download/execution, pass-the-hash activity using a local account, access to `IT_Automation.ps1` on a remote share, and credential reuse for movement to `WKSTN-1327`.
- **Assessment:** A plausible multi-stage credential-access and lateral-movement sequence in the training scenario.
- **Confidence:** Walkthrough-assisted; raw Elastic events and full command lines were not retained for independent validation in this report.
- **Publication note:** Passwords and complete credential hashes are omitted.

## E-05 — Second host, DCSync and ransomware staging

- **Source:** Published Medium walkthrough by Mobius, used as an external reference.
- **Reported activity:** `wsmprovhost.exe` parent process on the second host; further local administrator hash dumping; DCSync attempt targeting `backupda`; PowerShell download attempt for `ransomboogey.exe`.
- **Assessment:** If confirmed in raw telemetry, these behaviours indicate severe lateral movement and domain credential exposure, followed by ransomware staging.
- **Confidence:** Walkthrough-assisted; raw event records were not retained for independent validation.
- **Important limitation:** The download attempt does not prove that the ransomware binary executed or encrypted files.

## Analyst validation notes

- Correlate using Process GUIDs, parent Process GUIDs, timestamps and host identifiers—not PID alone.
- Preserve full raw event JSON and event record IDs when reproducing this investigation.
- Mark conclusions as observed, inferred or reference-assisted.
- Do not publish live credentials, plaintext passwords or complete credential hashes.
