# Boogeyman 3 — Indicator and Artefact Register

**Publication policy:** Credential hashes, plaintext passwords, and direct executable download links are excluded. URLs are defanged so they cannot be clicked accidentally.

| Type | Indicator / artefact | Context | Evidence status |
|---|---|---|---|
| Host | `WKSTN-0051` | Initial compromised workstation | Directly reviewed |
| User | `QUICKLOGISTICS\\evan.hutchinson` | Initial execution context | Directly reviewed |
| File | `ProjectFinancialSummary_Q3.pdf.hta` | Initial HTA attachment | Directly reviewed |
| Process | `mshta.exe` PID 6392 | Executes the HTA file | Directly reviewed |
| File | `D:\\review.dat` | File passed to `rundll32.exe` | Directly reviewed in process command line |
| Process | `rundll32.exe` | Executes `review.dat,DllRegisterServer` | Directly reviewed |
| Scheduled task | `Review` | Persistence task | Directly reviewed in PowerShell command |
| Process | `fodhelper.exe` PID 5180 | UAC-bypass-related process | Directly reviewed |
| Process | `powershell.exe` PID 7116 | Hidden, non-interactive, encoded PowerShell | Directly reviewed |
| Registry path | `HKCU\\Software\\Microsoft\\Windows Update` | Value read by PowerShell | Directly reviewed in command line |
| IP:Port | `165.232.170.151:80` | Reported network connection associated with payload | Walkthrough-assisted; validate in raw network telemetry |
| Tool | Mimikatz | Credential-dumping tool | Walkthrough-assisted |
| File | `IT_Automation.ps1` | Script accessed from remote share | Walkthrough-assisted |
| Host | `WKSTN-1327` | Lateral-movement target | Walkthrough-assisted |
| Process | `wsmprovhost.exe` | PowerShell Remoting host process | Walkthrough-assisted |
| Account | `backupda` | Additional DCSync target account | Walkthrough-assisted |
| URL | `hxxp://ff[.]sillytechninja[.]io/ransomboogey[.]exe` | Reported ransomware download URL | Walkthrough-assisted |

## Credential data deliberately omitted

The lab walkthrough contains credential hashes and a plaintext password. They are intentionally not reproduced here. Publishing recovered credential material is unnecessary for demonstrating the investigation and creates avoidable exposure.

## Validation guidance

Before using any indicator in a real environment:

1. Confirm it against current endpoint, identity and network telemetry.
2. Verify timestamps, host identity and process ancestry.
3. Check whether the indicator is unique to the lab or has legitimate uses.
4. Defang URLs and domains in public reports.
5. Do not block an IP or domain solely because it appears in a training-room answer.
