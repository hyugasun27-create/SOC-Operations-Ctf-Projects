# Boogeyman 3 — Attack Timeline

**Host initially investigated:** `WKSTN-0051`  
**User context:** `QUICKLOGISTICS\\evan.hutchinson`  
**Incident window:** August 29–30, 2023  
**Time zone:** Lab timestamps shown as recorded in Elastic.

| Timestamp / stage | Host | Event | Evidence status |
|---|---|---|---|
| 2023-08-29 23:51:15.856 | WKSTN-0051 | `mshta.exe` PID 6392 executes `D:\\ProjectFinancialSummary_Q3.pdf.hta`; parent `explorer.exe` PID 2940 | Directly reviewed; Sysmon Event ID 1 |
| 2023-08-29 23:51:16 approx. | WKSTN-0051 | `rundll32.exe` and PowerShell activity associated with `review.dat`; scheduled task `Review` created | Directly reviewed in lab events/notes |
| 2023-08-29 23:54:49.213 | WKSTN-0051 | `fodhelper.exe` PID 5180 spawned by `rundll32.exe` PID 4672 | Directly reviewed; Sysmon Event ID 1 |
| 2023-08-29 23:54:49.444 | WKSTN-0051 | Hidden PowerShell PID 7116 spawned by `fodhelper.exe` PID 5180; command reads HKCU Windows Update registry value and invokes encoded PowerShell | Directly reviewed; Sysmon Event ID 1 |
| Later stage | WKSTN-0051 | Mimikatz download and credential dumping | Walkthrough-assisted; raw event not retained |
| Later stage | Network share | Access to `IT_Automation.ps1` | Walkthrough-assisted; raw event not retained |
| Later stage | WKSTN-1327 | PowerShell Remoting / `wsmprovhost.exe` activity and further credential dumping | Walkthrough-assisted; raw event not retained |
| Later stage | Domain Controller | DCSync attempt targeting `backupda` in addition to administrator | Walkthrough-assisted; raw event not retained |
| Final stage | WKSTN-0051 / external host | Attempted download of `ransomboogey.exe` | Walkthrough-assisted; successful execution not established |

## Process chain directly reviewed on WKSTN-0051

```text
explorer.exe (PID 2940)
└── mshta.exe (PID 6392)
    ├── rundll32.exe (PID 3680) [observed in earlier process event]
    └── powershell.exe (PID 6204) [scheduled-task creation command]

Later observed sequence:
rundll32.exe (PID 4672)
└── fodhelper.exe (PID 5180)
    └── powershell.exe (PID 7116)
```

**Correlation note:** Do not join events on PID alone. Validate timestamps, Process GUIDs and parent Process GUIDs. Windows may reuse a PID after a process exits.

## Timeline limitations

This is a high-level reconstruction, not a complete forensic timeline. Later-stage timestamps and event identifiers must be added only after direct review of the corresponding Elastic events.
