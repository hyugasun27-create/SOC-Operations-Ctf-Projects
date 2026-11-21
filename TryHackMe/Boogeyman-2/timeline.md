# Boogeyman 2 — Incident Timeline

Record timestamps exactly as shown in the source, including timezone. Normalize only after preserving the original value.

| Timestamp (source timezone) | Event | Process / user | Evidence source | Confidence |
|---|---|---|---|---|
| Pending | Phishing email received | Pending | Email artifact | Pending |
| Pending | Malicious document opened | Pending | Pending | Pending |
| Pending | Macro execution observed | Pending | Document / memory | Pending |
| Pending | Stage-two payload downloaded | Pending | Pending | Pending |
| Pending | Stage-two payload executed | Pending | Memory / process evidence | Pending |
| Pending | Malicious binary downloaded | Pending | Pending | Pending |
| Pending | C2 connection established | Pending | Memory / network evidence | Pending |
| Pending | Scheduled task created | Pending | Memory / task evidence | Pending |

## Correlation notes

- Correlate process IDs with parent process IDs and process creation times.
- Distinguish observed events from analyst interpretation.
- Link every timeline entry to an evidence ID.
- Note timezone differences between email, endpoint, and memory artifacts.
