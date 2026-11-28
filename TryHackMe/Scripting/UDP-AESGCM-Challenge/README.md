# TryHackMe Scripting — UDP Communication & AES-GCM Decryption

## Project overview

This project documents a hands-on challenge from the TryHackMe **Scripting** room. The task was to build a Python UDP client, follow a multi-step server protocol, retrieve AES-GCM-encrypted candidate flags, decrypt them, and identify the correct result using a SHA-256 checksum.

From an SOC L1 perspective, the exercise demonstrates network protocol handling, careful treatment of binary evidence, cryptographic validation, systematic troubleshooting, and reproducible documentation.

> **Authorized lab use only:** Run the script only against the TryHackMe machine assigned to your own active session. The target IP changes between sessions.

## Objective

1. Connect to the lab UDP service on port \`4000\`.
2. Follow the required request sequence: \`hello\` → \`ready\` → \`final\`.
3. Extract the AES key, nonce (the server calls it \`iv\`), and expected SHA-256 digest.
4. Receive multiple encrypted candidates and their authentication tags.
5. Decrypt each candidate using AES-GCM.
6. Calculate SHA-256 for each plaintext and compare it with the server's expected digest.
7. Report only the candidate that passes checksum verification.

## Environment and dependencies

- TryHackMe AttackBox (Linux)
- Python 3
- PyCA \`cryptography\`
- Python standard-library modules: \`socket\`, \`hashlib\`, and \`argparse\`

Install the dependency if needed:

\`\`\`bash
python3 -m pip install cryptography
python3 -c "import cryptography; print('Cryptography ready')"
\`\`\`

## Run the solution

Save \`solve_udp.py\`, then run:

\`\`\`bash
python3 solve_udp.py <TASK_3_MACHINE_IP>
\`\`\`

Use the current IP displayed by TryHackMe for your Task 3 machine. Do not reuse an IP from an earlier lab session.

## Protocol observations

The server required three client messages:

| Client payload | Purpose |
|---|---|
| \`hello\` | Initiates communication |
| \`ready\` | Returns encryption parameters and the expected checksum |
| \`final\` | Starts delivery of encrypted candidate flags |

The \`ready\` response provided:

- AES key: \`thisisaverysecretkeyl337\` (24 bytes, valid AES-192 key)
- Nonce / IV: \`secureivl337\` (12 bytes)
- Expected SHA-256 digest: \`5d77f018d2bf777860548655d84d7382dc27d6ce816ede68f65d72621463d9da\`

The checksum arrived as 32 raw binary bytes embedded in the response. The script preserves those bytes and converts them to hexadecimal for comparison.

### UDP datagram ordering

The first ciphertext was returned directly in response to the \`final\` request. Subsequent datagrams followed this order:

\`\`\`text
response to "final" = ciphertext 1
next datagram        = authentication tag 1
next datagram        = ciphertext 2
next datagram        = authentication tag 2
next datagram        = ciphertext 3
next datagram        = authentication tag 3
...
\`\`\`

This boundary matters: the first datagram received **after** the \`final\` response is the first authentication tag, not the first ciphertext. Pairing packets from the wrong starting point causes AES-GCM authentication failures.

## AES-GCM decryption

AES-GCM provides authenticated encryption: it protects confidentiality and verifies integrity/authenticity.

PyCA's \`AESGCM.decrypt()\` expects the authentication tag appended to the ciphertext:

\`\`\`python
plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
\`\`\`

The final \`None\` indicates that this challenge does not use additional authenticated data (AAD).

A successful AES-GCM decryption means the ciphertext/tag pair authenticated under the supplied key and nonce. It does **not** by itself prove that the plaintext is the requested flag. The SHA-256 checksum is the additional validation step that identifies the correct candidate.

## Challenges encountered and resolutions

### 1. Host/IP resolution error

**Observed error:**

\`\`\`text
socket.gaierror: [Errno -2] Name or service not known
\`\`\`

**Cause:** The script still contained a placeholder value instead of the active Task 3 machine IP.

**Resolution:** Replaced the placeholder with the current lab IP. The final script accepts the IP as a command-line argument so it does not need to be edited for every new session.

### 2. Initial server response did not contain the encryption details

**Observation:** The response to \`hello\` instructed the client to send \`ready\`.

**Resolution:** Added the second UDP request, \`b"ready"\`, and captured the key, nonce, and checksum from the response.

### 3. First decrypted candidate failed checksum validation

**Observation:** The first plaintext candidate was \`THM{F5WIVIL3}\`, but its SHA-256 digest was:

\`\`\`text
cecbde8b2df973cee9102d4ec9d48863af624b869485343efb084ad6d506796c
\`\`\`

This did not match the expected digest.

**Resolution:** Did not assume that a successful decryption meant the challenge was solved. Continued processing the remaining candidates and used the supplied checksum as the acceptance criterion.

### 4. AES-GCM authentication failures caused by packet misalignment

**Cause:** An early collection attempt treated the first datagram in the follow-up receive loop as ciphertext. In fact, the first ciphertext had already arrived as the direct response to \`final\`; the next datagram was its tag.

**Resolution:** Preserved the direct \`final\` response as ciphertext 1, then received tag 1. Subsequent datagrams were processed as ciphertext/tag pairs. Each pair was authenticated independently.

### 5. Binary payloads were not readable as ordinary text

**Cause:** Ciphertext, authentication tags, and the expected digest are binary data. Decoding them as UTF-8 can introduce replacement characters and corrupt the evidence.

**Resolution:** Kept network data as Python \`bytes\`. Used \`.hex()\` only for safe display and comparison, and passed the original bytes directly to the cryptographic API.

## Result

The candidate matching the server-provided SHA-256 digest was:

\`\`\`text
THM{eW-sCrIpTiNg-AnD-cRyPtO}
\`\`\`

Verified SHA-256:

\`\`\`text
5d77f018d2bf777860548655d84d7382dc27d6ce816ede68f65d72621463d9da
\`\`\`

The solution script checks the digest programmatically before reporting success.

## SOC L1 skills demonstrated

This is a controlled scripting challenge, not a production incident. The workflow nevertheless demonstrates useful SOC L1 habits:

- **Validate evidence:** Do not treat the first plausible result as correct; verify it against an independent integrity value.
- **Understand network traffic:** Recognize UDP datagrams, request/response sequencing, and packet-order dependencies.
- **Preserve raw evidence:** Keep binary payloads intact rather than relying on lossy text decoding.
- **Troubleshoot methodically:** Use errors and observed responses to isolate configuration and protocol issues.
- **Document reproducibly:** Record the objective, observations, root causes, fixes, and validation outcome.

## Repository contents

\`\`\`text
TryHackMe/
└── Scripting/
    └── UDP-AESGCM-Challenge/
        ├── README.md
        ├── solve_udp.py
        └── .gitignore
\`\`\`

## Publishing and safety notes

- Check the current TryHackMe room rules before publishing challenge flags or solution details.
- Do not publish personal credentials, VPN configuration, tokens, or unrelated lab secrets.
- The target IP is provided at runtime and is not hardcoded in the script.
- Add your own screenshots of the successful run if you want visual evidence; redact unrelated sensitive information.
