#!/usr/bin/env python3
"""
TryHackMe Scripting room: UDP + AES-GCM challenge.

Usage:
    python3 solve_udp.py <TASK_3_MACHINE_IP>

Run only against the TryHackMe machine assigned to your active lab session.
"""

import argparse
import hashlib
import socket
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


UDP_PORT = 4000
SOCKET_TIMEOUT = 8
MAX_DATAGRAM_SIZE = 4096
GCM_TAG_LENGTH = 16


def receive_datagram(sock, description):
    """Receive one UDP datagram and report a useful timeout error."""
    try:
        data, sender = sock.recvfrom(MAX_DATAGRAM_SIZE)
    except socket.timeout as exc:
        raise TimeoutError(
            f"Timed out waiting for {description}. "
            "Check the lab machine status and target IP."
        ) from exc

    print(f"[+] Received {description}: {len(data)} bytes from {sender}")
    return data


def parse_server_parameters(response):
    """
    Extract the key, nonce, and SHA-256 digest from the 'ready' response.

    The checksum is embedded as 32 raw bytes, not as a 64-character
    hexadecimal string. Keep it as bytes until converting with .hex().
    """
    key_start = response.index(b"key:") + len(b"key:")
    iv_marker = response.index(b" iv:", key_start)
    key = response[key_start:iv_marker]

    nonce_start = iv_marker + len(b" iv:")
    nonce_end = response.index(b" to decrypt", nonce_start)
    nonce = response[nonce_start:nonce_end]

    digest_start = response.index(b"checksum of ") + len(b"checksum of ")
    digest_end = response.index(b" send final", digest_start)
    expected_digest = response[digest_start:digest_end]

    if len(expected_digest) != 32:
        raise ValueError(
            f"Expected a 32-byte SHA-256 digest, got {len(expected_digest)} bytes."
        )

    if len(key) not in (16, 24, 32):
        raise ValueError(f"Invalid AES key length: {len(key)} bytes.")

    if len(nonce) != 12:
        raise ValueError(f"Expected a 12-byte GCM nonce, got {len(nonce)} bytes.")

    return key, nonce, expected_digest.hex()


def decrypt_candidates(sock, first_ciphertext, aesgcm, nonce, expected_hash):
    """
    Decrypt candidate flags in the order sent by the server.

    The response to 'final' is ciphertext 1. The next UDP datagram is
    tag 1. After that, datagrams arrive as ciphertext 2, tag 2, etc.
    """
    ciphertext = first_ciphertext
    candidate_number = 1

    while True:
        # Receive the tag belonging to the current ciphertext.
        tag = receive_datagram(
            sock, f"authentication tag for candidate {candidate_number}"
        )

        if len(tag) != GCM_TAG_LENGTH:
            raise ValueError(
                f"Candidate {candidate_number} has a {len(tag)}-byte tag; "
                f"expected {GCM_TAG_LENGTH} bytes."
            )

        try:
            # PyCA AESGCM expects ciphertext and tag concatenated.
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
        except InvalidTag:
            print(
                f"[-] Candidate {candidate_number}: AES-GCM authentication failed. "
                "Check packet order and encryption parameters."
            )
        else:
            # Hash the raw plaintext bytes before decoding them for display.
            actual_hash = hashlib.sha256(plaintext).hexdigest()
            candidate_text = plaintext.decode("utf-8", errors="replace")

            print(f"[+] Candidate {candidate_number}: {candidate_text}")
            print(f"    SHA-256: {actual_hash}")

            if actual_hash == expected_hash:
                print("\n[SUCCESS] The SHA-256 checksum matches.")
                print(f"[+] Verified flag: {candidate_text}")
                return candidate_text

            print("[-] Checksum mismatch; checking the next candidate.")

        # The next datagram is the next candidate's ciphertext.
        ciphertext = receive_datagram(
            sock, f"ciphertext for candidate {candidate_number + 1}"
        )
        candidate_number += 1


def main():
    parser = argparse.ArgumentParser(
        description="Retrieve and verify the flag from the TryHackMe UDP lab."
    )
    parser.add_argument(
        "target_ip",
        help="Current IP address of your TryHackMe Task 3 machine",
    )
    args = parser.parse_args()

    server = (args.target_ip, UDP_PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(SOCKET_TIMEOUT)

        # 1. Initiate the server's request/response protocol.
        sock.sendto(b"hello", server)
        hello_response = receive_datagram(sock, "hello response")
        print("[SERVER]", hello_response.decode("utf-8", errors="replace"))

        # 2. Ask the server for the encryption parameters and expected digest.
        sock.sendto(b"ready", server)
        ready_response = receive_datagram(sock, "ready response")

        try:
            key, nonce, expected_hash = parse_server_parameters(ready_response)
        except (ValueError, IndexError) as exc:
            print(f"[-] Could not parse server parameters: {exc}", file=sys.stderr)
            return 1

        print(f"[+] AES key length: {len(key)} bytes")
        print(f"[+] Nonce length: {len(nonce)} bytes")
        print(f"[+] Expected SHA-256: {expected_hash}")

        aesgcm = AESGCM(key)

        # 3. Request the encrypted candidates. This response is ciphertext 1.
        sock.sendto(b"final", server)
        first_ciphertext = receive_datagram(sock, "first ciphertext")

        try:
            decrypt_candidates(sock, first_ciphertext, aesgcm, nonce, expected_hash)
        except TimeoutError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
