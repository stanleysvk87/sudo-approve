#!/usr/bin/python3 -I
"""Verify a WebAuthn assertion locally – so the sudo-approve backend is only a relay, never trusted.

v1 trusted the backend's word ("status": "approved"). Whoever controlled the backend container could approve
any sudo. v2: the PAM side picks the challenge itself and checks the authenticator's signature here, against
public keys pinned in a root-owned file. A compromised backend can then only relay or refuse – it cannot
approve.

The challenge binds host, command and a fresh nonce:

    challenge = SHA-256("sudo-approve/v2" 0x00 host 0x00 command 0x00 nonce)

Checks follow the W3C Web Authentication spec, "Verifying an Authentication Assertion" (Level 2, §7.2):
clientDataJSON type/challenge/origin, rpIdHash, User Present flag, signature over
authenticatorData || SHA-256(clientDataJSON) with the pinned public key of that credential.

Usage (all input via environment and stdin, nothing through a shell):
    SA_HOST=… SA_CMD=… SA_NONCE=<hex> sudo-approve-verify.py challenge          → prints base64url challenge
    SA_HOST=… SA_CMD=… SA_NONCE=<hex> sudo-approve-verify.py check < status.json → exit 0 only if valid

Environment (optional): SA_RP_ID (default sudo-approve.midgardnet.org),
SA_CREDENTIALS (default /etc/sudo-approve/credentials.json, must be root-owned and not writable by others).
"""

import base64
import hashlib
import json
import os
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

RP_ID = os.environ.get("SA_RP_ID", "sudo-approve.midgardnet.org")
CREDENTIALS = os.environ.get("SA_CREDENTIALS", "/etc/sudo-approve/credentials.json")


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def challenge() -> bytes:
    host = os.environ["SA_HOST"].encode()
    cmd = os.environ["SA_CMD"].encode()
    nonce = bytes.fromhex(os.environ["SA_NONCE"])
    if len(nonce) < 16:
        raise ValueError("nonce too short")
    return hashlib.sha256(b"sudo-approve/v2\0" + host + b"\0" + cmd + b"\0" + nonce).digest()


def pinned() -> dict:
    st = os.stat(CREDENTIALS)
    # as root (the real case): the file must be root's; a test run as a user may use its own file
    if st.st_uid not in (0, os.geteuid()) or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(f"{CREDENTIALS} must be owned by root and not writable by others")
    with open(CREDENTIALS, encoding="utf-8") as f:
        data = json.load(f)
    return {c["id"]: serialization.load_pem_public_key(c["public_key_pem"].encode()) for c in data}


def verify_signature(key, sig: bytes, msg: bytes) -> None:
    if isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key.verify(sig, msg)
    elif isinstance(key, rsa.RSAPublicKey):
        key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise InvalidSignature("unsupported key type")


def check(status: dict) -> str:
    """Return the credential id on success, raise on any failure."""
    if status.get("status") != "approved":
        raise ValueError("not approved")
    a = status.get("assertion") or {}
    cred_id = a["rawId"]
    keys = pinned()
    if cred_id not in keys:
        raise ValueError("unknown credential (not pinned)")
    cdj = b64url_decode(a["clientDataJSON"])
    auth = b64url_decode(a["authenticatorData"])
    sig = b64url_decode(a["signature"])
    cd = json.loads(cdj)
    if cd.get("type") != "webauthn.get":
        raise ValueError("clientData type")
    if cd.get("challenge") != b64url(challenge()):
        raise ValueError("challenge does not match this sudo request")
    if cd.get("origin") != f"https://{RP_ID}":
        raise ValueError("origin")
    if cd.get("crossOrigin"):
        raise ValueError("cross-origin")
    if len(auth) < 37:
        raise ValueError("authenticatorData too short")
    if auth[:32] != hashlib.sha256(RP_ID.encode()).digest():
        raise ValueError("rpIdHash")
    if not auth[32] & 0x01:
        raise ValueError("user not present")
    verify_signature(keys[cred_id], sig, auth + hashlib.sha256(cdj).digest())
    return cred_id


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("challenge", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "challenge":
            print(b64url(challenge()))
            return 0
        cred = check(json.load(sys.stdin))
        print(f"ok {cred[:12]}", file=sys.stderr)
        return 0
    except Exception as e:  # any failure = not approved; PAM falls through to the next method
        print(f"refused: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
