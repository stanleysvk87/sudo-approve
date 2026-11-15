#!/usr/bin/env python3
"""Export the registered WebAuthn public keys for pinning on each PAM machine.

    export-credentials.py /path/to/sudo-approve.db > credentials.json
    sudo install -o root -g root -m 644 credentials.json /etc/sudo-approve/credentials.json

Only public keys leave the database. Review the list (names, count) before installing: whatever is in this file
can approve sudo. Supported COSE key types: EC2 P-256 (ES256), OKP Ed25519 (EdDSA), RSA (RS256).
"""

import base64
import json
import sqlite3
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from fido2.webauthn import AttestedCredentialData


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def cose_to_key(cose):
    kty = cose[1]
    if kty == 2 and cose[-1] == 1:  # EC2, P-256
        x = int.from_bytes(cose[-2], "big")
        y = int.from_bytes(cose[-3], "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if kty == 1 and cose[-1] == 6:  # OKP, Ed25519
        return ed25519.Ed25519PublicKey.from_public_bytes(cose[-2])
    if kty == 3:  # RSA
        n = int.from_bytes(cose[-1], "big")
        e = int.from_bytes(cose[-2], "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    raise ValueError(f"unsupported COSE key {dict(cose)}")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    conn = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    out = []
    for name, blob in conn.execute("SELECT name, credential_data FROM credentials ORDER BY id"):
        cd = AttestedCredentialData(blob)
        pem = cose_to_key(cd.public_key).public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        out.append({"id": b64url(cd.credential_id), "name": name, "public_key_pem": pem.decode()})
        print(f"  {name}", file=sys.stderr)
    json.dump(out, sys.stdout, indent=1)
    print(file=sys.stderr)
    print(f"{len(out)} keys exported", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
