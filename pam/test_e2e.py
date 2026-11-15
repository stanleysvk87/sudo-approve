"""End-to-end: the real backend (app.py) + a simulated authenticator + the local verifier, including attacks on
the backend itself.

Needs: fastapi, httpx, fido2==2.2.1, cryptography. Run: python3 pam/test_e2e.py
"""

import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

TMP = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(TMP, "db.sqlite")
os.environ["RP_ID"] = "sudo-approve.midgardnet.org"
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from fastapi.testclient import TestClient  # noqa: E402
from fido2.cose import ES256  # noqa: E402
from fido2.webauthn import AttestedCredentialData, Aaguid  # noqa: E402

import app  # noqa: E402

RP = "sudo-approve.midgardnet.org"
VERIFY = os.path.join(HERE, "sudo-approve-verify.py")
client = TestClient(app.app)


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Authenticator:
    """A software passkey, registered straight into the backend's database."""

    def __init__(self, name):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        acd = AttestedCredentialData.create(
            Aaguid(bytes(16)), self.cred_id, ES256.from_cryptography_key(self.key.public_key())
        )
        conn = sqlite3.connect(os.environ["DB_PATH"])
        conn.execute(
            "INSERT INTO credentials (credential_data, name, created_at) VALUES (?,?,0)", (bytes(acd), name)
        )
        conn.commit()
        conn.close()

    def pin(self):
        pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {"id": b64url(self.cred_id), "name": "test", "public_key_pem": pem.decode()}

    def approve(self, challenge_id):
        begin = client.post(f"/api/approve/{challenge_id}/begin")
        assert begin.status_code == 200, begin.text
        ch = begin.json()["publicKey"]["challenge"]
        cd = json.dumps({"type": "webauthn.get", "challenge": ch, "origin": f"https://{RP}"}).encode()
        auth = hashlib.sha256(RP.encode()).digest() + bytes([0x05]) + (1).to_bytes(4, "big")
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        payload = {
            "id": b64url(self.cred_id),
            "rawId": b64url(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(cd),
                "authenticatorData": b64url(auth),
                "signature": b64url(sig),
            },
        }
        r = client.post(f"/api/approve/{challenge_id}/complete", json=payload)
        assert r.status_code == 200, r.text


def pam_side(pins, host="yggdrasil", cmd="/usr/bin/apt upgrade"):
    """What sudo-remote-approve.sh does, minus ntfy: own nonce, challenge, request."""
    creds = os.path.join(TMP, f"pins-{os.urandom(4).hex()}.json")
    with open(creds, "w") as f:
        json.dump(pins, f)
    env = {
        "SA_HOST": host,
        "SA_CMD": cmd,
        "SA_NONCE": os.urandom(32).hex(),
        "SA_CREDENTIALS": creds,
        "PATH": "/usr/bin:/bin",
    }
    ch = subprocess.run(
        [sys.executable, "-I", VERIFY, "challenge"], env=env, capture_output=True, text=True, check=True
    ).stdout.strip()
    r = client.post("/api/challenge", json={"host": host, "command": cmd, "challenge": ch})
    assert r.status_code == 200, r.text
    return r.json()["challenge_id"], env


def verify(challenge_id, env, status=None):
    status = status or client.get(f"/api/challenge/{challenge_id}/status").json()
    p = subprocess.run(
        [sys.executable, "-I", VERIFY, "check"], input=json.dumps(status), env=env, capture_output=True, text=True
    )
    return p.returncode == 0


def test_real_flow_is_approved():
    phone = Authenticator("iphone")
    cid, env = pam_side([phone.pin()])
    assert not verify(cid, env), "pending must not pass"
    phone.approve(cid)
    assert verify(cid, env)


def test_attacker_adds_own_key_to_backend_db():
    # whoever can write the backend's SQLite file (owned by the user!) registers a key and approves
    phone = Authenticator("iphone")
    attacker = Authenticator("attacker")
    cid, env = pam_side([phone.pin()])
    attacker.approve(cid)
    assert client.get(f"/api/challenge/{cid}/status").json()["status"] == "approved"  # v1 would grant root here
    assert not verify(cid, env), "an unpinned key approved sudo"


def test_backend_lies_approved():
    phone = Authenticator("iphone")
    cid, env = pam_side([phone.pin()])
    conn = sqlite3.connect(os.environ["DB_PATH"])
    conn.execute("UPDATE challenges SET status='approved' WHERE id=?", (cid,))
    conn.commit()
    conn.close()
    assert not verify(cid, env)
    # with a made-up assertion
    fake = {"status": "approved", "assertion": {"rawId": phone.pin()["id"], "clientDataJSON": "e30",
                                                 "authenticatorData": "AA", "signature": "AA"}}
    assert not verify(cid, env, fake)


def test_approval_cannot_be_moved_to_another_sudo():
    phone = Authenticator("iphone")
    cid, env = pam_side([phone.pin()], cmd="/usr/bin/systemctl status caddy")
    phone.approve(cid)
    status = client.get(f"/api/challenge/{cid}/status").json()
    # the same approval presented for a different, waiting sudo request
    _, env2 = pam_side([phone.pin()], cmd="/bin/bash")
    assert verify(cid, env, status)
    assert not verify(cid, env2, status)


def test_command_with_quotes_cannot_inject_fields():
    # the exact jq expression the PAM script uses to build the request
    evil = 'ls", "challenge": "' + "A" * 43 + '", "x": "'
    out = subprocess.run(
        ["jq", "-nc", "--arg", "h", "yggdrasil", "--arg", "c", evil, "--arg", "ch", "B" * 43,
         "{host:$h, command:$c, challenge:$ch}"],
        capture_output=True, text=True, check=True,
    ).stdout
    body = json.loads(out)
    assert body == {"host": "yggdrasil", "command": evil, "challenge": "B" * 43}


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
