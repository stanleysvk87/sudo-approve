"""Tests for sudo-approve-verify.py with a simulated authenticator (P-256 and Ed25519).

Run: python3 -m pytest pam/test_verify.py   (or: python3 pam/test_verify.py)
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFY = os.path.join(HERE, "sudo-approve-verify.py")
RP = "sudo-approve.midgardnet.org"


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class World:
    def __init__(self):
        self.dir = tempfile.mkdtemp()
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.ed = ed25519.Ed25519PrivateKey.generate()
        self.creds = os.path.join(self.dir, "credentials.json")
        pins = []
        for cid, k in (("ec-cred", self.ec), ("ed-cred", self.ed)):
            pem = k.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pins.append({"id": cid, "name": cid, "public_key_pem": pem.decode()})
        with open(self.creds, "w") as f:
            json.dump(pins, f)
        os.chmod(self.creds, 0o644)
        self.env = {
            "SA_HOST": "yggdrasil",
            "SA_CMD": "/usr/bin/systemctl restart caddy",
            "SA_NONCE": os.urandom(32).hex(),
            "SA_CREDENTIALS": self.creds,
            "PATH": "/usr/bin:/bin",
        }

    def run(self, mode, stdin="", env=None):
        e = dict(self.env)
        e.update(env or {})
        p = subprocess.run(
            [sys.executable, "-I", VERIFY, mode], input=stdin, env=e, capture_output=True, text=True
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()

    def assertion(self, key="ec", challenge=None, origin=None, rp=RP, flags=0x05, cred=None, tamper=False):
        if challenge is None:
            _, challenge, _ = self.run("challenge")
        cd = json.dumps(
            {"type": "webauthn.get", "challenge": challenge, "origin": origin or f"https://{RP}"}
        ).encode()
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
        msg = auth + hashlib.sha256(cd).digest()
        if key == "ec":
            sig = self.ec.sign(msg, ec.ECDSA(hashes.SHA256()))
        else:
            sig = self.ed.sign(msg)
        if tamper:
            sig = bytes([sig[0] ^ 1]) + sig[1:]
        return json.dumps(
            {
                "status": "approved",
                "assertion": {
                    "rawId": cred or ("ec-cred" if key == "ec" else "ed-cred"),
                    "clientDataJSON": b64url(cd),
                    "authenticatorData": b64url(auth),
                    "signature": b64url(sig),
                },
            }
        )


def test_valid_p256_and_ed25519():
    w = World()
    assert w.run("check", w.assertion("ec"))[0] == 0
    assert w.run("check", w.assertion("ed"))[0] == 0


def test_approval_for_another_command_or_nonce_is_refused():
    w = World()
    a = w.assertion("ec")
    # the backend shows "systemctl restart caddy" but a different command is being run
    assert w.run("check", a, {"SA_CMD": "/bin/bash"})[0] == 1
    assert w.run("check", a, {"SA_HOST": "mjolnir"})[0] == 1
    # an old approval (other nonce) cannot be replayed
    assert w.run("check", a, {"SA_NONCE": os.urandom(32).hex()})[0] == 1


def test_forgeries_are_refused():
    w = World()
    assert w.run("check", w.assertion(tamper=True))[0] == 1
    assert w.run("check", w.assertion(origin="https://evil.example"))[0] == 1
    assert w.run("check", w.assertion(rp="evil.example"))[0] == 1
    assert w.run("check", w.assertion(flags=0x04))[0] == 1  # user not present
    assert w.run("check", w.assertion(cred="unknown"))[0] == 1
    assert w.run("check", w.assertion(challenge="A" * 43))[0] == 1
    # a key the backend knows but we never pinned: sign with a fresh key under a pinned id
    other = ec.generate_private_key(ec.SECP256R1())
    w.ec = other
    assert w.run("check", w.assertion("ec"))[0] == 1


def test_backend_saying_approved_without_assertion_is_refused():
    w = World()
    assert w.run("check", json.dumps({"status": "approved"}))[0] == 1
    assert w.run("check", "not json")[0] == 1


def test_writable_pin_file_is_refused():
    w = World()
    os.chmod(w.creds, 0o666)
    assert w.run("check", w.assertion("ec"))[0] == 1


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
