import os
import secrets
import sqlite3
import time
from enum import Enum
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AttestedCredentialData,
)
from fido2.utils import websafe_encode

RP_ID = os.environ.get("RP_ID", "sudo-approve.midgardnet.org")
RP_NAME = "Homelab Sudo Approve"
DB_PATH = os.environ.get("DB_PATH", "/data/sudo-approve.db")
CHALLENGE_TTL = 90  # sekund
SETUP_TOKEN = os.environ.get("SETUP_TOKEN")  # povinne pre /register - pozri README

Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)

app = FastAPI()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            credential_data BLOB NOT NULL,
            name TEXT,
            created_at REAL NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            host TEXT,
            command TEXT,
            state TEXT,
            created_at REAL NOT NULL
        )"""
    )
    conn.commit()
    conn.close()


init_db()


def to_json(o):
    """Rekurzivne prevedie fido2 struktury (bytes, Enum) na JSON-friendly tvar."""
    if isinstance(o, bytes):
        return websafe_encode(o)
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, dict):
        return {k: to_json(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [to_json(v) for v in o]
    return o


def stored_credentials():
    conn = db()
    rows = conn.execute("SELECT * FROM credentials").fetchall()
    conn.close()
    return [AttestedCredentialData(r["credential_data"]) for r in rows]


# --- registracia noveho kluca ---

REGISTER_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Registracia kluca</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:-apple-system,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;text-align:center}
button{font-size:18px;padding:14px 28px;border-radius:10px;border:none;background:#2563eb;color:#fff}
#status{margin-top:24px;font-size:16px;white-space:pre-wrap;word-break:break-word}</style></head>
<body>
<h2>Registracia FIDO2 kluca</h2>
<p>Pomenuj poverenie (napr. "Idem Key" alebo "Face ID iPad"), zasun/pripoj kluc a stlac tlacidlo.</p>
<input id="credname" type="text" placeholder="nazov poverenia" style="font-size:16px;padding:8px;width:80%;margin-bottom:12px">
<br>
<button onclick="register()">Zaregistrovat kluc</button>
<div id="status"></div>
<script>
const TOKEN = "__TOKEN__";
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
}
function unb64url(str) {
  str = str.replace(/-/g,'+').replace(/_/g,'/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) buf[i]=bin.charCodeAt(i);
  return buf.buffer;
}
async function register() {
  document.getElementById('status').textContent = 'Cakam na dotyk kluca...';
  const beginResp = await fetch('/api/register/begin?token=' + encodeURIComponent(TOKEN), {method:'POST'});
  const begin = await beginResp.json();
  const pub = begin.publicKey;
  pub.challenge = unb64url(pub.challenge);
  pub.user.id = unb64url(pub.user.id);
  if (pub.excludeCredentials) {
    pub.excludeCredentials = pub.excludeCredentials.map(c => ({...c, id: unb64url(c.id)}));
  }
  let cred;
  try {
    cred = await navigator.credentials.create({publicKey: pub});
  } catch (e) {
    document.getElementById('status').textContent = 'Chyba: ' + e;
    return;
  }
  const payload = {
    state_id: begin.state_id,
    id: cred.id,
    rawId: b64url(cred.rawId),
    type: cred.type,
    name: document.getElementById('credname').value || 'credential',
    response: {
      clientDataJSON: b64url(cred.response.clientDataJSON),
      attestationObject: b64url(cred.response.attestationObject),
    }
  };
  const completeResp = await fetch('/api/register/complete?token=' + encodeURIComponent(TOKEN), {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)
  });
  if (completeResp.ok) {
    document.getElementById('status').textContent = 'Kluc zaregistrovany.';
  } else {
    document.getElementById('status').textContent = 'Zlyhalo: ' + await completeResp.text();
  }
}
</script>
</body></html>"""


def check_setup_token(token: str | None):
    if not SETUP_TOKEN:
        # bez nastaveneho SETUP_TOKEN je /register natvrdo zakazany,
        # nie tichou dohodou spolahnutou len na sietovy IP-allowlist
        raise HTTPException(403, "SETUP_TOKEN nie je nastaveny na serveri")
    if not token or not secrets.compare_digest(token, SETUP_TOKEN):
        raise HTTPException(403, "neplatny alebo chybajuci token")


@app.get("/register", response_class=HTMLResponse)
def register_page(token: str = Query(default="")):
    check_setup_token(token)
    return REGISTER_PAGE.replace("__TOKEN__", token)


_reg_states = {}


@app.post("/api/register/begin")
def register_begin(token: str = Query(default="")):
    check_setup_token(token)
    existing = stored_credentials()
    user = PublicKeyCredentialUserEntity(
        id=b"stanley", name="stanley", display_name="Stanislav"
    )
    options, state = server.register_begin(
        user,
        credentials=existing,
        user_verification="preferred",
    )
    state_id = secrets.token_urlsafe(16)
    _reg_states[state_id] = (state, time.time())
    return JSONResponse({"state_id": state_id, "publicKey": to_json(options["publicKey"])})


@app.post("/api/register/complete")
async def register_complete(request: Request, token: str = Query(default="")):
    check_setup_token(token)
    body = await request.json()
    entry = _reg_states.pop(body["state_id"], None)
    if not entry:
        raise HTTPException(400, "neznamy alebo expirovany state_id")
    state, _ts = entry

    auth_data = server.register_complete(state, response=body)

    conn = db()
    conn.execute(
        "INSERT INTO credentials (credential_data, name, created_at) VALUES (?,?,?)",
        (bytes(auth_data.credential_data), body.get("name", "credential"), time.time()),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


# --- schvalovanie sudo poziadavky ---

APPROVE_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>Potvrdit sudo</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:-apple-system,sans-serif;max-width:480px;margin:60px auto;padding:0 20px;text-align:center}}
#status{{margin-top:24px;font-size:18px;white-space:pre-wrap;word-break:break-word}}
.cmd{{font-family:monospace;background:#f1f5f9;padding:8px;border-radius:6px;margin:16px 0}}</style></head>
<body>
<h2>Potvrdit sudo prikaz</h2>
<div class="cmd">{host}: {command}</div>
<div id="status">Cakam na dotyk kluca...</div>
<script>
function unb64url(str) {{
  str = str.replace(/-/g,'+').replace(/_/g,'/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) buf[i]=bin.charCodeAt(i);
  return buf.buffer;
}}
function b64url(buf) {{
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
}}
async function approve() {{
  const challengeId = "{challenge_id}";
  try {{
    const beginResp = await fetch('/api/approve/' + challengeId + '/begin', {{method:'POST'}});
    if (!beginResp.ok) {{
      document.getElementById('status').textContent = 'Poziadavka uz nie je platna.';
      return;
    }}
    const begin = await beginResp.json();
    const pub = begin.publicKey;
    pub.challenge = unb64url(pub.challenge);
    pub.allowCredentials = (pub.allowCredentials||[]).map(c => ({{...c, id: unb64url(c.id)}}));
    const assertion = await navigator.credentials.get({{publicKey: pub}});
    const payload = {{
      id: assertion.id,
      rawId: b64url(assertion.rawId),
      type: assertion.type,
      response: {{
        clientDataJSON: b64url(assertion.response.clientDataJSON),
        authenticatorData: b64url(assertion.response.authenticatorData),
        signature: b64url(assertion.response.signature),
      }}
    }};
    const completeResp = await fetch('/api/approve/' + challengeId + '/complete', {{
      method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(payload)
    }});
    if (completeResp.ok) {{
      document.getElementById('status').textContent = 'Schvalene.';
      setTimeout(() => window.close(), 1200);
    }} else {{
      document.getElementById('status').textContent = 'Zlyhalo: ' + await completeResp.text();
    }}
  }} catch (e) {{
    document.getElementById('status').textContent = 'Chyba: ' + e;
  }}
}}
approve();
</script>
</body></html>"""


@app.post("/api/challenge")
async def create_challenge(request: Request):
    body = await request.json()
    challenge_id = secrets.token_urlsafe(16)
    conn = db()
    # priebezne cistenie starych zaznamov, aby tabulka nerastla neobmedzene
    conn.execute("DELETE FROM challenges WHERE created_at < ?", (time.time() - 86400,))
    conn.execute(
        "INSERT INTO challenges (id, status, host, command, created_at) VALUES (?,?,?,?,?)",
        (challenge_id, "pending", body.get("host", "?"), body.get("command", "sudo"), time.time()),
    )
    conn.commit()
    conn.close()
    return {"challenge_id": challenge_id, "url": f"https://{RP_ID}/approve/{challenge_id}"}


@app.get("/approve/{challenge_id}", response_class=HTMLResponse)
def approve_page(challenge_id: str):
    conn = db()
    row = conn.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
    conn.close()
    if not row:
        return HTMLResponse("Neznama poziadavka.", status_code=404)
    if time.time() - row["created_at"] > CHALLENGE_TTL:
        return HTMLResponse("Poziadavka vypršala.", status_code=410)
    return APPROVE_PAGE.format(
        host=row["host"], command=row["command"], challenge_id=challenge_id
    )


_auth_states = {}


@app.post("/api/approve/{challenge_id}/begin")
def approve_begin(challenge_id: str):
    conn = db()
    row = conn.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
    conn.close()
    if not row or row["status"] != "pending" or time.time() - row["created_at"] > CHALLENGE_TTL:
        raise HTTPException(400, "neplatna poziadavka")

    creds = stored_credentials()
    if not creds:
        raise HTTPException(400, "ziadny zaregistrovany kluc")

    options, state = server.authenticate_begin(creds, user_verification="preferred")
    _auth_states[challenge_id] = (state, time.time())
    return JSONResponse({"publicKey": to_json(options["publicKey"])})


@app.post("/api/approve/{challenge_id}/complete")
async def approve_complete(challenge_id: str, request: Request):
    body = await request.json()
    conn = db()
    row = conn.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
    if not row or row["status"] != "pending":
        conn.close()
        raise HTTPException(400, "neplatna poziadavka")

    entry = _auth_states.pop(challenge_id, None)
    if not entry:
        conn.close()
        raise HTTPException(400, "chybajuci stav, zacni znova")
    state, _ts = entry

    creds = stored_credentials()
    try:
        server.authenticate_complete(state, creds, response=body)
    except Exception as e:
        conn.close()
        raise HTTPException(400, f"overenie zlyhalo: {e}")

    conn.execute("UPDATE challenges SET status='approved' WHERE id=?", (challenge_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/challenge/{challenge_id}/status")
def challenge_status(challenge_id: str):
    conn = db()
    row = conn.execute("SELECT * FROM challenges WHERE id=?", (challenge_id,)).fetchone()
    conn.close()
    if not row:
        return {"status": "unknown"}
    if row["status"] == "pending" and time.time() - row["created_at"] > CHALLENGE_TTL:
        return {"status": "expired"}
    return {"status": row["status"]}
