# sudo-approve

Approve `sudo` remotely with a physical FIDO2 security key, Face ID, or Touch ID
— no app, no subscription, no code to type. Tap a push notification, touch your
key, done.

## Why

I wanted to approve `sudo` on my homelab servers from my iPad using the same
FIDO2 hardware key I already use for local login — ideally without typing a
TOTP code every time I'm away from the machine. The commercial paths
(`pam_rssh` + SSH agent forwarding through a terminal app, various "FIDO2 SSH
client" apps) turned out to be either paywalled, undocumented for this exact
combination, or both.

Turns out Safari on iOS/iPadOS already speaks WebAuthn natively — the same
standard behind FIDO2 and Passkeys — so a self-hosted web page can talk
directly to a security key or Face ID/Touch ID with zero extra software. This
is that page, plus the glue to hook it into PAM.

## How it works

```mermaid
sequenceDiagram
    participant U as sudo (server)
    participant P as PAM script
    participant B as sudo-approve backend
    participant N as ntfy (push)
    participant S as Safari (iPad/iPhone)

    U->>P: auth via pam_exec
    P->>B: POST /api/challenge
    B-->>P: challenge_id + approve URL
    P->>N: push notification (Click: approve URL)
    N-->>S: notification appears
    S->>S: tap notification
    S->>B: GET /approve/{id}
    S->>B: WebAuthn ceremony (auto-starts on load)
    Note over S: touch key / Face ID / Touch ID
    S->>B: POST /api/approve/{id}/complete (signed assertion)
    B->>B: verify signature against registered credential
    P->>B: poll GET /api/challenge/{id}/status (every 2s)
    B-->>P: status: approved
    P-->>U: exit 0 → sudo granted
```

If anything fails or times out (backend unreachable, notification never
tapped, key not touched in time), the PAM script exits non-zero and PAM falls
through to the next configured method — TOTP, then password. **This is never
the only way in.** It's a convenience layer on top of whatever you already
have, not a replacement.

## Components

- **`app.py`** — FastAPI backend, WebAuthn server (`python-fido2`), SQLite
  storage. Runs once, centrally (I run it on my always-on homelab server).
- **`pam/sudo-remote-approve.sh`** — the `pam_exec` script deployed to every
  machine you want this on. Creates a challenge, sends the push, polls for
  approval.
- **`docker-compose.yml` / `Dockerfile`** — runs the backend as a non-root
  user in a container.

## Setup

### 1. Backend

```bash
cp .env.example .env   # set SETUP_TOKEN to a long random value
docker compose up -d --build
```

Put it behind a reverse proxy with a real TLS certificate — WebAuthn requires
HTTPS (or localhost). Set `RP_ID` to that domain.

Restrict access at the network level (reverse proxy IP allowlist, VPN-only,
whatever fits your setup) — `SETUP_TOKEN` gates the registration endpoint
itself, but the whole thing is meant to sit inside a trusted network
boundary, not be exposed to the open internet.

### 2. Register a credential

Visit `https://your-domain/register?token=<SETUP_TOKEN>`, name the
credential, and follow the browser prompt. Repeat for every key/device you
want to be able to approve with (I registered my physical key, Face ID, and
Touch ID — any of the three can approve).

### 3. Push notifications

The script expects an `ntfy` (or compatible) push endpoint. Set the topic URL
and an auth token in whatever credentials file
`pam/sudo-remote-approve.sh` reads — adjust the script for your own notifier
if you use something else.

### 4. Wire it into PAM

Add a line to `/etc/pam.d/sudo`, positioned wherever you want it tried
relative to your other `auth` methods (`sufficient` control, so success
grants immediately and failure falls through):

```
auth  sufficient  pam_exec.so seteuid /usr/local/bin/sudo-remote-approve.sh
```

**Back up `/etc/pam.d/sudo` before touching it.** A broken PAM stack can lock
you out of `sudo` entirely.

## Security model

Real WebAuthn/FIDO2 challenge-response — a fresh random challenge per
request, verified against the public key registered for that credential. Not
a bearer-token push button (rejected that approach early on: it's vulnerable
to MFA-fatigue-style attacks, the kind behind the 2022 Uber breach — an
attacker spamming approval requests until someone taps "yes" by reflex).

`/register` is gated by `SETUP_TOKEN` so registering a new credential
requires knowing that token, not just being on the right subnet.

This is a homelab project, not an audited security product. Read the code
before trusting it with anything that matters.

## Known limitations

- No cleanup of very old, never-approved challenge rows beyond a 24h purge
  on each new request — fine for personal use, would need real housekeeping
  at any scale.
- The backend is a single point of failure for the *convenience* path, by
  design — see the fallback behavior above.
