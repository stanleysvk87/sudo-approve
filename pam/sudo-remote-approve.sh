#!/bin/bash
# pam_exec skript: pokusi sa schvalit sudo na dialku cez FIDO2/WebAuthn
# (ntfy push -> ipad -> dotyk kluca). Pri akomkolvek zlyhani/timeoute
# vracia nenulovy exit kod a PAM automaticky spadne na dalsiu metodu
# (TOTP / FIDO2 dotyk / heslo) - toto NIKDY nie je jediny sposob prihlasenia.

set -u
umask 077

BACKEND="https://sudo-approve.midgardnet.org"
# v2: the approval is verified HERE against pinned public keys (/etc/sudo-approve/credentials.json); the backend only
# relays. A compromised backend can refuse, but never approve.
VERIFY=/usr/local/bin/sudo-approve-verify
HOST="$(hostname)"
CMD="${SUDO_COMMAND:-sudo}"
TIMEOUT=85
POLL_INTERVAL=2
LOG=/var/log/sudo-remote-approve.log

# Beží ako root (pam_exec seteuid pri sudo = PAM_USER root). Preto nič z domova používateľa: súbor, ktorý môže
# meniť on, by tu root spustil (source) a mohol by schváliť sudo bez Face ID. Bezpečnostný audit 14. 11. 2026.
# /etc/sudo-approve/ntfy.env: root:root 600, len KEY=hodnota (NTFY_TOPIC, NTFY_REPORTER_TOKEN, voliteľne RESOLVE_IP).
NTFY_CREDS="/etc/sudo-approve/ntfy.env"
NTFY_TOPIC=""
NTFY_REPORTER_TOKEN=""
RESOLVE_IP=""

echo "$(date -Is) start user=$(id -un 2>&1) home=${HOME:-unset}" >> "$LOG"

if [ ! -f "$NTFY_CREDS" ]; then
  echo "$(date -Is) chyba: $NTFY_CREDS neexistuje" >> "$LOG"
  exit 1
fi
if [ "$(stat -c '%u %a' "$NTFY_CREDS")" != "0 600" ]; then
  echo "$(date -Is) chyba: $NTFY_CREDS musí byť root 600" >> "$LOG"
  exit 1
fi
# načítanie bez spustenia: len povolené kľúče, hodnota je text
while IFS='=' read -r key val; do
  val=${val%$'\r'}; val=${val#\"}; val=${val%\"}; val=${val#\'}; val=${val%\'}
  case "$key" in
    NTFY_TOPIC) NTFY_TOPIC=$val ;;
    NTFY_REPORTER_TOKEN) NTFY_REPORTER_TOKEN=$val ;;
    RESOLVE_IP) RESOLVE_IP=$val ;;
  esac
done < "$NTFY_CREDS"
if [ -z "$NTFY_TOPIC" ] || [ -z "$NTFY_REPORTER_TOKEN" ]; then
  echo "$(date -Is) chyba: v $NTFY_CREDS chýba NTFY_TOPIC alebo NTFY_REPORTER_TOKEN" >> "$LOG"
  exit 1
fi
# stroj mimo domácej siete (victus): opi priamo cez IP, nezávisle od DNS cudzej siete
RESOLVE=()
if [ -n "$RESOLVE_IP" ]; then
  RESOLVE=(--resolve "sudo-approve.midgardnet.org:443:$RESOLVE_IP" --resolve "ntfy.midgardnet.org:443:$RESOLVE_IP")
fi

if [ ! -x "$VERIFY" ]; then
  echo "$(date -Is) chyba: $VERIFY chýba" >> "$LOG"
  exit 1
fi
NONCE=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
if ! CHAL=$(env -i SA_HOST="$HOST" SA_CMD="$CMD" SA_NONCE="$NONCE" "$VERIFY" challenge 2>>"$LOG"); then
  echo "$(date -Is) chyba: challenge sa nedal vypočítať" >> "$LOG"
  exit 1
fi
# JSON cez jq: príkaz s úvodzovkami nesmie rozbiť (ani doplniť) polia požiadavky
body=$(jq -nc --arg h "$HOST" --arg c "$CMD" --arg ch "$CHAL" '{host:$h, command:$c, challenge:$ch}')
if ! resp=$(curl -s -m 5 "${RESOLVE[@]}" -X POST "$BACKEND/api/challenge" \
  -H "Content-Type: application/json" \
  -d "$body"); then
  echo "$(date -Is) chyba: nepodarilo sa vytvorit challenge (backend nedostupny)" >> "$LOG"
  exit 1
fi

challenge_id=$(printf '%s' "$resp" | jq -r '.challenge_id // empty')
url=$(printf '%s' "$resp" | jq -r '.url // empty')

if [ -z "$challenge_id" ] || [ -z "$url" ]; then
  echo "$(date -Is) chyba: prazdny challenge_id/url, resp=$resp" >> "$LOG"
  exit 1
fi

echo "$(date -Is) challenge vytvoreny: $challenge_id" >> "$LOG"

NTFY_PUBLIC_URL="https://ntfy.midgardnet.org"
if ! ntfy_out=$(curl -s -f -m 10 "${RESOLVE[@]}" -X POST "${NTFY_PUBLIC_URL}/${NTFY_TOPIC}" \
  -H "Authorization: Bearer ${NTFY_REPORTER_TOKEN}" \
  -H "Title: sudo na $HOST" \
  -H "Click: $url" \
  -H "Priority: urgent" \
  -H "Tags: warning" \
  -d "$CMD" 2>&1); then
  echo "$(date -Is) chyba: ntfy push zlyhal: $ntfy_out" >> "$LOG"
  exit 1
fi
echo "$(date -Is) ntfy push odoslany" >> "$LOG"
# notifikacia sa neposlala -> nema zmysel cakat 85s naprazdno,
# nikto sa o poziadavke nedozvie

echo "Cakam na schvalenie z iPadu..." >&2

elapsed=0
while [ "$elapsed" -lt "$TIMEOUT" ]; do
  sleep "$POLL_INTERVAL"
  elapsed=$((elapsed + POLL_INTERVAL))
  st_json=$(curl -s -m 5 "${RESOLVE[@]}" "$BACKEND/api/challenge/$challenge_id/status" 2>/dev/null)
  status=$(printf '%s' "$st_json" | jq -r '.status // empty' 2>/dev/null)
  case "$status" in
    approved)
      # the backend's word is not enough: check the authenticator's signature ourselves
      if printf '%s' "$st_json" | env -i SA_HOST="$HOST" SA_CMD="$CMD" SA_NONCE="$NONCE" "$VERIFY" check 2>>"$LOG"; then
        echo "$(date -Is) schválené, podpis overený lokálne" >> "$LOG"
        exit 0
      fi
      echo "$(date -Is) POZOR: backend hlási approved, ale podpis neprešiel lokálnym overením" >> "$LOG"
      # this should never happen unless the backend lies: loud alarm
      curl -s -m 5 "${RESOLVE[@]}" -X POST "${NTFY_PUBLIC_URL}/${NTFY_TOPIC}" \
        -H "Authorization: Bearer ${NTFY_REPORTER_TOKEN}" \
        -H "Title: POPLACH sudo-approve na $HOST" -H "Priority: urgent" -H "Tags: rotating_light" \
        -d "Backend hlasil approved bez platneho podpisu. Mozny napadnuty sudo-approve. Sudo NEPUSTENE." >/dev/null 2>&1
      exit 1 ;;
    expired|unknown) exit 1 ;;
  esac
done

exit 1
