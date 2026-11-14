#!/bin/bash
# pam_exec skript: pokusi sa schvalit sudo na dialku cez FIDO2/WebAuthn
# (ntfy push -> ipad -> dotyk kluca). Pri akomkolvek zlyhani/timeoute
# vracia nenulovy exit kod a PAM automaticky spadne na dalsiu metodu
# (TOTP / FIDO2 dotyk / heslo) - toto NIKDY nie je jediny sposob prihlasenia.

set -u
umask 077

BACKEND="https://sudo-approve.midgardnet.org"
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

if ! resp=$(curl -s -m 5 "${RESOLVE[@]}" -X POST "$BACKEND/api/challenge" \
  -H "Content-Type: application/json" \
  -d "{\"host\":\"$HOST\",\"command\":\"$CMD\"}"); then
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
  status=$(curl -s -m 5 "${RESOLVE[@]}" "$BACKEND/api/challenge/$challenge_id/status" 2>/dev/null | jq -r '.status // empty')
  case "$status" in
    approved) exit 0 ;;
    expired|unknown) exit 1 ;;
  esac
done

exit 1
