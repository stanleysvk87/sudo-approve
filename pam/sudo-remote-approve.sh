#!/bin/bash
# pam_exec skript: pokusi sa schvalit sudo na dialku cez FIDO2/WebAuthn
# (ntfy push -> ipad -> dotyk kluca). Pri akomkolvek zlyhani/timeoute
# vracia nenulovy exit kod a PAM automaticky spadne na dalsiu metodu
# (TOTP / FIDO2 dotyk / heslo) - toto NIKDY nie je jediny sposob prihlasenia.

set -u

BACKEND="https://sudo-approve.midgardnet.org"
HOST="$(hostname)"
CMD="${SUDO_COMMAND:-sudo}"
TIMEOUT=85
POLL_INTERVAL=2
LOG=/tmp/sudo-remote-approve.log

NTFY_CREDS="/home/stanley/.config/ntfy/credentials.env"

echo "$(date -Is) start user=$(id -un 2>&1) home=${HOME:-unset}" >> "$LOG"

if [ ! -f "$NTFY_CREDS" ]; then
  echo "$(date -Is) chyba: $NTFY_CREDS neexistuje" >> "$LOG"
  exit 1
fi
# shellcheck disable=SC1090
source "$NTFY_CREDS"

if ! resp=$(curl -s -m 5 -X POST "$BACKEND/api/challenge" \
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
if ! ntfy_out=$(curl -s -f -m 10 -X POST "${NTFY_PUBLIC_URL}/${NTFY_TOPIC}" \
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
  status=$(curl -s -m 5 "$BACKEND/api/challenge/$challenge_id/status" 2>/dev/null | jq -r '.status // empty')
  case "$status" in
    approved) exit 0 ;;
    expired|unknown) exit 1 ;;
  esac
done

exit 1
