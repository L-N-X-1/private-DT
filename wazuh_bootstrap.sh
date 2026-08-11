#!/usr/bin/env bash
#
# wazuh_bootstrap.sh
# ------------------
# Linux counterpart to Install-WazuhAgent.ps1. Fetches enrollment material
# from wazuh-cert-issuer, hands it to wazuh_enroll.sh, then shreds it.
#
# Usage:
#   sudo ./wazuh_bootstrap.sh -c /etc/wazuh-bootstrap/bootstrap.conf
#
# bootstrap.conf (chmod 600, root:root):
#   ISSUER_URL="https://wazuh-enroll.corp.local:8443"
#   BOOTSTRAP_TOKEN="wzb1...."
#   ISSUER_PINS="sha256//<base64 SPKI hash of issuer.crt>"
#   AGENT_GROUP="linux-agents"
#
# Everything needed to reach and verify the issuer lives in that one file --
# no CA certificate has to be pre-placed on the host, which matches how the
# Windows package carries TlsPinsSha256 inside bootstrap.json.
#
# ISSUER_CA="/path/to/agents-rootCA.pem" is still honoured and takes
# precedence when the file exists, for hosts that already have it.
#
# Compute the pin on the manager:
#   openssl x509 -in /etc/wazuh-cert-issuer/tls/issuer.crt -pubkey -noout |
#     openssl pkey -pubin -outform der |
#     openssl dgst -sha256 -binary | openssl enc -base64
#
# Idempotent and safe to run from a systemd timer: if the agent is already
# enrolled and its service is up, it exits 0 without touching the issuer.

set -euo pipefail

CONF="/etc/wazuh-bootstrap/bootstrap.conf"
FORCE=0
AGENT_NAME="$(hostname -s)"
ENROLL_SCRIPT="$(dirname "$(readlink -f "$0")")/wazuh_enroll.sh"

usage() {
  echo "Usage: sudo $0 [-c <bootstrap.conf>] [-n <agent_name>] [-e <wazuh_enroll.sh>] [-f]"
  echo "  -f   Re-enroll even if the agent already looks healthy"
  exit 1
}

while getopts "c:n:e:fh" opt; do
  case "$opt" in
    c) CONF="$OPTARG" ;;
    n) AGENT_NAME="$OPTARG" ;;
    e) ENROLL_SCRIPT="$OPTARG" ;;
    f) FORCE=1 ;;
    h|*) usage ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "ERROR: must run as root." >&2; exit 1; }
[ -f "$CONF" ] || { echo "ERROR: config not found at $CONF" >&2; exit 1; }
[ -f "$ENROLL_SCRIPT" ] || { echo "ERROR: wazuh_enroll.sh not found at $ENROLL_SCRIPT" >&2; exit 1; }

# shellcheck disable=SC1090
. "$CONF"

: "${ISSUER_URL:?ISSUER_URL not set in $CONF}"
: "${BOOTSTRAP_TOKEN:?BOOTSTRAP_TOKEN not set in $CONF}"
AGENT_GROUP="${AGENT_GROUP:-linux-agents}"

log() { echo "$(date -Is) [bootstrap] $*"; }

# ---------- already healthy? ----------
if [ "$FORCE" -eq 0 ]; then
  if systemctl is-active --quiet wazuh-agent 2>/dev/null \
     && [ -s /var/ossec/etc/client.keys ]; then
    log "agent already enrolled and running; nothing to do (use -f to force)"
    exit 0
  fi
fi

# ---------- fetch material ----------
WORK="$(mktemp -d /run/wazuh-bootstrap.XXXXXX)"
chmod 700 "$WORK"
cleanup() {
  # /run is tmpfs, but shred anyway in case someone repointed TMPDIR to disk.
  find "$WORK" -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

CURL_TLS=()
if [ -n "${ISSUER_CA:-}" ] && [ -f "${ISSUER_CA:-}" ]; then
  # Chain verification against a CA file. Strongest option when the file is
  # available -- it validates hostname and expiry as well as the chain.
  CURL_TLS=(--cacert "$ISSUER_CA")
  log "TLS: verifying issuer against CA file $ISSUER_CA"

elif [ -n "${ISSUER_PINS:-}" ]; then
  # Public-key pinning: the trust anchor lives in bootstrap.conf itself, so
  # no CA file has to be pre-placed on the host. This is the curl equivalent
  # of the TlsPinsSha256 callback in Install-WazuhAgent.ps1.
  #
  # --insecure disables chain and hostname checks, but --pinnedpubkey is
  # enforced independently of it: curl aborts unless the server's public key
  # hashes to one of these values. A MITM presenting any other certificate
  # fails, so the bootstrap token is never sent to it.
  #
  # Note this pins the PUBLIC KEY (SPKI), not the certificate. Renewing
  # issuer.crt with the same key pair keeps the pin valid; generating a new
  # key does not. See bootstrap.conf.example for how to compute the value.
  CURL_TLS=(--insecure --pinnedpubkey "$ISSUER_PINS")
  log "TLS: verifying issuer by public-key pin (no CA file needed)"

elif [ "${ISSUER_TLS_INSECURE:-0}" = "1" ]; then
  # Deliberate escape hatch. Anything that answers on the issuer port gets
  # handed a bootstrap token that mints agent certificates. Lab use only.
  CURL_TLS=(--insecure)
  log "WARNING: ISSUER_TLS_INSECURE=1 -- the issuer's identity is NOT verified."
  log "WARNING: the bootstrap token will be sent to whatever answers on that port."

else
  echo "ERROR: no way to verify the issuer's TLS certificate." >&2
  echo "       Set ONE of the following in $CONF:" >&2
  echo "         ISSUER_PINS=\"sha256//<base64>\"            (recommended -- no extra file)" >&2
  echo "         ISSUER_CA=\"/path/to/agents-rootCA.pem\"    (chain verification)" >&2
  echo "         ISSUER_TLS_INSECURE=1                     (lab only, no verification)" >&2
  exit 1
fi

# --pinnedpubkey landed in curl 7.39. Fail loudly rather than silently
# dropping the only thing standing between the token and a MITM.
if [ -n "${ISSUER_PINS:-}" ] && ! curl --help all 2>/dev/null | grep -q -- '--pinnedpubkey'; then
  echo "ERROR: this curl does not support --pinnedpubkey (needs >= 7.39)." >&2
  echo "       Set ISSUER_CA instead, or upgrade curl." >&2
  exit 1
fi

RESP="$WORK/resp.json"
HTTP_CODE=""
for attempt in 1 2 3 4 5; do
  log "requesting enrollment material (attempt $attempt/5)"
  set +e
  HTTP_CODE="$(curl -sS --max-time 30 -o "$RESP" -w '%{http_code}' \
    "${CURL_TLS[@]}" \
    -X POST "${ISSUER_URL%/}/v1/agent-bootstrap" \
    -H "Authorization: Bearer ${BOOTSTRAP_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"agent_name\":\"${AGENT_NAME}\",\"platform\":\"linux\"}")"
  rc=$?
  set -e
  [ $rc -eq 0 ] && [ "$HTTP_CODE" = "200" ] && break

  # 4xx that isn't 429 will not fix itself.
  if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "429" ] \
     && [ "$HTTP_CODE" -ge 400 ] && [ "$HTTP_CODE" -lt 500 ]; then
    echo "ERROR: issuer returned HTTP $HTTP_CODE -- $(cat "$RESP" 2>/dev/null)" >&2
    echo "       (expired bootstrap token? wrong agent name?)" >&2
    exit 1
  fi
  [ "$attempt" -eq 5 ] && { echo "ERROR: issuer unreachable after 5 attempts (last: ${HTTP_CODE:-curl rc=$rc})" >&2; exit 1; }
  sleep $((attempt * 5))
done

command -v jq >/dev/null || { echo "ERROR: jq is required. apt install jq / dnf install jq" >&2; exit 1; }

CERT="$WORK/agent.cert"
KEY="$WORK/agent.key"
CA="$WORK/manager-ca.pem"

jq -r '.cert_pem_b64'       "$RESP" | base64 -d > "$CERT"
jq -r '.key_pem_b64'        "$RESP" | base64 -d > "$KEY"
jq -r '.manager_ca_pem_b64' "$RESP" | base64 -d > "$CA"
MANAGER="$(jq -r '.manager' "$RESP")"
GROUP="$(jq -r '.agent_group // empty' "$RESP")"; GROUP="${GROUP:-$AGENT_GROUP}"
ENROLL_PW="$(jq -r '.enrollment_password' "$RESP")"
chmod 600 "$CERT" "$KEY" "$CA"

log "received cert for $(jq -r '.agent_name' "$RESP"), manager $MANAGER, group $GROUP"

# ---------- enroll ----------
# The password goes in via the environment rather than the command line so it
# doesn't show up in /proc/<pid>/cmdline for every local user to read.
set +e
WAZUH_ENROLL_PW="$ENROLL_PW" bash -c '
  exec "$1" -m "$2" -P "$WAZUH_ENROLL_PW" -n "$3" -g "$4" -v "$5" -x "$6" -k "$7"
' _ "$ENROLL_SCRIPT" "$MANAGER" "$AGENT_NAME" "$GROUP" "$CA" "$CERT" "$KEY"
ENROLL_RC=$?
set -e

# Keep the manager CA -- it's a public cert and the agent needs it to verify
# the manager on any future automatic re-enrollment.
install -m 644 -D "$CA" /etc/wazuh-bootstrap/manager-ca.pem

if [ $ENROLL_RC -ne 0 ]; then
  echo "ERROR: wazuh_enroll.sh exited $ENROLL_RC -- see /var/ossec/logs/ossec.log" >&2
  exit $ENROLL_RC
fi

log "enrollment complete; cert and key shredded"
exit 0