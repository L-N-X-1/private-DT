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
# Optional knobs, also read from bootstrap.conf:
#   BOOTSTRAP_INSTALL_JQ=0   Never install jq via the package manager. Use on
#                            hosts where config management owns package state
#                            or that have no route to a distro mirror. The
#                            python3 fallback still applies. Default is 1.
#   DPKG_LOCK_WAIT=<secs>    How long to wait for the dpkg/apt lock before
#                            giving up on installing jq. Default 600.
#
# JSON parser precedence: jq if already present -> install jq -> python3.
# python3 is last on purpose: it exists nearly everywhere, so checking it
# before the install step would make the install step unreachable.
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
# Checked before the JSON parser so a healthy host with no jq and no network
# route to a mirror still exits 0 instead of failing a pre-flight it doesn't need.
if [ "$FORCE" -eq 0 ]; then
  if systemctl is-active --quiet wazuh-agent 2>/dev/null \
     && [ -s /var/ossec/etc/client.keys ]; then
    log "agent already enrolled and running; nothing to do (use -f to force)"
    exit 0
  fi
fi

# ---------- JSON parser pre-flight ----------
# This runs BEFORE the issuer is contacted. Failing here costs a log line;
# failing after the fetch would mean the issuer has already minted a cert and
# key for this host that we then throw away, leaving a live credential in its
# records for an agent that never enrolled.
#
# Order of preference:
#   1. jq, if already installed
#   2. python3 stdlib, present on essentially every distro that runs Wazuh
#   3. install jq via the package manager (unless BOOTSTRAP_INSTALL_JQ=0)
#
# Sets jget(), which takes a top-level key name and echoes its value, or the
# empty string when the key is absent or null.

# Same unattended-upgrades race that bites the agent package install: apt
# exits 100 rather than queueing behind whoever holds the dpkg lock. Wait it
# out here too, otherwise a first-boot bootstrap fails on `apt-get install jq`
# for a reason that clears itself in a couple of minutes.
wait_for_dpkg_lock() {
  local waited=0 max="${DPKG_LOCK_WAIT:-600}"
  command -v fuser >/dev/null 2>&1 || return 0
  while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
              /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if [ "$waited" -ge "$max" ]; then
      echo "ERROR: dpkg/apt lock still held after ${max}s; cannot install jq." >&2
      return 1
    fi
    [ "$waited" -eq 0 ] && log "dpkg/apt is locked (unattended-upgrades?); waiting up to ${max}s..."
    sleep 10
    waited=$((waited + 10))
  done
  [ "$waited" -gt 0 ] && log "dpkg/apt lock released after ${waited}s"
  return 0
}

install_jq() {
  if   command -v apt-get >/dev/null 2>&1; then
    wait_for_dpkg_lock || return 1
    timeout 300 env DEBIAN_FRONTEND=noninteractive \
      apt-get -o DPkg::Lock::Timeout=300 update -qq \
      && timeout 300 env DEBIAN_FRONTEND=noninteractive \
      apt-get -o DPkg::Lock::Timeout=300 install -y -qq jq
  elif command -v dnf >/dev/null 2>&1; then
    # dnf before yum: Fedora and modern RHEL ship a yum symlink pointing here.
    timeout 300 dnf install -y -q jq
  elif command -v yum >/dev/null 2>&1; then
    timeout 300 yum install -y -q jq
  elif command -v zypper >/dev/null 2>&1; then
    timeout 300 zypper --non-interactive --quiet install jq
  elif command -v apk >/dev/null 2>&1; then
    timeout 300 apk add --no-cache jq
  elif command -v pacman >/dev/null 2>&1; then
    timeout 300 pacman -Sy --noconfirm --needed jq
  else
    echo "ERROR: no supported package manager found; install jq manually." >&2
    return 1
  fi
}

use_jq() {
  jget() { jq -r --arg k "$1" 'getpath([$k]) // "" | tostring' "$RESP"; }
}

use_python() {
  jget() {
    python3 -c 'import json,sys
v = json.load(open(sys.argv[1])).get(sys.argv[2])
print("" if v is None else v)' "$RESP" "$1"
  }
}

ensure_json_parser() {
  if command -v jq >/dev/null 2>&1; then
    use_jq
    return 0
  fi

  # Try to install jq BEFORE falling back to python3. python3 is present on
  # essentially every distro that runs Wazuh, so checking it first meant the
  # install branch below was unreachable in practice and jq never appeared.
  if [ "${BOOTSTRAP_INSTALL_JQ:-1}" = "1" ]; then
    log "jq not found; installing it"
    set +e
    install_jq
    local rc=$?
    set -e
    if [ $rc -eq 0 ] && command -v jq >/dev/null 2>&1; then
      log "jq installed: $(jq --version 2>/dev/null)"
      use_jq
      return 0
    fi
    log "jq install did not succeed (rc=$rc); looking for a fallback parser"
  else
    log "BOOTSTRAP_INSTALL_JQ=0; not installing jq"
  fi

  # Fallback: no package manager, no network route to a mirror, or config
  # management owns package state. Parsing the response is all we need.
  if command -v python3 >/dev/null 2>&1; then
    log "using python3 to parse the issuer response"
    use_python
    return 0
  fi

  echo "ERROR: no JSON parser available -- jq could not be installed and" >&2
  echo "       python3 is not present. Install one of them and re-run." >&2
  return 1
}

ensure_json_parser || exit 1

# ---------- fetch material ----------
WORK="$(mktemp -d /run/wazuh-bootstrap.XXXXXX)"
chmod 700 "$WORK"
cleanup() {
  # /run is tmpfs, but shred anyway in case someone repointed TMPDIR to disk.
  find "$WORK" -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Created before any redirect below, so the key is never briefly world-readable
# between `> file` and the `chmod 600` that used to follow it.
umask 077

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

CERT="$WORK/agent.cert"
KEY="$WORK/agent.key"
CA="$WORK/manager-ca.pem"

jget cert_pem_b64       | base64 -d > "$CERT"
jget key_pem_b64        | base64 -d > "$KEY"
jget manager_ca_pem_b64 | base64 -d > "$CA"
MANAGER="$(jget manager)"
GROUP="$(jget agent_group)"; GROUP="${GROUP:-$AGENT_GROUP}"
ENROLL_PW="$(jget enrollment_password)"
chmod 600 "$CERT" "$KEY" "$CA"

# A truncated or unexpected response is easier to diagnose here than three
# steps later inside wazuh_enroll.sh.
[ -s "$CERT" ] && [ -s "$KEY" ] && [ -s "$CA" ] || {
  echo "ERROR: issuer response was missing cert, key or manager CA." >&2
  exit 1
}
[ -n "$MANAGER" ] || { echo "ERROR: issuer response had no manager address." >&2; exit 1; }

log "received cert for $(jget agent_name), manager $MANAGER, group $GROUP"

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