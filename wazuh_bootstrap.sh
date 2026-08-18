#!/usr/bin/env bash
#
# wazuh_bootstrap.sh
# ------------------
# One-shot enrollment wrapper. Fetches this host's certificate material from
# wazuh-cert-issuer over pinned TLS, hands it to wazuh_enroll.sh, then
# destroys every piece of it.
#
# There is no timer and no self-heal. The token is single-use, so a second
# run needs a freshly minted one. An agent that later loses client.keys is
# repaired by running this again, not automatically.
#
# Usage:
#   ./mint_token.py --ttl 1h --single-use        # on the issuer host
#   sudo /opt/wazuh-bootstrap/wazuh_bootstrap.sh # paste token at the prompt
#
#   # non-interactive (CI, cloud-init):
#   printf '%s' "$TOKEN" | sudo /opt/wazuh-bootstrap/wazuh_bootstrap.sh --token-stdin
#
# The token is NEVER accepted as a command-line argument. /proc/<pid>/cmdline
# is world-readable on a default Linux install, so any local user could read
# it for the duration of the run.

set -euo pipefail

CONF="${BOOTSTRAP_CONF:-/etc/wazuh-bootstrap/bootstrap.conf}"
ENROLL_SCRIPT="${ENROLL_SCRIPT:-/opt/wazuh-bootstrap/wazuh_enroll.sh}"

# /run is tmpfs: the private key never touches persistent storage, and it is
# gone on reboot even if this script dies mid-way. Do not move this to /etc
# or /tmp -- on ext4/btrfs/SSD, shred cannot reliably overwrite what was
# already written to disk.
WORKDIR="/run/wazuh-bootstrap"

cleanup() {
  if [ -d "$WORKDIR" ]; then
    find "$WORKDIR" -type f -exec shred -u {} + 2>/dev/null || true
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT INT TERM

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must be run as root (use sudo)."

# base64 and shred are in coreutils and are always present. curl and jq are
# not: jq in particular is absent from a default install on nearly every
# distro. Install them rather than failing, since the endpoint already needs
# repo access to fetch the wazuh-agent package a moment later.
install_prereqs() {
  local missing=() pkgs=()
  # command -> package name. gpg comes from gnupg and is absent from
  # minimal/cloud Ubuntu images, where the enroll script would then die
  # importing the Wazuh signing key.
  for tool in curl jq gpg; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
      case "$tool" in
        gpg) pkgs+=("gnupg") ;;
        *)   pkgs+=("$tool") ;;
      esac
    fi
  done
  [ "${#missing[@]}" -eq 0 ] && return 0

  echo "-- Missing prerequisites: ${missing[*]}. Installing..."

  local os_id="" os_like=""
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_id="${ID:-}"; os_like="${ID_LIKE:-}"
  fi

  case "$os_id $os_like" in
    *ubuntu*|*debian*)
      # Same unattended-upgrades race the enroll script handles: apt exits
      # 100 immediately rather than queueing behind a held lock.
      apt-get -o DPkg::Lock::Timeout=300 update -qq
      DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 \
        install -y "${pkgs[@]}"
      ;;
    *rhel*|*centos*|*rocky*|*almalinux*|*fedora*|*amzn*|*ol*)
      local pkg="yum"
      command -v dnf >/dev/null 2>&1 && pkg="dnf"
      # jq lives in EPEL on RHEL 8/9 derivatives; if this fails, that is why.
      "$pkg" install -y "${pkgs[@]}"
      ;;
    *)
      die "cannot auto-install ${missing[*]} on this distro (ID=$os_id).
       Install them manually and re-run."
      ;;
  esac

  for tool in "${missing[@]}"; do
    command -v "$tool" >/dev/null 2>&1 || \
      die "$tool still not available after install. On RHEL-family systems jq
       usually needs EPEL: dnf install -y epel-release"
  done
  echo "   Installed."
}

# Check outbound access to the package repo BEFORE spending the token. A
# single-use token is burned the moment the issuer authenticates it, so
# discovering there is no internet three steps later costs a fresh mint.
check_repo_reachable() {
  echo "-- Checking outbound access to packages.wazuh.com..."
  if curl -fsSL --max-time 20 --retry 2 \
       https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /dev/null 2>/dev/null; then
    echo "   OK."
    return 0
  fi
  echo "ERROR: cannot reach packages.wazuh.com." >&2
  echo "       The agent package cannot be installed from here. Stopping now" >&2
  echo "       rather than burning your bootstrap token on a run that would" >&2
  echo "       fail a few steps later." >&2
  echo >&2
  echo "       Diagnose with:" >&2
  echo "         curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | head -3" >&2
  echo "         getent hosts packages.wazuh.com" >&2
  echo >&2
  echo "       Set SKIP_REPO_CHECK=1 to bypass this (e.g. if you mirror the" >&2
  echo "       repo internally or preinstall the agent package)." >&2
  exit 1
}

install_prereqs
[ "${SKIP_REPO_CHECK:-0}" = "1" ] || check_repo_reachable

[ -f "$CONF" ] || die "config not found at $CONF"
# shellcheck disable=SC1090
. "$CONF"

: "${ISSUER_URL:?ISSUER_URL not set in $CONF}"
: "${ISSUER_PINS:?ISSUER_PINS not set in $CONF}"
AGENT_GROUP="${AGENT_GROUP:-linux-agents}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"
AGENT_VERSION="${AGENT_VERSION:-4.14.3}"

if [ -n "${BOOTSTRAP_TOKEN:-}" ]; then
  die "BOOTSTRAP_TOKEN is set in $CONF. Remove it -- tokens are single-use and
       must not be stored on the endpoint. This script reads the token from
       stdin or an interactive prompt."
fi

# ---------- read the token ----------
if [ "${1:-}" = "--token-stdin" ]; then
  IFS= read -r TOKEN || true
else
  printf 'Bootstrap token: ' >&2
  IFS= read -rs TOKEN || true
  printf '\n' >&2
fi
[ -n "${TOKEN:-}" ] || die "no token supplied."
case "$TOKEN" in
  wzb1.*) ;;
  *) die "that does not look like a bootstrap token (expected it to start with wzb1.)." ;;
esac

mkdir -p "$WORKDIR"
chmod 700 "$WORKDIR"

# ---------- fetch the material ----------
echo "-- Requesting enrollment material from $ISSUER_URL for '$AGENT_NAME'..."

# --insecure plus --pinnedpubkey is deliberate and is NOT the same as bare
# --insecure. The issuer's cert is signed by agents-rootCA, which is not in
# the system trust store and which we do not have yet -- that is what we are
# fetching. The public-key pin is what authenticates the server. curl exits
# 60 on a chain failure and 90 on a pin mismatch; both are fatal below.
#
# The token goes in a header, not the URL: query strings land in access logs.
HTTP_CODE=$(curl --silent --show-error \
  --insecure --pinnedpubkey "$ISSUER_PINS" \
  --max-time 30 --retry 3 --retry-delay 5 --retry-connrefused \
  --write-out '%{http_code}' \
  --output "$WORKDIR/response.json" \
  -X POST "$ISSUER_URL/v1/agent-bootstrap" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"agent_name\":\"$AGENT_NAME\",\"platform\":\"linux\"}") || {
    rc=$?
    case "$rc" in
      90) die "TLS public-key pin mismatch. The issuer presented an unexpected
       certificate. Either issuer.crt was rotated without updating
       ISSUER_PINS, or something is intercepting the connection. Do not
       work around this by removing --pinnedpubkey." ;;
      28) die "timed out reaching $ISSUER_URL (curl 28)." ;;
       7) die "could not connect to $ISSUER_URL (curl 7). Check the host, port 8443, and firewall." ;;
       *) die "curl failed with exit code $rc." ;;
    esac
  }

unset TOKEN

if [ "$HTTP_CODE" != "200" ]; then
  detail=$(jq -r '.detail // .error // "no detail"' < "$WORKDIR/response.json" 2>/dev/null || echo "unparseable response")
  case "$HTTP_CODE" in
    401) die "issuer rejected the token (401): $detail
       A single-use token is burned on first use, including on a run that
       failed later. Mint a fresh one." ;;
    429) die "issuer refused (429): $detail" ;;
    *)   die "issuer returned HTTP $HTTP_CODE: $detail" ;;
  esac
fi

# ---------- unpack ----------
CERT="$WORKDIR/agent.cert"
KEY="$WORKDIR/agent.key"
CA="$WORKDIR/manager-ca.pem"

umask 077
jq -r '.cert_pem_b64'       < "$WORKDIR/response.json" | base64 -d > "$CERT"
jq -r '.key_pem_b64'        < "$WORKDIR/response.json" | base64 -d > "$KEY"
jq -r '.manager_ca_pem_b64' < "$WORKDIR/response.json" | base64 -d > "$CA"
MANAGER=$(jq -r '.manager'     < "$WORKDIR/response.json")
GROUP=$(jq -r   '.agent_group' < "$WORKDIR/response.json")
NAME=$(jq -r    '.agent_name'  < "$WORKDIR/response.json")

for f in "$CERT" "$KEY" "$CA"; do
  [ -s "$f" ] || die "issuer response was missing or empty for $(basename "$f")."
done
chmod 600 "$CERT" "$KEY" "$CA"

# The issuer decides the final name and group -- it may have pinned them to
# the token. Trust its answer over anything we guessed locally.
[ -n "$NAME" ] && [ "$NAME" != "null" ] && AGENT_NAME="$NAME"
[ -n "$GROUP" ] && [ "$GROUP" != "null" ] && AGENT_GROUP="$GROUP"
[ -n "$MANAGER" ] && [ "$MANAGER" != "null" ] || die "issuer did not return a manager address."

if jq -e 'has("enrollment_password")' < "$WORKDIR/response.json" >/dev/null 2>&1; then
  echo "WARNING: the issuer still returns enrollment_password. That field is no" >&2
  echo "         longer consumed and should be removed from app.py -- it is a" >&2
  echo "         non-expiring secret being handed out for no reason." >&2
fi

echo "-- Material received (agent: $AGENT_NAME, manager: $MANAGER, group: $AGENT_GROUP)"
echo "-- Agent package version: $AGENT_VERSION"
echo

# ---------- enroll ----------
[ -x "$ENROLL_SCRIPT" ] || die "enrollment script not found or not executable at $ENROLL_SCRIPT"

"$ENROLL_SCRIPT" \
  -m "$MANAGER" \
  -n "$AGENT_NAME" \
  -g "$AGENT_GROUP" \
  -V "$AGENT_VERSION" \
  -v "$CA" \
  -x "$CERT" \
  -k "$KEY"

  # ---------- Sprint 3: endpoint command auditing ----------
# Runs AFTER enrollment so a failed enrollment does not leave a host with
# audit rules but no agent to ship them.
#
# Non-fatal on purpose. The agent is enrolled and reporting at this point;
# an auditd problem should not make the operator think enrollment failed and
# burn a second single-use token re-running the whole thing. The script is
# idempotent and standalone, so the repair is just re-running it.
AUDIT_SETUP="${AUDIT_SETUP:-/opt/wazuh-bootstrap/wazuh_audit_setup.sh}"

if [ -x "$AUDIT_SETUP" ]; then
  echo
  echo "-- Configuring command auditing (Sprint 3 Phase 1)..."
  if "$AUDIT_SETUP" ${AUDIT_TIMER:+--install-timer}; then
    echo "-- Command auditing configured."
  else
    echo "WARNING: command auditing setup reported problems. The agent is" >&2
    echo "         enrolled and reporting -- do NOT re-run this bootstrap" >&2
    echo "         script (the token is spent). Fix and re-run:" >&2
    echo "           sudo $AUDIT_SETUP --check" >&2
  fi
else
  echo
  echo "NOTE: $AUDIT_SETUP not found -- command auditing not configured."
  echo "      Copy it to /opt/wazuh-bootstrap/ and run it separately."
fi
# cleanup() runs from the EXIT trap and removes the whole tmpfs directory --
# certificate, private key, manager CA, and the raw response.
echo
echo "-- Enrollment material destroyed. Nothing was written to persistent storage."
echo "-- wazuh-agent is enabled and will start on every boot."
echo "-- There is no self-heal: if this agent later loses client.keys, mint a"
echo "   fresh single-use token and run this script again."