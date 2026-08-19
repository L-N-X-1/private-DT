#!/usr/bin/env bash
#
# wazuh_enroll.sh
# ----------------
# Installs (if needed) and enrolls a Wazuh agent with a manager, then
# verifies the enrollment actually succeeded instead of trusting a
# silent "install completed" exit code.
#
# Usage:
#   sudo ./wazuh_enroll.sh -v <manager_ca> -x <agent_cert> -k <agent_key> [-m 192.168.29.192] [-n agent-name]
#   (manager defaults to 192.168.29.192 if -m is not given)
#
# Notes:
#   - Must be run as root (via sudo) since it installs packages and
#     writes to /var/ossec.
#   - The manager runs with <use_password>no</use_password> and
#     <ssl_agent_ca> set, so the agent's own certificate (-x/-k) is the
#     credential. -P is retained only for managers that still require a
#     registration password; it is optional and normally unused.
#   - Because the certificate is the only factor, ssl_agent_ca MUST be
#     configured and working on the manager. Without it, a manager with
#     use_password=no accepts enrollment from anyone who can reach 1515.
#   - Safe to re-run: if the agent is already enrolled, it will
#     re-enroll cleanly (old key is dropped by agent-auth) and restart
#     the service.
#   - Strips the default journald localfile block from ossec.conf so
#     auth/syslog events (centrally managed via the manager's group
#     config) aren't double-ingested through both journald and the
#     flat log files. Re-running this script on an already-enrolled
#     host will also retroactively clean it up.
#   - Log SOURCES are owned by the manager-side group config
#     (/var/ossec/etc/shared/linux-agents/agent.conf), NOT by this
#     script. Declaring them in both places makes logcollector open two
#     readers for the same file, which double-counts events and skews
#     any frequency-based rule. Pass -l to write them locally anyway
#     (useful if you don't trust group assignment to succeed) -- but if
#     you do, remove the matching <localfile> entries from the group
#     config first.
#   - Writes the <client> section into the LOCAL ossec.conf. <client>
#     is not a valid section in shared agent.conf: it's what tells the
#     agent which manager to talk to, so it has to be present before
#     the agent can fetch shared config at all.
#   - Installs net-tools (for netstat) if it is missing, since the
#     manager-pushed netstat command blocks need it and it is absent
#     from most modern default installs. Non-fatal: a failure here
#     warns and continues rather than failing an enrollment that has
#     already spent a single-use bootstrap token.
#   - Verifies the manager's identity during enrollment via
#     -v <ca_cert_path>. Without it, agent-auth will accept a TLS cert
#     from *anything* answering on the registration port. See:
#     https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/manager-identity-verification.html
#   - Presents this agent's own signed cert via -x <cert_path>
#     -k <key_path>, so the manager can verify the agent's identity
#     (requires ssl_agent_ca set on the manager). Both flags must be
#     given together. See:
#     https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/agent-identity-verification.html

set -euo pipefail

# ---------- defaults ----------
AGENT_NAME="$(hostname)"
REG_SERVER=""
MANAGER="192.168.29.192"
REG_PASSWORD=""
REG_PORT=1515
EVENT_PORT=1514
AGENT_GROUP="linux-agents"
# Pinned to match the manager. The agent must never be newer than the
# manager; an unpinned "install latest" will eventually violate that
# silently the first time Wazuh publishes a new release.
AGENT_VERSION="4.14.3"
MANAGER_CA=""
AGENT_CERT=""
AGENT_KEY=""
OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOCAL_LOG_SOURCES=0
CONF_BACKUP=""

usage() {
  echo "Usage: sudo $0 -v <manager_ca> -x <agent_cert> -k <agent_key> [-m <manager_ip>] [-n <agent_name>] [-r <registration_server_ip>] [-g <agent_group>]"
  echo
  echo "  -m   Wazuh manager IP/host (used for WAZUH_MANAGER, i.e. where events go). Default: 192.168.29.192"
  echo "  -n   Agent name to register as (default: system hostname)"
  echo "  -r   Registration server IP/host, if different from -m (default: same as -m)"
  echo "  -g   Agent group to enroll into (must already exist on the manager). Default: linux-agents"
  echo "  -V   wazuh-agent package version to install. Default: 4.14.3 (match your manager)."
  echo "       Only used when the agent is not already installed."
  echo "  -v   Path to the manager's CA certificate (agents-rootCA.pem). agent-auth verifies"
  echo "       the manager's TLS cert during enrollment instead of trusting whatever answers"
  echo "       on the registration port."
  echo "  -x   Path to this agent's own signed certificate. Must be given together with -k."
  echo "       This is the credential the manager checks against ssl_agent_ca."
  echo "  -k   Path to this agent's own private key. Must be given together with -x."
  echo "  -P   Registration password. Optional, and normally unused: the manager runs with"
  echo "       use_password=no. Only needed against a manager that still requires one."
  echo "  -l   Also write baseline auth/syslog <localfile> blocks into the LOCAL"
  echo "       ossec.conf. Off by default because the manager-side group config"
  echo "       already declares them -- having both double-ingests every event."
  echo "       Only use this if you also remove them from the group's agent.conf."
  exit 1
}

while getopts "m:P:n:r:g:v:x:k:V:lh" opt; do
  case "$opt" in
    m) MANAGER="$OPTARG" ;;
    P) REG_PASSWORD="$OPTARG" ;;
    n) AGENT_NAME="$OPTARG" ;;
    r) REG_SERVER="$OPTARG" ;;
    g) AGENT_GROUP="$OPTARG" ;;
    V) AGENT_VERSION="$OPTARG" ;;
    v) MANAGER_CA="$OPTARG" ;;
    x) AGENT_CERT="$OPTARG" ;;
    k) AGENT_KEY="$OPTARG" ;;
    l) LOCAL_LOG_SOURCES=1 ;;
    h) usage ;;
    *) usage ;;
  esac
done

[ -z "$MANAGER" ] && usage
[ -z "$REG_SERVER" ] && REG_SERVER="$MANAGER"

# Refuse to enroll with no credential at all. Against a manager configured
# the way this project expects (use_password=no + ssl_agent_ca), running
# without -x/-k would either be rejected by authd or -- if ssl_agent_ca is
# misconfigured -- succeed anonymously, which is far worse than failing.
if [ -z "$AGENT_CERT" ] && [ -z "$REG_PASSWORD" ]; then
  echo "ERROR: no enrollment credential given." >&2
  echo "       Pass -x <cert> -k <key> (normal), or -P <password> against a manager" >&2
  echo "       that still uses one. Enrolling with neither is never correct." >&2
  exit 1
fi

if [ -n "$MANAGER_CA" ] && [ ! -f "$MANAGER_CA" ]; then
  echo "ERROR: manager CA cert not found at $MANAGER_CA (check the -v path)." >&2
  exit 1
fi

if [ -n "$AGENT_CERT" ] || [ -n "$AGENT_KEY" ]; then
  if [ -z "$AGENT_CERT" ] || [ -z "$AGENT_KEY" ]; then
    echo "ERROR: -x and -k must be given together (agent identity verification needs both cert and key)." >&2
    exit 1
  fi
  if [ ! -f "$AGENT_CERT" ]; then
    echo "ERROR: agent cert not found at $AGENT_CERT (check the -x path)." >&2
    exit 1
  fi
  if [ ! -f "$AGENT_KEY" ]; then
    echo "ERROR: agent key not found at $AGENT_KEY (check the -k path)." >&2
    exit 1
  fi
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run as root (use sudo)." >&2
  exit 1
fi

# Sweep backups left behind by earlier runs that died before their cleanup.
rm -f "${OSSEC_CONF}".bak.* /var/ossec/etc/client.keys.bak.* 2>/dev/null || true

# ---------- distro family detection (drives package manager + log paths) ----------
OS_ID="unknown"
OS_ID_LIKE=""
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_ID_LIKE="${ID_LIKE:-}"
fi

case "$OS_ID" in
  ubuntu|debian) OS_FAMILY="debian" ;;
  rhel|centos|rocky|almalinux|fedora|amzn|ol) OS_FAMILY="rhel" ;;
  *)
    case " $OS_ID_LIKE " in
      *" debian "*) OS_FAMILY="debian" ;;
      *" rhel "*|*" fedora "*|*" centos "*) OS_FAMILY="rhel" ;;
      *) OS_FAMILY="unknown" ;;
    esac
    ;;
esac

if [ "$OS_FAMILY" = "unknown" ]; then
  echo "ERROR: unrecognized/unsupported Linux distro (ID=$OS_ID, ID_LIKE=$OS_ID_LIKE)." >&2
  echo "       This script supports Debian/Ubuntu (apt) and RHEL/CentOS/Rocky/Alma/Fedora/Amazon Linux (yum/dnf) families." >&2
  exit 1
fi

# Baseline log paths differ by family: Debian ships auth.log/syslog,
# RHEL-family ships secure/messages instead.
case "$OS_FAMILY" in
  debian) AUTH_LOG_PATH="/var/log/auth.log"; SYS_LOG_PATH="/var/log/syslog" ;;
  rhel)   AUTH_LOG_PATH="/var/log/secure";   SYS_LOG_PATH="/var/log/messages" ;;
esac

echo "== Wazuh Agent Enrollment =="
echo "  Manager (events, port $EVENT_PORT):        $MANAGER"
echo "  Registration server (port $REG_PORT):       $REG_SERVER"
echo "  Agent name:                                 $AGENT_NAME"
echo "  Agent group:                                 $AGENT_GROUP"
echo "  Detected distro family:                      $OS_FAMILY (ID=$OS_ID)"
echo "  Agent version (if not installed):            $AGENT_VERSION"
if [ -n "$MANAGER_CA" ]; then
  echo "  Manager identity verification:               ENABLED ($MANAGER_CA)"
else
  echo "  Manager identity verification:               DISABLED (no -v given -- manager identity is NOT verified during enrollment)"
fi
if [ -n "$AGENT_CERT" ]; then
  echo "  Agent identity verification (this agent):    ENABLED ($AGENT_CERT)"
else
  echo "  Agent identity verification (this agent):    DISABLED (no -x/-k given -- falling back to a registration password)"
fi
if [ "$LOCAL_LOG_SOURCES" -eq 1 ]; then
  echo "  Baseline log sources:                        LOCAL (-l given -- remove them from the group agent.conf!)"
else
  echo "  Baseline log sources:                        manager group config (linux-agents/agent.conf)"
fi
echo

# ---------- 1. connectivity pre-check ----------
for check in "$REG_SERVER:$REG_PORT:registration" "$MANAGER:$EVENT_PORT:event"; do
  IFS=: read -r c_host c_port c_label <<< "$check"
  echo "-- Checking connectivity to $c_label port ($c_host:$c_port)..."
  if command -v nc >/dev/null 2>&1; then
    if ! nc -z -w 5 "$c_host" "$c_port"; then
      echo "ERROR: cannot reach $c_host on port $c_port ($c_label port)." >&2
      echo "       Check firewall rules and that the corresponding Wazuh service is running." >&2
      exit 1
    fi
    echo "   OK: port $c_port is reachable."
  else
    if [ "$OS_FAMILY" = "debian" ]; then
      echo "   (netcat not installed, skipping pre-check -- install with 'apt-get install netcat-openbsd')"
    else
      echo "   (netcat not installed, skipping pre-check -- install with 'dnf install nmap-ncat')"
    fi
  fi
done
echo

# ---------- 2. install the agent if not already installed ----------
wazuh_agent_installed() {
  case "$OS_FAMILY" in
    debian) dpkg -s wazuh-agent >/dev/null 2>&1 ;;
    rhel)   rpm -q wazuh-agent >/dev/null 2>&1 ;;
  esac
}

if ! wazuh_agent_installed; then
  echo "-- wazuh-agent not installed. Installing..."

  # Debian/Ubuntu run unattended-upgrades on a boot-triggered timer that
  # routinely overlaps a first-boot bootstrap. apt does not queue behind it:
  # it exits 100 immediately, which propagates all the way up and fails the
  # whole enrollment for a reason that resolves itself in a couple of minutes.
  wait_for_dpkg_lock() {
    local waited=0 max="${DPKG_LOCK_WAIT:-600}"
    command -v fuser >/dev/null 2>&1 || return 0
    while fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
                /var/lib/apt/lists/lock >/dev/null 2>&1; do
      if [ "$waited" -ge "$max" ]; then
        echo "ERROR: dpkg/apt lock still held after ${max}s. Holder:" >&2
        fuser -v /var/lib/dpkg/lock-frontend 2>&1 >/dev/null | head -5 >&2
        echo "       Wait for unattended-upgrades to finish and re-run, or set" >&2
        echo "       DPKG_LOCK_WAIT=<seconds> to wait longer." >&2
        return 1
      fi
      if [ "$waited" -eq 0 ]; then
        echo "   dpkg/apt is locked (unattended-upgrades?); waiting up to ${max}s..."
      fi
      sleep 10
      waited=$((waited + 10))
    done
    [ "$waited" -gt 0 ] && echo "   Lock released after ${waited}s."
    return 0
  }

  case "$OS_FAMILY" in
    debian)
      wait_for_dpkg_lock || exit 1

      # -s not -f: gpg creates the keyring file before it parses anything, so
      # a failed import leaves a zero-byte file behind. Testing -f would make
      # the next run skip the import and fail much later with NO_PUBKEY.
      if [ ! -s /usr/share/keyrings/wazuh.gpg ]; then
        echo "   Importing Wazuh GPG key..."
        rm -f /usr/share/keyrings/wazuh.gpg
        keytmp="$(mktemp)"
        # -f so an HTTP error is a curl failure rather than an error page
        # piped into gpg; --show-error so we learn why.
        if ! curl -fsSL --show-error --retry 3 --retry-delay 3 --max-time 60 \
             https://packages.wazuh.com/key/GPG-KEY-WAZUH -o "$keytmp"; then
          rm -f "$keytmp"
          echo "ERROR: could not download the Wazuh GPG key." >&2
          echo "       This host needs outbound HTTPS to packages.wazuh.com." >&2
          echo "       Test it directly with:" >&2
          echo "         curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | head -3" >&2
          echo "       If your endpoints have no internet egress, mirror the repo" >&2
          echo "       internally or install the .deb from S3 artifacts/ instead." >&2
          exit 1
        fi
        if ! gpg --batch --no-default-keyring \
             --keyring "gnupg-ring:/usr/share/keyrings/wazuh.gpg" --import "$keytmp"; then
          rm -f "$keytmp" /usr/share/keyrings/wazuh.gpg
          echo "ERROR: the downloaded file was not a valid OpenPGP key." >&2
          echo "       A captive portal or proxy may be returning an HTML page." >&2
          exit 1
        fi
        rm -f "$keytmp"
        chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "   Key imported."
      fi

      if [ ! -f /etc/apt/sources.list.d/wazuh.list ]; then
        echo "   Adding Wazuh apt repository..."
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
          > /etc/apt/sources.list.d/wazuh.list
      fi

      # -o DPkg::Lock::Timeout makes apt itself block rather than exit 100 if
      # something grabs the lock between our check above and this call.
      apt-get -o DPkg::Lock::Timeout=300 update -qq

      wait_for_dpkg_lock || exit 1

      # No WAZUH_REGISTRATION_PASSWORD: the manager runs use_password=no and
      # the package's own enrollment is disabled by the <client> block below.
      # Enrollment is done explicitly by agent-auth in step 6.
      #
      # The Wazuh apt repo names packages <version>-1, e.g. 4.14.3-1.
      if ! apt-cache show "wazuh-agent=${AGENT_VERSION}-1" >/dev/null 2>&1; then
        echo "ERROR: wazuh-agent ${AGENT_VERSION}-1 is not available in the apt repo." >&2
        echo "       Available versions:" >&2
        apt-cache madison wazuh-agent 2>/dev/null | head -10 >&2
        exit 1
      fi

      env WAZUH_MANAGER="$MANAGER" \
          WAZUH_REGISTRATION_SERVER="$REG_SERVER" \
          WAZUH_AGENT_NAME="$AGENT_NAME" \
          apt-get -o DPkg::Lock::Timeout=300 install -y "wazuh-agent=${AGENT_VERSION}-1"

      # Without a hold, the next unattended-upgrades run pulls whatever the
      # repo considers current -- which is how an agent silently ends up
      # newer than its manager. Release the hold deliberately when you
      # upgrade the manager: apt-mark unhold wazuh-agent
      apt-mark hold wazuh-agent >/dev/null 2>&1 || true
      echo "   Pinned wazuh-agent at ${AGENT_VERSION} (apt-mark hold)."
      ;;

    rhel)
      if [ ! -f /etc/yum.repos.d/wazuh.repo ]; then
        echo "   Importing Wazuh GPG key..."
        if ! rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH; then
          echo "ERROR: could not import the Wazuh GPG key." >&2
          echo "       This host needs outbound HTTPS to packages.wazuh.com." >&2
          echo "       Test it directly with:" >&2
          echo "         curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | head -3" >&2
          exit 1
        fi

        echo "   Adding Wazuh yum repository..."
        # Quoted heredoc delimiter ('EOF') so $releasever is left literal --
        # yum/dnf expand that themselves, we must not expand it here.
        cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
      fi

      PKG_MGR="yum"
      command -v dnf >/dev/null 2>&1 && PKG_MGR="dnf"

      env WAZUH_MANAGER="$MANAGER" \
          WAZUH_REGISTRATION_SERVER="$REG_SERVER" \
          WAZUH_AGENT_NAME="$AGENT_NAME" \
          "$PKG_MGR" install -y "wazuh-agent-${AGENT_VERSION}-1"

      # versionlock needs a plugin that is not installed by default
      # (python3-dnf-plugin-versionlock / yum-plugin-versionlock). Best
      # effort -- if it is missing, the version is still what we installed,
      # it just isn't protected from a future `dnf update`.
      if "$PKG_MGR" versionlock add wazuh-agent >/dev/null 2>&1; then
        echo "   Pinned wazuh-agent at ${AGENT_VERSION} (versionlock)."
      else
        echo "   NOTE: versionlock plugin unavailable; wazuh-agent is NOT protected"
        echo "         from a future '$PKG_MGR update'. Install it with:"
        echo "           $PKG_MGR install -y python3-dnf-plugin-versionlock"
      fi
      ;;
  esac
else
  echo "-- wazuh-agent already installed, skipping package install."
fi
echo

# ---------- 2b. install net-tools (netstat) ----------
# Sprint 3 pushes <command>/<full_command> blocks from the manager's shared
# agent.conf, and the netstat-based ones need the netstat binary, which lives
# in net-tools. That package is NOT installed by default on modern
# Ubuntu/Debian or on minimal RHEL-family/cloud images, so without this the
# command blocks run and return nothing -- a silent gap, not an error.
#
# Deliberately NON-FATAL. By the time this runs the bootstrap wrapper has
# already spent its single-use token; aborting here would force a fresh mint
# for a package the operator can install by hand in one command afterwards.
#
# Note: this does NOT provide `nc` for the connectivity pre-check above --
# that is netcat-openbsd (Debian) / nmap-ncat (RHEL), a separate package.
have_netstat() {
  command -v netstat >/dev/null 2>&1 || [ -x /usr/sbin/netstat ] || [ -x /bin/netstat ]
}

install_net_tools() {
  if have_netstat; then
    echo "-- net-tools already present, skipping."
    return 0
  fi

  echo "-- netstat not found. Installing net-tools..."
  case "$OS_FAMILY" in
    debian)
      # Same unattended-upgrades race as the agent install: DPkg::Lock::Timeout
      # makes apt block on a held lock instead of exiting 100 immediately.
      if ! DEBIAN_FRONTEND=noninteractive \
           apt-get -o DPkg::Lock::Timeout=300 install -y net-tools >/dev/null 2>&1; then
        # Package lists can be empty or stale when wazuh-agent was already
        # installed and we skipped the apt-get update in step 2.
        apt-get -o DPkg::Lock::Timeout=300 update -qq || true
        DEBIAN_FRONTEND=noninteractive \
          apt-get -o DPkg::Lock::Timeout=300 install -y net-tools || return 1
      fi
      ;;
    rhel)
      local pkg_mgr="yum"
      command -v dnf >/dev/null 2>&1 && pkg_mgr="dnf"
      "$pkg_mgr" install -y net-tools || return 1
      ;;
  esac

  have_netstat || return 1
  echo "   Installed."
}

if ! install_net_tools; then
  echo "WARNING: could not install net-tools." >&2
  echo "         Enrollment continues -- the agent is unaffected -- but any" >&2
  echo "         manager-pushed netstat command block will produce no output." >&2
  echo "         Fix it by hand; no re-enrollment is needed:" >&2
  if [ "$OS_FAMILY" = "debian" ]; then
    echo "           sudo apt-get install -y net-tools" >&2
  else
    echo "           sudo dnf install -y net-tools" >&2
  fi
fi
echo

# ---------- 3. strip default journald localfile block (idempotent) ----------
# The stock Wazuh Linux agent config ships with a <localfile> block that
# tails the whole systemd journal. On distros where rsyslog also mirrors
# journal content into /var/log/auth.log and /var/log/syslog (which we
# explicitly monitor via the manager-side group config), this causes every
# PAM/auth event to be ingested TWICE -- once via journald, once via the
# flat log file -- which skews frequency-based detection rules later.
if [ -f "$OSSEC_CONF" ] && grep -q "<log_format>journald</log_format>" "$OSSEC_CONF" 2>/dev/null; then
  echo "-- Removing default journald localfile block from ossec.conf..."
  awk '
    /<localfile>/ { in_block=1; block=$0 ORS; next }
    in_block && /<\/localfile>/ {
      block = block $0 ORS
      if (block ~ /<log_format>journald<\/log_format>/ && block ~ /<location>journald<\/location>/) {
        # drop this block entirely
      } else {
        printf "%s", block
      }
      in_block=0; block=""
      next
    }
    in_block { block = block $0 ORS; next }
    { print }
  ' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
  # preserve original ownership/permissions (wazuh agent is picky about this)
  chown --reference="$OSSEC_CONF" "${OSSEC_CONF}.tmp" 2>/dev/null || true
  chmod --reference="$OSSEC_CONF" "${OSSEC_CONF}.tmp" 2>/dev/null || true
  mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"
  echo "   Removed."
else
  echo "-- No journald localfile block found (already clean or config not yet present), skipping."
fi
echo

# ---------- 4. baseline syslog/auth log collection (opt-in, -l) ----------
add_localfile_if_missing() {
  local location="$1"
  local log_format="${2:-syslog}"
  if grep -q "<location>${location}</location>" "$OSSEC_CONF" 2>/dev/null; then
    echo "   Localfile for $location already present, skipping."
    return
  fi
  echo "   Adding localfile block for $location..."
  local block
  block=$(printf '  <localfile>\n    <log_format>%s</log_format>\n    <location>%s</location>\n  </localfile>' "$log_format" "$location")
  awk -v block="$block" '
    /<\/ossec_config>/ && !done { print block; done=1 }
    { print }
  ' "$OSSEC_CONF" > "${OSSEC_CONF}.tmp"
  chown --reference="$OSSEC_CONF" "${OSSEC_CONF}.tmp" 2>/dev/null || true
  chmod --reference="$OSSEC_CONF" "${OSSEC_CONF}.tmp" 2>/dev/null || true
  mv "${OSSEC_CONF}.tmp" "$OSSEC_CONF"
}

if [ "$LOCAL_LOG_SOURCES" -eq 0 ]; then
  echo "-- Baseline log sources left to the manager group config (pass -l to write them locally)."
elif [ -f "$OSSEC_CONF" ]; then
  echo "-- Writing baseline syslog/auth log collection locally ($AUTH_LOG_PATH, $SYS_LOG_PATH)..."
  add_localfile_if_missing "$AUTH_LOG_PATH" "syslog"
  add_localfile_if_missing "$SYS_LOG_PATH" "syslog"
else
  echo "-- ossec.conf not found yet, skipping baseline log verification (unexpected after install)." >&2
fi
echo

# ---------- 5. write the local <client> section ----------
# <client> cannot live in the manager's shared agent.conf: it's what tells
# the agent which manager to contact, so it must be in place before the
# agent can pull shared config at all.
#
# <enrollment><enabled>no</enabled> is deliberate, and there is deliberately
# no <server_ca_path>: the bootstrap wrapper shreds every certificate --
# including the manager CA -- once enrollment succeeds. The agent therefore
# holds no credential it could re-enroll with, so leaving enrollment on
# would only produce a TLS failure loop in ossec.log. Repair means re-running
# the bootstrap wrapper with a fresh single-use token.
#
# Note the ongoing agent->manager channel on 1514 is NOT TLS: it is Wazuh's
# own protocol keyed by the AES secret in client.keys. Deleting the manager
# CA does not affect it.
write_client_block() {
  local conf="$1" manager="$2"
  local tmp block

  block="  <client>
    <server>
      <address>${manager}</address>
      <port>${EVENT_PORT}</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <enrollment>
      <enabled>no</enabled>
    </enrollment>
  </client>"

  CONF_BACKUP="${conf}.bak.$$"
  cp -a "$conf" "$CONF_BACKUP"
  tmp="$(mktemp)"

  # '<client>' as a literal won't match '<client_buffer>', and '</client>'
  # won't match '</client_buffer>', so a client_buffer section survives.
  if grep -q '<client>' "$conf"; then
    awk -v block="$block" '
      /<client>/    { inblock=1; print block; next }
      /<\/client>/  { inblock=0; next }
      inblock       { next }
                    { print }
    ' "$conf" > "$tmp"
  else
    awk -v block="$block" '
      !done && /<\/ossec_config>/ { print block; done=1 }
      { print }
    ' "$conf" > "$tmp"
  fi

  # cat, not mv -- preserves the original owner/mode that wazuh-agentd expects
  cat "$tmp" > "$conf"
  rm -f "$tmp"
  echo "-- wrote <client> block (manager ${manager}:${EVENT_PORT}) to $conf"
}

# Restore the pre-edit ossec.conf. Used when the agent won't come up, so a
# bad edit doesn't leave a previously working host with a dead agent.
restore_conf() {
  if [ -n "$CONF_BACKUP" ] && [ -f "$CONF_BACKUP" ]; then
    echo "         Restoring the previous ossec.conf." >&2
    cat "$CONF_BACKUP" > "$OSSEC_CONF"
    rm -f "$CONF_BACKUP"
    CONF_BACKUP=""
    systemctl restart wazuh-agent >/dev/null 2>&1 || true
  fi
}

# ---------- 5b. enable manager-pushed commands ----------
# Wazuh drops <command>/<full_command> localfile blocks that arrive from the
# manager's shared agent.conf unless the agent opts in (ossec.log 1108).
# Sprint 3 delivers netstat/process-diff blocks that way, so without this they
# are silently ignored.
#
# TRADE-OFF: the manager can now execute commands on this endpoint. Accepted
# here because the manager is internal-only and single-tenant. This would need
# rethinking in a hosted or multi-tenant deployment.
enable_remote_commands() {
  local lio=/var/ossec/etc/local_internal_options.conf
  local opt key created=0

  [ -f "$lio" ] || { touch "$lio"; created=1; }

  for opt in logcollector.remote_commands=1 wazuh_command.remote_commands=1; do
    grep -qxF "$opt" "$lio" && continue
    key="${opt%%=*}"
    # Remove any stale =0 line first, or the file ends up with both and the
    # last one silently wins.
    sed -i "\|^${key}=|d" "$lio"
    echo "$opt" >> "$lio"
    echo "-- local_internal_options.conf: set $opt"
  done

  # Only set ownership on a file we created; don't stomp existing perms.
  if [ "$created" -eq 1 ]; then
    chown root:wazuh "$lio" 2>/dev/null || true
    chmod 640 "$lio" 2>/dev/null || true
  fi
}
enable_remote_commands

write_client_block "$OSSEC_CONF" "$MANAGER"

# ---------- 6. enroll ----------
echo "-- Enrolling agent with $REG_SERVER:$REG_PORT (group: $AGENT_GROUP) ..."

# We have to clear client.keys before calling agent-auth, otherwise it sees a
# key already present and just skips re-enrollment. But if we truncate it and
# agent-auth then fails, we'd leave a PREVIOUSLY WORKING agent with no key at
# all. So: back up the existing key first, and put it back if enrollment fails.
KEY_BACKUP=""
if [ -s /var/ossec/etc/client.keys ]; then
  KEY_BACKUP="/var/ossec/etc/client.keys.bak.$$"
  cp -p /var/ossec/etc/client.keys "$KEY_BACKUP"
fi
: > /var/ossec/etc/client.keys || true

# Build the argument list conditionally. An empty "$REG_PASSWORD" passed
# after -P would make agent-auth consume the NEXT flag as the password
# value -- so -P followed by -G would silently swallow the group and hang.
AUTH_ARGS=(-m "$REG_SERVER" -p "$REG_PORT" -A "$AGENT_NAME" -G "$AGENT_GROUP")
if [ -n "$REG_PASSWORD" ]; then
  AUTH_ARGS+=(-P "$REG_PASSWORD")
fi
if [ -n "$MANAGER_CA" ]; then
  AUTH_ARGS+=(-v "$MANAGER_CA")
fi
if [ -n "$AGENT_CERT" ]; then
  AUTH_ARGS+=(-x "$AGENT_CERT" -k "$AGENT_KEY")
fi

# agent-auth has no client-side timeout and will block indefinitely on a
# stalled TLS handshake. Bound it so a firewall drop fails loudly.
if ! timeout 120 /var/ossec/bin/agent-auth "${AUTH_ARGS[@]}"; then
  rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "ERROR: agent-auth timed out after 120s (stalled TLS handshake or dropped packets)." >&2
  else
    echo "ERROR: agent-auth failed (exit $rc). See output above for the reason" >&2
    echo "       (connection refused, TLS error, cert verification failure, etc.)." >&2
  fi
  if [ -n "$KEY_BACKUP" ]; then
    echo "         Restoring the previous client.keys so this agent isn't left with no key at all." >&2
    mv "$KEY_BACKUP" /var/ossec/etc/client.keys
  fi
  restore_conf
  exit 1
fi
[ -n "$KEY_BACKUP" ] && rm -f "$KEY_BACKUP"
echo

# ---------- 7. verify a key was actually written ----------
if [ ! -s /var/ossec/etc/client.keys ]; then
  echo "ERROR: enrollment reported success but /var/ossec/etc/client.keys is still empty." >&2
  exit 1
fi
echo "-- Enrollment key written."
echo

# ---------- 8. restart and verify connection ----------
# Exactly one restart. A bare `systemctl restart` here would abort the whole
# script under `set -e` on failure, making the restore path below unreachable
# -- and restarting twice resets the connection sequence right before we go
# looking for it in the log.
echo "-- Restarting wazuh-agent..."
systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null 2>&1 || true

if ! systemctl restart wazuh-agent; then
  echo "ERROR: wazuh-agent failed to restart." >&2
  restore_conf
  exit 1
fi

# systemctl restart returns success once the unit is launched. A malformed
# ossec.conf typically lets wazuh-agentd start and then exit a moment later,
# so the config backup has to survive until after this check.
sleep 3
if ! systemctl is-active --quiet wazuh-agent; then
  echo "ERROR: wazuh-agent started then stopped -- most likely a bad ossec.conf." >&2
  systemctl status wazuh-agent --no-pager || true
  restore_conf
  exit 1
fi

# Only now is it safe to drop the backup.
rm -f "$CONF_BACKUP"
CONF_BACKUP=""

echo "-- Service is active. Checking log for connection confirmation..."
# tail, not a whole-file grep: a "Connected to the server" line from an
# enrollment weeks ago would otherwise report SUCCESS on a run that failed.
connected=0
for _ in 1 2 3 4 5 6 7 8; do
  sleep 2
  if tail -n 50 /var/ossec/logs/ossec.log 2>/dev/null | grep -q "Connected to the server"; then
    connected=1
    break
  fi
done

if [ "$connected" -eq 1 ]; then
  echo "SUCCESS: agent enrolled and connected to $MANAGER."
else
  echo "WARNING: service is running but 'Connected to the server' not seen in the last 50 log lines after 16s."
  echo "         On a multi-node cluster this is often just the agent landing on a worker"
  echo "         before the master has replicated its key -- it usually resolves within a minute."
  echo "         Tail the log to confirm manually:"
  echo "           tail -f /var/ossec/logs/ossec.log"
fi

echo
echo "== Done =="