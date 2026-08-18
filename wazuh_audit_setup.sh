#!/usr/bin/env bash
#
# wazuh_audit_setup.sh
# --------------------
# Sprint 3, Phase 1: Linux command auditing.
#
# Installs auditd, deploys execve audit rules keyed for Wazuh's built-in
# decoders, tunes audit log rotation, and (optionally) installs the
# interactive bash command shim.
#
# DELIBERATELY SEPARATE FROM wazuh_bootstrap.sh:
#
#   Nothing here needs a secret. bootstrap.sh is gated on a single-use token
#   because it handles certificate material; this script handles endpoint
#   configuration only. Keeping them apart means you can:
#     - run this against the agents you already enrolled in Sprint 2 without
#       minting a fresh token for each one, and
#     - put it on a timer for drift enforcement, which bootstrap.sh cannot
#       have (its token is burned on first use).
#
# Fully idempotent. Safe to run repeatedly; the timer relies on that.
#
# Usage:
#   sudo ./wazuh_audit_setup.sh                 # install + configure
#   sudo ./wazuh_audit_setup.sh --check         # report state, change nothing
#   sudo ./wazuh_audit_setup.sh --install-timer # + daily drift enforcement
#   sudo ./wazuh_audit_setup.sh --no-bash-audit # auditd only, skip the shim

set -euo pipefail

# ---------- defaults ----------
AUDIT_BUFFER=8192
BASH_AUDIT=1
INSTALL_TIMER=0
CHECK_ONLY=0
AGENT_RESTART=1
AUDIT_MAX_LOG_MB=50
AUDIT_NUM_LOGS=5

# Rule files. The numeric prefixes matter: augenrules concatenates
# /etc/audit/rules.d/* in lexical order, so we must land AFTER the distro's
# base config (10-base-config.rules, which issues `-D` and would wipe us) and
# BEFORE any finalize file (99-finalize.rules, which may set `-e 2` and lock
# the rule set).
BUFFER_RULES=/etc/audit/rules.d/20-wazuh-buffer.rules
WAZUH_RULES=/etc/audit/rules.d/50-wazuh.rules
BASH_SHIM=/etc/profile.d/wazuh-bash-audit.sh
AUDITD_CONF=/etc/audit/auditd.conf

usage() {
  cat <<'EOF'
Usage: sudo ./wazuh_audit_setup.sh [options]

  -c, --check           Report current state and exit. Changes nothing.
  -B, --no-bash-audit   Skip /etc/profile.d/wazuh-bash-audit.sh.
                        auditd execve rules are the authoritative source;
                        the shim is only a human-readable convenience layer.
  -T, --install-timer   Install systemd timer that re-asserts this config
                        daily. Safe: no secrets, fully idempotent.
  -R, --no-agent-restart
                        Do not restart wazuh-agent even if it is not yet
                        reading audit.log. Use in maintenance windows; you
                        must restart it yourself or no audit events ship.
  -b, --buffer N        auditd backlog buffer (default 8192). Raise on busy
                        servers; a full buffer silently DROPS events.
  -h, --help
EOF
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    -c|--check)         CHECK_ONLY=1 ;;
    -B|--no-bash-audit) BASH_AUDIT=0 ;;
    -T|--install-timer) INSTALL_TIMER=1 ;;
    -R|--no-agent-restart) AGENT_RESTART=0 ;;
    -b|--buffer)        AUDIT_BUFFER="${2:?--buffer needs a value}"; shift ;;
    -h|--help)          usage ;;
    *) echo "ERROR: unknown option: $1" >&2; usage ;;
  esac
  shift
done

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "-- $*"; }
warn() { echo "WARNING: $*" >&2; }

[ "$(id -u)" -eq 0 ] || die "must be run as root (use sudo)."

# ---------- distro family detection ----------
# Same shape as wazuh_enroll.sh so the two scripts agree about what they are
# running on.
OS_ID="unknown"; OS_ID_LIKE=""
if [ -f /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"; OS_ID_LIKE="${ID_LIKE:-}"
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

[ "$OS_FAMILY" != "unknown" ] || \
  die "unsupported distro (ID=$OS_ID, ID_LIKE=$OS_ID_LIKE). Supports Debian/Ubuntu and RHEL-family."

echo "== Wazuh Linux Command Auditing (Sprint 3, Phase 1) =="
echo "  Distro family:       $OS_FAMILY (ID=$OS_ID)"
echo "  Audit buffer:        $AUDIT_BUFFER"
echo "  Bash shim:           $([ "$BASH_AUDIT" -eq 1 ] && echo ENABLED || echo skipped)"
echo "  Mode:                $([ "$CHECK_ONLY" -eq 1 ] && echo 'CHECK ONLY' || echo 'apply')"
echo

# ---------- 1. install auditd ----------
install_auditd() {
  if command -v auditctl >/dev/null 2>&1 && command -v augenrules >/dev/null 2>&1; then
    info "auditd already installed ($(auditctl -v 2>/dev/null | head -1))."
    return 0
  fi

  [ "$CHECK_ONLY" -eq 0 ] || { warn "auditd NOT installed."; return 0; }

  info "Installing auditd..."
  case "$OS_FAMILY" in
    debian)
      # Same unattended-upgrades lock race wazuh_enroll.sh handles: without
      # the timeout apt exits 100 immediately instead of queueing.
      apt-get -o DPkg::Lock::Timeout=300 update -qq
      DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 \
        install -y auditd audispd-plugins
      ;;
    rhel)
      local pkg="yum"; command -v dnf >/dev/null 2>&1 && pkg="dnf"
      "$pkg" install -y audit
      ;;
  esac

  command -v auditctl >/dev/null 2>&1 || die "auditd install did not provide auditctl."
  info "   Installed."
}

# auditd is one of the few services that must be enabled before rules load,
# because augenrules --load talks to a running kernel audit subsystem.
enable_auditd() {
  [ "$CHECK_ONLY" -eq 0 ] || return 0
  systemctl enable auditd >/dev/null 2>&1 || true
  systemctl is-active --quiet auditd || systemctl start auditd || true
}

# auditd refuses `systemctl restart` on RHEL-family ("Operation refused, unit
# auditd.service may be requested by dependency only"). service(8) routes
# around it via the initscript shim. Try systemd first, fall back.
restart_auditd() {
  systemctl restart auditd >/dev/null 2>&1 && return 0
  service auditd restart   >/dev/null 2>&1 && return 0
  warn "could not restart auditd; rules were still loaded via augenrules."
  return 0
}

# ---------- 2. audit userspace version -> auid syntax ----------
# `auid!=unset` is the readable form but only parses on audit >= 2.8.
# Ubuntu 18.04 / RHEL 7 need the raw sentinel 4294967295 (unsigned -1).
# Getting this wrong makes augenrules reject the ENTIRE file, so detect it.
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

detect_auid_syntax() {
  local ver
  ver="$(auditctl -v 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)"
  if [ -n "$ver" ] && version_ge "$ver" "2.8"; then
    AUID_UNSET="unset"
  else
    AUID_UNSET="4294967295"
  fi
  info "audit userspace ${ver:-unknown} -> using 'auid!=$AUID_UNSET'"
}

# ---------- 3. immutability check ----------
# `-e 2` locks the rule set until reboot. If a hardening baseline (CIS, STIG)
# already set it, we can write the files but cannot load them now. Detect and
# say so plainly rather than failing with an opaque auditctl error.
AUDIT_IMMUTABLE=0
check_immutable() {
  local enabled
  enabled="$(auditctl -s 2>/dev/null | awk '/^enabled/ {print $2}' || true)"
  if [ "$enabled" = "2" ]; then
    AUDIT_IMMUTABLE=1
    warn "audit rules are IMMUTABLE (-e 2). Rules will be written to disk but"
    warn "cannot be loaded until this host reboots. Everything else still applies."
  fi
}

# ---------- 4. write the rules ----------
write_buffer_rules() {
  local tmp; tmp="$(mktemp)"
  cat > "$tmp" <<EOF
## Managed by wazuh_audit_setup.sh -- do not edit by hand.
## Control settings only. Loaded after the distro base config (which issues
## -D), so these override the base buffer without wiping any rules.

## Backlog buffer. execve auditing is high-volume; a full buffer DROPS events
## silently, which is the worst possible failure mode for an audit trail.
-b $AUDIT_BUFFER

## Wait rather than drop when the backlog fills.
--backlog_wait_time 0

## Failure mode: 1 = log to syslog. Deliberately NOT 2 (kernel panic) --
## an audit misconfiguration should not take production hosts down.
-f 1
EOF
  install_if_changed "$tmp" "$BUFFER_RULES" 640
}

write_wazuh_rules() {
  local tmp; tmp="$(mktemp)"
  cat > "$tmp" <<EOF
## Managed by wazuh_audit_setup.sh -- do not edit by hand.
##
## The -k keys are not arbitrary. Wazuh's shipped audit decoders and the
## rules in ruleset/rules/audit_rules.xml match on audit-wazuh-c / -w / -x,
## so renaming a key means the events arrive but never alert.
##
## No -D here on purpose: this file is concatenated with the distro base
## config, and -D would delete every rule loaded before it.

## --- Command execution ---------------------------------------------------
## auid is the LOGIN uid, preserved across sudo/su. If ahmed logs in, sudoes
## to root, and runs rm -rf, auid still says ahmed while uid says root. That
## attribution is the entire point of auditing execve rather than reading
## bash history. auid>=1000 also excludes the enormous noise floor of system
## daemons, which never have a login uid.
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=$AUID_UNSET -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=$AUID_UNSET -k audit-wazuh-c

## Direct root console/SSH logins have auid=0 and would otherwise be invisible
## to the rule above -- i.e. the single most privileged session type would be
## the one you cannot see.
-a always,exit -F arch=b64 -S execve -F auid=0 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid=0 -k audit-wazuh-c

## --- Privilege escalation ------------------------------------------------
-w /usr/bin/sudo    -p x  -k audit-wazuh-x
-w /bin/su          -p x  -k audit-wazuh-x
-w /usr/bin/su      -p x  -k audit-wazuh-x
-w /etc/sudoers     -p wa -k audit-wazuh-w
-w /etc/sudoers.d/  -p wa -k audit-wazuh-w

## --- Execution from staging areas ----------------------------------------
## World-writable directories are where downloaded payloads land before they
## run. Low volume, high signal: legitimate software is not executed from
## /dev/shm.
-w /tmp     -p x -k audit-wazuh-x
-w /var/tmp -p x -k audit-wazuh-x
-w /dev/shm -p x -k audit-wazuh-x

## --- Credential and identity files ---------------------------------------
-w /etc/passwd  -p wa -k audit-wazuh-w
-w /etc/shadow  -p wa -k audit-wazuh-w
-w /etc/group   -p wa -k audit-wazuh-w
-w /etc/gshadow -p wa -k audit-wazuh-w

## --- Persistence ---------------------------------------------------------
-w /etc/crontab     -p wa -k audit-wazuh-w
-w /etc/cron.d/     -p wa -k audit-wazuh-w
-w /var/spool/cron/ -p wa -k audit-wazuh-w

## NOTE: FIM whodata paths are NOT listed here. Wazuh installs and removes
## its own audit rules for every <directories whodata="yes"> entry at agent
## start. Duplicating them here causes double alerts and leaves orphaned
## rules behind when you change agent.conf.
EOF
  install_if_changed "$tmp" "$WAZUH_RULES" 640
}

# Compare-then-write. Two reasons this matters more than it looks:
#   1. The timer runs this daily; rewriting an identical file would churn
#      mtime and make "did this actually change?" unanswerable.
#   2. RULES_CHANGED gates the augenrules reload, so a no-op run does not
#      flush and rebuild the kernel rule set for nothing.
RULES_CHANGED=0
install_if_changed() {
  local src="$1" dst="$2" mode="$3"
  if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
    rm -f "$src"
    info "$(basename "$dst"): already current."
    return 0
  fi
  if [ "$CHECK_ONLY" -eq 1 ]; then
    warn "$(basename "$dst") is MISSING or OUT OF DATE."
    rm -f "$src"; RULES_CHANGED=1
    return 0
  fi
  [ -f "$dst" ] && cp -p "$dst" "$dst.bak.$(date +%Y%m%d%H%M%S)"
  install -o root -g root -m "$mode" "$src" "$dst"
  rm -f "$src"
  RULES_CHANGED=1
  info "$(basename "$dst"): written."
}

# ---------- 5. auditd.conf rotation ----------
# Unbounded audit logs are a genuine outage risk: on RHEL the default
# max_log_file_action is ROTATE but space_left_action can suspend the box.
# Bound the size explicitly.
tune_auditd_conf() {
  [ -f "$AUDITD_CONF" ] || { warn "$AUDITD_CONF not found; skipping rotation tuning."; return 0; }

  local changed=0 k v
  set_conf_key() {
    k="$1"; v="$2"
    if grep -qE "^\s*${k}\s*=" "$AUDITD_CONF"; then
      local cur
      cur="$(grep -E "^\s*${k}\s*=" "$AUDITD_CONF" | tail -1 | sed 's/.*=\s*//' | tr -d '[:space:]')"
      [ "$cur" = "$v" ] && return 0
      [ "$CHECK_ONLY" -eq 1 ] && { warn "auditd.conf: $k is '$cur', want '$v'."; return 0; }
      sed -i -E "s|^\s*${k}\s*=.*|${k} = ${v}|" "$AUDITD_CONF"
    else
      [ "$CHECK_ONLY" -eq 1 ] && { warn "auditd.conf: $k not set, want '$v'."; return 0; }
      echo "${k} = ${v}" >> "$AUDITD_CONF"
    fi
    changed=1
    info "auditd.conf: $k = $v"
  }

  set_conf_key "max_log_file"        "$AUDIT_MAX_LOG_MB"
  set_conf_key "num_logs"            "$AUDIT_NUM_LOGS"
  set_conf_key "max_log_file_action" "ROTATE"

  [ "$changed" -eq 1 ] && AUDITD_CONF_CHANGED=1 || true
}
AUDITD_CONF_CHANGED=0

# ---------- 6. load the rules ----------
load_rules() {
  [ "$CHECK_ONLY" -eq 0 ] || return 0

  if [ "$AUDIT_IMMUTABLE" -eq 1 ]; then
    warn "skipping rule load: audit is immutable until reboot."
    return 0
  fi

  if [ "$RULES_CHANGED" -eq 0 ] && [ "$AUDITD_CONF_CHANGED" -eq 0 ]; then
    info "No rule changes; skipping reload."
    return 0
  fi

  info "Loading audit rules..."
  if ! augenrules --load; then
    die "augenrules --load failed. Check syntax with:
       augenrules --check
       auditctl -R $WAZUH_RULES"
  fi
  [ "$AUDITD_CONF_CHANGED" -eq 1 ] && restart_auditd
  info "   Loaded."
}

# ---------- 7. bash interactive shim ----------
# Explicitly a convenience layer, not a control. A user can unset
# PROMPT_COMMAND, run /bin/sh, or exec directly -- all of which bypass this
# and none of which bypass the execve rules above. It exists because reading
# "user=ahmed pwd=/opt cmd=systemctl restart nginx" in the dashboard is far
# faster for an analyst than reconstructing the same thing from raw auditd
# SYSCALL/EXECVE record pairs.
write_bash_shim() {
  [ "$BASH_AUDIT" -eq 1 ] || { info "Bash shim skipped (--no-bash-audit)."; return 0; }

  local tmp; tmp="$(mktemp)"
  cat > "$tmp" <<'SHIM'
# Managed by wazuh_audit_setup.sh -- do not edit by hand.
#
# Logs each interactive bash command to syslog (local6), where the Wazuh
# agent already collects it via the syslog/messages localfile. No new
# localfile block is needed on the manager side.
#
# NOT a security control -- trivially bypassed by unsetting PROMPT_COMMAND
# or using another shell. auditd execve rules are the authoritative source.

if [ -n "${BASH_VERSION:-}" ] && [ -n "${PS1:-}" ] && [ -z "${WAZUH_BASH_AUDIT:-}" ]; then
  export WAZUH_BASH_AUDIT=1
  export HISTTIMEFORMAT="%F %T "
  # Guard against a double-append when this file is sourced twice (su - , tmux).
  case "${PROMPT_COMMAND:-}" in
    *wazuh_audit_log*) : ;;
    *)
      wazuh_audit_log() {
        local rc=$?
        local cmd
        cmd=$(HISTTIMEFORMAT='' history 1 2>/dev/null | sed 's/^ *[0-9]* *//')
        [ -n "$cmd" ] || return 0
        # Skip the repeat that fires when you press Enter on an empty prompt.
        [ "$cmd" = "${WAZUH_LAST_CMD:-}" ] && return 0
        WAZUH_LAST_CMD="$cmd"
        logger -p local6.info -t bash-audit -- \
          "user=$(id -un) auid=$(cat /proc/self/loginuid 2>/dev/null || echo -1) tty=$(tty 2>/dev/null || echo none) pwd=$PWD rc=$rc cmd=$cmd"
        return 0
      }
      PROMPT_COMMAND="wazuh_audit_log${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
      export PROMPT_COMMAND
      ;;
  esac
fi
SHIM
  install_if_changed "$tmp" "$BASH_SHIM" 644
}

# ---------- 8. systemd drift enforcement timer ----------
# bootstrap.sh cannot have a timer: its token is single-use. This script can,
# because it needs no credential. That asymmetry is the reason the two are
# separate files.
install_timer() {
  [ "$INSTALL_TIMER" -eq 1 ] || return 0
  [ "$CHECK_ONLY" -eq 0 ] || { info "Would install drift timer."; return 0; }

  local self="/opt/wazuh-bootstrap/wazuh_audit_setup.sh"
  if [ ! -x "$self" ]; then
    install -D -o root -g root -m 750 "$0" "$self"
    info "Installed self to $self"
  fi

  # Note: --install-timer is deliberately NOT passed here. The timer would
  # otherwise reinstall itself on every fire.
  local exec_args=""
  [ "$BASH_AUDIT" -eq 1 ] || exec_args="$exec_args --no-bash-audit"
  [ "$AGENT_RESTART" -eq 1 ] || exec_args="$exec_args --no-agent-restart"

  cat > /etc/systemd/system/wazuh-audit-enforce.service <<EOF
[Unit]
Description=Re-assert Wazuh auditd command-auditing configuration
After=auditd.service
Wants=auditd.service

[Service]
Type=oneshot
ExecStart=${self}${exec_args}
# No secrets involved, so unlike enrollment this is safe to run unattended.
EOF

  cat > /etc/systemd/system/wazuh-audit-enforce.timer <<'EOF'
[Unit]
Description=Daily Wazuh audit configuration drift enforcement

[Timer]
OnBootSec=5min
OnUnitActiveSec=24h
# Spread the fleet out so 200 hosts do not all reload rules in the same second.
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now wazuh-audit-enforce.timer >/dev/null 2>&1
  info "Drift timer installed (daily, +/-30min jitter)."
}

# ---------- 8b. make the running agent pick up audit.log ----------
# logcollector skips a <localfile> whose target did not exist when it started.
# agent.conf has declared /var/log/audit/audit.log since Sprint 2, but on a
# host without auditd that block was a silent no-op -- and it stays one until
# the agent restarts.
#
# This matters most in the bootstrap path: wazuh_enroll.sh restarts the agent
# and confirms connection BEFORE this script runs, so without this a freshly
# enrolled host would ship zero audit events while looking perfectly healthy.
#
# Conditional, not unconditional: on the daily timer run the agent is already
# reading the file, and restarting it every 24h would drop the logcollector
# read position and re-send events.
maybe_restart_agent() {
  [ "$CHECK_ONLY" -eq 0 ] || return 0
  [ "$AGENT_RESTART" -eq 1 ] || { info "Agent restart skipped (--no-agent-restart)."; return 0; }

  systemctl list-unit-files 2>/dev/null | grep -q '^wazuh-agent\.service' || {
    info "wazuh-agent not installed here; nothing to restart."
    return 0
  }
  [ -s /var/log/audit/audit.log ] || {
    info "No audit.log yet; skipping agent restart."
    return 0
  }
  if grep -q "Analyzing file: '/var/log/audit/audit.log'" /var/ossec/logs/ossec.log 2>/dev/null; then
    info "Agent already reading audit.log; no restart needed."
    return 0
  fi

  info "Restarting wazuh-agent so it picks up /var/log/audit/audit.log..."
  if ! systemctl restart wazuh-agent; then
    warn "wazuh-agent failed to restart. Audit rules are live but events are"
    warn "not being shipped. Check: systemctl status wazuh-agent"
    return 0
  fi
  sleep 3
  systemctl is-active --quiet wazuh-agent \
    || warn "wazuh-agent started then stopped -- check ossec.conf."
  info "   Restarted."
}

# ---------- 9. verification ----------
verify() {
  echo
  echo "== Verification =="
  local fail=0

  if command -v auditctl >/dev/null 2>&1; then
    local n
    n="$(auditctl -l 2>/dev/null | grep -c 'audit-wazuh' || true)"
    if [ "${n:-0}" -gt 0 ]; then
      echo "  [OK]   $n wazuh-keyed audit rules loaded in kernel"
    else
      echo "  [FAIL] no audit-wazuh rules loaded (auditctl -l)"; fail=1
    fi
    echo "  [INFO] backlog: $(auditctl -s 2>/dev/null | tr '\n' ' ' | sed 's/  */ /g')"
  else
    echo "  [FAIL] auditctl not present"; fail=1
  fi

  if [ -s /var/log/audit/audit.log ]; then
    echo "  [OK]   /var/log/audit/audit.log exists and is non-empty"
  else
    echo "  [WARN] /var/log/audit/audit.log missing or empty (may just be new)"
  fi

  # The manager-side agent.conf declares this localfile, but the agent skips
  # a localfile whose target does not exist -- which is exactly what was
  # happening before auditd was installed.
  if [ -f /var/ossec/etc/ossec.conf ]; then
    if grep -q "Analyzing file: '/var/log/audit/audit.log'" /var/ossec/logs/ossec.log 2>/dev/null; then
      echo "  [OK]   Wazuh agent is reading audit.log"
    else
      echo "  [WARN] agent not yet reading audit.log -- restart it:"
      echo "         systemctl restart wazuh-agent"
    fi
    if grep -qi "Remote commands are not accepted" /var/ossec/logs/ossec.log 2>/dev/null; then
      echo "  [WARN] remote_commands still disabled in this log -- if wazuh_enroll.sh"
      echo "         ran before Sprint 3, restart the agent to clear the stale warning."
    fi
  else
    echo "  [WARN] Wazuh agent not installed on this host"
  fi

  if [ "$BASH_AUDIT" -eq 1 ]; then
    [ -f "$BASH_SHIM" ] && echo "  [OK]   bash shim present at $BASH_SHIM" \
                        || { echo "  [FAIL] bash shim missing"; fail=1; }
  fi

  echo
  if [ "$fail" -eq 0 ]; then
    echo "Result: OK"
  else
    echo "Result: PROBLEMS FOUND (see [FAIL] above)"
    return 1
  fi
}

# ---------- run ----------
install_auditd
enable_auditd
detect_auid_syntax
check_immutable
write_buffer_rules
write_wazuh_rules
tune_auditd_conf
load_rules
write_bash_shim
install_timer
maybe_restart_agent

# Capture rather than let `set -e` abort here: a partial failure should still
# print the diagnostic guidance below, and the timer needs a truthful exit
# code to mark the unit failed.
VERIFY_RC=0
verify || VERIFY_RC=$?

if [ "$CHECK_ONLY" -eq 0 ]; then
  cat <<'EOF'

-- Done. Test it in a NEW shell (the shim only loads at login):

     sudo whoami            # -> auditd execve alert, auid = your login user
     id                     # -> bash-audit syslog line
     cp /bin/ls /tmp/x && chmod +x /tmp/x && /tmp/x   # -> audit-wazuh-x

   Then on the manager:
     docker exec wazuh.master tail -f /var/ossec/logs/alerts/alerts.log

   If events arrive but nothing alerts, decode a raw line first:
     docker exec -it wazuh.master /var/ossec/bin/wazuh-logtest
EOF
fi

exit "$VERIFY_RC"