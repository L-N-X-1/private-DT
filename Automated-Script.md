# Wazuh Agent Deployment Guide

Packaging steps for turning the Wazuh agent deployment files into a single transportable installer, for both Windows and Linux.

---

## Windows — Inno Setup (`.exe`)

### Files needed
Place these together with `WazuhAgent.iss` in one folder:

- `bootstrap.json`
- `Detect-WazuhAgent.ps1`
- `Install-WazuhAgent.ps1`
- `sysmonconfig.xml`
- `Uninstall-WazuhAgent.ps1`
- `wazuh_enroll.ps1`
- `WazuhAgent.iss` — the Inno Setup script

### Prerequisites
- [Inno Setup](https://jrsoftware.org/isinfo.php) (free)

### Build steps
1. Open `WazuhAgent.iss` in the Inno Setup Compiler (File → Open).
2. **Build → Compile** (or press `F9`).
3. Output lands at `Output\WazuhAgent-Setup.exe`.

### What it does
- Extracts all 6 files to `Program Files\WazuhAgentDeploy`
- Runs `Install-WazuhAgent.ps1` from that folder via PowerShell (`-ExecutionPolicy Bypass`)
- Registers an entry in **Apps & Features**
- On uninstall, automatically runs `Uninstall-WazuhAgent.ps1`

### Deploying
Copy **only** `WazuhAgent-Setup.exe` to the target machine.

```powershell
# Interactive
WazuhAgent-Setup.exe

# Silent (for GPO / Intune / RMM push)
WazuhAgent-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
```

---

## Linux — makeself (`.sh`)

### Files needed
Place these together with `install.sh` in a `wazuh-bundle/` folder:

- `wazuh_bootstrap.sh`
- `wazuh_enroll.sh`
- `bootstrap.conf`
- `wazuh-bootstrap.service`
- `wazuh-bootstrap.timer`
- `install.sh` — runs automatically on extraction

> `agents-rootCA.pem` is no longer required after the script update, so it's dropped from the bundle and from `install.sh`.

### `install.sh`
```bash
#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run this installer as root (sudo)."
    exit 1
fi

echo "==> Installing Wazuh bootstrap..."

mkdir -p /opt/wazuh-bootstrap /etc/wazuh-bootstrap

cp wazuh_bootstrap.sh wazuh_enroll.sh /opt/wazuh-bootstrap/
chmod +x /opt/wazuh-bootstrap/*.sh

cp bootstrap.conf /etc/wazuh-bootstrap/bootstrap.conf
chmod 600 /etc/wazuh-bootstrap/bootstrap.conf

echo "==> Installing systemd units..."

cp wazuh-bootstrap.service wazuh-bootstrap.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wazuh-bootstrap.timer
systemctl start wazuh-bootstrap.service

echo "==> Done. wazuh-bootstrap.timer is enabled and running."
```

### Prerequisites
- `makeself` (single script, no compile step, works on both apt- and dnf-based distros)

```bash
git clone https://github.com/megastep/makeself.git
# or: sudo apt install makeself   /   sudo dnf install makeself
```

### Build steps
```bash
chmod +x install.sh
./makeself/makeself.sh --gzip wazuh-bundle wazuh-agent-installer.sh "Wazuh Agent Bootstrap Installer" ./install.sh
```

This produces a single file: `wazuh-agent-installer.sh` — all bundle files are embedded inside it.

### Deploying
Copy **only** `wazuh-agent-installer.sh` to the target machine.

```bash
sudo ./wazuh-agent-installer.sh
```

It self-extracts to a temp directory, runs `install.sh` (root check included), then cleans up the temp extraction — the real files remain in `/opt/wazuh-bootstrap`, `/etc/wazuh-bootstrap`, and `/etc/systemd/system`.

> No automatic uninstall hook exists for a raw `.sh` (unlike the Windows EXE's Apps & Features integration). If a clean uninstall path is needed later, an `uninstall.sh` can be added, or the bundle can be moved to a native `.deb` package where `apt remove` would trigger it automatically.

---

## Summary

| | Windows | Linux |
|---|---|---|
| Tool | Inno Setup | makeself |
| Output | `WazuhAgent-Setup.exe` | `wazuh-agent-installer.sh` |
| Silent install | `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` | N/A (always non-interactive once run) |
| Uninstall | Automatic via Apps & Features | Manual (no hook yet) |
