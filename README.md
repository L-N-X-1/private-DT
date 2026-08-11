# Automated Wazuh agent enrollment — Intune + REST cert issuer + S3

Turns your current manual flow (issue a cert by hand, copy `PC1.cert`/`PC1.key`
to the box, run the enroll script with the password typed on the command line)
into: **Intune pushes an app, the endpoint asks for its own certificate, enrolls,
and destroys the material.**

---

## 0. Read this before you build anything

Right now, an attacker who wants into your Wazuh fleet needs two things they
can't easily get: the enrollment password *and* a cert signed by
`agents-rootCA`. The second one is hard because issuing it requires the CA
private key, which lives on one box you control.

The moment you expose issuance over REST, that changes. **Whoever can
successfully call `POST /v1/agent-bootstrap` gets both.** The per-agent
certificate stops being an independent second factor and becomes a *derived*
credential — it is only as trustworthy as the thing that authenticated the
call.

This isn't an argument against doing it. Automation is the right call at any
real fleet size, and manually minting certs doesn't scale past a few dozen
hosts. It's an argument for putting your security effort in the right place:
the **bootstrap credential** is now your fleet's trust anchor. Everything
below treats it that way — short TTLs, single-use where practical, rate
limits, an audit trail, and an internal-only listener.

Concretely, the issuer never goes on a public IP. If remote laptops need to
enroll, they reach it over your VPN, the same way they reach 1514/1515.

**The reachability problem, up front:** your manager is `192.168.29.192`.
Intune-managed laptops sitting in a coffee shop cannot reach that address, so
they cannot enroll and cannot report. You need one of: Always On VPN with a
device tunnel (so it's up before user logon, which is when the Intune install
runs), a reverse proxy publishing 1514/1515/8443, or accepting that agents
only work on-network. Decide this before packaging, because it determines
whether your Intune app succeeds on day one or fails for every remote user.

---

## What gets built

| Component | Where it runs | Purpose |
|---|---|---|
| `cert-issuer` (Flask + nginx) | Wazuh manager host | Mints agent certs on demand, hands back manager CA + enrollment password |
| S3 bucket | AWS | Stores manager CA pem + enrollment password; **only the issuer reads it** |
| `Install-WazuhAgent.ps1` | Windows endpoints, via Intune | Calls the issuer, installs agent + Sysmon, enrolls, shreds material |
| `wazuh_bootstrap.sh` + timer | Linux endpoints | Same, plus hourly self-heal |
| `agent.conf` per group | Manager | Central config the agents sync automatically |

Your existing `wazuh_enroll.ps1` / `wazuh_enroll.sh` / `issue_agent_cert.sh`
are reused unchanged — the new pieces wrap them.

---

## Phase 1 — Manager prep (do this first, it's independent of everything else)

### 1.1 Add the `<force>` block to authd

Your `<auth>` block has no `<force>` section, so authd uses its defaults —
which refuse to replace an agent that is currently connected under the same
name. That is exactly what happens when Intune re-runs the installer on a
live machine, or when a laptop is reimaged and comes back with the same
hostname. Automated enrollment will fail intermittently until you fix this.

See `manager/authd-force-block.md` for the block and the trade-off it makes.

### 1.2 Create the groups

```bash
docker exec -it <manager-container> /var/ossec/bin/agent_groups -a -g windows-agents -q
docker exec -it <manager-container> /var/ossec/bin/agent_groups -a -g linux-agents -q
```

### 1.3 Push the shared `agent.conf`

`manager/agent.conf-windows-agents.xml` → `/var/ossec/etc/shared/windows-agents/agent.conf`

This is the "agent receives a basic configuration and syncs automatically"
requirement. Agents pull it within ~10 minutes of any change. Validate with
`verify-agent-conf` **before** restarting — a malformed `agent.conf` is pushed
to every agent in the group and can take the whole group offline at once.

> Note the multi-node caveat: you're running `multi-node/`, so shared config
> and `client.keys` are synced from the master to workers by the cluster
> daemon. Make changes on the **master** only.

### 1.4 Restart and confirm

```bash
docker exec <manager-container> /var/ossec/bin/wazuh-control restart
docker exec <manager-container> tail -50 /var/ossec/logs/ossec.log | grep -i authd
```

---

## Phase 2 — S3

Full commands, bucket policy, and IAM policy in `aws/s3-setup.md`.

Short version: private bucket, versioning on, SSE-KMS with a customer-managed
key, a bucket policy denying non-TLS access, and an IAM policy granting
`s3:GetObject` on **exactly two object keys** plus `kms:Decrypt`. Upload
`agents-rootCA.pem` and the enrollment password.

Use `printf`, not `echo`, for the password file — a trailing newline silently
becomes part of the secret.

---

## Phase 3 — Deploy the cert issuer

On the manager host (where `agents-rootCA.key` already lives).

### 3.1 Lay out the CA directory

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wazuh-issuer

sudo mkdir -p /opt/wazuh-ca
sudo cp agents-rootCA.key agents-rootCA.pem issue_agent_cert.sh /opt/wazuh-ca/
sudo chmod +x /opt/wazuh-ca/issue_agent_cert.sh

# The CA key is readable by the issuer and nobody else.
sudo chown root:wazuh-issuer /opt/wazuh-ca/agents-rootCA.key
sudo chmod 640 /opt/wazuh-ca/agents-rootCA.key
sudo chmod 644 /opt/wazuh-ca/agents-rootCA.pem

# CAcreateserial needs to write agents-rootCA.srl next to the CA cert.
sudo chown wazuh-issuer:wazuh-issuer /opt/wazuh-ca
sudo chmod 750 /opt/wazuh-ca
```

### 3.2 Install the app

```bash
sudo mkdir -p /opt/wazuh-cert-issuer /etc/wazuh-cert-issuer/tls /var/lib/wazuh-cert-issuer
sudo cp cert-issuer/app.py cert-issuer/mint_token.py cert-issuer/requirements.txt /opt/wazuh-cert-issuer/
sudo python3 -m venv /opt/wazuh-cert-issuer/venv
sudo /opt/wazuh-cert-issuer/venv/bin/pip install -r /opt/wazuh-cert-issuer/requirements.txt
sudo chown -R wazuh-issuer:wazuh-issuer /var/lib/wazuh-cert-issuer

# Bootstrap token signing secret
sudo sh -c 'head -c 32 /dev/urandom | base64 > /etc/wazuh-cert-issuer/token.secret'
sudo chown root:wazuh-issuer /etc/wazuh-cert-issuer/token.secret
sudo chmod 640 /etc/wazuh-cert-issuer/token.secret

sudo cp cert-issuer/issuer.env.example /etc/wazuh-cert-issuer/issuer.env
sudo chown root:wazuh-issuer /etc/wazuh-cert-issuer/issuer.env
sudo chmod 640 /etc/wazuh-cert-issuer/issuer.env
sudoedit /etc/wazuh-cert-issuer/issuer.env    # bucket name, region, credentials
```

### 3.3 Issue the issuer's own TLS cert

Sign it with `agents-rootCA` so the CA pem you already ship to endpoints
doubles as the trust anchor for this endpoint:

```bash
cd /etc/wazuh-cert-issuer/tls
sudo openssl req -new -nodes -newkey rsa:4096 \
  -keyout issuer.key -out issuer.csr \
  -subj "/C=US/CN=wazuh-enroll.corp.local" \
  -addext "subjectAltName=DNS:wazuh-enroll.corp.local,IP:192.168.29.192"

sudo openssl x509 -req -days 825 -in issuer.csr \
  -CA /opt/wazuh-ca/agents-rootCA.pem -CAkey /opt/wazuh-ca/agents-rootCA.key \
  -CAcreateserial -copy_extensions copyall -out issuer.crt

sudo chmod 600 issuer.key
```

`-copy_extensions copyall` is not optional. Without it the SAN is dropped and
.NET/PowerShell will reject the cert — and it fails at TLS handshake with a
generic error that is genuinely annoying to diagnose.

Grab the pin for the Intune package now:

```bash
openssl x509 -in /opt/wazuh-ca/agents-rootCA.pem -noout -fingerprint -sha256 |
  sed 's/.*=//; s/://g'
```

### 3.4 nginx + systemd

```bash
sudo cp cert-issuer/nginx-wazuh-cert-issuer.conf /etc/nginx/conf.d/
sudo nginx -t && sudo systemctl reload nginx

sudo cp cert-issuer/wazuh-cert-issuer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-cert-issuer
```

### 3.5 Smoke test

```bash
curl --cacert /opt/wazuh-ca/agents-rootCA.pem https://wazuh-enroll.corp.local:8443/healthz

TOKEN=$(sudo -u wazuh-issuer TOKEN_SECRET_FILE=/etc/wazuh-cert-issuer/token.secret \
  /opt/wazuh-cert-issuer/venv/bin/python /opt/wazuh-cert-issuer/mint_token.py \
  --ttl 15m --single-use --agent-name TEST-01)

curl --cacert /opt/wazuh-ca/agents-rootCA.pem \
  -X POST https://wazuh-enroll.corp.local:8443/v1/agent-bootstrap \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"agent_name":"TEST-01","platform":"linux"}' | jq 'keys'
```

Then confirm the guardrails actually bite — replay the same token (expect
401 `token already used`), and try `{"agent_name":"../../etc/passwd"}` with a
fresh token (expect 400).

---

## Phase 4 — Bootstrap tokens

Two flavours, and the choice is a real trade-off rather than a formality:

**Fleet token** — one token, embedded in the Intune package, valid 30 days.
Any device that has the package can enroll. Simple, and it survives Autopilot
where you can't pre-generate a per-device secret. But anyone who extracts the
package gets 30 days of cert issuance.

```bash
./mint_token.py --ttl 30d --scope windows
```

**Single-use token** — pinned to one agent name, burned on first use. Right
for servers and anything hand-built.

```bash
./mint_token.py --ttl 1h --single-use --agent-name FIN-SRV-01
```

For workstations under Intune, use a fleet token, keep the TTL to 30 days, and
rotate by bumping `Revision` in `bootstrap.json` and re-uploading the app.
That's the honest trade: you accept a shared secret in exchange for zero-touch
Autopilot, and you compensate with short expiry, the 6 req/min nginx rate
limit, the per-name cooldown, and an audit log you actually read.

**Stronger option, no license needed:** every Intune-enrolled Windows device
already holds a certificate from *Microsoft Intune MDM Device CA* in
`LocalMachine\My`, with the Entra device ID as CN. That is a real per-device
identity you already own. Uncomment the `ssl_client_certificate` lines in the
nginx config, point them at that CA, and set `AUTH_MODE=either` — now the
device authenticates with something it can't share, and the fleet token is
just a fallback. This is the closest you'll get to Cloud PKI without paying
for Cloud PKI. Export the CA from an enrolled device:

```powershell
Get-ChildItem Cert:\LocalMachine\My |
  Where-Object { $_.Issuer -like "*Intune MDM*" } |
  Select-Object Subject, Issuer, Thumbprint
```

Then export the issuing CA from `Cert:\LocalMachine\CA` and convert to PEM.

---

## Phase 5 — Windows via Intune

### 5.1 Assemble the package folder

```
WazuhPackage\
  Install-WazuhAgent.ps1      (from intune/)
  Detect-WazuhAgent.ps1       (from intune/)
  Uninstall-WazuhAgent.ps1    (from intune/)
  wazuh_enroll.ps1            (yours, unchanged)
  bootstrap.json              (from bootstrap.json.example, filled in)
  sysmonconfig.xml            (optional — SwiftOnSecurity or Olaf Hartong)
```

Fill in `bootstrap.json`: issuer URL, the fleet token, and the SHA256 pins from
step 3.3.

On the Sysmon config: your script's built-in baseline excludes nothing, which
means full-fidelity process/network/file/registry events from every endpoint.
That's the right starting point for tuning and the wrong thing to leave running
across a whole fleet — the event volume will be substantial and your indexer
will feel it. Ship a tuned config (SwiftOnSecurity's is the usual starting
point) in the package via `SysmonConfigFile`, and roll out to a pilot ring
first so you can measure EPS before it's everywhere.

### 5.2 Package it

```powershell
IntuneWinAppUtil.exe -c .\WazuhPackage -s Install-WazuhAgent.ps1 -o .\out -q
```

### 5.3 Create the Win32 app

Intune admin center → **Apps → Windows → Add → Windows app (Win32)**, upload
the `.intunewin`.

**Program**

- Install: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-WazuhAgent.ps1`
- Uninstall: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-WazuhAgent.ps1`
- Install behavior: **System**
- Device restart behavior: No specific action

**Requirements**

- 64-bit, Windows 10 1809 or later

**Detection rules** → *Use a custom detection script* → upload
`Detect-WazuhAgent.ps1`. Run as 32-bit: **No**.

The detection script is what makes this self-healing. It checks that WazuhSvc
is running, `client.keys` is non-empty, Sysmon is running, and the registry
marker is at the current revision. If any of that breaks, Intune re-runs the
installer, which pulls a fresh cert and re-enrolls. No human involved.

It deliberately does **not** check whether the agent is currently *connected*.
A laptop off the VPN is disconnected but perfectly well installed — failing
detection on that would reinstall the agent every 8 hours for every remote
user. Chase disconnected agents from the Wazuh dashboard instead.

**Assignments** — start with a pilot device group of 5–10 machines. Add to
the Enrollment Status Page only after the pilot is clean; a blocking app that
fails turns every Autopilot build into a support ticket.

### 5.4 Watch the first run

On a pilot device: `C:\ProgramData\WazuhBootstrap\install.log`, and the Intune
Management Extension log at
`C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log`.

---

## Phase 6 — Linux

```bash
sudo mkdir -p /opt/wazuh-bootstrap /etc/wazuh-bootstrap
sudo cp linux/wazuh_bootstrap.sh wazuh_enroll.sh /opt/wazuh-bootstrap/
sudo chmod +x /opt/wazuh-bootstrap/*.sh
sudo cp /opt/wazuh-ca/agents-rootCA.pem /etc/wazuh-bootstrap/
sudo cp linux/bootstrap.conf.example /etc/wazuh-bootstrap/bootstrap.conf
sudo chmod 600 /etc/wazuh-bootstrap/bootstrap.conf
sudoedit /etc/wazuh-bootstrap/bootstrap.conf      # paste the token

sudo cp linux/wazuh-bootstrap.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-bootstrap.timer
sudo systemctl start wazuh-bootstrap.service
journalctl -u wazuh-bootstrap -f
```

The service is a no-op when the agent is healthy, so the hourly timer costs
nothing and gives you the same self-heal behaviour Intune provides on Windows.

Bake `/opt/wazuh-bootstrap` and the config into your golden image or
cloud-init and new Linux hosts enroll themselves on first boot.

---

## Phase 7 — Rollout order

1. Manager changes (Phase 1) — safe, reversible, no endpoint impact.
2. Issuer + S3 (Phases 2–3), tested with `curl` only.
3. One Linux VM you can rebuild freely.
4. One Windows VM, script run manually with `-BootstrapConfig`.
5. Intune pilot ring, 5–10 devices, 48 hours.
6. Watch indexer EPS and disk growth. Tune Sysmon before widening.
7. Broad assignment.

---

## Operations

**Rotating the fleet token.** Mint a new one, update `bootstrap.json`, bump
`Revision`, repackage, bump the app version in Intune. Devices with the old
revision fail detection and re-run with the new token. Old tokens expire on
their own — there is no revocation list.

**Revoking an agent cert.** There isn't one. `openssl x509 -req` signing
produces no CRL and no OCSP, and Wazuh's `ssl_agent_ca` check only validates
the chain. This is why `CERT_DAYS=2` matters: expiry *is* the revocation
mechanism. Since the cert is used once at enrollment and then shredded, a
short life costs nothing. To actually remove an agent, delete it from the
manager (`agent_control -r -i <id>` or the API) — that kills its `client.keys`
entry, which is the credential that matters after enrollment.

**Rotating the CA.** Painful, so plan for it: `agents-rootCA` signs the manager
cert, every agent cert, and now the issuer's TLS cert. Rotating means
reissuing all three and re-running enrollment fleet-wide. Check the CA's
expiry now (`openssl x509 -in agents-rootCA.pem -noout -dates`) and put the
date in a calendar.

**Auditing.** `journalctl -u wazuh-cert-issuer | grep -E 'ISSUE|DENY|FAIL'`.
Every issuance logs source IP, agent name, auth mode, and a cert fingerprint.
Ship this to Wazuh itself — an issuance for a hostname that isn't in your
device inventory is a genuine alert, and it's the single highest-value
detection in this whole design.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `401 invalid token: token expired` | Fleet token aged out. Mint, repackage, bump revision. |
| `401 token already used` | Single-use token replayed. Mint a fresh one. |
| `429 too_soon` | Re-issue cooldown. Wait, or lower `REISSUE_COOLDOWN`. |
| PowerShell TLS error reaching the issuer | Pin mismatch, or SAN missing (forgot `-copy_extensions copyall`). |
| `Duplicated ID` / `Duplicated name` from authd | The `<force>` block from Phase 1.1 isn't applied. |
| `Unable to read CA certificate file` in `ossec.log` | `ssl_agent_ca` path wrong inside the container. |
| Agent enrolls, then never connects | 1514 blocked, or the endpoint is off-VPN. Enrollment (1515) and events (1514) are separate ports. |
| `issuance_failed` 500 | Check `journalctl -u wazuh-cert-issuer`. Usually CA key permissions or `.srl` not writable. |

---

## Known gaps, stated plainly

- **The fleet token is a shared secret on every endpoint.** Mitigated, not
  eliminated. Moving to Intune MDM client certs (Phase 4) is the real fix and
  costs nothing but configuration.
- **No revocation.** Short cert lifetimes only. Fine here because the cert is
  ephemeral; would not be fine if you kept certs on disk long-term.
- **The issuer is a single point of failure and a high-value target.** It sits
  on the box with the CA key. If you outgrow this, the next step is a proper
  CA (step-ca, Vault PKI, EJBCA) with the signing key in an HSM or KMS, and
  this service becomes a thin client to it. The REST contract above stays the
  same, which is why it's worth keeping the interface narrow now.
- **`ssl_verify_host` stays `no`.** Correct for DHCP laptops — CN-is-the-IP
  breaks the moment a device changes network. Don't turn it on for
  workstations.

# Windows pin (cert thumbprint) — hex, uppercase, no colons
openssl x509 -in /etc/wazuh-cert-issuer/tls/issuer.crt -noout -fingerprint -sha256 |
  cut -d= -f2 | tr -d ':'
openssl x509 -in /opt/wazuh-ca/agents-rootCA.pem -noout -fingerprint -sha256 |
  cut -d= -f2 | tr -d ':'

# Linux pin (SPKI) — base64
openssl x509 -in /etc/wazuh-cert-issuer/tls/issuer.crt -pubkey -noout |
  openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64