# Sprint 3 — Advanced Endpoint Monitoring (FIM, Commands & Ports)

**Written against:** `L-N-X-1/private-DT` @ main — multi-node Wazuh in Docker, manager at
`192.168.29.192`, agent groups `windows-agents` / `linux-agents`, shared `agent.conf`
pushed via `docker cp`.

**Constraint:** no S3, no Intune. Config delivery is scripted/manual on both platforms.

---

## The mental model for this sprint

Sprints 1 and 2 built *transport*: a manager, and agents that can talk to it. Sprint 3
is about **what the agents actually say**. Three capabilities, and it's worth being
precise about which mechanism delivers which, because they are not interchangeable:

| Question you want answered | Mechanism | Delivered by |
|---|---|---|
| What changed on disk? | FIM / `syscheck` | `agent.conf` |
| **Who** changed it, and with what process? | FIM **whodata** | `agent.conf` + auditd (Linux) / SACL (Windows) |
| What executed? | auditd `execve` (Linux) / Sysmon EID 1 (Windows) | **outside** `agent.conf` |
| What commands did a human type? | bash `PROMPT_COMMAND` / PowerShell 4104 | **outside** `agent.conf` |
| What's installed / running / listening right now? | `syscollector` | `agent.conf` |
| What *newly started* listening? | `netstat` diff via `full_command` | `agent.conf` + `local_internal_options` |

The rightmost column is the whole reason this sprint is more work than editing one XML
file. Roughly half of Sprint 3 lives on the endpoint, not on the manager.

---

## Phase 0 — Baseline and guardrails (do this first, ~half a day)

Skipping this phase is the single most common way this sprint goes wrong. You are about
to multiply your event volume by somewhere between 10× and 200×, and you need a "before"
number to compare against.

### 0.1 Measure your current event rate

```bash
docker exec wazuh.master cat /var/ossec/var/run/wazuh-analysisd.state
```

Note `events_processed` and `events_received`. Sample it twice, 60 seconds apart, and
divide — that's your current EPS. Write it down.

Then get your index growth:

```bash
curl -sk -u admin:<pass> "https://localhost:9200/_cat/indices/wazuh-alerts-*?v&h=index,docs.count,store.size&s=index"
```

### 0.2 Check disk headroom

```bash
docker system df -v | grep -i wazuh
df -h /var/lib/docker
```

Full-fidelity Sysmon plus auditd `execve` on a handful of endpoints can produce several
GB/day. If you have less than ~50 GB free, set retention policy *before* you turn
anything on, not after the disk fills and the indexer goes read-only.

### 0.3 Confirm the `remote_commands` gap

This is the bug in your current setup. Wazuh deliberately ignores `<localfile>` blocks
containing `<command>` or `<full_command>` when they arrive from the manager's shared
`agent.conf` — the reasoning is that a compromised manager would otherwise get arbitrary
code execution on every endpoint. It's a sensible default, and it silently disables your
`df -P` and `last -n 20` blocks today.

Verify on any Linux agent:

```bash
grep -i 'remote commands' /var/ossec/logs/ossec.log
# Expect: "WARNING: (1108): Remote commands are not accepted from the manager.
#          Ignoring it on the agent.conf file."
```

You have two options, and it's a real security trade-off rather than a formality:

- **Option A (recommended for this project):** enable remote commands on agents. Add to
  `/var/ossec/etc/local_internal_options.conf` on each endpoint:

  ```
  logcollector.remote_commands=1
  wazuh_command.remote_commands=1
  ```

  This keeps *all* config centralized in `agent.conf`, which is the whole point of your
  group-based design. The cost: your manager can now run commands on every endpoint.
  Given the manager is yours and internal-only, this is a reasonable call.

- **Option B:** put command-based `<localfile>` blocks in each endpoint's local
  `ossec.conf` instead. More secure, but you lose central management and now need a
  config-push mechanism for something `agent.conf` was supposed to solve.

Go with A, but **document the decision and its trade-off** — that's the kind of thing
that belongs in your report.

Your existing bootstrap scripts are the delivery vehicle. Add to `wazuh_bootstrap.sh`
(idempotent, so the hourly timer enforces it):

```bash
LIO=/var/ossec/etc/local_internal_options.conf
for opt in "logcollector.remote_commands=1" "wazuh_command.remote_commands=1"; do
    grep -qxF "$opt" "$LIO" 2>/dev/null || echo "$opt" >> "$LIO"
done
```

### 0.4 Snapshot your working config

```bash
docker exec wazuh.master tar czf - /var/ossec/etc/shared > shared-backup-$(date +%F).tar.gz
```

You will break `agent.conf` at some point this sprint. A malformed one pushes to every
agent in the group and can take the whole group offline simultaneously — your own README
already warns about this. Always run `verify-agent-conf` before restarting.

---

## Phase 1 — Linux command auditing

### 1.1 Why auditd, and why not just bash history

Sprint 3 says "Bash history on Linux." Taken literally, that means reading `~/.bash_history`,
and it's the wrong approach: that file is written only on clean shell exit, is trivially
editable by the user who owns it, misses everything non-interactive, and misses anything
run under `sh`, `zsh`, cron, or a service account.

The defensible answer is a **two-layer** approach, and explaining the layering is worth
marks in itself:

- **auditd `execve` rules** — kernel-level, captures every `exec()` regardless of shell,
  cannot be bypassed by a user without root. This is your authoritative source.
- **A `PROMPT_COMMAND` shim** — logs each interactive command to syslog in a
  human-readable form. Bypassable, so it is *not* a security control; it's a
  readability/UX layer that makes the dashboard pleasant for the shell-session use case.

Say that out loud in your documentation. "We use auditd for assurance and bash logging
for legibility" is a much stronger position than pretending bash history is a control.

### 1.2 Install and configure auditd

On each Linux endpoint:

```bash
# Debian/Ubuntu
sudo apt-get install -y auditd audispd-plugins
# RHEL/Rocky
sudo dnf install -y audit
sudo systemctl enable --now auditd
```

Create `/etc/audit/rules.d/wazuh.rules`:

```
## Buffer — raise it, execve auditing is high-volume and a full buffer drops events
-b 8192
--backlog_wait_time 0

## Failure mode: 1 = log to syslog (safe). 2 = kernel panic (do NOT use here).
-f 1

## Command execution by real users (auid >= 1000). The audit-wazuh-c key is what
## Wazuh's built-in audit decoders look for.
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k audit-wazuh-c

## Direct root logins (auid=0) — otherwise invisible to the rule above
-a always,exit -F arch=b64 -S execve -F auid=0 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid=0 -k audit-wazuh-c

## Privilege escalation
-w /usr/bin/sudo   -p x -k audit-wazuh-x
-w /bin/su         -p x -k audit-wazuh-x
-w /etc/sudoers    -p wa -k audit-wazuh-w
-w /etc/sudoers.d/ -p wa -k audit-wazuh-w

## Execution from world-writable / staging locations — high-signal, low-volume
-w /tmp     -p x -k audit-wazuh-x
-w /var/tmp -p x -k audit-wazuh-x
-w /dev/shm -p x -k audit-wazuh-x
```

Load them:

```bash
sudo augenrules --load
sudo auditctl -l          # confirm rules are live
```

**`auid` is the key concept here.** It's the *login* UID — the identity of the human who
first authenticated, preserved across `sudo` and `su`. So when someone logs in as `ahmed`,
sudoes to root, and runs `rm -rf`, auditd still records `auid=ahmed`. `uid` alone would
just say `root` and tell you nothing. Filtering on `auid>=1000` also neatly excludes the
enormous background noise of system daemons.

Tune `/etc/audit/auditd.conf` so audit logs don't eat the disk:

```
max_log_file = 50
num_logs = 5
max_log_file_action = ROTATE
```

### 1.3 Wire it into Wazuh

Your Linux `agent.conf` already has this — no change needed:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

It was previously a no-op because the file didn't exist (the agent silently skips
missing `localfile` targets — as your own comment notes). Now it does.

Confirm the manager is decoding it:

```bash
docker exec wazuh.master grep -rn "audit-wazuh-c" /var/ossec/ruleset/rules/
```

You should land in `audit_rules.xml`, around the 807xx–809xx range. Test the decoder
directly with a sample line:

```bash
docker exec -it wazuh.master /var/ossec/bin/wazuh-logtest
# paste a line from /var/log/audit/audit.log containing key="audit-wazuh-c"
```

`wazuh-logtest` is the single most useful tool in this sprint. Use it constantly — it
tells you which decoder matched, which rule fired, and at what level, without waiting
for a real event to travel across the network.

### 1.4 Bash session logging (the legibility layer)

Create `/etc/profile.d/wazuh-bash-audit.sh`:

```sh
# Interactive shell command logging → syslog → Wazuh
# NOTE: bypassable by design (user can unset PROMPT_COMMAND, use sh, etc).
# auditd execve rules are the authoritative source; this is for readability.
if [ -n "$BASH_VERSION" ] && [ -n "$PS1" ]; then
  export HISTTIMEFORMAT="%F %T "
  export PROMPT_COMMAND='_rc=$?; _cmd=$(history 1 | sed "s/^ *[0-9]* *//"); \
    logger -p local6.info -t bash-audit \
    "user=$(whoami) auid=$(id -un) tty=$(tty) pwd=$PWD rc=$_rc cmd=${_cmd}"'
fi
```

`logger` writes to syslog, which your `agent.conf` already collects via `/var/log/syslog`
and `/var/log/messages` — so no new `localfile` is needed. That's a deliberately cheap
integration.

Now add a decoder so the fields are searchable rather than one blob string. On the
manager, `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="bash-audit">
  <program_name>bash-audit</program_name>
</decoder>

<decoder name="bash-audit-fields">
  <parent>bash-audit</parent>
  <regex offset="after_parent">user=(\S+) auid=(\S+) tty=(\S+) pwd=(\S+) rc=(\d+) cmd=(.*)$</regex>
  <order>srcuser, audit.login_user, tty, pwd, exit_code, command</order>
</decoder>
```

And `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="bash_audit,">
  <rule id="100200" level="3">
    <decoded_as>bash-audit</decoded_as>
    <description>Bash: $(srcuser) ran: $(command)</description>
  </rule>

  <rule id="100201" level="10">
    <if_sid>100200</if_sid>
    <field name="command">curl|wget|nc |ncat|base64 -d|chmod \+x|/dev/tcp/</field>
    <description>Bash: suspicious download/exec pattern by $(srcuser): $(command)</description>
    <mitre><id>T1105</id></mitre>
  </rule>
</group>
```

Rule 100200 at level 3 keeps routine commands out of your alert noise while still
indexing them; 100201 promotes the interesting ones. **Validate before restarting:**

```bash
docker exec wazuh.master /var/ossec/bin/wazuh-logtest -t
docker exec wazuh.master /var/ossec/bin/wazuh-control restart
```

---

## Phase 2 — Linux FIM, deepened

### 2.1 realtime vs whodata — the distinction that matters

Your current config uses `realtime="yes"`. That's inotify: the kernel tells Wazuh a file
changed, immediately. What it **cannot** tell you is which process or user did it. You
get "`/etc/passwd` changed at 14:32" and nothing else.

`whodata="yes"` routes FIM through auditd instead. Wazuh installs its own audit rules on
the monitored paths and correlates the audit record with the file change, giving you the
user, the login UID, the process name, and the PID. For "trace modified, downloaded, or
executed binaries," this is the requirement — the *who* is the whole point.

Two things to know:
- `whodata` and `realtime` are mutually exclusive on a directory. Setting `whodata="yes"`
  supersedes `realtime`; don't set both.
- `whodata` **requires auditd**, which you just installed in Phase 1. This is why Phase 1
  comes first.

Also worth knowing: inotify has a per-user watch limit that large `realtime` trees will
silently exhaust. If you keep any `realtime` directories, raise it:

```bash
echo 'fs.inotify.max_user_watches=524288' | sudo tee /etc/sysctl.d/99-wazuh.conf
sudo sysctl --system
```

### 2.2 Replacement `<syscheck>` block

Replace the `<syscheck>` section of `agent.conf-linux-agents.xml` with:

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>21600</frequency>          <!-- 6h baseline sweep -->
  <scan_on_start>yes</scan_on_start>
  <alert_new_files>yes</alert_new_files>

  <!-- Config surface: who changed it matters more than what -->
  <directories check_all="yes" whodata="yes" report_changes="yes">/etc</directories>
  <directories check_all="yes" whodata="yes" report_changes="yes">/root/.ssh</directories>
  <directories check_all="yes" whodata="yes" report_changes="yes">/etc/wazuh-bootstrap</directories>

  <!-- System binaries: whodata, but NO report_changes (binary diffs are useless
       and expensive to compute and store) -->
  <directories check_all="yes" whodata="yes">/bin,/sbin,/usr/bin,/usr/sbin,/usr/local/bin,/usr/local/sbin</directories>

  <!-- Persistence mechanisms -->
  <directories check_all="yes" whodata="yes">/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/etc/cron.weekly,/var/spool/cron</directories>
  <directories check_all="yes" whodata="yes">/etc/systemd/system,/usr/lib/systemd/system</directories>

  <!-- Staging areas: restrict to executable/script types only, or /tmp will
       drown you in editor swap files and package-manager scratch -->
  <directories check_all="yes" whodata="yes"
               restrict="\.(sh|py|pl|elf|bin|so|ko)$">/tmp,/var/tmp,/dev/shm</directories>

  <!-- Downloads: the "downloaded binaries" half of the milestone -->
  <directories check_all="yes" whodata="yes">/home/*/Downloads</directories>

  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/random-seed</ignore>
  <ignore>/etc/adjtime</ignore>
  <ignore>/etc/resolv.conf</ignore>
  <ignore>/etc/ld.so.cache</ignore>
  <ignore type="sregex">\.log$|\.swp$|\.tmp$|\.swx$|~$</ignore>

  <nodiff>/etc/shadow</nodiff>
  <nodiff>/etc/gshadow</nodiff>
  <nodiff>/root/.ssh</nodiff>

  <skip_nfs>yes</skip_nfs>
  <skip_dev>yes</skip_dev>
  <skip_proc>yes</skip_proc>
  <skip_sys>yes</skip_sys>
  <process_priority>10</process_priority>
  <max_eps>100</max_eps>

  <synchronization>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <max_eps>10</max_eps>
  </synchronization>
</syscheck>
```

### 2.3 Design decisions worth explaining in your writeup

- **`report_changes` only on text config.** It stores a copy of every monitored file
  under `/var/ossec/queue/diff/` so it can produce a diff. On `/etc` that's genuinely
  useful — you see the exact line added to `sshd_config`. On `/usr/bin` it doubles your
  binary storage to produce an unreadable diff. Selective use is the correct call.
- **`nodiff` on `/etc/shadow`.** Without it, the diff feature would ship password hashes
  into your alert stream in plaintext. This is a security control, not an optimization.
- **`restrict` on `/tmp`.** Whodata on an unrestricted `/tmp` is one of the fastest ways
  to melt an indexer. The regex narrows it to file types that could plausibly be malware.
- **`/home/*/Downloads` uses a wildcard**, which Wazuh expands per-user. Directly serves
  the "downloaded binaries" requirement.
- **`process_priority` and `max_eps`** exist so FIM scans don't starve production
  workloads or flood the manager. Keep them.

---

## Phase 3 — Windows command auditing

This is the phase most affected by dropping Intune, because **none of it is deliverable
via `agent.conf`**. Sysmon config and audit-policy registry values are endpoint-local
state that Wazuh doesn't manage.

### 3.1 Tune Sysmon first

Your README already flags this: `Install-WazuhAgent.ps1` falls back to a built-in
baseline that excludes nothing. Full-fidelity Sysmon on a workstation produces
process, network, file, registry, WMI, DNS, and named-pipe events with no filtering.
On a single workstation that is hundreds of EPS. Do not roll that to a fleet.

Get a tuned config:

```powershell
# SwiftOnSecurity — the standard starting point, well-commented, conservative
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
                  -OutFile "C:\ProgramData\WazuhBootstrap\sysmonconfig.xml"
```

Olaf Hartong's `sysmon-modular` is the more granular alternative (per-technique modules
you compose) — better if you want to map explicitly to MITRE ATT&CK in your report.

Apply it:

```powershell
Sysmon64.exe -c C:\ProgramData\WazuhBootstrap\sysmonconfig.xml
```

The event IDs that carry Sprint 3:

| EID | Meaning | Sprint 3 relevance |
|---|---|---|
| 1 | Process creation | **Full command line**, parent process, hashes — this is your "what commands executed" |
| 3 | Network connection | Which process opened which socket |
| 7 | Image loaded | DLL side-loading; noisy, keep filtered |
| 11 | File created | Complements FIM for downloads |
| 13 | Registry value set | Persistence |
| 22 | DNS query | Very high value, moderate volume |

### 3.2 Enable PowerShell Script Block Logging

Your `agent.conf` already collects `Microsoft-Windows-PowerShell/Operational`. But the
channel is nearly empty by default — the interesting event (**EID 4104**, script block
logging) has to be switched on. Without it you're collecting an empty channel and will
wonder why PowerShell activity never appears.

```powershell
$sbl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $sbl -Force | Out-Null
Set-ItemProperty -Path $sbl -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Module logging (EID 4103) — pipeline detail, higher volume
$ml = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path "$ml\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path $ml -Name "EnableModuleLogging" -Value 1 -Type DWord
Set-ItemProperty -Path "$ml\ModuleNames" -Name "*" -Value "*"
```

4104 is the one that matters: it logs the **deobfuscated** script block. Base64-encoded
or string-concatenated payloads get logged in their decoded form, which is exactly what
makes it the highest-value Windows telemetry available.

Deliberately skipping **transcription** (`EnableTranscripting`) — it writes .txt files
per session to disk, needs its own storage and collection path, and largely duplicates
4104. Note that as a considered exclusion rather than an oversight.

### 3.3 Command line in Security 4688

Windows Security EID 4688 logs process creation but **omits the command line by default**,
which makes it nearly useless on its own.

```powershell
# Enable the subcategory
auditpol /set /subcategory:"Process Creation" /success:enable

# Include the command line
$k = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
```

**Decide consciously whether you want both 4688 and Sysmon EID 1.** They cover the same
ground and running both roughly doubles your process-event volume. Sysmon EID 1 is
strictly richer — hashes, parent GUID, integrity level, original filename. My
recommendation: enable 4688 anyway, because it's your detection for "Sysmon was killed"
(process events keep flowing from a source an attacker has to disable separately), but
add a Security-channel filter so it isn't collected on every host in the pilot. Whichever
you choose, justify it — this is a genuine engineering trade-off and a good thing to
discuss.

### 3.4 Delivering this without Intune

Your Linux side already solves this with `wazuh-bootstrap.timer` running an idempotent
script hourly. Mirror that on Windows: write `Configure-EndpointAuditing.ps1` containing
sections 3.1–3.3 (all idempotent — setting a registry value to the value it already has
is a no-op), then register a scheduled task:

```powershell
$action  = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\WazuhBootstrap\Configure-EndpointAuditing.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "Wazuh-EndpointAuditing" -Action $action `
    -Trigger $trigger -Principal $principal -Force
```

You can go further and reuse `Detect-WazuhAgent.ps1` as the task's guard condition —
which reconstructs your Intune self-healing behaviour with no Intune. That's a nice
architectural point for the report: *the detection/remediation pattern was portable; only
the delivery channel changed.*

If your Windows hosts are domain-joined, GPO is the cleaner path for the registry values
(Computer Config → Policies → Admin Templates → Windows Components → Windows PowerShell).
Use it if available; the scheduled task is the fallback for workgroup machines.

---

## Phase 4 — Windows FIM, deepened

Windows whodata uses SACLs rather than auditd. Wazuh sets the SACL on monitored
directories itself, provided the agent runs as SYSTEM — which it does.

Replace the `<syscheck>` block in `agent.conf-windows-agents.xml`:

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>21600</frequency>
  <scan_on_start>yes</scan_on_start>
  <alert_new_files>yes</alert_new_files>

  <!-- Downloads and Desktop: the "downloaded binaries" requirement.
       restrict= keeps the volume sane by ignoring documents and media. -->
  <directories check_all="yes" whodata="yes"
               restrict="\.(exe|dll|ps1|bat|cmd|vbs|js|jse|scr|hta|msi|jar|lnk|iso)$">C:\Users\*\Downloads</directories>
  <directories check_all="yes" whodata="yes"
               restrict="\.(exe|dll|ps1|bat|cmd|vbs|js|jse|scr|hta|msi|jar|lnk)$">C:\Users\*\Desktop</directories>

  <!-- Living-off-the-land staging -->
  <directories check_all="yes" whodata="yes"
               restrict="\.(exe|dll|ps1|bat|cmd|vbs|scr)$">C:\Users\*\AppData\Local\Temp</directories>
  <directories check_all="yes" whodata="yes"
               restrict="\.(exe|dll|ps1|bat|cmd|vbs|scr)$">C:\Windows\Temp</directories>

  <!-- Persistence -->
  <directories check_all="yes" whodata="yes">%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup</directories>
  <directories check_all="yes" whodata="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
  <directories check_all="yes" whodata="yes">C:\Windows\System32\Tasks</directories>

  <!-- Config / integrity -->
  <directories check_all="yes" whodata="yes" report_changes="yes">%WINDIR%\System32\drivers\etc</directories>
  <directories check_all="yes" whodata="yes" report_changes="yes">C:\Program Files (x86)\ossec-agent\ossec.conf</directories>

  <!-- System binaries: scheduled scan only. whodata on all of System32 is a
       well-known way to bury an indexer; the scheduled hash comparison catches
       tampering without the per-event firehose. -->
  <directories check_all="yes" realtime="no">%WINDIR%\System32</directories>

  <ignore type="sregex">\.log$|\.tmp$|\.etl$|\.evtx$</ignore>
  <ignore>C:\Users\*\AppData\Local\Temp\chrome_*</ignore>

  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
  <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>

  <process_priority>10</process_priority>
  <max_eps>100</max_eps>

  <synchronization>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <max_eps>10</max_eps>
  </synchronization>
</syscheck>
```

Two additions worth calling out: `<windows_registry>` gives you FIM on the registry Run
keys, which is where the majority of commodity Windows persistence lands and has no Linux
equivalent. And note that `%WINDIR%\System32` deliberately drops to scheduled scanning —
integrity checking without real-time cost.

---

## Phase 5 — Ports, processes, and network state

### 5.1 What syscollector does and doesn't do

Your `syscollector` config is already correct: `<ports all="no">yes</ports>` collects
**listening** ports only (`all="yes"` would add every ephemeral outbound socket — huge
volume, near-zero value).

The limitation: syscollector populates the **Inventory** dashboards. It's *state*, not
*events*. It answers "what is listening right now?" beautifully. It does not, by itself,
generate an alert when a new port opens.

Drop the interval for tighter visibility:

```xml
<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>30m</interval>
  <scan_on_start>yes</scan_on_start>
  <hardware>yes</hardware>
  <os>yes</os>
  <network>yes</network>
  <packages>yes</packages>
  <ports all="no">yes</ports>
  <processes>yes</processes>
  <hotfixes>yes</hotfixes>   <!-- Windows only -->
</wodle>
```

30 minutes is a reasonable floor; below that you're paying real CPU on the endpoint for
a full package enumeration that rarely changes.

### 5.2 Alerting on port changes

For "a new port opened" as an *alert*, use the `full_command` netstat pattern. Wazuh's
default ruleset diffs consecutive `full_command` outputs under the same `<alias>` and
fires when the output changes.

**Linux** — add to `agent.conf-linux-agents.xml`:

```xml
<localfile>
  <log_format>full_command</log_format>
  <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
  <alias>netstat listening ports</alias>
  <frequency>360</frequency>
</localfile>
```

The `sed` chain normalizes the output so cosmetic reordering doesn't trigger false
positives — that normalization is why this specific incantation is the one in Wazuh's
docs rather than a bare `netstat`.

**Windows** — add to `agent.conf-windows-agents.xml`:

```xml
<localfile>
  <log_format>full_command</log_format>
  <command>netstat -nao | findstr /R /C:"[UT][DC]P.*LISTENING" /C:"UDP"</command>
  <alias>netstat listening ports</alias>
  <frequency>360</frequency>
</localfile>
```

**Both depend on Phase 0.3.** Without `logcollector.remote_commands=1` these are silently
ignored, exactly like your `df -P` block is today.

Find the rule that fires:

```bash
docker exec wazuh.master grep -rn "netstat" /var/ossec/ruleset/rules/
```

You're looking for the "Listened ports status changed" rule (ID in the low 500s,
`ossec_rules.xml`). Confirm the ID on your version rather than trusting a number from a
blog post — ruleset IDs do shift between releases.

### 5.3 Process monitoring

Same diff mechanism, useful on servers where the process set should be stable:

```xml
<!-- Linux -->
<localfile>
  <log_format>full_command</log_format>
  <command>ps -e -o comm= | sort -u</command>
  <alias>running processes</alias>
  <frequency>600</frequency>
</localfile>
```

Note `comm=` (name only, sorted, deduplicated) rather than full `ps aux`. Including PIDs
or CPU percentages means the output differs on every single run and the rule fires
constantly — a classic way to build an alert everyone learns to ignore.

On workstations, skip this. Users open and close applications all day; the diff is
meaningless. Server groups only — which is a good argument for splitting
`linux-agents` into `linux-servers` and `linux-workstations` groups now.

---

## Phase 6 — Deploy and validate

### 6.1 Push order

Never push both platforms at once. If something breaks you want to know which change did it.

```bash
# 1. Validate locally first
xmllint --noout agent.conf-linux-agents.xml

# 2. Push to the MASTER only (cluster syncs to workers)
docker cp agent.conf-linux-agents.xml \
  wazuh.master:/var/ossec/etc/shared/linux-agents/agent.conf
docker exec wazuh.master chown wazuh:wazuh \
  /var/ossec/etc/shared/linux-agents/agent.conf

# 3. Validate as the manager sees it — BEFORE restarting
docker exec wazuh.master /var/ossec/bin/verify-agent-conf

# 4. Restart
docker exec wazuh.master /var/ossec/bin/wazuh-control restart
```

Agents pull the new config within ~10 minutes, or immediately on agent restart.

Confirm an agent actually received it:

```bash
# On the endpoint
sudo ls -l /var/ossec/etc/shared/
sudo grep -i "shared config" /var/ossec/logs/ossec.log | tail -5
```

Roll to **one** Linux VM and **one** Windows VM first. Watch for 24 hours. Then widen.

### 6.2 Validation matrix — this is your milestone evidence

Run each test and screenshot the resulting alert. This table *is* your Sprint 3 sign-off.

| # | Test | Command | Expected |
|---|---|---|---|
| 1 | Linux FIM + whodata | `sudo touch /etc/sprint3-test && echo x \| sudo tee -a /etc/hosts` | FIM alert naming the *user* and *process* |
| 2 | Linux download detection | `wget https://example.com/ -O /home/user/Downloads/test.sh` | FIM "new file added" in Downloads |
| 3 | Linux exec from /tmp | `cp /bin/ls /tmp/notls && chmod +x /tmp/notls && /tmp/notls` | auditd `audit-wazuh-x` alert |
| 4 | Linux command audit | `sudo whoami` then `id` | auditd execve alert with correct `auid` |
| 5 | Bash logging | `curl -s https://example.com > /dev/null` | Custom rule 100201 fires |
| 6 | Linux new port | `nc -l -p 4444 &` then wait for next cycle | "Listened ports status changed" |
| 7 | Win FIM Downloads | Save any `.exe` to Downloads | FIM alert with whodata user field |
| 8 | Win process + cmdline | `cmd.exe /c whoami /priv` | Sysmon EID 1 with full command line |
| 9 | Win PowerShell 4104 | `powershell -enc <base64 of 'Write-Host hi'>` | 4104 showing **decoded** script |
| 10 | Win persistence | `reg add HKCU\...\Run /v Test /d calc.exe` | Registry FIM alert |
| 11 | Win new port | `python -m http.server 8080` | "Listened ports status changed" |
| 12 | Inventory populated | Dashboard → Endpoints → Inventory | Ports, processes, packages all present |

Test 9 is the showpiece — demonstrating that base64-obfuscated PowerShell appears in the
dashboard in plaintext is the single most convincing demo in this sprint.

Clean up your test artifacts afterward, and note in your report that you did.

### 6.3 Build the dashboard views

The milestone says "comprehensive log visibility." Raw alerts in Discover don't
demonstrate that. Build saved searches / a small dashboard:

- **What ran** — filter `rule.groups: sysmon_event1 or rule.groups: audit_command`,
  columns: `agent.name`, `data.win.eventdata.image` / `data.audit.exe`, command line, user
- **Commands executed** — `rule.id: 100200 or rule.id: 100201`, columns: `srcuser`, `command`, `pwd`
- **File integrity** — `rule.groups: syscheck`, columns: `syscheck.path`, `syscheck.event`, `syscheck.audit.effective_user.name`
- **Open ports** — Inventory tab per agent, plus a saved search on the netstat change rule
- **Top talkers** — visualization: count by `agent.name`, use this to spot your noisiest
  endpoint before it costs you disk

---

## Phase 7 — Tune before you widen

After 24–48 hours on the pilot pair:

```bash
docker exec wazuh.master cat /var/ossec/var/run/wazuh-analysisd.state
```

Compare against your Phase 0 number. Expect a large multiple — that's normal. What you're
watching for is whether the *absolute* number is sustainable.

Find what's flooding you:

```bash
docker exec wazuh.master bash -c \
  "grep -oP '(?<=Rule: )[0-9]+' /var/ossec/logs/alerts/alerts.log | sort | uniq -c | sort -rn | head -20"
```

Common offenders and their fixes:

| Symptom | Fix |
|---|---|
| FIM alerts from package updates | Add `<ignore>` for the package cache; consider scheduled scan on `/usr` |
| Sysmon EID 7 (image loaded) flood | Tighten the Sysmon config's ImageLoad section, or drop EID 7 entirely |
| auditd events from a service account | Add `-F auid!=<uid>` exclusion to the audit rule |
| netstat rule firing constantly | Your command output isn't stable — check the `sed` normalization |
| Chrome/Firefox temp file noise | Extend the `<ignore>` sregex |

Only after this is quiet should you assign the config to the full group.

Also set retention now, before disk pressure forces it:

```bash
curl -sk -u admin:<pass> -X PUT "https://localhost:9200/_plugins/_ism/policies/wazuh-retention" \
  -H 'Content-Type: application/json' -d '{ ... ISM policy ... }'
```

---

## Deliverables checklist

- [ ] `local_internal_options.conf` change baked into `wazuh_bootstrap.sh` (Linux) and the new PS script (Windows)
- [ ] `/etc/audit/rules.d/wazuh.rules` deployed and loading via `augenrules`
- [ ] `/etc/profile.d/wazuh-bash-audit.sh` deployed
- [ ] `local_decoder.xml` + `local_rules.xml` on the manager, validated with `wazuh-logtest`
- [ ] Updated `agent.conf-linux-agents.xml` (whodata FIM, netstat, process diff)
- [ ] Updated `agent.conf-windows-agents.xml` (whodata FIM, registry FIM, netstat)
- [ ] `Configure-EndpointAuditing.ps1` + scheduled task (the Intune replacement)
- [ ] Tuned `sysmonconfig.xml` committed to the repo
- [ ] Validation matrix completed with screenshots
- [ ] Dashboard saved searches created
- [ ] Before/after EPS and disk figures recorded
- [ ] README updated: mark S3/Intune sections as *not used in current deployment*, document the `remote_commands` trade-off

---

## Known gaps to state plainly (your README already does this well — keep the habit)

- **`PROMPT_COMMAND` logging is bypassable.** A user can `unset PROMPT_COMMAND` or run
  `sh`. auditd is the control; this is the convenience layer. Saying so is stronger than
  pretending otherwise.
- **Enabling `remote_commands` means the manager can execute code on every endpoint.**
  Accepted here because the manager is internal-only and yours. Would need rethinking in
  a multi-tenant or hosted setup.
- **FIM whodata depends on auditd.** If auditd dies, whodata silently degrades. Monitor
  the auditd service itself — a Wazuh rule for "auditd stopped" is worth writing.
- **Sysmon can be disabled by an admin-level attacker.** Sysmon EID 4 (service state
  change) and the Windows 4688 fallback are your partial answer. Not a complete one.
- **No egress filtering on the netstat check.** It shows what's listening, not what's
  connecting outbound. Sysmon EID 3 partly covers this on Windows; Linux would need
  auditd socket rules or a separate tool.
- **Whodata on Windows sets SACLs, which persist after Wazuh is uninstalled.** Minor, but
  worth noting for clean teardown.
