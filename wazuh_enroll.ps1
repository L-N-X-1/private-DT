#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs (if needed) and enrolls a Wazuh agent on Windows with a manager,
    then verifies enrollment actually succeeded.

.DESCRIPTION
    Mirrors the Linux wazuh_enroll.sh script's logic:
      1. Pre-checks connectivity to the registration port (1515)
      2. Installs the agent via MSI if not already present
      3. Installs Sysmon (if not already present) and wires it into ossec.conf
      4. Performs (or re-performs) enrollment via agent-auth.exe
      5. Verifies client.keys was actually written
      6. Restarts the service and checks the log for a live connection

    Safe to re-run: skips reinstall if already present, and always redoes
    enrollment.

.PARAMETER Manager
    Wazuh manager IP/hostname (used for events, port 1514).

.PARAMETER RegistrationPassword
    Registration password for enrollment (port 1515).

.PARAMETER AgentName
    Name to register the agent as. Defaults to the machine's hostname.

.PARAMETER RegistrationServer
    Registration server IP/hostname, if different from -Manager. Defaults to -Manager.

.PARAMETER RegistrationPasswordFile
    Path to a file containing the registration password (instead of passing it
    as plaintext on the command line). Recommended over -RegistrationPassword.

.PARAMETER AgentGroup
    Wazuh agent group to enroll into (must already exist on the manager).
    Defaults to "windows-agents".

.PARAMETER ManagerCaPath
    Path to the manager's CA certificate (rootCA.pem or equivalent). When
    given, agent-auth.exe verifies the manager's TLS cert during enrollment
    instead of trusting whatever answers on the registration port. Without
    this, the registration password authenticates the agent to the manager,
    but nothing authenticates the manager to the agent. Omit to keep the
    previous (unverified) behavior. See:
    https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/manager-identity-verification.html

.PARAMETER AgentCertificatePath
    Path to this agent's own signed certificate. Must be given together with
    -AgentKeyPath. Lets the manager verify this agent's identity in return
    (requires ssl_agent_ca configured on the manager). See:
    https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/agent-identity-verification.html

.PARAMETER AgentKeyPath
    Path to this agent's own private key. Must be given together with
    -AgentCertificatePath.

.PARAMETER SysmonConfigPath
    Path to a custom Sysmon XML config to use instead of the built-in
    baseline (process create/terminate, network connect, file create,
    registry events). Optional.

.PARAMETER SkipSysmon
    Skip installing/configuring Sysmon entirely.

.PARAMETER LocalLogSources
    Also write the Sysmon <localfile> block into the LOCAL ossec.conf.
    Off by default: the manager-side group config
    (/var/ossec/etc/shared/windows-agents/agent.conf) already declares that
    channel, and declaring it in both places makes logcollector open two
    readers for it, double-counting every Sysmon event and skewing any
    frequency-based rule. Only use this if you also remove the matching
    <localfile> entry from the group's agent.conf.

.PARAMETER Version
    Wazuh agent version to install (only used if not already installed).
    Defaults to 4.14.6. Must not be newer than your manager's version.

.EXAMPLE
    .\wazuh_enroll.ps1 -Manager 192.168.1.250 -RegistrationPasswordFile C:\secrets\wazuh_pw.txt

.EXAMPLE
    .\wazuh_enroll.ps1 -Manager 192.168.1.250 -RegistrationPassword 'secret' -AgentName "FIN-PC01" -AgentGroup "finance-workstations"

.EXAMPLE
    .\wazuh_enroll.ps1 -Manager 192.168.1.250 -RegistrationPasswordFile C:\secrets\wazuh_pw.txt -ManagerCaPath C:\secrets\wazuh-manager-ca.pem

.EXAMPLE
    .\wazuh_enroll.ps1 -Manager 192.168.1.250 -RegistrationPasswordFile C:\secrets\wazuh_pw.txt -ManagerCaPath C:\secrets\wazuh-manager-ca.pem -AgentCertificatePath C:\secrets\FIN-PC01.cert -AgentKeyPath C:\secrets\FIN-PC01.key
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Manager,

    [Parameter(Mandatory = $false)]
    [string]$RegistrationPassword,

    [Parameter(Mandatory = $false)]
    [string]$RegistrationPasswordFile,

    [Parameter(Mandatory = $false)]
    [string]$AgentName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [string]$RegistrationServer = $Manager,

    [Parameter(Mandatory = $false)]
    [string]$AgentGroup = "windows-agents",

    [Parameter(Mandatory = $false)]
    [string]$ManagerCaPath,

    [Parameter(Mandatory = $false)]
    [string]$AgentCertificatePath,

    [Parameter(Mandatory = $false)]
    [string]$AgentKeyPath,

    [Parameter(Mandatory = $false)]
    [string]$SysmonConfigPath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipSysmon,

    [Parameter(Mandatory = $false)]
    [switch]$LocalLogSources,

    [Parameter(Mandatory = $false)]
    [string]$Version = "4.14.3"
)

$ErrorActionPreference = "Stop"

if (-not $RegistrationPassword -and -not $RegistrationPasswordFile) {
    Write-Host "ERROR: provide either -RegistrationPassword or -RegistrationPasswordFile." -ForegroundColor Red
    exit 1
}
if ($RegistrationPasswordFile) {
    if (-not (Test-Path $RegistrationPasswordFile)) {
        Write-Host "ERROR: password file not found at $RegistrationPasswordFile" -ForegroundColor Red
        exit 1
    }
    $RegistrationPassword = (Get-Content $RegistrationPasswordFile -Raw).Trim()
}
if ($ManagerCaPath -and -not (Test-Path $ManagerCaPath)) {
    Write-Host "ERROR: manager CA cert not found at $ManagerCaPath (check -ManagerCaPath)." -ForegroundColor Red
    exit 1
}
if (($AgentCertificatePath -and -not $AgentKeyPath) -or ($AgentKeyPath -and -not $AgentCertificatePath)) {
    Write-Host "ERROR: -AgentCertificatePath and -AgentKeyPath must be given together." -ForegroundColor Red
    exit 1
}
if ($AgentCertificatePath -and -not (Test-Path $AgentCertificatePath)) {
    Write-Host "ERROR: agent cert not found at $AgentCertificatePath" -ForegroundColor Red
    exit 1
}
if ($AgentKeyPath -and -not (Test-Path $AgentKeyPath)) {
    Write-Host "ERROR: agent key not found at $AgentKeyPath" -ForegroundColor Red
    exit 1
}
# Note: msiexec.exe and agent-auth.exe both require the password as a literal
# process argument, so it will still be briefly visible in process listings
# (e.g. Get-CimInstance Win32_Process) during those two calls regardless of
# how it was supplied here. Using -RegistrationPasswordFile avoids it sitting
# in PowerShell history and avoids retyping it as a literal on the command
# line (which risks it landing in Event ID 4688 if command-line process
# auditing is enabled) -- but it doesn't eliminate the exposure entirely.

$RegPort      = 1515
$EventPort    = 1514
$InstallDir   = "C:\Program Files (x86)\ossec-agent"
$MsiPath      = Join-Path $env:TEMP "wazuh-agent-$Version.msi"
$MsiUrl       = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi"
$ClientKeys   = Join-Path $InstallDir "client.keys"
$OssecLog     = Join-Path $InstallDir "ossec.log"
$OssecConf    = Join-Path $InstallDir "ossec.conf"
$AgentAuthExe = Join-Path $InstallDir "agent-auth.exe"
$ServiceName  = "WazuhSvc"

$SysmonDir     = "C:\Program Files\Sysmon"
$SysmonZipPath = Join-Path $env:TEMP "Sysmon.zip"
$SysmonZipUrl  = "https://download.sysinternals.com/files/Sysmon.zip"
$SysmonExe     = Join-Path $SysmonDir "Sysmon64.exe"

# Built-in starter baseline: full visibility (no exclusions) into process
# creation, network connections, process termination, file creation, and
# registry events. This is a starting point, not a tuned production config --
# expect to add exclusions later once you see what's noisy in your environment.
$DefaultSysmonConfig = @"
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="exclude" />
    <NetworkConnect onmatch="exclude" />
    <ProcessTerminate onmatch="exclude" />
    <FileCreate onmatch="exclude" />
    <RegistryEvent onmatch="exclude" />
  </EventFiltering>
</Sysmon>
"@

function Write-Step {
    param([string]$Message)
    Write-Host "-- $Message" -ForegroundColor Cyan
}

function Fail {
    param([string]$Message)
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

# Windows PowerShell 5.1's `Set-Content -Encoding UTF8` writes a UTF-8 BOM.
# Three bytes of EF BB BF ahead of <ossec_config> and the agent's XML parser
# can refuse the file -- which shows up as the service starting and then
# dying immediately. Always write config through this instead.
function Write-TextNoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

# Sweep backups left behind by earlier runs that died before their cleanup.
# Under Intune's re-run-on-failed-detection loop these otherwise pile up.
Get-ChildItem -Path "$InstallDir\ossec.conf.bak.*", "$InstallDir\client.keys.bak.*" `
    -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "== Wazuh Agent Enrollment ==" -ForegroundColor Yellow
Write-Host "  Manager (events, port $EventPort):        $Manager"
Write-Host "  Registration server (port $RegPort):       $RegistrationServer"
Write-Host "  Agent name:                                $AgentName"
Write-Host "  Agent group:                               $AgentGroup"
if ($ManagerCaPath) {
    Write-Host "  Manager identity verification:            ENABLED ($ManagerCaPath)"
} else {
    Write-Host "  Manager identity verification:            DISABLED (no -ManagerCaPath given -- manager identity is NOT verified during enrollment)" -ForegroundColor Yellow
}
if ($AgentCertificatePath) {
    Write-Host "  Agent identity verification (this agent): ENABLED ($AgentCertificatePath)"
} else {
    Write-Host "  Agent identity verification (this agent): DISABLED (no -AgentCertificatePath/-AgentKeyPath given)" -ForegroundColor Yellow
}
if ($LocalLogSources) {
    Write-Host "  Sysmon log source:                        LOCAL (-LocalLogSources given -- remove it from the group agent.conf!)" -ForegroundColor Yellow
} else {
    Write-Host "  Sysmon log source:                        manager group config (windows-agents/agent.conf)"
}
Write-Host ""

# ---------- 1. connectivity pre-check ----------
$portChecks = @(
    @{ Target = $RegistrationServer; Port = $RegPort;   Label = "registration" },
    @{ Target = $Manager;            Port = $EventPort; Label = "event" }
)
foreach ($check in $portChecks) {
    Write-Step "Checking connectivity to $($check.Label) port ($($check.Target):$($check.Port))..."
    $portTest = Test-NetConnection -ComputerName $check.Target -Port $check.Port -WarningAction SilentlyContinue
    if (-not $portTest.TcpTestSucceeded) {
        Fail "cannot reach $($check.Target) on port $($check.Port) ($($check.Label) port). Check firewall rules and that the corresponding Wazuh service is running/reachable."
    }
    Write-Host "   OK: port $($check.Port) is reachable." -ForegroundColor Green
}
Write-Host ""

# ---------- 2. install the agent if not already installed ----------
$alreadyInstalled = (Test-Path $InstallDir) -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)

if (-not $alreadyInstalled) {
    Write-Step "wazuh-agent not installed. Downloading and installing version $Version..."

    try {
        Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing
    } catch {
        Fail "failed to download MSI from $MsiUrl - $($_.Exception.Message)"
    }

    $msiArgs = @(
        "/i", "`"$MsiPath`"",
        "/q",
        "WAZUH_MANAGER=`"$Manager`"",
        "WAZUH_REGISTRATION_SERVER=`"$RegistrationServer`"",
        "WAZUH_REGISTRATION_PASSWORD=`"$RegistrationPassword`"",
        "WAZUH_AGENT_NAME=`"$AgentName`""
    )

    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        Fail "msiexec install failed with exit code $($proc.ExitCode)."
    }
    Write-Host "   Install completed." -ForegroundColor Green
} else {
    Write-Step "wazuh-agent already installed, skipping package install."
}
Write-Host ""

if (-not (Test-Path $InstallDir)) {
    Fail "install directory $InstallDir not found after install. Something went wrong."
}

# ---------- 3. install & configure Sysmon (this is the "Sysmon logs" baseline) ----------
if (-not $SkipSysmon) {
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) { $sysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }

    if (-not (Test-Path $SysmonDir)) {
        New-Item -ItemType Directory -Path $SysmonDir -Force | Out-Null
    }

    # Resolve which config to apply: a supplied file, or our built-in baseline.
    if ($SysmonConfigPath) {
        if (-not (Test-Path $SysmonConfigPath)) {
            Fail "Sysmon config not found at $SysmonConfigPath"
        }
        $activeSysmonConfig = $SysmonConfigPath
        Write-Step "Using supplied Sysmon config: $activeSysmonConfig"
    } else {
        $activeSysmonConfig = Join-Path $SysmonDir "sysmonconfig-baseline.xml"
        Write-Step "No -SysmonConfigPath given, writing built-in baseline Sysmon config..."
        Write-TextNoBom -Path $activeSysmonConfig -Text $DefaultSysmonConfig
    }

    if (-not $sysmonSvc) {
        Write-Step "Sysmon not installed. Downloading Sysmon..."
        try {
            Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $SysmonZipPath -UseBasicParsing
        } catch {
            Fail "failed to download Sysmon from $SysmonZipUrl - $($_.Exception.Message)"
        }
        Expand-Archive -Path $SysmonZipPath -DestinationPath $SysmonDir -Force

        Write-Step "Installing Sysmon with baseline config..."
        $sysmonProc = Start-Process -FilePath $SysmonExe -ArgumentList @("-accepteula", "-i", "`"$activeSysmonConfig`"") -Wait -PassThru -NoNewWindow
        if ($sysmonProc.ExitCode -ne 0) {
            Fail "Sysmon install failed with exit code $($sysmonProc.ExitCode)."
        }
        Write-Host "   Sysmon installed." -ForegroundColor Green
    } else {
        Write-Step "Sysmon already installed, re-applying baseline config (safe to re-run)..."
        $sysmonProc = Start-Process -FilePath $SysmonExe -ArgumentList @("-c", "`"$activeSysmonConfig`"") -Wait -PassThru -NoNewWindow
        if ($sysmonProc.ExitCode -ne 0) {
            Fail "Sysmon config update failed with exit code $($sysmonProc.ExitCode)."
        }
        Write-Host "   Sysmon config updated." -ForegroundColor Green
    }

    # Reading the Sysmon channel is normally the group config's job. Declaring
    # the same channel locally AND in shared agent.conf makes logcollector
    # open two readers for it, so every Sysmon event lands twice. Opt in with
    # -LocalLogSources only if you've removed it from windows-agents/agent.conf.
    if ($LocalLogSources) {
        if (Test-Path $OssecConf) {
            $ossecContent = Get-Content $OssecConf -Raw
            if ($ossecContent -notmatch "Microsoft-Windows-Sysmon/Operational") {
                Write-Step "Adding Sysmon localfile block to ossec.conf..."
                $sysmonBlock = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
                # MatchEvaluator rather than -replace: the replacement text is
                # taken literally, so `$` sequences in it are never treated as
                # capture-group references.
                $updatedContent = [regex]::Replace(
                    $ossecContent, '</ossec_config>',
                    { param($m) "$sysmonBlock`r`n</ossec_config>" }, 1)
                Write-TextNoBom -Path $OssecConf -Text $updatedContent
                Write-Host "   Added." -ForegroundColor Green
            } else {
                Write-Step "Sysmon localfile block already present in ossec.conf, skipping."
            }
        }
    } else {
        Write-Step "Sysmon channel left to the manager group config (pass -LocalLogSources to write it locally)."
    }
} else {
    Write-Step "Skipping Sysmon (-SkipSysmon passed)."
}
Write-Host ""

# ---------- 4. write the local <client> section ----------
# <client> cannot live in the manager's shared agent.conf: it's the section
# that tells the agent which manager to contact and how, so it must already
# be in place before the agent can pull shared config. Centralized config
# only supports localfile / syscheck / rootcheck / sca / wodle /
# active-response / labels / client_buffer.
function Set-WazuhClientBlock {
    param(
        [Parameter(Mandatory)][string]$ConfPath,
        [Parameter(Mandatory)][string]$Manager,
        [string]$ManagerCaKeepPath = "C:\ProgramData\WazuhBootstrap\manager-ca.pem",
        [int]$Port = 1514
    )

    if (-not (Test-Path $ConfPath)) { Fail "ossec.conf not found at $ConfPath" }

    # <enrollment><enabled>no</enabled> is deliberate: the manager enforces
    # ssl_agent_ca and this host no longer holds a client cert, so any
    # self-initiated re-enrollment would fail the TLS handshake and just
    # spam the log. Repair happens via the Intune detection script re-running
    # the installer, which fetches a fresh cert.
    $block = @"
  <client>
    <server>
      <address>$Manager</address>
      <port>$Port</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <enrollment>
      <enabled>no</enabled>
      <server_ca_path>$ManagerCaKeepPath</server_ca_path>
    </enrollment>
  </client>
"@

    $backup = "$ConfPath.bak.$PID"
    Copy-Item $ConfPath $backup -Force

    $content = Get-Content $ConfPath -Raw

    # (?s) so . matches newlines. '<client>' with the closing bracket so we
    # don't accidentally match <client_buffer>.
    $pattern = '(?s)<client>.*?</client>'
    if ([regex]::IsMatch($content, $pattern)) {
        # MatchEvaluator, not -replace: the replacement text contains
        # Windows paths and $-sequences that .NET would otherwise treat
        # as capture-group references.
        $content = [regex]::Replace($content, $pattern, { param($m) $block }, 1)
    } else {
        $content = [regex]::Replace($content, '</ossec_config>', { param($m) "$block`r`n</ossec_config>" }, 1)
    }

    Write-TextNoBom -Path $ConfPath -Text $content
    Write-Step "Wrote <client> block (manager ${Manager}:${Port}) to ossec.conf"
    return $backup
}

# Restore the pre-edit ossec.conf. Used when the agent won't come up, so a
# bad edit doesn't leave a previously working host with a dead agent.
function Restore-OssecConf {
    if ($script:confBackup -and (Test-Path $script:confBackup)) {
        Write-Host "         Restoring the previous ossec.conf." -ForegroundColor Yellow
        Move-Item $script:confBackup $OssecConf -Force
        $script:confBackup = $null
        Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
}

$confBackup = Set-WazuhClientBlock -ConfPath $OssecConf -Manager $Manager -Port $EventPort

# ---------- 5. enroll (re-enroll even if already installed) ----------
Write-Step "Enrolling agent with ${RegistrationServer}:$RegPort (group: $AgentGroup) ..."

if (-not (Test-Path $AgentAuthExe)) {
    Fail "agent-auth.exe not found at $AgentAuthExe. Is the agent installed correctly?"
}

# We have to clear client.keys before calling agent-auth.exe -- otherwise it
# sees a key already present and just skips re-enrollment. But if we clear it
# and agent-auth.exe then fails (bad password this run, network blip, authd
# hiccup), we'd leave a PREVIOUSLY WORKING agent with no key at all, turning
# a routine re-run into an outage for an agent that was fine before we
# touched it. So: back up the existing key first, and restore it if
# enrollment fails.
$keyBackup = $null
if ((Test-Path $ClientKeys) -and (Get-Item $ClientKeys).Length -gt 0) {
    $keyBackup = "$ClientKeys.bak.$PID"
    Copy-Item $ClientKeys $keyBackup -Force
}
if (Test-Path $ClientKeys) {
    Clear-Content $ClientKeys -ErrorAction SilentlyContinue
}

$authArgs = @(
    "-m", $RegistrationServer,
    "-p", $RegPort,
    "-A", $AgentName,
    "-P", $RegistrationPassword,
    "-G", $AgentGroup
)
if ($ManagerCaPath) {
    $authArgs += @("-v", $ManagerCaPath)
}
if ($AgentCertificatePath) {
    $authArgs += @("-x", $AgentCertificatePath, "-k", $AgentKeyPath)
}

$authProc = Start-Process -FilePath $AgentAuthExe -ArgumentList $authArgs -Wait -PassThru -NoNewWindow
if ($authProc.ExitCode -ne 0) {
    if ($keyBackup) {
        Write-Host "         Restoring the previous client.keys so this agent isn't left with no key at all." -ForegroundColor Yellow
        Move-Item $keyBackup $ClientKeys -Force
    }
    Restore-OssecConf
    Fail "agent-auth.exe exited with code $($authProc.ExitCode). Check $OssecLog for the reason (bad password, connection refused, TLS error, cert verification failure, etc.)."
}
if ($keyBackup -and (Test-Path $keyBackup)) {
    Remove-Item $keyBackup -Force
}
Write-Host ""

# ---------- 6. verify a key was actually written ----------
if (-not (Test-Path $ClientKeys) -or (Get-Item $ClientKeys).Length -eq 0) {
    Fail "enrollment reported success but $ClientKeys is still empty."
}
Write-Step "Enrollment key written:"
Get-Content $ClientKeys
Write-Host ""

# ---------- 7. restart and verify connection ----------
Write-Step "Restarting $ServiceName..."
try { Restart-Service -Name $ServiceName -Force }
catch {
    Restore-OssecConf
    Fail "failed to restart service $ServiceName - $($_.Exception.Message)"
}

# Restart-Service returns once the service reports started. A malformed
# ossec.conf typically lets the agent start and then exit a moment later, so
# the backup has to survive until after this check -- deleting it any earlier
# leaves nothing to roll back to.
Start-Sleep -Seconds 5

$svc = Get-Service -Name $ServiceName
if ($svc.Status -ne "Running") {
    Restore-OssecConf
    Fail "$ServiceName started then stopped (status: $($svc.Status)) -- most likely a bad ossec.conf."
}

# Only now is it safe to drop the backup.
if ($confBackup -and (Test-Path $confBackup)) { Remove-Item $confBackup -Force }
$confBackup = $null

Write-Step "Service is running. Checking log for connection confirmation..."

$connected = $false
for ($i = 0; $i -lt 8; $i++) {
    Start-Sleep -Seconds 2
    if (Test-Path $OssecLog) {
        $recentLog = Get-Content $OssecLog -Tail 50
        if ($recentLog -match "Connected to the server") {
            $connected = $true
            break
        }
    }
}

if ($connected) {
    Write-Host "SUCCESS: agent enrolled and connected to $Manager." -ForegroundColor Green
} else {
    Write-Host "WARNING: 'Connected to the server' not seen in the last 50 log lines after 16s." -ForegroundColor Yellow
    Write-Host "         On a multi-node cluster this is often just the agent landing on a worker"
    Write-Host "         before the master has replicated its key -- it usually resolves within a minute."
    Write-Host "         Tail the log to confirm manually:"
    Write-Host "           Get-Content `"$OssecLog`" -Wait -Tail 20"
}

Write-Host ""
Write-Host "== Done ==" -ForegroundColor Yellow