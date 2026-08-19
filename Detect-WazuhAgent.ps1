<#
    Intune Win32 app detection script.

    Intune's contract: exit 0 AND write something to stdout  => installed.
    Anything else => not installed, so Intune re-runs the installer.

    That re-run is the self-healing mechanism: if the service is wiped,
    client.keys is emptied, or Sysmon is uninstalled, the next detection
    cycle (~every 8h, or on demand) pulls a fresh cert and re-enrolls.

    -------------------------------------------------------------------------
    SCOPE: WHAT BELONGS IN THIS FILE AND WHAT DOES NOT

    Failing detection here costs a FULL RE-ENROLLMENT: Intune re-runs
    Install-WazuhAgent.ps1, which fetches fresh certificate material, runs
    wazuh_enroll.ps1, and restarts the service. That is the right response to
    "the agent is gone". It is the wrong response to "a registry DWORD is 0" --
    it pulls a secret onto disk to fix something that needs no secret, and it
    does so on a repeating schedule.

    So this script checks IDENTITY AND PRESENCE only:
      - is the agent installed, enrolled, and running
      - is Sysmon installed and running
      - is the bootstrap revision current

    Audit settings (4688, 4104, remote_commands) are checked by
    Configure-EndpointAuditing.ps1 -Check, deployed as an Intune Remediation.
    Failing THAT re-runs only the auditing script -- no certificates involved.

    Set $CheckAuditSettings = $true below ONLY if you are not running the
    Remediation. Two loops measuring the same keys is the same mistake
    Install-EnforcementTask already guards against: whichever fires first
    silently repairs what the other is meant to be reporting on.
    -------------------------------------------------------------------------

    Deliberately NOT checked here: whether the agent is currently connected
    to the manager. A laptop off the VPN is disconnected but perfectly well
    installed -- failing detection on that would reinstall the agent every
    8 hours for every remote user. Use the Wazuh dashboard (or a Proactive
    Remediation) to chase disconnected agents instead.
#>

$ErrorActionPreference = "SilentlyContinue"

$InstallDir   = "C:\Program Files (x86)\ossec-agent"
$ClientKeys   = Join-Path $InstallDir "client.keys"
$LocalOptions = Join-Path $InstallDir "local_internal_options.conf"
$MarkerKey    = "HKLM:\SOFTWARE\Wazuh\Bootstrap"

$MinRevision  = 1     # bump this and the Intune app version to force re-run

# Must track $AuditRev in Configure-EndpointAuditing.ps1. Only consulted when
# $CheckAuditSettings is $true -- but keep it accurate either way, because the
# Remediation detection reads the same value.
$MinAuditRev  = 2     # rev 2: added remote_commands enforcement

# See SCOPE above. Leave $false when Configure-EndpointAuditing.ps1 -Check is
# deployed as a Remediation.
$CheckAuditSettings = $false

$problems = @()

# --------------------------------------------------------- presence ----
$svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $svc)                        { $problems += "WazuhSvc service missing" }
elseif ($svc.Status -ne "Running")    { $problems += "WazuhSvc not running ($($svc.Status))" }

if (-not (Test-Path $ClientKeys))     { $problems += "client.keys missing" }
elseif ((Get-Item $ClientKeys).Length -eq 0) { $problems += "client.keys empty (not enrolled)" }

$sysmon = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $sysmon) { $sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
if (-not $sysmon)                     { $problems += "Sysmon service missing" }
elseif ($sysmon.Status -ne "Running") { $problems += "Sysmon not running" }

# ----------------------------------------------------------- marker ----
# Separate ifs, not an elseif chain. Chained, a stale BootstrapRev masks the
# AuditRev result, so the portal shows one reason when both are wrong and the
# second only appears after the first is fixed.
$marker = Get-ItemProperty -Path $MarkerKey -ErrorAction SilentlyContinue
if (-not $marker) {
    $problems += "bootstrap marker missing"
} else {
    if ([int]($marker.BootstrapRev) -lt $MinRevision) { $problems += "bootstrap revision too old" }
    if ($CheckAuditSettings -and [int]($marker.AuditRev) -lt $MinAuditRev) {
        $problems += "audit config revision too old"
    }
}

# ---------------------------------------------- audit (opt-in only) ----
if ($CheckAuditSettings) {

    # Registry rather than shelling out to auditpol: keeps this well inside
    # Intune's 60s detection budget.
    $cmdLine = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
                                -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    if (-not $cmdLine -or $cmdLine.ProcessCreationIncludeCmdLine_Enabled -ne 1) {
        $problems += "4688 command-line logging disabled"
    }

    # agent.conf has collected the PowerShell channel since Sprint 2, but
    # without this the channel is nearly empty -- collection looks healthy
    # while carrying nothing.
    $sbl = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                            -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    if (-not $sbl -or $sbl.EnableScriptBlockLogging -ne 1) {
        $problems += "PowerShell script block logging disabled"
    }

    # remote_commands. Without this, <localfile><command> stanzas pushed from
    # the shared agent.conf are accepted and never executed -- the agent stays
    # healthy and only the command-based telemetry goes quiet. This is the
    # netstat gap; it was invisible because nothing measured it.
    #
    # Anchored to an ACTIVE assignment: an unanchored match also hits the
    # "# logcollector.remote_commands=0" comment the MSI ships and would
    # report configured while the setting is off.
    if (Test-Path $LocalOptions) {
        $lio = Get-Content -Path $LocalOptions -ErrorAction SilentlyContinue
        foreach ($key in @("logcollector.remote_commands", "wazuh_command.remote_commands")) {
            $pattern = '^\s*' + [regex]::Escape($key) + '\s*=\s*1\s*$'
            if (-not ($lio | Where-Object { $_ -match $pattern })) {
                $problems += "$key not enabled"
            }
        }
    } else {
        $problems += "local_internal_options.conf missing"
    }
}

# ------------------------------------------------------------ verdict ----
if ($problems.Count -gt 0) {
    # No stdout on the not-detected path.
    exit 1
}

$auditNote = if ($CheckAuditSettings) { ", audit rev $($marker.AuditRev)" } else { "" }
Write-Output "Wazuh agent enrolled as $($marker.AgentName) against $($marker.Manager) (rev $($marker.BootstrapRev)$auditNote)"
exit 0