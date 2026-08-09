<#
    Intune Win32 app detection script.

    Intune's contract: exit 0 AND write something to stdout  => installed.
    Anything else => not installed, so Intune re-runs the installer.

    That re-run is the self-healing mechanism: if the service is wiped,
    client.keys is emptied, or Sysmon is uninstalled, the next detection
    cycle (~every 8h, or on demand) pulls a fresh cert and re-enrolls.

    Deliberately NOT checked here: whether the agent is currently connected
    to the manager. A laptop off the VPN is disconnected but perfectly well
    installed -- failing detection on that would reinstall the agent every
    8 hours for every remote user. Use the Wazuh dashboard (or a Proactive
    Remediation) to chase disconnected agents instead.
#>

$ErrorActionPreference = "SilentlyContinue"

$InstallDir = "C:\Program Files (x86)\ossec-agent"
$ClientKeys = Join-Path $InstallDir "client.keys"
$MarkerKey  = "HKLM:\SOFTWARE\Wazuh\Bootstrap"
$MinRevision = 1     # bump this and the Intune app version to force re-run

$problems = @()

$svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $svc)                        { $problems += "WazuhSvc service missing" }
elseif ($svc.Status -ne "Running")    { $problems += "WazuhSvc not running ($($svc.Status))" }

if (-not (Test-Path $ClientKeys))     { $problems += "client.keys missing" }
elseif ((Get-Item $ClientKeys).Length -eq 0) { $problems += "client.keys empty (not enrolled)" }

$sysmon = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $sysmon) { $sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
if (-not $sysmon)                     { $problems += "Sysmon service missing" }
elseif ($sysmon.Status -ne "Running") { $problems += "Sysmon not running" }

$marker = Get-ItemProperty -Path $MarkerKey -ErrorAction SilentlyContinue
if (-not $marker)                     { $problems += "bootstrap marker missing" }
elseif ([int]($marker.BootstrapRev) -lt $MinRevision) { $problems += "bootstrap revision too old" }

if ($problems.Count -gt 0) {
    # No stdout on the not-detected path.
    exit 1
}

Write-Output "Wazuh agent enrolled as $($marker.AgentName) against $($marker.Manager) (rev $($marker.BootstrapRev))"
exit 0
