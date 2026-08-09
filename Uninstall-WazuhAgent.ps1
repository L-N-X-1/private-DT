#Requires -RunAsAdministrator
<#
    Intune Win32 app uninstall command.
    Removes the agent and Sysmon, and clears the detection marker.

    Note: this does not remove the agent record from the manager. Do that
    from the Wazuh dashboard or API, or let <purge>yes</purge> plus the
    <force> block reclaim the name when the device is rebuilt.
#>
$ErrorActionPreference = "SilentlyContinue"

$log = "C:\ProgramData\WazuhBootstrap\uninstall.log"
New-Item -ItemType Directory -Path (Split-Path $log) -Force | Out-Null
function Log($m) { "$(Get-Date -Format s) $m" | Tee-Object -FilePath $log -Append }

Log "Stopping services"
Stop-Service WazuhSvc -Force
Stop-Service Sysmon64 -Force

Log "Uninstalling Wazuh agent MSI"
$product = Get-CimInstance Win32_Product -Filter "Name LIKE 'Wazuh Agent%'"
if ($product) {
    Start-Process msiexec.exe -ArgumentList @("/x", $product.IdentifyingNumber, "/qn", "/norestart") -Wait -NoNewWindow
}

$sysmonExe = "C:\Program Files\Sysmon\Sysmon64.exe"
if (Test-Path $sysmonExe) {
    Log "Uninstalling Sysmon"
    Start-Process $sysmonExe -ArgumentList @("-u", "force") -Wait -NoNewWindow
}

Remove-Item "HKLM:\SOFTWARE\Wazuh\Bootstrap" -Recurse -Force
Remove-Item "C:\ProgramData\WazuhBootstrap" -Recurse -Force
Log "Done"
exit 0
