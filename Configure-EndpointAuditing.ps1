#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sprint 3, Phase 3: Windows command-line auditing configuration.

.DESCRIPTION
    Enables the telemetry that Sysmon and agent.conf cannot turn on by
    themselves:

      1. Security 4688 process creation, WITH the command line
      2. PowerShell script block logging (EID 4104) and module logging (4103)
      3. Optional: re-assert an already-installed Sysmon's config (drift only)

    DELIBERATELY SEPARATE FROM Install-WazuhAgent.ps1, for the same reason
    wazuh_audit_setup.sh is separate from wazuh_bootstrap.sh on Linux:
    nothing here needs a secret. That means it can run against hosts you
    already enrolled without re-bootstrapping them, and it can be used
    directly as an Intune Remediation script -- neither of which is possible
    for anything that touches certificate material.

    DELIBERATELY NOT IN Detect-WazuhAgent.ps1. An Intune detection script
    must be read-only:
      - it runs on a tight loop and after every install attempt
      - Intune kills it at 60 seconds
      - a detection script that repairs what it measures always reports
        "installed", so a genuinely broken host never surfaces in reporting
    Detect-WazuhAgent.ps1 should CHECK these settings; this script FIXES them.
    That split is what makes the healing loop observable.

    WHAT THIS DOES NOT DO: install Sysmon. That stays in wazuh_enroll.ps1,
    which already downloads it, installs it, and applies -SysmonConfigPath
    from bootstrap.json's SysmonConfigFile. Duplicating it here would mean
    two places to change the version.

.PARAMETER Check
    Report state and exit. Changes nothing. Exit 0 = compliant,
    exit 1 = needs remediation. This is the Intune Remediations detection
    contract, so the same file serves both roles.

.PARAMETER SysmonConfigPath
    If given and Sysmon is already installed, re-apply this config. Covers
    config drift (someone ran `sysmon -c` with something else). Does not
    install Sysmon if absent.

.PARAMETER InstallTask
    Install a scheduled task for daily drift enforcement. Auto-skipped on
    Intune-managed hosts -- see -Force. Two enforcement loops fighting over
    the same registry keys makes Intune's compliance reporting a lie: the
    task quietly repairs what Intune is supposed to be measuring.

.PARAMETER Force
    Install the scheduled task even on an Intune-managed host. Only for a
    host you are deliberately excluding from the Remediations policy.

.PARAMETER SkipProcessCreation
    Do not enable Security 4688. Sysmon EID 1 already covers process
    creation more richly (hashes, parent GUID, integrity level). Use this
    where the duplicate volume is not worth the redundancy -- but see the
    note in the code before you decide.

.NOTES
    Log: C:\ProgramData\WazuhBootstrap\auditing.log
#>

[CmdletBinding()]
param(
    [switch]$Check,
    [string]$SysmonConfigPath,
    [switch]$InstallTask,
    [switch]$Force,
    [switch]$SkipProcessCreation
)

$ErrorActionPreference = "Stop"

$LogDir      = "C:\ProgramData\WazuhBootstrap"
$LogFile     = Join-Path $LogDir "auditing.log"
$MarkerKey   = "HKLM:\SOFTWARE\Wazuh\Bootstrap"
$TaskName    = "Wazuh-EndpointAuditing"
$SelfPath    = Join-Path $LogDir "Configure-EndpointAuditing.ps1"

# Bump this when you change what the script enforces. Detect-WazuhAgent.ps1
# compares against it, so bumping forces a re-run across the fleet.
$AuditRev    = 1

# Process Creation subcategory. The GUID is used rather than the display
# name because the name is localized -- "Process Creation" does not exist on
# a French or Japanese install, and auditpol silently matches nothing.
$SubcatProcessCreation = "{0CCE922B-69AE-11D9-BED3-505054503030}"

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$script:Problems = @()
$script:Changed  = 0

function Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    # UTF8 for the same reason Install-WazuhAgent.ps1 does it: Add-Content
    # defaults to ASCII in PS 5.1, and mixing encodings in one file renders
    # half of it as mojibake.
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Host $line
}
function Problem { param([string]$m) $script:Problems += $m; Log $m "WARN" }

# ---------------------------------------------------------------------------
# Registry helper. Compare-then-write so a daily task run that changes
# nothing is genuinely a no-op and $script:Changed stays a truthful signal.
# ---------------------------------------------------------------------------
function Set-PolicyValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord",
        [string]$Description
    )

    $current = $null
    if (Test-Path $Path) {
        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($prop) { $current = $prop.$Name }
    }

    if ($current -eq $Value) {
        Log "OK: $Description already set."
        return $true
    }

    if ($Check) {
        Problem "$Description is '$current', expected '$Value'."
        return $false
    }

    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    Log "SET: $Description -> $Value"
    $script:Changed++
    return $true
}

# ---------------------------------------------------------------------------
# 1. Security 4688 with command line
# ---------------------------------------------------------------------------
# 4688 without ProcessCreationIncludeCmdLine_Enabled logs that notepad.exe
# started and nothing about what it was told to do -- which is close to
# useless for detection. Both halves are required or neither is worth having.
#
# On overlap with Sysmon EID 1: they cover the same ground and running both
# roughly doubles process-event volume. Sysmon is strictly richer. 4688 is
# kept anyway because it comes from a different producer -- it is what still
# reports process creation after an attacker stops the Sysmon service, and
# EID 1 going silent while 4688 keeps flowing is itself the detection.
function Set-ProcessCreationAuditing {
    if ($SkipProcessCreation) {
        Log "Skipping Security 4688 (-SkipProcessCreation)."
        return
    }

    Set-PolicyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
                    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 `
                    -Description "4688 command-line inclusion" | Out-Null

    # auditpol has no registry equivalent that is safe to write directly.
    $raw = & auditpol.exe /get /subcategory:"$SubcatProcessCreation" /r 2>$null
    $enabled = $false
    if ($LASTEXITCODE -eq 0 -and $raw) {
        # CSV: Machine Name,Policy Target,Subcategory,Subcategory GUID,
        #      Inclusion Setting,Exclusion Setting
        $row = $raw | Select-Object -Skip 1 | Where-Object { $_ -match '\S' } | Select-Object -First 1
        if ($row) {
            $fields = $row -split ','
            if ($fields.Count -ge 5) {
                $setting = $fields[4].Trim('" ')
                # Localization caveat: "Success" is English-only. On a
                # localized Windows this check can false-negative, and the
                # cost of that is one extra idempotent auditpol /set call.
                # Preferred over false-POSITIVE, which would leave 4688 off
                # while reporting compliant.
                $enabled = ($setting -match 'Success')
                Log "auditpol Process Creation inclusion setting: '$setting'"
            }
        }
    }

    if ($enabled) {
        Log "OK: Process Creation auditing already enabled."
        return
    }

    if ($Check) {
        Problem "auditpol Process Creation success auditing is not enabled."
        return
    }

    & auditpol.exe /set /subcategory:"$SubcatProcessCreation" /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Problem "auditpol failed to enable Process Creation (exit $LASTEXITCODE)."
    } else {
        Log "SET: auditpol Process Creation success auditing enabled."
        $script:Changed++
    }
}

# ---------------------------------------------------------------------------
# 2. PowerShell logging
# ---------------------------------------------------------------------------
# agent.conf has collected Microsoft-Windows-PowerShell/Operational since
# Sprint 2, but that channel is nearly empty by default -- so the collection
# looked healthy while carrying almost nothing.
#
# EID 4104 logs the DEOBFUSCATED script block. Base64-encoded and
# string-concatenated payloads are recorded in their decoded form, which is
# what makes this the highest-value single Windows setting in Sprint 3.
function Set-PowerShellLogging {
    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                    -Name "EnableScriptBlockLogging" -Value 1 `
                    -Description "PowerShell script block logging (4104)" | Out-Null

    # Deliberately NOT enabling EnableScriptBlockInvocationLogging: it adds a
    # start/stop pair around every block and multiplies volume for very
    # little extra detection value.

    Set-PolicyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
                    -Name "EnableModuleLogging" -Value 1 `
                    -Description "PowerShell module logging (4103)" | Out-Null

    # Module logging does nothing without a module list. '*' means all.
    #
    # The property is literally named "*", which rules out Get/Set-ItemProperty:
    # their -Name parameter accepts wildcards, so -Name "*" means "every
    # property" rather than "the property called star". Reading would return
    # the whole key and writing could hit unrelated values. The .NET registry
    # API takes the name literally, so use it.
    $mnSubKey = "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    $currentAll = $null
    try {
        $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($mnSubKey, $false)
        if ($rk) { $currentAll = $rk.GetValue("*"); $rk.Close() }
    } catch { }

    if ($currentAll -eq "*") {
        Log "OK: PowerShell module list already '*'."
    } elseif ($Check) {
        Problem "PowerShell ModuleNames '*' not set (module logging inert without it)."
    } else {
        $rk = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($mnSubKey)
        $rk.SetValue("*", "*", [Microsoft.Win32.RegistryValueKind]::String)
        $rk.Close()
        Log "SET: PowerShell module list -> *"
        $script:Changed++
    }

    # Transcription is intentionally left off. It writes .txt files per
    # session, needs its own storage, retention and collection path, and
    # largely duplicates 4104. Excluded by decision, not by oversight.
}

# ---------------------------------------------------------------------------
# 3. Sysmon config drift (re-apply only; install stays in wazuh_enroll.ps1)
# ---------------------------------------------------------------------------
function Set-SysmonConfig {
    if (-not $SysmonConfigPath) { return }

    if (-not (Test-Path $SysmonConfigPath)) {
        Problem "Sysmon config not found at $SysmonConfigPath"
        return
    }

    # $env:ProgramFiles resolves to 'Program Files (x86)' in a 32-bit
    # PowerShell host, which would miss Sysmon entirely. Hard-code the
    # 64-bit path rather than depend on the host's bitness.
    $sysmonExe = "C:\Program Files\Sysmon\Sysmon64.exe"
    if (-not (Test-Path $sysmonExe)) {
        Log "Sysmon not installed here; skipping config re-apply. (Install is wazuh_enroll.ps1's job.)" "WARN"
        return
    }

    $hash = (Get-FileHash -Path $SysmonConfigPath -Algorithm SHA256).Hash
    $applied = $null
    $m = Get-ItemProperty -Path $MarkerKey -ErrorAction SilentlyContinue
    if ($m) { $applied = $m.SysmonConfigHash }

    if ($applied -eq $hash) {
        Log "OK: Sysmon config hash matches what was last applied."
        return
    }

    if ($Check) {
        Problem "Sysmon config on disk does not match last-applied hash."
        return
    }

    Log "Applying Sysmon config from $SysmonConfigPath"
    $p = Start-Process -FilePath $sysmonExe -ArgumentList @("-c", "`"$SysmonConfigPath`"") `
                       -Wait -PassThru -NoNewWindow
    if ($p.ExitCode -ne 0) {
        Problem "Sysmon config apply failed (exit $($p.ExitCode))."
        return
    }
    New-Item -Path $MarkerKey -Force | Out-Null
    Set-ItemProperty -Path $MarkerKey -Name "SysmonConfigHash" -Value $hash -Force
    Log "SET: Sysmon config applied and hash recorded."
    $script:Changed++

    # Known limitation: this detects "the packaged config changed and was not
    # applied". It does NOT detect someone manually running `sysmon -c` with
    # a different file, because Sysmon does not expose the config it is
    # currently running in a form worth parsing.
}

# ---------------------------------------------------------------------------
# 4. Scheduled task -- for hosts Intune does not manage
# ---------------------------------------------------------------------------
function Test-IntuneManaged {
    if (Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue) { return $true }
    $enrollments = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue
    foreach ($e in $enrollments) {
        $p = Get-ItemProperty -Path $e.PSPath -ErrorAction SilentlyContinue
        if ($p.EnrollmentState -eq 1 -and $p.ProviderID -eq "MS DM Server") { return $true }
    }
    return $false
}

function Install-EnforcementTask {
    if (-not $InstallTask) { return }

    if ((Test-IntuneManaged) -and (-not $Force)) {
        Log "Intune-managed host detected -- NOT installing the scheduled task." "WARN"
        Log "  Use an Intune Remediation instead. Two enforcement loops writing the" "WARN"
        Log "  same keys makes Intune compliance reporting untrustworthy: the task" "WARN"
        Log "  silently repairs what Intune is meant to be measuring. Override with -Force." "WARN"
        return
    }

    if ($Check) { Log "Would install scheduled task '$TaskName'."; return }

    if ($PSCommandPath -and ($PSCommandPath -ne $SelfPath)) {
        Copy-Item -Path $PSCommandPath -Destination $SelfPath -Force
        Log "Copied self to $SelfPath"
    }

    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$SelfPath`""
    if ($SysmonConfigPath)   { $argList += " -SysmonConfigPath `"$SysmonConfigPath`"" }
    if ($SkipProcessCreation){ $argList += " -SkipProcessCreation" }
    # -InstallTask is not passed: the task would otherwise reinstall itself
    # on every run.

    $action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argList
    $trigger1  = New-ScheduledTaskTrigger -Daily -At "03:00"
    $trigger2  = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable `
                    -RandomDelay (New-TimeSpan -Minutes 30) `
                    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
                    -DontStopOnIdleEnd

    Register-ScheduledTask -TaskName $TaskName -Action $action `
        -Trigger @($trigger1, $trigger2) -Principal $principal `
        -Settings $settings -Force | Out-Null

    Log "Scheduled task '$TaskName' installed (daily 03:00 +/-30min, and at startup)."
}

# ---------------------------------------------------------------------------
Log "=== Endpoint auditing configuration (rev $AuditRev, mode: $(if($Check){'CHECK'}else{'APPLY'})) ==="

Set-ProcessCreationAuditing
Set-PowerShellLogging
Set-SysmonConfig
Install-EnforcementTask

if ($Check) {
    if ($script:Problems.Count -gt 0) {
        # stdout on the non-compliant path: Intune Remediations surfaces the
        # detection script's output in the portal, which is where you want to
        # read WHY a host was remediated.
        Write-Output ("Endpoint auditing non-compliant: " + ($script:Problems -join "; "))
        exit 1
    }
    Write-Output "Endpoint auditing compliant (rev $AuditRev)"
    exit 0
}

if ($script:Problems.Count -gt 0) {
    Log ("Completed with problems: " + ($script:Problems -join "; ")) "ERROR"
    exit 1
}

# Marker last, so it is only written on a clean run. Detect-WazuhAgent.ps1
# reads AuditRev; a partial run must not look complete to the detection loop.
New-Item -Path $MarkerKey -Force | Out-Null
Set-ItemProperty -Path $MarkerKey -Name "AuditRev"       -Value $AuditRev -Force
Set-ItemProperty -Path $MarkerKey -Name "AuditAppliedUtc" -Value ((Get-Date).ToUniversalTime().ToString("o")) -Force

Log "=== Done. $($script:Changed) setting(s) changed. ==="

if ($script:Changed -gt 0) {
    Write-Host ""
    Write-Host "Note: PowerShell logging applies to NEW sessions. Open a fresh" -ForegroundColor Yellow
    Write-Host "      console before testing. 4688 applies immediately." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Test:  powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA=" -ForegroundColor Cyan
    Write-Host "  Expect: EID 4104 in Microsoft-Windows-PowerShell/Operational"
    Write-Host "          showing the DECODED 'Write-Host hi'"
}
exit 0
