#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Intune Win32 app wrapper: fetch enrollment material from wazuh-cert-issuer,
    hand it to wazuh_enroll.ps1, then destroy it.

.DESCRIPTION
    Ships inside the .intunewin alongside wazuh_enroll.ps1 and bootstrap.json.
    Runs as SYSTEM. Sequence:

      1. Read bootstrap.json (issuer URL, bootstrap token, TLS pin)
      2. POST /v1/agent-bootstrap  -> cert, key, manager CA, enrollment password
      3. Write them to a SYSTEM-only ACL'd temp dir
      4. Call wazuh_enroll.ps1 with -ManagerCaPath/-AgentCertificatePath/-AgentKeyPath
      5. Shred the temp dir and drop a detection marker in the registry

    The agent cert exists on disk for the length of one enrollment. After that
    the agent authenticates with the key in client.keys, so there is nothing
    left on the endpoint for an attacker to steal and replay.

.NOTES
    Log: C:\ProgramData\WazuhBootstrap\install.log
    Exit 0 = success. Any non-zero exit makes Intune report a failed install.
#>

[CmdletBinding()]
param(
    [string]$BootstrapConfig,
    [string]$AgentName       = $env:COMPUTERNAME,
    [switch]$KeepCertOnDisk      # only for troubleshooting; leaves the key behind
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LogDir  = "C:\ProgramData\WazuhBootstrap"
$LogFile = Join-Path $LogDir "install.log"
$MarkerKey = "HKLM:\SOFTWARE\Wazuh\Bootstrap"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $BootstrapConfig) { $BootstrapConfig = Join-Path $ScriptDir "bootstrap.json" }

function Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $LogFile -Value $line
    Write-Host $line
}

function Die {
    param([string]$Message, [int]$Code = 1)
    Log $Message "ERROR"
    exit $Code
}

Log "=== Wazuh bootstrap starting on $AgentName ==="

# ---------------------------------------------------------------- config ----
if (-not (Test-Path $BootstrapConfig)) { Die "bootstrap.json not found at $BootstrapConfig" }
$cfg = Get-Content $BootstrapConfig -Raw | ConvertFrom-Json

foreach ($required in @("IssuerUrl", "BootstrapToken")) {
    if (-not $cfg.$required) { Die "bootstrap.json is missing '$required'" }
}
$issuerUrl = $cfg.IssuerUrl.TrimEnd("/") + "/v1/agent-bootstrap"
$agentGroup = if ($cfg.AgentGroup) { $cfg.AgentGroup } else { "windows-agents" }

# ------------------------------------------------------------ TLS pinning ----
# The issuer's cert is signed by agents-rootCA, which Windows has never heard
# of. Rather than dumping a private CA into the machine trust store (which
# would make every cert it ever signs trusted for every purpose), pin the
# expected SHA256 thumbprints and validate manually for this one call.
$pins = @()
if ($cfg.TlsPinsSha256) { $pins = @($cfg.TlsPinsSha256 | ForEach-Object { $_.ToUpper() -replace '[^0-9A-F]', '' }) }

$originalCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
if ($pins.Count -gt 0) {
    Log "Pinning issuer TLS to $($pins.Count) thumbprint(s)"
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($senderObj, $cert, $chain, $errors)
        $seen = @()
        if ($cert)  { $seen += ([Security.Cryptography.X509Certificates.X509Certificate2]$cert).GetCertHashString("SHA256") }
        if ($chain) { foreach ($el in $chain.ChainElements) { $seen += $el.Certificate.GetCertHashString("SHA256") } }
        foreach ($s in $seen) { if ($pins -contains $s.ToUpper()) { return $true } }
        return $false
    }
} else {
    Log "No TlsPinsSha256 in bootstrap.json -- relying on the machine trust store" "WARN"
}

# ----------------------------------------------------------- call issuer ----
$payload = @{ agent_name = $AgentName; platform = "windows" } | ConvertTo-Json -Compress
$resp = $null
$maxAttempts = 5

for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        Log "Requesting enrollment material from $issuerUrl (attempt $attempt/$maxAttempts)"
        $resp = Invoke-RestMethod -Uri $issuerUrl -Method Post `
            -Headers @{ Authorization = "Bearer $($cfg.BootstrapToken)" } `
            -ContentType "application/json" -Body $payload -TimeoutSec 30 -UseBasicParsing
        break
    } catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }

        # 4xx other than 429 will not fix themselves -- fail fast rather than
        # hammering the issuer with a token it has already rejected.
        if ($status -and $status -ne 429 -and $status -lt 500) {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
            Die "Issuer rejected the request with HTTP $status. Check the bootstrap token has not expired: $($_.Exception.Message)"
        }
        if ($attempt -eq $maxAttempts) {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
            Die "Could not reach the issuer after $maxAttempts attempts: $($_.Exception.Message)"
        }
        $backoff = [Math]::Pow(2, $attempt) * 3
        Log "Attempt $attempt failed ($($_.Exception.Message)). Retrying in ${backoff}s" "WARN"
        Start-Sleep -Seconds $backoff
    }
}
[Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback

if (-not $resp.cert_pem_b64) { Die "Issuer response did not contain a certificate" }
Log "Received cert for '$($resp.agent_name)' (valid $($resp.cert_valid_days) days), manager $($resp.manager)"

# ------------------------------------------------- write material to disk ----
$secretDir = Join-Path $env:ProgramData "WazuhBootstrap\material"
if (Test-Path $secretDir) { Remove-Item $secretDir -Recurse -Force }
New-Item -ItemType Directory -Path $secretDir -Force | Out-Null

# SYSTEM + Administrators only. Inheritance off, so a loose ACL on ProgramData
# doesn't quietly make the private key world-readable for the next 30 seconds.
$acl = Get-Acl $secretDir
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
    $account = New-Object Security.Principal.SecurityIdentifier($sid)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        $account, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
}
Set-Acl -Path $secretDir -AclObject $acl

$certPath = Join-Path $secretDir "agent.cert"
$keyPath  = Join-Path $secretDir "agent.key"
$caPath   = Join-Path $secretDir "manager-ca.pem"
$pwPath   = Join-Path $secretDir "authd.pass"

[IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($resp.cert_pem_b64))
[IO.File]::WriteAllBytes($keyPath,  [Convert]::FromBase64String($resp.key_pem_b64))
[IO.File]::WriteAllBytes($caPath,   [Convert]::FromBase64String($resp.manager_ca_pem_b64))
[IO.File]::WriteAllText($pwPath, $resp.enrollment_password, (New-Object Text.UTF8Encoding($false)))

$enrollExit = 1
try {
    # ------------------------------------------------------------ enroll ----
    $enrollScript = Join-Path $ScriptDir "wazuh_enroll.ps1"
    if (-not (Test-Path $enrollScript)) { throw "wazuh_enroll.ps1 not found next to this script" }

    $enrollArgs = @{
        Manager                  = $resp.manager
        RegistrationPasswordFile = $pwPath
        AgentName                = $resp.agent_name
        AgentGroup               = $agentGroup
        ManagerCaPath            = $caPath
        AgentCertificatePath     = $certPath
        AgentKeyPath             = $keyPath
    }
    if ($cfg.SysmonConfigFile) {
        $sysmonCfg = Join-Path $ScriptDir $cfg.SysmonConfigFile
        if (Test-Path $sysmonCfg) { $enrollArgs["SysmonConfigPath"] = $sysmonCfg }
        else { Log "SysmonConfigFile '$($cfg.SysmonConfigFile)' not found in package, using built-in baseline" "WARN" }
    }
    if ($cfg.AgentVersion) { $enrollArgs["Version"] = $cfg.AgentVersion }

    Log "Handing off to wazuh_enroll.ps1"
    & $enrollScript @enrollArgs *>&1 | Tee-Object -FilePath $LogFile -Append
    $enrollExit = $LASTEXITCODE
    if ($null -eq $enrollExit) { $enrollExit = 0 }
}
finally {
    # ------------------------------------------------------------ shred ----
    if (-not $KeepCertOnDisk) {
        foreach ($f in @($certPath, $keyPath, $pwPath)) {
            if (Test-Path $f) {
                try {
                    $len = (Get-Item $f).Length
                    [IO.File]::WriteAllBytes($f, (New-Object byte[] $len))
                } catch { }
                Remove-Item $f -Force -ErrorAction SilentlyContinue
            }
        }
        # The manager CA is a public cert -- the agent keeps it so it can
        # verify the manager on any future auto re-enrollment.
        $keepCa = Join-Path $env:ProgramData "WazuhBootstrap\manager-ca.pem"
        if (Test-Path $caPath) { Move-Item $caPath $keepCa -Force -ErrorAction SilentlyContinue }
        Remove-Item $secretDir -Recurse -Force -ErrorAction SilentlyContinue
        Log "Enrollment material shredded from disk"
    } else {
        Log "-KeepCertOnDisk set: private key left at $keyPath" "WARN"
    }
}

if ($enrollExit -ne 0) { Die "wazuh_enroll.ps1 exited with code $enrollExit" $enrollExit }

# ----------------------------------------------------------- marker ----
New-Item -Path $MarkerKey -Force | Out-Null
Set-ItemProperty -Path $MarkerKey -Name "AgentName"     -Value $resp.agent_name
Set-ItemProperty -Path $MarkerKey -Name "Manager"       -Value $resp.manager
Set-ItemProperty -Path $MarkerKey -Name "Group"         -Value $agentGroup
Set-ItemProperty -Path $MarkerKey -Name "EnrolledUtc"   -Value (Get-Date).ToUniversalTime().ToString("o")
$rev = if ($cfg.Revision) { [string]$cfg.Revision } else { "1" }
Set-ItemProperty -Path $MarkerKey -Name "BootstrapRev"  -Value $rev

Log "=== Wazuh bootstrap completed successfully ==="
exit 0
