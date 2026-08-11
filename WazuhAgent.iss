; ============================================================
; Wazuh Agent Deployment - Inno Setup Script
; Bundles all deployment files into ONE installer EXE with a
; standard wizard UI (Welcome / License / Progress / Finish).
;
; IMPORTANT: Place this .iss file in the SAME folder as:
;   bootstrap.json
;   Detect-WazuhAgent.ps1
;   Install-WazuhAgent.ps1
;   sysmonconfig.xml
;   Uninstall-WazuhAgent.ps1
;   wazuh_enroll.ps1
; ============================================================

#define MyAppName "Wazuh Agent"
#define MyAppVersion "1.0"
#define MyAppPublisher "YourOrg"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\WazuhAgentDeploy
DisableProgramGroupPage=yes
; Installing/enrolling an agent needs local admin rights
PrivilegesRequired=admin
OutputDir=Output
OutputBaseFilename=WazuhAgent-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Shows an entry in "Apps & Features" with a working Uninstall
UninstallDisplayName={#MyAppName}

[Files]
; All files get extracted to {app} so relative paths inside your
; scripts (e.g. ".\bootstrap.json") still resolve correctly.
Source: "bootstrap.json";             DestDir: "{app}"; Flags: ignoreversion
Source: "Detect-WazuhAgent.ps1";      DestDir: "{app}"; Flags: ignoreversion
Source: "Install-WazuhAgent.ps1";     DestDir: "{app}"; Flags: ignoreversion
Source: "sysmonconfig.xml";           DestDir: "{app}"; Flags: ignoreversion
Source: "Uninstall-WazuhAgent.ps1";   DestDir: "{app}"; Flags: ignoreversion
Source: "wazuh_enroll.ps1";           DestDir: "{app}"; Flags: ignoreversion

[Run]
; Runs after files are copied, while the wizard shows progress.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
    Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Install-WazuhAgent.ps1"""; \
    WorkingDir: "{app}"; \
    StatusMsg: "Installing Wazuh Agent..."; \
    Flags: waituntilterminated runhidden

[UninstallRun]
; Runs when the user uninstalls via "Apps & Features"
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; \
    Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Uninstall-WazuhAgent.ps1"""; \
    WorkingDir: "{app}"; \
    Flags: waituntilterminated runhidden
