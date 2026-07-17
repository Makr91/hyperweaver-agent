; Inno Setup script for Hyperweaver Agent.
; Compiled by CI as:
;   ISCC.exe /DAppVersion=<version> packaging\windows\hyperweaver-agent.iss
; Paths are relative to this file's directory.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "Hyperweaver Agent"
#define AppExeName "hyperweaver-agent.exe"
#define AppPublisher "STARTcloud"
#define AppURL "https://github.com/Makr91/hyperweaver-agent"

[Setup]
; Never change AppId — Windows uses it to identify the app across upgrades.
AppId={{7C8E2F5B-9D14-4A14-B4C3-52E6D0F9A7E1}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE.md
OutputDir=..\..\dist
OutputBaseFilename=HyperweaverAgent-Setup
SetupIconFile=..\..\internal\tray\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
WizardStyle=modern

[Tasks]
Name: "startupicon"; Description: "Start {#AppName} when Windows starts"; GroupDescription: "Startup:"

[Files]
Source: "..\..\bin\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; STARTcloud PKI seed (Mark's shape-A ruling, sync 2026-07-17): root-ca.crt
; is the OFFLINE root's certificate — the trust anchor; the intermediate pair
; (public by design, key decrypted at packaging) is what the agent copies
; into <config dir>\ssl on first TLS start and signs its certificates from,
; serving the full chain so leaves verify against the trusted root.
Source: "..\ssl\root-ca.crt"; DestDir: "{app}\ssl-seed"; Flags: ignoreversion
Source: "..\ssl\ca-certificate.crt"; DestDir: "{app}\ssl-seed"; DestName: "ca.crt"; Flags: ignoreversion
Source: "..\ssl\ca-certificate.key"; DestDir: "{app}\ssl-seed"; DestName: "ca.key"; Flags: ignoreversion
; Provisioner seed archives (staged by CI from the provisioner repos'
; release artifacts; absent in dev builds — skipifsourcedoesntexist): the
; agent extracts them into the user-writable provisioners directory on
; startup, never overwriting existing versions.
Source: "..\provisioners-seed\*"; DestDir: "{app}\provisioners-seed"; Flags: ignoreversion skipifsourcedoesntexist

[Registry]
; hwa:// custom URL scheme (architecture item 5): browsers hand hwa://open to
; Windows, Windows spawns the agent with the URI as an argument, and that
; process forwards the action to the running instance (single-instance
; handoff). HKA resolves to HKLM for admin installs, HKCU otherwise.
Root: HKA; Subkey: "Software\Classes\hwa"; ValueType: string; ValueName: ""; ValueData: "URL:Hyperweaver Agent Protocol"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\hwa"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKA; Subkey: "Software\Classes\hwa\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExeName},0"
Root: HKA; Subkey: "Software\Classes\hwa\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExeName}"" ""%1"""

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Run]
; Plant the STARTcloud PKI machine-wide at the ONE elevated moment (Mark's
; shape-A ruling, sync 2026-07-17): the OFFLINE root's certificate is the
; trust anchor — yearly intermediate rotation never re-prompts — and the
; intermediate lands in the CA store so chains build.
Filename: "{sys}\certutil.exe"; Parameters: "-f -addstore Root ""{app}\ssl-seed\root-ca.crt"""; StatusMsg: "Installing STARTcloud root CA (trust anchor)..."; Flags: runhidden
Filename: "{sys}\certutil.exe"; Parameters: "-f -addstore CA ""{app}\ssl-seed\ca.crt"""; StatusMsg: "Installing STARTcloud intermediate CA..."; Flags: runhidden
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
