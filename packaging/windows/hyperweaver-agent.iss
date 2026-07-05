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

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
