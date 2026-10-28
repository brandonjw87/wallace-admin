#define AppVer "2.1.0"
[Setup]
AppId={{6B1E5F2A-7C9D-4E1B-9A55-57A11ACE0002}
AppName=Wallace Network Health
AppVersion={#AppVer}
AppPublisher=Brandon Wallace
DefaultDirName={localappdata}\Programs\WallaceNetworkHealth
DefaultGroupName=Wallace Network Health
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=WallaceNetworkHealth-Setup-{#AppVer}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile=src\app.ico
UninstallDisplayIcon={app}\WallaceNetworkHealth.exe
WizardStyle=modern
CloseApplications=force
CloseApplicationsFilter=WallaceNetworkHealth.exe

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"
Name: "startup"; Description: "Start Wallace Network Health when I sign in"; Flags: unchecked

[InstallDelete]
; v1 (NSIS) leftovers - its uninstaller is replaced by this one
Type: files; Name: "{app}\Uninstall.exe"
Type: files; Name: "{userprograms}\Wallace Network Health\Uninstall.lnk"

[Files]
Source: "out\WallaceNetworkHealth.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\Wallace Network Health\Wallace Network Health"; Filename: "{app}\WallaceNetworkHealth.exe"; AppUserModelID: "WallaceNetworkHealth"
Name: "{userprograms}\Wallace Network Health\Mini monitor"; Filename: "{app}\WallaceNetworkHealth.exe"; Parameters: "--mini"
Name: "{userprograms}\Wallace Network Health\Uninstall Wallace Network Health"; Filename: "{uninstallexe}"
Name: "{userdesktop}\Wallace Network Health"; Filename: "{app}\WallaceNetworkHealth.exe"; Tasks: desktopicon
Name: "{userstartup}\Wallace Network Health"; Filename: "{app}\WallaceNetworkHealth.exe"; Tasks: startup

[Registry]
; remove v1's NSIS uninstall entry so Apps & features shows only v2
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\WallaceNetworkHealth"; Flags: deletekey

[Run]
Filename: "{app}\WallaceNetworkHealth.exe"; Description: "Launch Wallace Network Health"; Flags: nowait postinstall skipifsilent
