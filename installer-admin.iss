#define AppVer "3.4.2"
[Setup]
; new AppId: WALLACE Admin installs side by side; the old Wallace Network Health install is NOT removed
AppId={{6B1E5F2A-7C9D-4E1B-9A55-57A11ACE0003}
AppName=WALLACE Admin
AppVersion={#AppVer}
AppPublisher=Brandon Wallace
DefaultDirName={localappdata}\Programs\WALLACE Admin
DefaultGroupName=WALLACE Admin
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=WALLACE-Admin-Setup-{#AppVer}
Compression=lzma2/max
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
SetupIconFile=src\app.ico
UninstallDisplayIcon={app}\WALLACEAdmin.exe
UninstallDisplayName=WALLACE Admin
WizardStyle=modern
CloseApplications=force
CloseApplicationsFilter=WALLACEAdmin.exe,WallaceNetworkHealth.exe

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"
Name: "startup"; Description: "Start WALLACE Admin when I sign in (replaces the old Wallace Network Health startup shortcut)"

[InstallDelete]
; retire the OLD app's launch shortcuts only - its program files, data and uninstaller are kept until Brandon OKs removal
Type: files; Name: "{userdesktop}\Wallace Network Health.lnk"
Type: files; Name: "{userstartup}\Wallace Network Health.lnk"
Type: files; Name: "{userprograms}\Wallace Network Health\Wallace Network Health.lnk"
Type: files; Name: "{userprograms}\Wallace Network Health\Mini monitor.lnk"

[Files]
Source: "out-admin\WALLACEAdmin.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\WALLACE Admin\WALLACE Admin"; Filename: "{app}\WALLACEAdmin.exe"; AppUserModelID: "WALLACEAdmin"
Name: "{userprograms}\WALLACE Admin\WALLACE Admin mini monitor"; Filename: "{app}\WALLACEAdmin.exe"; Parameters: "--mini"
Name: "{userprograms}\WALLACE Admin\Uninstall WALLACE Admin"; Filename: "{uninstallexe}"
Name: "{userdesktop}\WALLACE Admin"; Filename: "{app}\WALLACEAdmin.exe"; Tasks: desktopicon
Name: "{userstartup}\WALLACE Admin"; Filename: "{app}\WALLACEAdmin.exe"; Tasks: startup

[Run]
Filename: "{app}\WALLACEAdmin.exe"; Description: "Launch WALLACE Admin"; Flags: nowait postinstall skipifsilent

