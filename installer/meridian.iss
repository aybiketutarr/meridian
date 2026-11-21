; Inno Setup script: builds Meridian-Setup-<version>.exe from the PyInstaller folder dist\Meridian.
; CI does it for you (.github/workflows/release.yml). By hand:  iscc /DAppVersion=0.5.1 installer\meridian.iss
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{400EE762-1338-40DE-B528-EB47655A522F}
AppName=Meridian
AppVersion={#AppVersion}
AppPublisher=Meridian
AppPublisherURL=https://github.com/aybiketutarr/meridian
AppSupportURL=https://github.com/aybiketutarr/meridian/issues
DefaultDirName={autopf}\Meridian
DefaultGroupName=Meridian
DisableProgramGroupPage=yes
; No administrator needed: it installs for the current user. The dialog lets someone choose "all users" if they want.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=Meridian-Setup-{#AppVersion}
SetupIconFile=..\assets\meridian.ico
UninstallDisplayIcon={app}\Meridian.exe
UninstallDisplayName=Meridian
LicenseFile=..\LICENSE
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
#if FileExists(CompilerPath + "Languages\Turkish.isl")
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
#endif
#if FileExists(CompilerPath + "Languages\German.isl")
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
#endif
#if FileExists(CompilerPath + "Languages\Spanish.isl")
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
#endif
#if FileExists(CompilerPath + "Languages\French.isl")
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
#endif

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\Meridian\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Meridian"; Filename: "{app}\Meridian.exe"
Name: "{autodesktop}\Meridian"; Filename: "{app}\Meridian.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Meridian.exe"; Description: "{cm:LaunchProgram,Meridian}"; Flags: nowait postinstall skipifsilent
; Real scans need nmap. Offered only when it is not installed yet (its installer asks for its own permissions and installs Npcap).
Filename: "https://nmap.org/download.html#windows"; Description: "Open the nmap download page (needed for real scans)"; Flags: shellexec postinstall skipifsilent unchecked; Check: not NmapInstalled

[Code]
function NmapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf}\Nmap\nmap.exe')) or FileExists(ExpandConstant('{commonpf32}\Nmap\nmap.exe'));
end;

// The program is removed in any case. Saved scans, devices and notes are only deleted if the person says yes (silent uninstall keeps them).
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if SuppressibleMsgBox('Also delete Meridian''s saved scan history, trusted devices and settings?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
      DelTree(ExpandConstant('{localappdata}\Meridian'), True, True, True);
end;
