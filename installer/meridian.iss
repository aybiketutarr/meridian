; Inno Setup script: builds Meridian-Setup-<version>.exe from the PyInstaller folder dist\Meridian.
; CI does it for you (.github/workflows/release.yml). By hand:  iscc /DAppVersion=0.5.2 installer\meridian.iss
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
; Real scans need nmap. When it is missing, winget downloads it from its own verified source and shows nmap's normal setup (it asks for permission and installs Npcap).
; Without winget the nmap download page is offered instead. nmap goes first, so Meridian finds it when it starts.
Filename: "{cmd}"; Parameters: "/C winget install --id Insecure.Nmap -e --interactive --accept-package-agreements --accept-source-agreements"; Description: "Install nmap now (needed for real scans)"; Flags: postinstall skipifsilent runasoriginaluser; Check: (not NmapInstalled) and WingetAvailable
Filename: "https://nmap.org/download.html#windows"; Description: "Open the nmap download page (needed for real scans)"; Flags: shellexec postinstall skipifsilent unchecked; Check: (not NmapInstalled) and (not WingetAvailable)
Filename: "{app}\Meridian.exe"; Description: "{cm:LaunchProgram,Meridian}"; Flags: nowait postinstall skipifsilent

[Code]
function NmapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf}\Nmap\nmap.exe')) or FileExists(ExpandConstant('{commonpf32}\Nmap\nmap.exe'));
end;

var
  WingetChecked, WingetOk: Boolean;

// winget ships with current Windows 10/11 ("App Installer"). Asked once.
function WingetAvailable: Boolean;
var
  Code: Integer;
begin
  if not WingetChecked then
  begin
    WingetChecked := True;
    WingetOk := Exec(ExpandConstant('{cmd}'), '/C winget --version', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
  end;
  Result := WingetOk;
end;

// The program is removed in any case. Saved scans, devices and notes are only deleted if the person says yes (silent uninstall keeps them).
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if SuppressibleMsgBox('Also delete Meridian''s saved scan history, trusted devices and settings?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) = IDYES then
      DelTree(ExpandConstant('{localappdata}\Meridian'), True, True, True);
end;
