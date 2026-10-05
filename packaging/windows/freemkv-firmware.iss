; Per-user installers for the freemkv firmware tools, mirroring freemkv's
; packaging/windows/freemkv.iss: %LOCALAPPDATA%\Programs, no admin, the install
; dir added to / removed from the user PATH, Start-menu shortcuts, UNSIGNED.
; Built by .github/workflows/release.yml, once per Tool:
;   iscc /DTool=<tool> /DArch=<x86_64|aarch64> /DAppVersion=X.Y.Z /DBinDir=<dir with the .exe> /O<out> freemkv-firmware.iss
;   Tool=freemkv-flash     freemkv-flash.exe (CLI) + freemkv-flash-gui.exe -> freemkv-flash-<arch>-windows-setup.exe
;   Tool=freemkv-fw        freemkv-fw.exe (CLI) + freemkv-fw-gui.exe       -> freemkv-fw-<arch>-windows-setup.exe
;   Tool=freemkv-firmware  all four of the above                           -> freemkv-firmware-<arch>-windows-setup.exe
; One AppId per tool across both architectures (same install dir), so
; installing the other architecture's build upgrades in place.
; The CLIs are console programs on PATH; the GUIs get Start-menu shortcuts.
#ifndef AppVersion
  #error AppVersion must be defined (/DAppVersion=X.Y.Z)
#endif
#ifndef BinDir
  #error BinDir must be defined (/DBinDir=...)
#endif
#ifndef Arch
  #define Arch "x86_64"
#endif
#if Arch == "x86_64"
  #define InnoArch "x64compatible"
#elif Arch == "aarch64"
  #define InnoArch "arm64"
#else
  #error Arch must be x86_64 or aarch64
#endif
#ifndef Tool
  #error Tool must be defined (/DTool=freemkv-flash, freemkv-fw or freemkv-firmware)
#endif

; Never change an AppGuid: it is how upgrades and the uninstaller find an install.
#if Tool == "freemkv-firmware"
  #define AppTitle "freemkv firmware tools"
  #define AppGuid "B9F92368-31D9-48B8-8A1D-8BE48F476B1C"
  #define MainGui "freemkv-flash-gui"
#elif Tool == "freemkv-flash"
  #define AppTitle "freemkv Flash"
  #define AppGuid "31D06487-B4CD-45ED-8EAE-A79F56A6539A"
  #define MainGui "freemkv-flash-gui"
#elif Tool == "freemkv-fw"
  #define AppTitle "freemkv Modify"
  #define AppGuid "D8B77225-68BD-4296-97AE-B2A1588BF752"
  #define MainGui "freemkv-fw-gui"
#else
  #error Tool must be freemkv-flash, freemkv-fw or freemkv-firmware
#endif

[Setup]
AppId={{{#AppGuid}}
AppName={#AppTitle}
AppVersion={#AppVersion}
AppVerName={#AppTitle} {#AppVersion}
AppPublisher=freemkv
AppPublisherURL=https://github.com/freemkv/freemkv-firmware
VersionInfoVersion={#AppVersion}
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\{#Tool}
DisableDirPage=yes
DisableProgramGroupPage=yes
ArchitecturesAllowed={#InnoArch}
ArchitecturesInstallIn64BitMode={#InnoArch}
MinVersion=10.0
ChangesEnvironment=yes
; Relative to this script's directory (SourceDir defaults to it).
SetupIconFile=..\..\crates\{#MainGui}\assets\freemkv.ico
UninstallDisplayIcon={app}\{#MainGui}.exe
UninstallDisplayName={#AppTitle}
OutputBaseFilename={#Tool}-{#Arch}-windows-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
#if Tool == "freemkv-firmware"
Source: "{#BinDir}\freemkv-flash.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\freemkv-fw.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\freemkv-flash-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\freemkv-fw-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
#else
Source: "{#BinDir}\{#Tool}.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BinDir}\{#Tool}-gui.exe"; DestDir: "{app}"; Flags: ignoreversion
#endif

[Icons]
#if Tool == "freemkv-firmware"
Name: "{autoprograms}\freemkv Flash"; Filename: "{app}\freemkv-flash-gui.exe"
Name: "{autoprograms}\freemkv Modify"; Filename: "{app}\freemkv-fw-gui.exe"
Name: "{autodesktop}\freemkv Flash"; Filename: "{app}\freemkv-flash-gui.exe"; Tasks: desktopicon
Name: "{autodesktop}\freemkv Modify"; Filename: "{app}\freemkv-fw-gui.exe"; Tasks: desktopicon
#else
Name: "{autoprograms}\{#AppTitle}"; Filename: "{app}\{#Tool}-gui.exe"
Name: "{autodesktop}\{#AppTitle}"; Filename: "{app}\{#Tool}-gui.exe"; Tasks: desktopicon
#endif

[Code]
const
  EnvKey = 'Environment';

function PathIndex(Paths, Dir: string): Integer;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';');
end;

procedure AddToPath(Dir: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Paths) then
    Paths := '';
  if PathIndex(Paths, Dir) > 0 then
    exit;
  if (Paths <> '') and (Copy(Paths, Length(Paths), 1) <> ';') then
    Paths := Paths + ';';
  if not RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Paths + Dir) then
    SuppressibleMsgBox('Could not add ' + Dir + ' to your PATH. Add it by hand to run the command-line tools from a console.', mbError, MB_OK, IDOK);
end;

procedure RemoveFromPath(Dir: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Paths) then
    exit;
  P := PathIndex(Paths, Dir);
  if P = 0 then
    exit;
  Paths := ';' + Paths + ';';
  Delete(Paths, P, Length(Dir) + 1);
  Paths := Copy(Paths, 2, Length(Paths) - 2);
  if not RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Paths) then
    SuppressibleMsgBox('Could not remove ' + Dir + ' from your PATH. Remove it by hand.', mbError, MB_OK, IDOK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
