; Inno Setup script - builds mobiot-<version>-setup.exe from the PyInstaller onedir output.
; Invoked (from the repo root) as:
;   iscc /DVersion=0.3.3 /DSource=dist\mobiot packaging\installer.iss
#ifndef Version
  #define Version "0.0.0"
#endif
#ifndef Source
  #define Source "dist\mobiot"
#endif

[Setup]
; All relative paths below (and /DSource) resolve from the repository root.
SourceDir=..
AppId={{B3E2B7A6-9C4D-4E2A-8F1B-2A9C6D3E7F10}
AppName=Mobile Security and Research Framework
AppVersion={#Version}
AppVerName=Mobile Security and Research Framework {#Version}
AppPublisher=Keyur Aghao
AppPublisherURL=https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest
AppSupportURL=https://github.com/keyuraghao/Mobile_SAST_DAST_Pentest/issues
DefaultDirName={autopf}\Mobile Security and Research Framework
DefaultGroupName=Mobile Security and Research Framework
UninstallDisplayIcon={app}\mobiot.exe
OutputDir=dist
OutputBaseFilename=MSRF-{#Version}-setup
SetupIconFile=src\mobiot\data\icon.ico
LicenseFile=LICENSE
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequiredOverridesAllowed=dialog
ChangesEnvironment=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"
Name: "addtopath"; Description: "Add the mobiot command-line tool to PATH (for the CLI and MCP clients)"; GroupDescription: "Command line:"

[Files]
Source: "{#Source}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Mobile Security and Research Framework"; Filename: "{app}\mobiot.exe"; Comment: "Mobile & IoT SAST/DAST/pentest toolkit"
Name: "{group}\Uninstall Mobile Security and Research Framework"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Mobile Security and Research Framework"; Filename: "{app}\mobiot.exe"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "{code:PathRegKey}"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\mobiot.exe"; Description: "Launch Mobile Security and Research Framework"; Flags: nowait postinstall skipifsilent

[Code]
// After the app files are removed, offer to remove the per-user workspace
// (reports, captures, logs, downloaded emulator/SDK, config) so an uninstall
// can be complete. Default is No, to keep it for a later reinstall.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Answer: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    Answer := MsgBox('Also remove your mobiot workspace (reports, captures, logs, ' +
                     'downloaded emulator/SDK and config)?' + #13#10 + #13#10 +
                     'Choose No to keep it for a later reinstall.',
                     mbConfirmation, MB_YESNO or MB_DEFBUTTON2);
    if Answer = IDYES then
    begin
      DelTree(ExpandConstant('{localappdata}\mobiot'), True, True, True);
      DelTree(ExpandConstant('{userappdata}\mobiot'), True, True, True);
    end;
  end;
end;

function PathRegKey(Param: string): string;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
  Root: Integer;
begin
  if IsAdminInstallMode then Root := HKLM else Root := HKCU;
  if not RegQueryStringValue(Root, PathRegKey(''), 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;
