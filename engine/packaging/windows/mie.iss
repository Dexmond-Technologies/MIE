; Dexmond MIE per-user Windows installer (Inno Setup 6)
; All user-facing strings come from engine/packaging/wording.json via generated wording.iss.

#include "wording.iss"

[Setup]
AppId={{8E4C7D1A-5F23-4B9E-A612-3D9E40F5C8B2}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppVerName}
AppPublisher={#MyAppPublisher}
AppComments={#MyAppComments}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequired=lowest
DisableWelcomePage=no
DisableProgramGroupPage=yes
UsePreviousAppDir=yes
CloseApplications=no
RestartApplications=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#MyOutputDir}
OutputBaseFilename={#MyOutputBaseFilename}
Compression=lzma2
SolidCompression=yes
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\mie-service.exe
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoProductName={#MyAppName}
VersionInfoDescription={#MyAppComments}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1={#MyWelcomeHeading}
WelcomeLabel2={#MyWelcomeBody}

[Tasks]
Name: "autostart"; Description: "{#MyAutostartTask}"

[Files]
Source: "{#MyStageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
#if MyWithUI == "1"
Name: "{userprograms}\{#MyAppName}\{#MyStartMenuUI}"; Filename: "{app}\mie-ui.exe"; WorkingDir: "{app}"
#endif
Name: "{userprograms}\{#MyAppName}\{#MyStartMenuService}"; Filename: "{app}\mie-service.exe"; WorkingDir: "{app}"
Name: "{userprograms}\{#MyAppName}\{#MyStartMenuReadme}"; Filename: "{app}\README.txt"; WorkingDir: "{app}"
Name: "{userprograms}\{#MyAppName}\{#MyStartMenuUninstall}"; Filename: "{uninstallexe}"; WorkingDir: "{app}"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\mie-service.exe"""; Tasks: autostart; Flags: uninsdeletevalue

[Code]
procedure StopRunningService(const AppDir: String);
var
  CliExe: String;
  SvcExe: String;
  ResultCode: Integer;
  I: Integer;
begin
  CliExe := AppDir + '\mie.exe';
  SvcExe := AppDir + '\mie-service.exe';
  if not FileExists(CliExe) then
    Exit;

  Log('Asking running mie-service (if any) to stop via mie.exe shutdown');
  Exec(CliExe, 'shutdown', AppDir, SW_HIDE, ewWaitUntilTerminated, ResultCode);

  for I := 1 to 50 do
  begin
    if not Exec(CliExe, 'ping', AppDir, SW_HIDE, ewWaitUntilTerminated, ResultCode) then
      Break;
    if ResultCode <> 0 then
      Break;
    Sleep(200);
  end;

  { Allow the service process handle and image mapping to close cleanly }
  if FileExists(SvcExe) then
    Sleep(600);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  NeedsRestart := False;
  StopRunningService(WizardDirValue);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not WizardIsTaskSelected('autostart') then
    begin
      RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', '{#MyAppName}');
    end;
  end;
end;

function HasUninstallRemoveUserDataSwitch(var ExplicitKeep: Boolean): Boolean;
var
  I: Integer;
  Arg: String;
begin
  Result := False;
  ExplicitKeep := False;
  for I := 1 to ParamCount do
  begin
    Arg := ParamStr(I);
    if (CompareText(Arg, '/REMOVEUSERDATA') = 0) or (CompareText(Arg, '/REMOVEUSERDATA=1') = 0) then
    begin
      Result := True;
      Exit;
    end;
    if CompareText(Arg, '/REMOVEUSERDATA=0') = 0 then
    begin
      ExplicitKeep := True;
      Exit;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  UserDataDir: String;
  ExplicitKeep: Boolean;
  ShouldRemoveData: Boolean;
  Choice: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopRunningService(ExpandConstant('{app}'));
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    UserDataDir := ExpandConstant('{localappdata}\DexmondMIE');
    if DirExists(UserDataDir) then
    begin
      ExplicitKeep := False;
      ShouldRemoveData := HasUninstallRemoveUserDataSwitch(ExplicitKeep);
      if (not ShouldRemoveData) and (not ExplicitKeep) then
      begin
        Choice := SuppressibleMsgBox(
          '{#MyUninstallPromptPascal}',
          mbConfirmation,
          MB_YESNO or MB_DEFBUTTON2,
          IDNO
        );
        ShouldRemoveData := (Choice = IDYES);
      end;
      if ShouldRemoveData then
      begin
        Log('Removing user data folder: ' + UserDataDir);
        DelTree(UserDataDir, True, True, True);
      end
      else
      begin
        Log('Keeping user data folder: ' + UserDataDir);
      end;
    end;
  end;
end;
