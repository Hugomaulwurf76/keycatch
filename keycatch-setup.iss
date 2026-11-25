; KeyCatch – Installer und Deinstaller (Inno Setup 6.3 oder neuer, auch Inno Setup 7)
; Erst build-windows.bat ausführen, dann dieses Skript in Inno Setup öffnen und kompilieren.
; Das fertige Setup liegt danach im Unterordner "installer".

#define AppName "KeyCatch"
#define AppVersion "0.4.2"
#define AppExe "keycatch.exe"

[Setup]
; Die AppId nie ändern, sonst erkennt Windows Updates nicht als dasselbe Programm.
AppId={{78A794B9-1042-4C96-8B67-32E122C44C6F}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=KeyCatch
; Installation nur für den angemeldeten Benutzer, ohne Administratorrechte
; (Autostart, Startmenü und Datenbank liegen ebenfalls im Benutzerprofil).
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\{#AppName}
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=installer
OutputBaseFilename=KeyCatch-Setup-{#AppVersion}
SetupIconFile=assets\keycatch.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "de"; MessagesFile: "compiler:Languages\German.isl"

[Files]
Source: "{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Run]
; Legt die Startmenü-Verknüpfungen (inkl. Tastenkombination) an und übernimmt
; Autostart und Infobereich aus den bestehenden Einstellungen.
Filename: "{app}\{#AppExe}"; Parameters: "--setup"; StatusMsg: "KeyCatch wird eingerichtet ..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#AppExe}"; Description: "KeyCatch jetzt starten"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Laufendes Programm und Hintergrundprogramm im Infobereich beenden.
Filename: "{sys}\taskkill.exe"; Parameters: "/im {#AppExe} /f"; Flags: runhidden waituntilterminated; RunOnceId: "KeyCatchBeenden"

[UninstallDelete]
; Startmenü-Ordner, den KeyCatch selbst anlegt.
Type: filesandordirs; Name: "{userprograms}\KeyCatch"

[Code]
procedure KeyCatchBeenden();
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/im {#AppExe} /f', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
end;

// Vor der Installation (z. B. Update) ein laufendes KeyCatch beenden,
// sonst lässt sich keycatch.exe nicht ersetzen.
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  KeyCatchBeenden();
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Eintrag „Mit Windows starten“ entfernen.
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', 'KeyCatch');
  end;

  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{userappdata}\KeyCatch');
    if DirExists(DataDir) and not UninstallSilent then
    begin
      if MsgBox('Sollen auch die Datenbank, alle Backups und die Einstellungen gelöscht werden?' + #13#10 + #13#10 +
                'Ordner: ' + DataDir + #13#10 + #13#10 +
                'Achtung: Das kann nicht rückgängig gemacht werden. Alle gespeicherten Keys sind dann verloren.' + #13#10 +
                'Wählen Sie "Nein", um die Daten zu behalten (z. B. für eine spätere Neuinstallation).',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(DataDir, True, True, True);
      end;
    end;
  end;
end;
