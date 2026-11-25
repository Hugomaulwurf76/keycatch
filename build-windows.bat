@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where cargo >nul 2>nul
if errorlevel 1 (
  echo Rust ist nicht installiert.
  echo Bitte zuerst rustup-init.exe von https://rustup.rs herunterladen und installieren.
  pause
  exit /b 1
)

echo KeyCatch wird gebaut. Das dauert beim ersten Mal einige Minuten ...
rem Benutzerordner nicht in die Programmdatei schreiben (Pfade in Fehlermeldungen).
set "RUSTFLAGS=%RUSTFLAGS% --remap-path-prefix=%USERPROFILE%=~"
cargo build --release
if errorlevel 1 (
  echo Build fehlgeschlagen.
  pause
  exit /b 1
)

rem Laufende KeyCatch-/KeyLock-Programme beenden, sonst laesst sich die exe nicht ersetzen.
taskkill /im keycatch.exe /f >nul 2>nul
taskkill /im keylock.exe /f >nul 2>nul
timeout /t 1 /nobreak >nul

copy /y "target\release\keycatch.exe" "%~dp0keycatch.exe" >nul
if errorlevel 1 (
  echo keycatch.exe konnte nicht kopiert werden. Bitte alle KeyCatch-Fenster schliessen und erneut starten.
  pause
  exit /b 1
)
if exist "%~dp0keylock.exe" del "%~dp0keylock.exe"
echo keycatch.exe liegt jetzt in %~dp0

echo Startmenue und Tastenkombination werden eingerichtet ...
"%~dp0keycatch.exe" --setup
if errorlevel 1 (
  echo Einrichtung fehlgeschlagen.
  pause
  exit /b 1
)

echo.
echo Fertig.
pause
