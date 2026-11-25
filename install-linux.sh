#!/usr/bin/env bash
# Baut KeyCatch und installiert es für den aktuellen Benutzer (Debian 13).
set -euo pipefail
cd "$(dirname "$0")"

BIN=""
if command -v cargo >/dev/null 2>&1 && command -v cc >/dev/null 2>&1; then
  echo "KeyCatch wird gebaut. Das dauert beim ersten Mal einige Minuten ..."
  cargo build --release
  BIN=target/release/keycatch
elif [ -f keycatch-linux-x86_64 ]; then
  echo "Rust nicht gefunden – das mitgelieferte Programm wird verwendet."
  BIN=keycatch-linux-x86_64
else
  echo "Rust fehlt. Installation: sudo apt install rustup build-essential && rustup default stable"
  exit 1
fi

APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor"
mkdir -p "$HOME/.local/bin" "$APPS"
install -m 755 "$BIN" "$HOME/.local/bin/keycatch"
for s in 16 32 48 64 128 256; do
  install -D -m 644 "assets/keycatch-$s.png" "$ICONS/${s}x${s}/apps/keycatch.png"
done

# Reste einer früheren KeyLock-Installation entfernen
rm -f "$HOME/.local/bin/keylock" "$APPS/keylock.desktop" "$APPS/keylock-capture.desktop"

cat > "$APPS/keycatch.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=KeyCatch
Comment=API-Keys und App-Passwörter verschlüsselt verwalten
Exec=$HOME/.local/bin/keycatch
Icon=keycatch
Terminal=false
Categories=Utility;Security;
StartupWMClass=keycatch
EOF

cat > "$APPS/keycatch-capture.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=KeyCatch Erfassen
Comment=Inhalt der Zwischenablage als neuen Eintrag speichern
Exec=$HOME/.local/bin/keycatch capture
Icon=keycatch
Terminal=false
Categories=Utility;Security;
StartupWMClass=keycatch
EOF

update-desktop-database "$APPS" 2>/dev/null || true
gtk-update-icon-cache -f -t "$ICONS" 2>/dev/null || true
echo
echo "Fertig. KeyCatch liegt in $HOME/.local/bin/keycatch"
echo "Jetzt die Tastenkombination einrichten (siehe README.md)."
