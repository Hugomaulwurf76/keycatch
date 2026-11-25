#!/usr/bin/env bash
# Baut das Debian-Paket keycatch_<Version>_amd64.deb (Debian 13, Wayland/X11).
# Voraussetzungen: Rust (cargo), build-essential, dpkg-dev.
# Ergebnis: Unterordner "installer".
set -euo pipefail
cd "$(dirname "$0")"

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
ARCH=amd64
PKG=keycatch
OUT=installer
ROOT=$(mktemp -d)
chmod 755 "$ROOT"
trap 'rm -rf "$ROOT"' EXIT

echo "KeyCatch $VERSION wird gebaut ..."
# Benutzerordner nicht in die Programmdatei schreiben (Pfade in Fehlermeldungen).
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=~"
cargo build --release
BIN=target/release/keycatch

# Mindestversion der C-Bibliothek aus der fertigen Programmdatei ermitteln.
GLIBC=$(objdump -T "$BIN" 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1 | cut -d_ -f2)
GLIBC=${GLIBC:-2.36}

install -D -m 755 "$BIN" "$ROOT/usr/bin/keycatch"
for s in 16 32 48 64 128 256; do
  install -D -m 644 "assets/keycatch-$s.png" "$ROOT/usr/share/icons/hicolor/${s}x${s}/apps/keycatch.png"
done
install -D -m 644 README.md "$ROOT/usr/share/doc/$PKG/README.md"

mkdir -p "$ROOT/usr/share/applications"
cat > "$ROOT/usr/share/applications/keycatch.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=KeyCatch
Comment=API-Keys und App-Passwörter verschlüsselt verwalten
Exec=/usr/bin/keycatch
Icon=keycatch
Terminal=false
Categories=Utility;Security;
StartupWMClass=keycatch
EOF

cat > "$ROOT/usr/share/applications/keycatch-capture.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=KeyCatch Erfassen
Comment=Inhalt der Zwischenablage als neuen Eintrag speichern
Exec=/usr/bin/keycatch capture
Icon=keycatch
Terminal=false
Categories=Utility;Security;
StartupWMClass=keycatch
EOF

cat > "$ROOT/usr/share/doc/$PKG/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: KeyCatch
Source: lokal

Files: *
Copyright: 2026 KeyCatch
License: MIT
EOF

SIZE=$(du -sk "$ROOT/usr" | cut -f1)
mkdir -p "$ROOT/DEBIAN"
cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Architecture: $ARCH
Maintainer: KeyCatch <keycatch@localhost>
Installed-Size: $SIZE
Depends: libc6 (>= $GLIBC), libgcc-s1, libdbus-1-3, libegl1, libwayland-client0, libwayland-egl1, libxkbcommon0
Recommends: libx11-6, libx11-xcb1, libxcursor1, libxi6, libxkbcommon-x11-0, libfontconfig1, xdg-desktop-portal
Section: utils
Priority: optional
Description: API-Keys und App-Passwörter verschlüsselt speichern
 KeyCatch speichert API-Keys, App-Passwörter, Tokens und SSH-Keys per
 Tastenkombination aus der Zwischenablage in einer verschlüsselten
 Datenbank (XChaCha20-Poly1305, Argon2id).
EOF

mkdir -p "$OUT"
DEB="$OUT/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$ROOT" "$DEB"
echo
echo "Fertig: $DEB"
