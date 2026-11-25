# KeyCatch

Speichert API-Keys, App-Passwörter, Tokens und SSH-Keys per Tastenkombination in einer verschlüsselten Datenbank.

**Ablauf:** Key erstellen und kopieren → Tastenkombination → Typ wählen, Felder ausfüllen → Speichern. Zum Erfassen muss die Datenbank nicht entsperrt werden (Posteingang, siehe unten).
Die Zwischenablage wird dabei nicht verändert, der Key kann danach direkt eingefügt werden.

## Funktionen

- Erfassen aus der Zwischenablage (`keycatch capture`) ohne Master-Passwort oder PIN, Fenster schließt sich nach dem Speichern
- Eingabemaske passt sich dem Typ an, eigene Typen über `types.toml`
- Übersicht mit Suche, Anzeigen, Kopieren, Bearbeiten, Löschen (`keycatch`)
- **Einstellungen** (⚙ in der Übersicht):
  - Darstellung: Automatisch (System), Hell oder Dunkel; Farben Standard, Systemfarbe oder individuell (Akzent, Hintergrund, Buttons, Schrift)
  - Automatische Sperre nach X Minuten ohne Eingabe
  - PIN-Freigabe: nach dem ersten Entsperren mit Master-Passwort reicht ab dann immer die PIN – auch nach der automatischen Sperre und nach „Sperren“. Das Master-Passwort ist nur nötig, wenn keine PIN gesetzt ist, die PIN gelöscht wurde, dreimal falsch eingegeben wurde oder die Freigabe anders verloren ging (z. B. Schlüsselspeicher geleert, Datenbank getauscht).
  - Master-Passwort ändern
  - Backup-Codes erstellen (eigenes Fenster mit Drucken, Kopieren und Bestätigen)
  - Speicherort ändern / andere Datenbank öffnen (Synchronisierung über Nextcloud oder NAS)
  - Backup speichern, Backup-Ordner öffnen, Backup wiederherstellen
  - Windows, Programmstart (drei Schiebeschalter):
    - „Mit Windows starten“ – KeyCatch startet beim Anmelden
    - „Symbol im Infobereich anzeigen“ – Hintergrundprogramm unten rechts (Linksklick: Übersicht, Rechtsklick: Menü), übernimmt die Tastenkombination; startet auch ohne Autostart, sobald KeyCatch geöffnet wird
    - „Minimiert starten“ – nur mit Autostart: das Fenster startet minimiert in der Taskleiste
  - Tastenkombination: Feld anklicken, Kombination drücken
  - Einstellungen auf Standardwerte zurücksetzen (Speicherort, Einträge, PIN und Backup-Codes bleiben erhalten)

## Früherer Name KeyLock

Beim ersten Start übernimmt KeyCatch Einstellungen, Typen, Backups und die Datenbank aus den KeyLock-Ordnern (`keylock.klv` wird zu `keycatch.kcv`). Die Dateikennung im Kopfteil der Datenbank lautet aus Kompatibilitätsgründen weiterhin `KEYLOCK1`.

## Sicherheit

| | |
|---|---|
| Datenschlüssel | 256 Bit Zufall, verschlüsselt die gesamte Datenbank mit **XChaCha20-Poly1305** |
| Master-Passwort | **Argon2id** (128 MiB, 3 Durchläufe) → Schlüssel, der den Datenschlüssel entschlüsselt |
| Backup-Codes | 8 Codes à 100 Bit Zufall, jeweils eigener Schlüssel-Slot (Argon2id 16 MiB), nur einmal nutzbar |
| Authentifizierung | Der komplette Kopfteil (Kennung, Formatversion, Argon2-Parameter, Salts, Nonces, Schlüssel-Slots) ist Additional Authenticated Data der Datenverschlüsselung; jeder Slot zusätzlich mit eigener AAD. Jede Änderung eines Bytes wird erkannt (automatisch getestet). |
| Schutz vor Manipulation | Argon2-Werte über 1 GiB bzw. 10 Durchläufe werden abgelehnt |
| Speichern | Sperrdatei, temporäre Datei im selben Ordner, `fsync`, atomares Umbenennen |
| Arbeitsspeicher | Schlüssel, Passwörter, Codes und Klartext-Puffer werden mit `zeroize` überschrieben |
| Dateigröße | Inhalt wird auf 4-KiB-Blöcke aufgefüllt |
| Formatversion | `u16` im Kopfteil; Version 1 (KeyCatch 0.1) wird beim ersten Öffnen automatisch umgestellt, vorher wird eine Kopie im Backup-Ordner abgelegt |

**PIN-Freigabe:** Der Schlüssel für die Freigabe wird per HKDF-SHA256 aus Argon2id(PIN) und einem Sitzungsgeheimnis abgeleitet. Das Sitzungsgeheimnis liegt nur im Schlüsselspeicher des Systems (Windows: Anmeldeinformationsverwaltung, Linux: Kernel-Schlüsselbund) und wird beim Löschen der PIN oder nach drei falschen PINs gelöscht. Die PIN selbst steht nur verschlüsselt in der Datenbank.

**Posteingang:** Beim Erfassen bleibt die Datenbank gesperrt. Der neue Eintrag wird mit dem öffentlichen Posteingang-Schlüssel (**X25519**, HKDF-SHA256, XChaCha20-Poly1305, auf 1-KiB-Blöcke aufgefüllt) verschlüsselt und als eigene Datei abgelegt. Der private Schlüssel steht nur verschlüsselt in der Datenbank. Beim nächsten Entsperren (und alle paar Sekunden, solange die Übersicht offen ist) werden die Einträge übernommen und die Posteingang-Dateien gelöscht. Ohne Entsperren kann niemand die erfassten Einträge lesen – auch KeyCatch selbst nicht. Der Posteingang wird beim ersten Entsperren eingerichtet; bis dahin fragt das Erfassen wie bisher nach Master-Passwort oder PIN.

**Backup-Codes:** Wer einen Code hat, kann die Datenbank öffnen. Codes ausgedruckt und getrennt vom PC aufbewahren. Beim Drucken entsteht für 2 Minuten eine temporäre HTML-Datei, die danach (bzw. beim nächsten Start) gelöscht wird.

**Ohne Master-Passwort und ohne Backup-Code sind die Daten nicht wiederherstellbar.**

## Synchronisierung (Nextcloud / NAS)

1. Einstellungen → „In anderen Ordner verschieben …“ → Ordner im Nextcloud-Sync-Ordner oder auf der NAS-Freigabe wählen.
2. Auf dem zweiten Rechner: beim ersten Start auf dem Startbildschirm „Vorhandene Datenbank öffnen …“ (oder später Einstellungen → „Andere Datenbank öffnen …“) → dieselbe Datei wählen.

Speichern zwei Rechner gleichzeitig, legt die Sync-Software eine Konfliktkopie an (Dateiname mit „conflict“ / „Konflikt“). KeyCatch führt sie beim Entsperren und alle paar Sekunden in der Übersicht automatisch zusammen: neuere Änderung gewinnt, gelöschte Einträge bleiben gelöscht. Die Konfliktkopie wandert danach in den Backup-Ordner.

Sperrdateien, Backups, Posteingang und die PIN-Freigabe bleiben immer lokal auf dem jeweiligen Rechner.

## Backups

- Automatisch: einmal pro Tag vor dem ersten Speichern eine Kopie im Backup-Ordner, die letzten 14 bleiben.
- Manuell: „Backup speichern unter …“
- Wiederherstellen: Backup auswählen, Master-Passwort des Backups eingeben. Die aktuelle Datenbank wird vorher in den Backup-Ordner gesichert.

## Speicherorte

| | Windows | Linux |
|---|---|---|
| Datenbank (Standard) | `%APPDATA%\KeyCatch\data\keycatch.kcv` | `~/.local/share/keycatch/keycatch.kcv` |
| Backups | `%APPDATA%\KeyCatch\data\backups\` | `~/.local/share/keycatch/backups/` |
| Posteingang | `%APPDATA%\KeyCatch\data\inbox\` | `~/.local/share/keycatch/inbox/` |
| Einstellungen und Typen | `%APPDATA%\KeyCatch\config\` | `~/.config/keycatch/` |

## Installation Windows

1. Rust installieren: `rustup-init.exe` von https://rustup.rs (Visual Studio Build Tools mitinstallieren lassen).
2. Im Ordner `KeyCatch` doppelt auf **`build-windows.bat`** klicken.

Das Skript beendet laufende KeyCatch-Programme, baut `keycatch.exe` und legt im Startmenü „KeyCatch“ und „KeyCatch Erfassen“ an. Tastenkombination und Autostart werden nach den gespeicherten Einstellungen eingerichtet (Standard: Strg+Alt+K).

**Update:** Neue Dateien in den Ordner kopieren und `build-windows.bat` erneut ausführen. Die Datenbank bleibt erhalten.

## Installation Debian 13 (Wayland)

**Empfohlen: Debian-Paket** – `installer/keycatch_<Version>_amd64.deb` per Doppelklick installieren. Deinstallieren über die Softwareverwaltung (oder `sudo apt remove keycatch`). Datenbank, Backups und Einstellungen im Benutzerordner bleiben dabei erhalten; zum vollständigen Entfernen `~/.local/share/keycatch` und `~/.config/keycatch` löschen.

Paket selbst bauen (Rust und `build-essential` nötig): `bash build-deb.sh`

**Alternativ** ohne Paket, nur für den aktuellen Benutzer:

```
bash install-linux.sh
```

Ist Rust installiert (`sudo apt install rustup build-essential` und `rustup default stable`), baut das Skript KeyCatch aus dem Quellcode, sonst verwendet es das mitgelieferte `keycatch-linux-x86_64`.

**Tastenkombination:**
- **GNOME (auch Zorin OS) und Cinnamon (Linux Mint):** in KeyCatch unter Einstellungen → Tastenkombination festlegen, KeyCatch trägt sie selbst ein.
- **KDE Plasma:** Systemeinstellungen → Tastatur → Kurzbefehle → Neu hinzufügen → Anwendung → „KeyCatch Erfassen“ → Kurzbefehl festlegen. (KDE erlaubt das zuverlässig nur über die Systemeinstellungen.)

**Zwischenablage unter Wayland:** KeyCatch liest sie über „data-control“ (KDE Plasma, wlroots) und sonst über XWayland. Bleibt das Feld leer: hineinklicken und Strg+V.

**VirtualBox:** Der 3D-Treiber von VirtualBox zeichnet das Fenster nicht. KeyCatch erkennt VirtualBox und schaltet dort automatisch auf Software-Grafik um (`WGPU_BACKEND=gl`, `LIBGL_ALWAYS_SOFTWARE=1`).

Der „Kopieren“-Knopf stellt einen Key nur bereit, solange KeyCatch geöffnet ist (Eigenheit von Wayland/X11).

## Eigene Typen

`types.toml` im Einstellungsordner bearbeiten und KeyCatch neu starten:

```toml
[[typ]]
name = "Datenbank-Zugang"
secret_label = "Passwort"
title_from = ["host", "datenbank"]
fields = [
  { key = "host",      label = "Host" },
  { key = "datenbank", label = "Datenbank" },
  { key = "benutzer",  label = "Benutzer" },
  { key = "ablauf",    label = "Läuft ab am", kind = "date" },
  { key = "notiz",     label = "Notiz", kind = "multiline" },
]
```

Feldarten: `text`, `multiline`, `date` (TT.MM.JJJJ), `url`. Den `key` eines Feldes nachträglich nicht ändern.

## Entwicklung

- Tests: `cargo test` (u. a. Manipulation jedes Header-Bytes, Backup-Codes, PIN-Sperre, Konflikt-Zusammenführung, Umstellung von Format 1 mit `tests/fixtures/v1.klv`)
- Abhängigkeiten auf bekannte Sicherheitslücken prüfen: `cargo install cargo-audit` und `cargo audit`
- Krypto-Crates: `argon2` 0.6, `chacha20poly1305` 0.11, `hkdf` 0.13, `sha2` 0.11 (RustCrypto). Bei Updates immer `cargo test` laufen lassen – die Testdatei aus Format 1 muss weiter lesbar sein.
