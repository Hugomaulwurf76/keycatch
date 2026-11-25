//! Betriebssystem-spezifische Funktionen: Schlüsselspeicher, Systemfarbe,
//! Dateien öffnen/drucken, Tastenkombination einrichten.

use std::path::{Path, PathBuf};
use std::process::Command;

use eframe::egui::Color32;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Startet ein Hilfsprogramm ohne Konsolenfenster und liefert stdout.
fn run(program: &str, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

// ------------------------------------------------------------ Schlüsselspeicher

/// Richtet den Schlüsselspeicher des Betriebssystems ein (für die PIN-Freigabe).
pub fn init_keyring() -> bool {
    #[cfg(windows)]
    {
        match windows_native_keyring_store::Store::new() {
            Ok(s) => {
                keyring_core::set_default_store(s);
                true
            }
            Err(_) => false,
        }
    }
    #[cfg(target_os = "linux")]
    {
        match linux_keyutils_keyring_store::Store::new() {
            Ok(s) => {
                keyring_core::set_default_store(s);
                true
            }
            Err(_) => false,
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

// ------------------------------------------------------------ Systemfarbe

#[cfg(target_os = "linux")]
fn parse_rgb_triplet(s: &str) -> Option<Color32> {
    let v: Vec<u8> = s.split(',').filter_map(|x| x.trim().parse().ok()).collect();
    (v.len() >= 3).then(|| Color32::from_rgb(v[0], v[1], v[2]))
}

/// Akzentfarbe des Systems (Windows, KDE Plasma, GNOME 47+). None = unbekannt.
pub fn system_accent() -> Option<Color32> {
    #[cfg(windows)]
    {
        // HKCU\Software\Microsoft\Windows\DWM\AccentColor, Format 0xAABBGGRR
        let out = run("reg", &["query", r"HKCU\Software\Microsoft\Windows\DWM", "/v", "AccentColor"])?;
        let hexval = out.split_whitespace().find(|w| w.starts_with("0x"))?;
        let v = u32::from_str_radix(hexval.trim_start_matches("0x"), 16).ok()?;
        let r = (v & 0xff) as u8;
        let g = ((v >> 8) & 0xff) as u8;
        let b = ((v >> 16) & 0xff) as u8;
        Some(Color32::from_rgb(r, g, b))
    }
    #[cfg(target_os = "linux")]
    {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().to_uppercase();
        if desktop.contains("KDE") {
            let path = directories::BaseDirs::new()?.config_dir().join("kdeglobals");
            let text = std::fs::read_to_string(path).ok()?;
            let mut section = String::new();
            let mut accent = None;
            let mut selection = None;
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('[') {
                    section = line.to_string();
                } else if let Some((k, v)) = line.split_once('=') {
                    if section == "[General]" && k.trim() == "AccentColor" {
                        accent = parse_rgb_triplet(v);
                    }
                    if section == "[Colors:Selection]" && k.trim() == "BackgroundNormal" {
                        selection = parse_rgb_triplet(v);
                    }
                }
            }
            return accent.or(selection);
        }
        // GNOME 47+: benannte Akzentfarben (Werte aus der libadwaita-Dokumentation)
        let out = run("gsettings", &["get", "org.gnome.desktop.interface", "accent-color"])?;
        let name = out.trim().trim_matches('\'');
        let rgb = match name {
            "blue" => 0x3584e4,
            "teal" => 0x2190a4,
            "green" => 0x3a944a,
            "yellow" => 0xc88800,
            "orange" => 0xed5b00,
            "red" => 0xe62d42,
            "pink" => 0xd56199,
            "purple" => 0x9141ac,
            "slate" => 0x6f8396,
            _ => return None,
        };
        Some(Color32::from_rgb((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

// ------------------------------------------------------------ Dateien öffnen / drucken

pub fn open_path(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        Command::new("explorer").arg(path).creation_flags(CREATE_NO_WINDOW).spawn().is_ok()
    }
    #[cfg(not(windows))]
    {
        Command::new("xdg-open").arg(path).spawn().is_ok()
    }
}

const PRINT_PREFIX: &str = "keycatch-druck-";

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Öffnet die Codes als Druckseite im Browser. Die temporäre Datei wird nach
/// 2 Minuten bzw. beim nächsten Start gelöscht.
pub fn print_codes(codes: &[String], vault: &Path) -> Result<(), String> {
    let mut rows = String::new();
    for (i, c) in codes.iter().enumerate() {
        rows.push_str(&format!("<tr><td>{}.</td><td class=\"c\">{}</td><td class=\"box\">☐ benutzt</td></tr>\n", i + 1, html_escape(c)));
    }
    let html = format!(
        r#"<!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><title>KeyCatch – Backup-Codes</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2.5cm 2cm;color:#000}}
h1{{font-size:20pt;margin:0 0 4pt}} p{{font-size:11pt;margin:4pt 0}}
table{{border-collapse:collapse;margin-top:16pt}} td{{padding:7pt 12pt;border-bottom:1px solid #999;font-size:12pt}}
td.c{{font-family:ui-monospace,Consolas,monospace;font-size:15pt;letter-spacing:1px}}
td.box{{color:#555}} .w{{margin-top:18pt;font-weight:bold}}
</style></head><body onload="window.print()">
<h1>KeyCatch – Backup-Codes</h1>
<p>Erstellt am {date}</p>
<p>Datenbank: {db}</p>
<table>{rows}</table>
<p class="w">Jeder Code funktioniert genau einmal, wenn das Master-Passwort vergessen wurde.</p>
<p>Wer einen dieser Codes hat, kann die Datenbank öffnen. Sicher aufbewahren, nicht am PC speichern.</p>
</body></html>"#,
        date = crate::vault::local_now("%d.%m.%Y %H:%M"),
        db = html_escape(&vault.display().to_string()),
    );
    let name = format!("{PRINT_PREFIX}{}.html", crate::vault::new_id());
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, html).map_err(|e| e.to_string())?;
    if !open_path(&path) {
        let _ = std::fs::remove_file(&path);
        return Err("Browser konnte nicht geöffnet werden.".into());
    }
    let p = path.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(120));
        let _ = std::fs::remove_file(p);
    });
    Ok(())
}

/// Entfernt übrig gebliebene Druckdateien (z. B. wenn KeyCatch vorher beendet wurde).
pub fn cleanup_print_files() {
    if let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(PRINT_PREFIX) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

// ------------------------------------------------------------ Tastenkombination

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hotkey {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub key: String,
}

impl Hotkey {
    /// Format in der config.toml: "Ctrl+Alt+K"
    pub fn parse(s: &str) -> Option<Hotkey> {
        let mut h = Hotkey::default();
        for part in s.split('+').map(str::trim) {
            match part.to_ascii_lowercase().as_str() {
                "ctrl" | "strg" => h.ctrl = true,
                "alt" => h.alt = true,
                "shift" | "umschalt" => h.shift = true,
                "" => {}
                _ => h.key = part.to_ascii_uppercase(),
            }
        }
        (!h.key.is_empty()).then_some(h)
    }

    pub fn to_config(&self) -> String {
        let mut p = Vec::new();
        if self.ctrl {
            p.push("Ctrl");
        }
        if self.alt {
            p.push("Alt");
        }
        if self.shift {
            p.push("Shift");
        }
        p.push(&self.key);
        p.join("+")
    }

    pub fn display(&self) -> String {
        self.to_config().replace("Ctrl", "Strg").replace("Shift", "Umschalt")
    }

    /// Mindestens zwei der Tasten Strg/Alt/Umschalt (Vorgabe von Windows-
    /// Verknüpfungen, verhindert Kollisionen mit normalen Eingaben).
    pub fn is_valid(&self) -> bool {
        let mods = [self.ctrl, self.alt, self.shift].iter().filter(|b| **b).count();
        mods >= 2 && !self.key.is_empty()
    }

    #[cfg(target_os = "linux")]
    fn gnome(&self) -> String {
        let mut s = String::new();
        if self.ctrl {
            s.push_str("<Control>");
        }
        if self.alt {
            s.push_str("<Alt>");
        }
        if self.shift {
            s.push_str("<Shift>");
        }
        s.push_str(&self.key.to_lowercase());
        s
    }
}

pub fn capture_command() -> String {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("keycatch"));
    exe.display().to_string()
}

/// Windows: legt die Startmenü-Verknüpfungen „KeyCatch“ und „KeyCatch Erfassen“
/// an (mit oder ohne Tastenkombination) und entfernt den alten KeyLock-Ordner.
#[cfg(windows)]
fn write_shortcuts(hotkey: Option<&Hotkey>) -> Result<(), String> {
    let exe = capture_command().replace('\'', "''");
    let workdir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.display().to_string()))
        .unwrap_or_default()
        .replace('\'', "''");
    let hk = hotkey.map(|h| h.to_config().to_uppercase()).unwrap_or_default();
    let script = format!(
        "$base = Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs'; \
         Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $base 'KeyLock'); \
         $dir = Join-Path $base 'KeyCatch'; \
         New-Item -ItemType Directory -Force -Path $dir | Out-Null; \
         $sh = New-Object -ComObject WScript.Shell; \
         $a = $sh.CreateShortcut((Join-Path $dir 'KeyCatch.lnk')); \
         $a.TargetPath = '{exe}'; $a.WorkingDirectory = '{workdir}'; $a.IconLocation = '{exe},0'; $a.Save(); \
         $l = $sh.CreateShortcut((Join-Path $dir 'KeyCatch Erfassen.lnk')); \
         $l.TargetPath = '{exe}'; $l.Arguments = 'capture'; $l.WorkingDirectory = '{workdir}'; \
         $l.IconLocation = '{exe},0'; $l.Hotkey = '{hk}'; $l.Save()"
    );
    run("powershell", &["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .map(|_| ())
        .ok_or_else(|| "Die Startmenü-Verknüpfungen konnten nicht angelegt werden.".to_string())
}

/// Windows: Eintrag „Mit Windows starten“ setzen oder entfernen.
#[cfg(windows)]
pub fn set_autostart(enabled: bool) -> Result<(), String> {
    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    if enabled {
        let value = format!("\"{}\" --autostart", capture_command());
        run("reg", &["add", KEY, "/v", "KeyCatch", "/t", "REG_SZ", "/d", &value, "/f"])
            .map(|_| ())
            .ok_or_else(|| "Autostart konnte nicht eingetragen werden.".to_string())
    } else {
        // Fehlt der Eintrag, meldet reg einen Fehler – das ist hier egal.
        let _ = run("reg", &["delete", KEY, "/v", "KeyCatch", "/f"]);
        Ok(())
    }
}

/// Windows: startet das Hintergrundprogramm mit dem Symbol im Infobereich.
#[cfg(windows)]
pub fn start_tray() {
    use std::os::windows::process::CommandExt;
    if let Ok(exe) = std::env::current_exe() {
        let _ = Command::new(exe).arg("--tray").creation_flags(CREATE_NO_WINDOW).spawn();
    }
}

/// Windows: Einrichtung nach dem Bauen (wird von build-windows.bat aufgerufen).
#[cfg(windows)]
pub fn setup(settings: &crate::config::Settings) -> Result<(), String> {
    let h = Hotkey::parse(&settings.tastenkombination).unwrap_or_else(|| Hotkey::parse("Ctrl+Alt+K").unwrap());
    write_shortcuts(if settings.infobereich { None } else { Some(&h) })?;
    set_autostart(settings.autostart)?;
    if settings.infobereich {
        start_tray();
    }
    Ok(())
}

#[cfg(windows)]
impl Hotkey {
    /// Umwandlung für das Hintergrundprogramm (global-hotkey).
    pub fn to_global(&self) -> Option<global_hotkey::hotkey::HotKey> {
        use global_hotkey::hotkey::{Code, HotKey, Modifiers};
        use std::str::FromStr;
        let mut mods = Modifiers::empty();
        if self.ctrl {
            mods |= Modifiers::CONTROL;
        }
        if self.alt {
            mods |= Modifiers::ALT;
        }
        if self.shift {
            mods |= Modifiers::SHIFT;
        }
        let k = &self.key;
        let code_name = if k.len() == 1 && k.chars().all(|c| c.is_ascii_alphabetic()) {
            format!("Key{k}")
        } else if k.len() == 1 && k.chars().all(|c| c.is_ascii_digit()) {
            format!("Digit{k}")
        } else {
            k.clone()
        };
        let code = Code::from_str(&code_name).ok()?;
        Some(HotKey::new(Some(mods), code))
    }
}

/// Richtet die Tastenkombination ein. `tray`: Unter Windows übernimmt das
/// Hintergrundprogramm im Infobereich die Tastenkombination.
/// Ok = Meldung für den Benutzer.
pub fn apply_hotkey(h: &Hotkey, tray: bool) -> Result<String, String> {
    if !h.is_valid() {
        return Err("Bitte mindestens zwei der Tasten Strg, Alt und Umschalt verwenden.".into());
    }
    #[cfg(windows)]
    {
        if tray {
            write_shortcuts(None)?;
            Ok(format!("Tastenkombination {} ist eingerichtet (über das Symbol im Infobereich).", h.display()))
        } else {
            write_shortcuts(Some(h))?;
            Ok(format!("Tastenkombination {} ist eingerichtet.", h.display()))
        }
    }
    #[cfg(not(windows))]
    let _ = tray;
    #[cfg(target_os = "linux")]
    {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().to_uppercase();
        if desktop.contains("GNOME") {
            return apply_gnome(h);
        }
        if desktop.contains("CINNAMON") {
            return apply_cinnamon(h);
        }
        Err(format!(
            "Unter {} kann KeyCatch die Tastenkombination nicht selbst setzen. Bitte in den Systemeinstellungen \
             einen Kurzbefehl für „KeyCatch Erfassen“ anlegen: {}",
            if desktop.contains("KDE") { "KDE Plasma" } else { "diesem Desktop" },
            h.display()
        ))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("Auf diesem System nicht unterstützt.".into())
    }
}

#[cfg(target_os = "linux")]
fn apply_gnome(h: &Hotkey) -> Result<String, String> {
    const SCHEMA: &str = "org.gnome.settings-daemon.plugins.media-keys";
    const BASE: &str = "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/";
    let err = || "GNOME-Einstellungen konnten nicht geändert werden.".to_string();

    let list_raw = run("gsettings", &["get", SCHEMA, "custom-keybindings"]).ok_or_else(err)?;
    let mut paths: Vec<String> =
        list_raw.split('\'').filter(|s| s.starts_with('/')).map(|s| s.to_string()).collect();

    let sub = |p: &str| format!("{SCHEMA}.custom-keybinding:{p}");
    // Bereits vorhandenen KeyCatch-Eintrag wiederverwenden.
    let mut target = None;
    for p in &paths {
        if let Some(name) = run("gsettings", &["get", &sub(p), "name"]) {
            if name.trim().trim_matches('\'') == "KeyCatch Erfassen" {
                target = Some(p.clone());
                break;
            }
        }
    }
    let target = match target {
        Some(t) => t,
        None => {
            let mut n = 0;
            let t = loop {
                let cand = format!("{BASE}custom{n}/");
                if !paths.contains(&cand) {
                    break cand;
                }
                n += 1;
            };
            paths.push(t.clone());
            let list = format!("[{}]", paths.iter().map(|p| format!("'{p}'")).collect::<Vec<_>>().join(", "));
            run("gsettings", &["set", SCHEMA, "custom-keybindings", &list]).ok_or_else(err)?;
            t
        }
    };
    // Werte als GVariant-Text übergeben; der Pfad steht in einfachen
    // Anführungszeichen (GNOME zerlegt den Befehl wie eine Shell).
    let command = format!("'{}' capture", capture_command().replace('\'', "'\\''"));
    let gv = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    run("gsettings", &["set", &sub(&target), "name", &gv("KeyCatch Erfassen")]).ok_or_else(err)?;
    run("gsettings", &["set", &sub(&target), "command", &gv(&command)]).ok_or_else(err)?;
    run("gsettings", &["set", &sub(&target), "binding", &gv(&h.gnome())]).ok_or_else(err)?;
    Ok(format!("Tastenkombination {} ist in GNOME eingerichtet.", h.display()))
}

/// Liest eine Zeichenketten-Liste aus der Ausgabe von `gsettings get`
/// (z. B. `['custom0', '__dummy__']` oder `@as []`).
#[cfg(any(target_os = "linux", test))]
fn parse_strv(raw: &str) -> Vec<String> {
    raw.split('\'')
        .skip(1)
        .step_by(2)
        .map(String::from)
        .collect()
}

/// GVariant-Text für eine Zeichenkette.
#[cfg(target_os = "linux")]
fn gvariant_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Linux Mint (Cinnamon): eigene Tastenkürzel liegen unter
/// org.cinnamon.desktop.keybindings (Liste „custom-list“, je Eintrag name,
/// command und binding als Liste). Cinnamon lädt die Tastenkürzel neu, sobald
/// sich „custom-list“ ändert – deshalb wird die Liste zum Schluss immer neu
/// geschrieben (mit/ohne Platzhalter „__dummy__“, wie es Cinnamon selbst macht).
#[cfg(target_os = "linux")]
fn apply_cinnamon(h: &Hotkey) -> Result<String, String> {
    const SCHEMA: &str = "org.cinnamon.desktop.keybindings";
    const BASE: &str = "/org/cinnamon/desktop/keybindings/custom-keybindings/";
    const DUMMY: &str = "__dummy__";
    let err = || "Cinnamon-Einstellungen konnten nicht geändert werden.".to_string();

    let list_raw = run("gsettings", &["get", SCHEMA, "custom-list"]).ok_or_else(err)?;
    let mut names = parse_strv(&list_raw);

    let sub = |n: &str| format!("{SCHEMA}.custom-keybinding:{BASE}{n}/");
    let existing = names.iter().find(|n| {
        n.as_str() != DUMMY
            && run("gsettings", &["get", &sub(n), "name"]).is_some_and(|v| v.trim().trim_matches('\'') == "KeyCatch Erfassen")
    });
    let target = match existing {
        Some(n) => n.clone(),
        None => {
            let mut i = 0;
            loop {
                let cand = format!("custom{i}");
                if !names.contains(&cand) {
                    break cand;
                }
                i += 1;
            }
        }
    };

    let command = format!("'{}' capture", capture_command().replace('\'', "'\\''"));
    run("gsettings", &["set", &sub(&target), "name", &gvariant_str("KeyCatch Erfassen")]).ok_or_else(err)?;
    run("gsettings", &["set", &sub(&target), "command", &gvariant_str(&command)]).ok_or_else(err)?;
    run("gsettings", &["set", &sub(&target), "binding", &format!("[{}]", gvariant_str(&h.gnome()))])
        .ok_or_else(err)?;

    if !names.contains(&target) {
        names.push(target);
    }
    // Platzhalter umschalten, damit sich die Liste in jedem Fall ändert.
    if let Some(pos) = names.iter().position(|n| n == DUMMY) {
        names.remove(pos);
    } else {
        names.insert(0, DUMMY.to_string());
    }
    let list = format!("[{}]", names.iter().map(|n| gvariant_str(n)).collect::<Vec<_>>().join(", "));
    run("gsettings", &["set", SCHEMA, "custom-list", &list]).ok_or_else(err)?;
    Ok(format!("Tastenkombination {} ist in Cinnamon eingerichtet.", h.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotkey_parse() {
        let h = Hotkey::parse("Ctrl+Alt+K").unwrap();
        assert!(h.ctrl && h.alt && !h.shift && h.key == "K");
        assert_eq!(h.to_config(), "Ctrl+Alt+K");
        assert_eq!(h.display(), "Strg+Alt+K");
        assert!(h.is_valid());
        assert!(!Hotkey::parse("Ctrl+K").unwrap().is_valid());
    }

    #[test]
    fn strv_parse() {
        assert_eq!(parse_strv("['custom0', '__dummy__']"), ["custom0", "__dummy__"]);
        assert_eq!(parse_strv("['custom0']\n"), ["custom0"]);
        assert!(parse_strv("@as []").is_empty());
    }
}

/// Linux: Der 3D-Treiber von VirtualBox zeichnet das Fenster nicht (es bleibt
/// schwarz). Läuft KeyCatch in VirtualBox, wird deshalb auf OpenGL mit
/// Software-Grafik (Mesa llvmpipe) umgeschaltet – außer der Benutzer hat
/// WGPU_BACKEND oder LIBGL_ALWAYS_SOFTWARE selbst gesetzt.
#[cfg(target_os = "linux")]
pub fn prepare_graphics() {
    if std::env::var_os("WGPU_BACKEND").is_some() || std::env::var_os("LIBGL_ALWAYS_SOFTWARE").is_some() {
        return;
    }
    let in_virtualbox = ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .any(|s| s.contains("VirtualBox") || s.contains("innotek"));
    if in_virtualbox {
        // SAFETY: wird ganz am Anfang von main() aufgerufen, bevor weitere
        // Threads gestartet werden – niemand liest die Umgebung gleichzeitig.
        unsafe {
            std::env::set_var("WGPU_BACKEND", "gl");
            std::env::set_var("LIBGL_ALWAYS_SOFTWARE", "1");
        }
    }
}
