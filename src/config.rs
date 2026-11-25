//! Einstellungen und Eintragstypen (frei anpassbar über types.toml).

use std::fs;
use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::vault::LocalDirs;

pub const DEFAULT_DB_NAME: &str = "keycatch.kcv";

fn vault_path_for(settings: &Settings, data_dir: &std::path::Path) -> PathBuf {
    if settings.datenbank.trim().is_empty() {
        data_dir.join(DEFAULT_DB_NAME)
    } else {
        PathBuf::from(settings.datenbank.trim())
    }
}

fn save_settings_to(path: &std::path::Path, s: &Settings) -> Result<(), String> {
    let body = toml::to_string_pretty(s).map_err(|e| e.to_string())?;
    fs::write(path, format!("{SETTINGS_HEADER}{body}")).map_err(|e| format!("Einstellungen nicht gespeichert: {e}"))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    #[default]
    Text,
    Multiline,
    Date,
    Url,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub key: String,
    pub label: String,
    #[serde(default)]
    pub kind: FieldKind,
    #[serde(default)]
    pub hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    pub name: String,
    /// Beschriftung des Geheimnis-Feldes (z. B. "API-Key", "Passwort").
    pub secret_label: String,
    /// Aus diesen Feldern wird der Titel vorgeschlagen, wenn er leer ist.
    #[serde(default)]
    pub title_from: Vec<String>,
    #[serde(default)]
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypesFile {
    #[serde(rename = "typ")]
    pub types: Vec<TypeDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    /// Pfad zur Datenbank. Leer = Standardpfad.
    #[serde(default)]
    pub datenbank: String,
    /// Automatische Sperre nach so vielen Minuten ohne Eingabe (0 = aus).
    #[serde(default = "default_lock")]
    pub auto_sperre_minuten: u64,
    /// automatisch | hell | dunkel
    #[serde(default = "default_mode")]
    pub darstellung: String,
    /// standard | system | individuell
    #[serde(default = "default_accent")]
    pub akzent: String,
    /// Eigene Akzentfarbe als #RRGGBB
    #[serde(default = "default_accent_color")]
    pub akzent_farbe: String,
    /// Eigene Farben (nur bei akzent = "individuell"), #RRGGBB, leer = Standard
    #[serde(default)]
    pub farbe_hintergrund: String,
    #[serde(default)]
    pub farbe_button: String,
    #[serde(default)]
    pub farbe_schrift: String,
    #[serde(default)]
    pub pin_aktiv: bool,
    #[serde(default = "default_pin_minutes")]
    pub pin_minuten: u64,
    #[serde(default = "default_hotkey")]
    pub tastenkombination: String,
    /// Windows: beim Anmelden automatisch starten
    #[serde(default)]
    pub autostart: bool,
    /// Windows: Hintergrundprogramm mit Symbol im Infobereich (übernimmt die Tastenkombination)
    #[serde(default)]
    pub infobereich: bool,
    /// Windows: beim automatischen Start das Fenster minimiert in der Taskleiste öffnen
    #[serde(default)]
    pub minimiert_starten: bool,
}

fn default_lock() -> u64 {
    5
}
fn default_mode() -> String {
    "automatisch".into()
}
fn default_accent() -> String {
    "system".into()
}
fn default_accent_color() -> String {
    "#3584e4".into()
}
fn default_pin_minutes() -> u64 {
    15
}
fn default_hotkey() -> String {
    "Ctrl+Alt+K".into()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            datenbank: String::new(),
            auto_sperre_minuten: default_lock(),
            darstellung: default_mode(),
            akzent: default_accent(),
            akzent_farbe: default_accent_color(),
            farbe_hintergrund: String::new(),
            farbe_button: String::new(),
            farbe_schrift: String::new(),
            pin_aktiv: false,
            pin_minuten: default_pin_minutes(),
            tastenkombination: default_hotkey(),
            autostart: false,
            infobereich: false,
            minimiert_starten: false,
        }
    }
}

pub struct Config {
    pub settings: Settings,
    pub types: Vec<TypeDef>,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub vault_path: PathBuf,
    pub dirs: LocalDirs,
    pub warnings: Vec<String>,
    /// Hinweise (z. B. Übernahme aus KeyLock)
    pub notes: Vec<String>,
}

const DEFAULT_TYPES: &str = include_str!("../types.default.toml");

const SETTINGS_HEADER: &str = "# KeyCatch-Einstellungen (werden auch über das Programm geändert)\n\n";

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("", "", "KeyCatch")
}

/// Übernimmt Einstellungen und Daten aus der Zeit, als das Programm noch
/// „KeyLock“ hieß (einmalig, nur wenn es noch keine KeyCatch-Ordner gibt).
fn migrate_from_keylock(new: &ProjectDirs, notes: &mut Vec<String>) {
    let Some(old) = ProjectDirs::from("", "", "KeyLock") else { return };
    let pairs = [
        (old.config_dir().to_path_buf(), new.config_dir().to_path_buf()),
        (old.data_dir().to_path_buf(), new.data_dir().to_path_buf()),
    ];
    let mut moved = false;
    for (from, to) in &pairs {
        if from.is_dir() && !to.exists() {
            if let Some(parent) = to.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::rename(from, to) {
                Ok(()) => moved = true,
                Err(e) => notes.push(format!("Übernahme von {} fehlgeschlagen: {e}", from.display())),
            }
        }
    }
    if !moved {
        return;
    }
    // Leere alte Elternordner aufräumen (Windows: %APPDATA%\KeyLock).
    for (from, _) in &pairs {
        if let Some(parent) = from.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
    // Datenbankdatei auf den neuen Namen umstellen.
    let old_db = new.data_dir().join("keylock.klv");
    let new_db = new.data_dir().join(DEFAULT_DB_NAME);
    if old_db.is_file() && !new_db.exists() {
        let _ = fs::rename(&old_db, &new_db);
        let mut bak = old_db.as_os_str().to_owned();
        bak.push(".bak");
        let _ = fs::remove_file(PathBuf::from(bak));
    }
    // Eigene Typenliste aus KeyLock bleibt erhalten, die alte Sperrdatei nicht.
    let _ = fs::remove_dir_all(new.data_dir().join("locks"));
    notes.push("Daten und Einstellungen aus KeyLock wurden übernommen.".into());
}

/// Ein Datenbankpfad, der noch in den alten KeyLock-Ordner zeigt, wird umgeschrieben.
fn rewrite_old_path(settings: &mut Settings, new: &ProjectDirs) -> bool {
    let Some(old) = ProjectDirs::from("", "", "KeyLock") else { return false };
    let db = PathBuf::from(settings.datenbank.trim());
    if settings.datenbank.trim().is_empty() || !db.starts_with(old.data_dir()) {
        return false;
    }
    let Ok(rest) = db.strip_prefix(old.data_dir()) else { return false };
    let mut target = new.data_dir().join(rest);
    if target.file_name().is_some_and(|n| n == "keylock.klv") {
        target.set_file_name(DEFAULT_DB_NAME);
    }
    settings.datenbank = if target == new.data_dir().join(DEFAULT_DB_NAME) {
        String::new()
    } else {
        target.display().to_string()
    };
    true
}

impl Config {
    pub fn load() -> Config {
        let mut warnings = Vec::new();
        let dirs = project_dirs();
        let mut migrated_notes = Vec::new();
        if let Some(d) = &dirs {
            migrate_from_keylock(d, &mut migrated_notes);
        }
        let config_dir = dirs
            .as_ref()
            .map(|d| d.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let data_dir = dirs
            .as_ref()
            .map(|d| d.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let _ = fs::create_dir_all(&config_dir);

        // Einstellungen
        let settings_path = config_dir.join("config.toml");
        if !settings_path.exists() {
            let _ = save_settings_to(&settings_path, &Settings::default());
        }
        let mut settings: Settings = match fs::read_to_string(&settings_path) {
            Ok(s) => {
                let mut st: Settings = toml::from_str(&s).unwrap_or_else(|e| {
                    warnings.push(format!("config.toml fehlerhaft, Standardwerte aktiv: {e}"));
                    Settings::default()
                });
                // Version 0.3 hatte einen gemeinsamen Schalter für Autostart und Infobereich.
                if st.autostart && !s.contains("infobereich") {
                    st.infobereich = true;
                }
                st
            }
            Err(_) => Settings::default(),
        };

        // Typen
        let types_path = config_dir.join("types.toml");
        if !types_path.exists() {
            let _ = fs::write(&types_path, DEFAULT_TYPES);
        }
        let defaults: TypesFile = toml::from_str(DEFAULT_TYPES).expect("Standardtypen gültig");
        let types = match fs::read_to_string(&types_path) {
            Ok(s) => match toml::from_str::<TypesFile>(&s) {
                Ok(t) if !t.types.is_empty() => t.types,
                Ok(_) => defaults.types,
                Err(e) => {
                    warnings.push(format!("types.toml fehlerhaft, Standardtypen aktiv: {e}"));
                    defaults.types
                }
            },
            Err(_) => defaults.types,
        };

        if let Some(d) = &dirs
            && rewrite_old_path(&mut settings, d)
        {
            let _ = save_settings_to(&settings_path, &settings);
        }
        let vault_path = vault_path_for(&settings, &data_dir);
        let dirs = LocalDirs {
            locks: data_dir.join("locks"),
            backups: data_dir.join("backups"),
            inbox: data_dir.join("inbox"),
        };

        Config { settings, types, config_dir, data_dir, vault_path, dirs, warnings, notes: migrated_notes }
    }

    /// Speichert die Einstellungen und übernimmt einen geänderten Datenbankpfad.
    pub fn save(&mut self) -> Result<(), String> {
        save_settings_to(&self.config_dir.join("config.toml"), &self.settings)?;
        self.vault_path = vault_path_for(&self.settings, &self.data_dir);
        Ok(())
    }

    pub fn type_def(&self, name: &str) -> Option<&TypeDef> {
        self.types.iter().find(|t| t.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_types_parse() {
        let t: TypesFile = toml::from_str(DEFAULT_TYPES).unwrap();
        assert!(t.types.iter().any(|t| t.name == "API-Key"));
        assert!(t.types.iter().any(|t| t.name == "App-Passwort"));
    }

    #[test]
    fn settings_roundtrip_and_old_file() {
        let s = Settings::default();
        let txt = toml::to_string_pretty(&s).unwrap();
        assert_eq!(toml::from_str::<Settings>(&txt).unwrap(), s);
        // Alte config.toml (Version 0.1) ohne neue Felder
        let old: Settings = toml::from_str("datenbank = ''\nauto_sperre_minuten = 5\n").unwrap();
        assert_eq!(old.tastenkombination, "Ctrl+Alt+K");
    }
}
