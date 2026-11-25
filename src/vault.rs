//! Verschlüsselte Datenbank (eine Datei), Format v2.
//!
//! Aufbau:
//!   MAGIC "KEYLOCK1" (8) | VERSION u16 LE (=2) | SLOT_COUNT u8 |
//!   SLOTS (je 101 Byte) | DATA_NONCE (24) | CIPHERTEXT (+16 Byte Tag)
//!
//! Slot:  KIND u8 | m u32 | t u32 | p u32 | SALT 16 | NONCE 24 | WRAPPED_KEY 48
//!   KIND 1 = Master-Passwort, 2 = Backup-Code
//!
//! - Die Daten sind mit einem zufälligen 256-Bit-Datenschlüssel (DEK) per
//!   XChaCha20-Poly1305 verschlüsselt. AAD = der komplette Header (alles vor
//!   dem Ciphertext: Kennung, Version, alle Slots inkl. Argon2-Parametern,
//!   Salts und Nonces, Daten-Nonce).
//! - Jeder Slot enthält den DEK, verschlüsselt mit einem Schlüssel, der per
//!   Argon2id aus Master-Passwort bzw. Backup-Code abgeleitet wird.
//!   AAD des Slots = Kennung | Version | KIND | m | t | p | SALT.
//! - Der Klartext (JSON) wird auf 4-KiB-Blöcke aufgefüllt.
//!
//! Die Kennung "KEYLOCK1" bleibt aus Kompatibilitätsgründen (früherer Name).
//! Format v1 (bis 0.1.0, VERSION-Byte = 1) wird beim Öffnen gelesen und
//! automatisch nach v2 umgewandelt.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"KEYLOCK1";
const VERSION_V1: u16 = 1;
const VERSION_V2: u16 = 2;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAPPED_LEN: usize = KEY_LEN + TAG_LEN;
const SLOT_LEN: usize = 1 + 12 + SALT_LEN + NONCE_LEN + WRAPPED_LEN;
const PAD_BLOCK: usize = 4096;

pub const SLOT_PASSWORD: u8 = 1;
pub const SLOT_CODE: u8 = 2;

/// Argon2id für das Master-Passwort: 128 MiB, 3 Durchläufe, 1 Thread.
pub const KDF_PASSWORD: Kdf = Kdf { m: 128 * 1024, t: 3, p: 1 };
/// Backup-Codes haben 100 Bit Zufall – hier reicht ein leichterer Aufwand.
pub const KDF_CODE: Kdf = Kdf { m: 16 * 1024, t: 2, p: 1 };

pub const CODE_COUNT: usize = 8;
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_CHARS: usize = 20;

const AUTO_BACKUPS_KEEP: usize = 14;

// ---------------------------------------------------------------- Fehler

#[derive(Debug)]
pub enum VaultError {
    WrongPassword,
    WrongCode,
    NotAVault,
    UnsupportedVersion(u16),
    Replaced,
    Io(std::io::Error),
    Format(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::WrongPassword => write!(f, "Falsches Master-Passwort oder beschädigte Datenbank."),
            VaultError::WrongCode => write!(f, "Der Backup-Code ist ungültig."),
            VaultError::NotAVault => write!(f, "Die Datei ist keine KeyCatch-Datenbank."),
            VaultError::UnsupportedVersion(v) => write!(f, "Datenbank-Version {v} wird nicht unterstützt."),
            VaultError::Replaced => {
                write!(f, "Die Datenbank wurde durch eine andere ersetzt. Bitte neu entsperren.")
            }
            VaultError::Io(e) => write!(f, "Dateifehler: {e}"),
            VaultError::Format(e) => write!(f, "Formatfehler: {e}"),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

type Result<T> = std::result::Result<T, VaultError>;

// ---------------------------------------------------------------- Daten

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub id: String,
    /// Name des Typs, z. B. "API-Key" oder "App-Passwort".
    pub kind: String,
    pub title: String,
    pub secret: String,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    pub created: String,
    pub updated: String,
    /// Zeitstempel (Unix-Sekunden) der letzten Änderung – für das Zusammenführen.
    #[serde(default)]
    pub updated_ts: i64,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Daten für die PIN-Freigabe (liegen nur verschlüsselt in der Datenbank).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PinData {
    pub salt: String,
    pub key: String,
}

impl Drop for PinData {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Privater Posteingang-Schlüssel (X25519, hex) – liegt nur verschlüsselt in der Datenbank.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InboxKey {
    pub secret: String,
    pub created: i64,
}

impl Drop for InboxKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl InboxKey {
    pub fn bytes(&self) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        let raw = Zeroizing::new(unhex(&self.secret)?);
        let mut k = Zeroizing::new([0u8; KEY_LEN]);
        if raw.len() != KEY_LEN {
            return None;
        }
        k.copy_from_slice(&raw);
        Some(k)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub entries: Vec<Entry>,
    /// Löschmarker: Eintrags-ID -> Zeitpunkt der Löschung (für die Synchronisierung).
    #[serde(default)]
    pub deleted: BTreeMap<String, i64>,
    #[serde(default)]
    pub pin: Option<PinData>,
    #[serde(default)]
    pub pin_changed: i64,
    /// Schlüssel für den Posteingang (der erste ist der aktuelle; ältere bleiben
    /// erhalten, damit noch nicht übernommene Einträge lesbar bleiben).
    #[serde(default)]
    pub inbox_keys: Vec<InboxKey>,
}

impl VaultData {
    /// Führt einen anderen Stand ein (z. B. aus einer Konfliktkopie).
    /// Neuere Änderung gewinnt, Löschungen bleiben gelöscht.
    pub fn merge(&mut self, other: &VaultData) {
        for (id, ts) in &other.deleted {
            let e = self.deleted.entry(id.clone()).or_insert(*ts);
            if *ts > *e {
                *e = *ts;
            }
        }
        for o in &other.entries {
            match self.entries.iter_mut().find(|e| e.id == o.id) {
                Some(mine) => {
                    if o.updated_ts > mine.updated_ts {
                        *mine = o.clone();
                    }
                }
                None => self.entries.push(o.clone()),
            }
        }
        let deleted = self.deleted.clone();
        self.entries.retain(|e| deleted.get(&e.id).is_none_or(|ts| *ts < e.updated_ts));
        if other.pin_changed > self.pin_changed {
            self.pin = other.pin.clone();
            self.pin_changed = other.pin_changed;
        }
        for k in &other.inbox_keys {
            if !self.inbox_keys.iter().any(|m| m.secret == k.secret) {
                self.inbox_keys.push(k.clone());
            }
        }
    }

    pub fn delete(&mut self, id: &str) {
        self.entries.retain(|e| e.id != id);
        self.deleted.insert(id.to_string(), now_ts());
    }
}

// ---------------------------------------------------------------- Kryptografie

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kdf {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("Zufallsgenerator des Betriebssystems nicht verfügbar");
    b
}

pub fn derive_key(secret: &[u8], salt: &[u8], kdf: Kdf) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(kdf.m, kdf.t, kdf.p, Some(KEY_LEN))
        .map_err(|e| VaultError::Format(format!("Argon2-Parameter: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(secret, salt, key.as_mut())
        .map_err(|e| VaultError::Format(format!("Argon2: {e}")))?;
    Ok(key)
}

pub fn aead_encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], msg: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).expect("Schlüssellänge");
    cipher
        .encrypt(&XNonce::from(*nonce), Payload { msg, aad })
        .expect("Verschlüsselung")
}

pub fn aead_decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ct: &[u8], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(&XNonce::from(*nonce), Payload { msg: ct, aad }).ok().map(Zeroizing::new)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub kind: u8,
    pub kdf: Kdf,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    wrapped: [u8; WRAPPED_LEN],
}

impl Slot {
    fn aad(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(8 + 2 + 1 + 12 + SALT_LEN);
        a.extend_from_slice(MAGIC);
        a.extend_from_slice(&VERSION_V2.to_le_bytes());
        a.push(self.kind);
        a.extend_from_slice(&self.kdf.m.to_le_bytes());
        a.extend_from_slice(&self.kdf.t.to_le_bytes());
        a.extend_from_slice(&self.kdf.p.to_le_bytes());
        a.extend_from_slice(&self.salt);
        a
    }

    fn new(kind: u8, kdf: Kdf, secret: &[u8], dek: &[u8; KEY_LEN]) -> Result<Slot> {
        let mut slot = Slot { kind, kdf, salt: random(), nonce: random(), wrapped: [0; WRAPPED_LEN] };
        let kek = derive_key(secret, &slot.salt, kdf)?;
        let ct = aead_encrypt(&kek, &slot.nonce, dek, &slot.aad());
        slot.wrapped.copy_from_slice(&ct);
        Ok(slot)
    }

    fn unwrap_key(&self, secret: &[u8]) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
        let kek = derive_key(secret, &self.salt, self.kdf)?;
        Ok(aead_decrypt(&kek, &self.nonce, &self.wrapped, &self.aad()).map(|plain| {
            let mut k = Zeroizing::new([0u8; KEY_LEN]);
            k.copy_from_slice(&plain);
            k
        }))
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.kdf.m.to_le_bytes());
        out.extend_from_slice(&self.kdf.t.to_le_bytes());
        out.extend_from_slice(&self.kdf.p.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
    }

    fn read(b: &[u8]) -> Slot {
        let u = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let mut s = Slot {
            kind: b[0],
            kdf: Kdf { m: u(1), t: u(5), p: u(9) },
            salt: [0; SALT_LEN],
            nonce: [0; NONCE_LEN],
            wrapped: [0; WRAPPED_LEN],
        };
        let mut i = 13;
        s.salt.copy_from_slice(&b[i..i + SALT_LEN]);
        i += SALT_LEN;
        s.nonce.copy_from_slice(&b[i..i + NONCE_LEN]);
        i += NONCE_LEN;
        s.wrapped.copy_from_slice(&b[i..i + WRAPPED_LEN]);
        s
    }
}

// ---------------------------------------------------------------- Dateiformat

enum Parsed {
    V1 { kdf: Kdf, salt: [u8; SALT_LEN], nonce: [u8; NONCE_LEN], header_len: usize },
    V2 { slots: Vec<Slot>, data_nonce: [u8; NONCE_LEN], header_len: usize },
}

/// Obergrenzen schützen davor, dass eine manipulierte Datei beim Öffnen
/// riesige Speichermengen anfordert (Argon2 m in KiB).
fn kdf_ok(k: &Kdf) -> bool {
    (8 * k.p.max(1)..=1024 * 1024).contains(&k.m) && (1..=10).contains(&k.t) && (1..=8).contains(&k.p)
}

fn parse(bytes: &[u8]) -> Result<Parsed> {
    if bytes.len() < 10 || &bytes[..8] != MAGIC {
        return Err(VaultError::NotAVault);
    }
    // v1 hatte ein einzelnes Versions-Byte (=1); das nächste Byte war das
    // niederwertige Byte von m_cost und damit 0 – als u16 gelesen also 1.
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    match version {
        VERSION_V1 => {
            let header_len = 8 + 1 + 12 + SALT_LEN + NONCE_LEN;
            if bytes.len() < header_len + TAG_LEN {
                return Err(VaultError::NotAVault);
            }
            let u = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
            let mut salt = [0; SALT_LEN];
            salt.copy_from_slice(&bytes[21..21 + SALT_LEN]);
            let mut nonce = [0; NONCE_LEN];
            nonce.copy_from_slice(&bytes[21 + SALT_LEN..header_len]);
            let kdf = Kdf { m: u(9), t: u(13), p: u(17) };
            if !kdf_ok(&kdf) {
                return Err(VaultError::Format("Ungültige Argon2-Parameter in der Datei.".into()));
            }
            Ok(Parsed::V1 { kdf, salt, nonce, header_len })
        }
        VERSION_V2 => {
            if bytes.len() < 11 {
                return Err(VaultError::NotAVault);
            }
            let count = bytes[10] as usize;
            let header_len = 11 + count * SLOT_LEN + NONCE_LEN;
            if bytes.len() < header_len + TAG_LEN {
                return Err(VaultError::NotAVault);
            }
            let slots: Vec<Slot> =
                (0..count).map(|i| Slot::read(&bytes[11 + i * SLOT_LEN..11 + (i + 1) * SLOT_LEN])).collect();
            if slots.iter().any(|s| !kdf_ok(&s.kdf)) {
                return Err(VaultError::Format("Ungültige Argon2-Parameter in der Datei.".into()));
            }
            let mut data_nonce = [0; NONCE_LEN];
            data_nonce.copy_from_slice(&bytes[header_len - NONCE_LEN..header_len]);
            Ok(Parsed::V2 { slots, data_nonce, header_len })
        }
        v => Err(VaultError::UnsupportedVersion(v)),
    }
}

fn decode_data(plain: &[u8]) -> Result<VaultData> {
    serde_json::from_slice(plain).map_err(|e| VaultError::Format(e.to_string()))
}

fn encode_file(slots: &[Slot], dek: &[u8; KEY_LEN], data: &VaultData) -> Result<Vec<u8>> {
    let mut plain = Zeroizing::new(serde_json::to_vec(data).map_err(|e| VaultError::Format(e.to_string()))?);
    // Auffüllen auf volle 4-KiB-Blöcke (JSON erlaubt Leerzeichen am Ende).
    let padded = plain.len().div_ceil(PAD_BLOCK).max(1) * PAD_BLOCK;
    plain.resize(padded, b' ');

    let mut out = Vec::with_capacity(11 + slots.len() * SLOT_LEN + NONCE_LEN + padded + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION_V2.to_le_bytes());
    out.push(u8::try_from(slots.len()).map_err(|_| VaultError::Format("Zu viele Slots".into()))?);
    for s in slots {
        s.write(&mut out);
    }
    let data_nonce: [u8; NONCE_LEN] = random();
    out.extend_from_slice(&data_nonce);
    let ct = aead_encrypt(dek, &data_nonce, &plain, &out);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_v2(bytes: &[u8], dek: &[u8; KEY_LEN], data_nonce: &[u8; NONCE_LEN], header_len: usize) -> Option<Result<VaultData>> {
    aead_decrypt(dek, data_nonce, &bytes[header_len..], &bytes[..header_len]).map(|p| decode_data(&p))
}

// ---------------------------------------------------------------- Backup-Codes

/// Erzeugt einen Backup-Code (100 Bit Zufall), Anzeige: XXXXX-XXXXX-XXXXX-XXXXX.
pub fn generate_code() -> String {
    let raw: [u8; CODE_CHARS] = random();
    let chars: String = raw.iter().map(|b| CODE_ALPHABET[(b & 31) as usize] as char).collect();
    chars.as_bytes().chunks(5).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

/// Vereinheitlicht Eingaben: Großbuchstaben, ohne Bindestriche/Leerzeichen,
/// verwechselbare Zeichen (O→0, I/L→1) werden korrigiert.
pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            x => x,
        })
        .collect()
}

// ---------------------------------------------------------------- Pfade

/// Lokale Ordner (nicht im Sync-Ordner): Sperrdateien, Backups und Posteingang.
#[derive(Debug, Clone)]
pub struct LocalDirs {
    pub locks: PathBuf,
    pub backups: PathBuf,
    pub inbox: PathBuf,
}

impl LocalDirs {
    fn lock_file(&self, vault: &Path) -> PathBuf {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        vault.to_string_lossy().hash(&mut h);
        self.locks.join(format!("vault-{:016x}.lock", h.finish()))
    }
}

struct FileLock(File);

impl FileLock {
    fn acquire(dirs: &LocalDirs, vault: &Path) -> Result<Self> {
        fs::create_dir_all(&dirs.locks)?;
        let f = OpenOptions::new().create(true).truncate(false).write(true).open(dirs.lock_file(vault))?;
        f.lock()?;
        Ok(FileLock(f))
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// Atomar schreiben: temporäre Datei im selben Ordner, fsync, umbenennen.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{:08x}.tmp", u32::from_le_bytes(random())));
    let result = (|| -> Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    // Ordner-Eintrag ebenfalls auf die Platte bringen (unter Windows nicht nötig/möglich).
    #[cfg(unix)]
    if result.is_ok() {
        if let Some(dir) = path.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }
    }
    result
}

/// Tägliches automatisches Backup des bisherigen Stands, die letzten 14 bleiben.
fn auto_backup(dirs: &LocalDirs, vault: &Path) -> Result<()> {
    if !vault.exists() {
        return Ok(());
    }
    fs::create_dir_all(&dirs.backups)?;
    let name = format!("auto-{}.kcv", crate::vault::local_now("%Y-%m-%d"));
    let target = dirs.backups.join(&name);
    if !target.exists() {
        fs::copy(vault, &target)?;
    }
    let mut autos: Vec<PathBuf> = fs::read_dir(&dirs.backups)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("auto-")))
        .collect();
    autos.sort();
    while autos.len() > AUTO_BACKUPS_KEEP {
        let _ = fs::remove_file(autos.remove(0));
    }
    Ok(())
}

/// Kopie in den Backup-Ordner mit eigenem Namen (z. B. vor einer Wiederherstellung).
pub fn safety_copy(dirs: &LocalDirs, vault: &Path, label: &str) -> Result<Option<PathBuf>> {
    if !vault.exists() {
        return Ok(None);
    }
    fs::create_dir_all(&dirs.backups)?;
    let target = dirs.backups.join(format!("{label}-{}.kcv", crate::vault::local_now("%Y-%m-%d_%H-%M-%S")));
    fs::copy(vault, &target)?;
    Ok(Some(target))
}

fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

// ---------------------------------------------------------------- Vault

pub struct Vault {
    path: PathBuf,
    dirs: LocalDirs,
    dek: Zeroizing<[u8; KEY_LEN]>,
    pub data: VaultData,
    code_slots: usize,
    last_mtime: Option<SystemTime>,
}

#[derive(Clone, Copy)]
pub enum Unlock<'a> {
    Password(&'a str),
    Code(&'a str),
    Key(&'a [u8; KEY_LEN]),
}

impl Vault {
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    pub fn create(path: &Path, dirs: &LocalDirs, password: &str) -> Result<Self> {
        Self::create_with_kdf(path, dirs, password, KDF_PASSWORD)
    }

    pub fn create_with_kdf(path: &Path, dirs: &LocalDirs, password: &str, kdf: Kdf) -> Result<Self> {
        if path.exists() {
            return Err(VaultError::Format("Datenbank existiert bereits.".into()));
        }
        let _lock = FileLock::acquire(dirs, path)?;
        let dek = Zeroizing::new(random::<KEY_LEN>());
        let slot = Slot::new(SLOT_PASSWORD, kdf, password.as_bytes(), &dek)?;
        let data = VaultData::default();
        atomic_write(path, &encode_file(&[slot], &dek, &data)?)?;
        Ok(Vault { path: path.to_path_buf(), dirs: dirs.clone(), dek, data, code_slots: 0, last_mtime: mtime(path) })
    }

    /// Öffnet die Datenbank. Liefert bei Backup-Code zusätzlich, dass ein neues
    /// Master-Passwort gesetzt werden muss (der Code wird dabei verbraucht).
    pub fn open(path: &Path, dirs: &LocalDirs, how: Unlock) -> Result<Self> {
        let (dek, data, slots) = Self::read_with(path, how)?;
        let code_slots = slots.iter().filter(|s| s.kind == SLOT_CODE).count();
        let mut v = Vault { path: path.to_path_buf(), dirs: dirs.clone(), dek, data, code_slots, last_mtime: None };
        if slots.is_empty() {
            // Datei war noch Format v1 -> umwandeln (vorher Sicherheitskopie).
            let Unlock::Password(pw) = how else { return Err(VaultError::WrongPassword) };
            let _lock = FileLock::acquire(dirs, path)?;
            safety_copy(dirs, path, "vor-umstellung-v2")?;
            let slot = Slot::new(SLOT_PASSWORD, KDF_PASSWORD, pw.as_bytes(), &v.dek)?;
            atomic_write(path, &encode_file(&[slot], &v.dek, &v.data)?)?;
        }
        v.last_mtime = mtime(path);
        Ok(v)
    }

    /// Nur lesen (z. B. um ein Backup vor dem Wiederherstellen zu prüfen).
    pub fn peek(path: &Path, how: Unlock) -> Result<VaultData> {
        Self::read_with(path, how).map(|(_, d, _)| d)
    }

    /// Ergebnis: DEK, Daten, Slots (leer bei v1).
    fn read_with(path: &Path, how: Unlock) -> Result<(Zeroizing<[u8; KEY_LEN]>, VaultData, Vec<Slot>)> {
        let bytes = fs::read(path)?;
        match parse(&bytes)? {
            Parsed::V1 { kdf, salt, nonce, header_len } => {
                let Unlock::Password(pw) = how else {
                    return Err(VaultError::Format("Alte Datenbank: bitte mit Master-Passwort öffnen.".into()));
                };
                let key = derive_key(pw.as_bytes(), &salt, kdf)?;
                let plain = aead_decrypt(&key, &nonce, &bytes[header_len..], &bytes[..header_len])
                    .ok_or(VaultError::WrongPassword)?;
                let data = decode_data(&plain)?;
                Ok((Zeroizing::new(random()), data, Vec::new()))
            }
            Parsed::V2 { slots, data_nonce, header_len } => {
                let dek = match how {
                    Unlock::Password(pw) => {
                        let mut found = None;
                        for s in slots.iter().filter(|s| s.kind == SLOT_PASSWORD) {
                            if let Some(k) = s.unwrap_key(pw.as_bytes())? {
                                found = Some(k);
                                break;
                            }
                        }
                        found.ok_or(VaultError::WrongPassword)?
                    }
                    Unlock::Code(code) => {
                        let norm = normalize_code(code);
                        let mut found = None;
                        if norm.len() == CODE_CHARS {
                            for s in slots.iter().filter(|s| s.kind == SLOT_CODE) {
                                if let Some(k) = s.unwrap_key(norm.as_bytes())? {
                                    found = Some(k);
                                    break;
                                }
                            }
                        }
                        found.ok_or(VaultError::WrongCode)?
                    }
                    Unlock::Key(k) => Zeroizing::new(*k),
                };
                let data = decrypt_v2(&bytes, &dek, &data_nonce, header_len).ok_or(VaultError::WrongPassword)??;
                Ok((dek, data, slots))
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn dek(&self) -> &[u8; KEY_LEN] {
        &self.dek
    }

    pub fn code_slots(&self) -> usize {
        self.code_slots
    }

    /// Aktuellen Stand von der Platte lesen (mit unserem Datenschlüssel).
    fn read_current(&self) -> Result<(VaultData, Vec<Slot>)> {
        let bytes = fs::read(&self.path)?;
        match parse(&bytes)? {
            Parsed::V2 { slots, data_nonce, header_len } => {
                let data = decrypt_v2(&bytes, &self.dek, &data_nonce, header_len).ok_or(VaultError::Replaced)??;
                Ok((data, slots))
            }
            Parsed::V1 { .. } => Err(VaultError::Replaced),
        }
    }

    /// Ändert Daten und/oder Slots sicher: Sperre holen, aktuellen Stand lesen,
    /// Änderung anwenden, Tages-Backup anlegen, atomar zurückschreiben.
    fn transact<F>(&mut self, change: F) -> Result<()>
    where
        F: FnOnce(&mut VaultData, &mut Vec<Slot>) -> Result<()>,
    {
        let _lock = FileLock::acquire(&self.dirs, &self.path)?;
        let (mut data, mut slots) = self.read_current()?;
        change(&mut data, &mut slots)?;
        let bytes = encode_file(&slots, &self.dek, &data)?;
        auto_backup(&self.dirs, &self.path)?;
        atomic_write(&self.path, &bytes)?;
        self.data = data;
        self.code_slots = slots.iter().filter(|s| s.kind == SLOT_CODE).count();
        self.last_mtime = mtime(&self.path);
        Ok(())
    }

    pub fn modify<F: FnOnce(&mut VaultData)>(&mut self, change: F) -> Result<()> {
        self.transact(|d, _| {
            change(d);
            Ok(())
        })
    }

    pub fn set_password(&mut self, password: &str) -> Result<()> {
        let slot = Slot::new(SLOT_PASSWORD, KDF_PASSWORD, password.as_bytes(), &self.dek)?;
        self.transact(move |_, slots| {
            slots.retain(|s| s.kind != SLOT_PASSWORD);
            slots.insert(0, slot);
            Ok(())
        })
    }

    /// Ersetzt alle Backup-Codes durch die übergebenen.
    pub fn set_codes(&mut self, codes: &[String]) -> Result<()> {
        let mut new_slots = Vec::with_capacity(codes.len());
        for c in codes {
            new_slots.push(Slot::new(SLOT_CODE, KDF_CODE, normalize_code(c).as_bytes(), &self.dek)?);
        }
        self.transact(move |_, slots| {
            slots.retain(|s| s.kind != SLOT_CODE);
            slots.extend(new_slots);
            Ok(())
        })
    }

    /// Entfernt den Slot des benutzten Backup-Codes (Codes sind einmalig).
    pub fn consume_code(&mut self, code: &str) -> Result<()> {
        let norm = normalize_code(code);
        self.transact(move |_, slots| {
            let mut keep = Vec::with_capacity(slots.len());
            let mut removed = false;
            for s in slots.drain(..) {
                if !removed && s.kind == SLOT_CODE && s.unwrap_key(norm.as_bytes())?.is_some() {
                    removed = true;
                    continue;
                }
                keep.push(s);
            }
            *slots = keep;
            Ok(())
        })
    }

    /// Liest die Datei neu ein, wenn sie sich seit dem letzten Lesen/Schreiben geändert hat.
    pub fn reload_if_changed(&mut self) -> Result<bool> {
        let now = mtime(&self.path);
        if now.is_some() && now == self.last_mtime {
            return Ok(false);
        }
        let (data, slots) = self.read_current()?;
        self.data = data;
        self.code_slots = slots.iter().filter(|s| s.kind == SLOT_CODE).count();
        self.last_mtime = now;
        Ok(true)
    }

    /// Sucht Konfliktkopien der Sync-Software (Nextcloud, Syncthing, Synology …)
    /// neben der Datenbank, führt sie ein und verschiebt sie in den Backup-Ordner.
    pub fn merge_conflicts(&mut self) -> Result<usize> {
        let Some(dir) = self.path.parent() else { return Ok(0) };
        let stem = self.path.file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
        let own = self.path.file_name().map(|s| s.to_os_string());
        let mut found = Vec::new();
        for e in fs::read_dir(dir)?.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_lowercase();
            if Some(e.file_name()) == own || !p.is_file() || !name.starts_with(&stem) {
                continue;
            }
            if name.contains("conflict") || name.contains("konflikt") {
                found.push(p);
            }
        }
        if found.is_empty() {
            return Ok(0);
        }
        let mut others = Vec::new();
        let mut merged_files = Vec::new();
        for p in &found {
            let Ok(bytes) = fs::read(p) else { continue };
            if let Ok(Parsed::V2 { data_nonce, header_len, .. }) = parse(&bytes)
                && let Some(Ok(d)) = decrypt_v2(&bytes, &self.dek, &data_nonce, header_len)
            {
                others.push(d);
                merged_files.push(p.clone());
            }
        }
        if others.is_empty() {
            return Ok(0);
        }
        self.transact(|data, _| {
            for o in &others {
                data.merge(o);
            }
            Ok(())
        })?;
        fs::create_dir_all(&self.dirs.backups)?;
        for p in &merged_files {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let target = self.dirs.backups.join(format!("konflikt-{}-{name}", crate::vault::local_now("%Y-%m-%d_%H-%M-%S")));
            if fs::rename(p, &target).is_err() {
                fs::copy(p, &target)?;
                fs::remove_file(p)?;
            }
        }
        Ok(merged_files.len())
    }

    /// Posteingang-Ordner dieser Datenbank.
    pub fn inbox_dir(&self) -> PathBuf {
        crate::inbox::dir_for(&self.dirs.inbox, &self.path)
    }

    /// Richtet den Posteingang ein (Schlüssel erzeugen, falls noch keiner da ist)
    /// und legt den öffentlichen Schlüssel ab. Liefert `true`, wenn die Datei mit
    /// dem öffentlichen Schlüssel verändert war und ersetzt wurde.
    pub fn setup_inbox(&mut self) -> Result<bool> {
        if self.data.inbox_keys.iter().all(|k| k.bytes().is_none()) {
            let secret = crate::inbox::new_secret();
            let key = InboxKey { secret: hex(secret.as_ref()), created: now_ts() };
            self.transact(move |d, _| {
                if d.inbox_keys.iter().all(|k| k.bytes().is_none()) {
                    d.inbox_keys.insert(0, key);
                }
                Ok(())
            })?;
        }
        let Some(current) = self.data.inbox_keys.iter().find_map(|k| k.bytes()) else {
            return Err(VaultError::Format("Posteingang-Schlüssel fehlt.".into()));
        };
        crate::inbox::store_public(&self.inbox_dir(), &crate::inbox::public_of(&current)).map_err(VaultError::Format)
    }

    /// Übernimmt alle Einträge aus dem Posteingang. Ergebnis: (übernommen, nicht lesbar).
    pub fn import_inbox(&mut self) -> Result<(usize, usize)> {
        let files = crate::inbox::pending(&self.inbox_dir());
        if files.is_empty() {
            return Ok((0, 0));
        }
        let keys: Vec<Zeroizing<[u8; KEY_LEN]>> = self.data.inbox_keys.iter().filter_map(|k| k.bytes()).collect();
        let mut entries = Vec::new();
        let mut done = Vec::new();
        let mut failed = 0;
        for p in files {
            let Ok(bytes) = fs::read(&p) else {
                failed += 1;
                continue;
            };
            match keys.iter().find_map(|k| crate::inbox::open(k, &bytes)) {
                Some(e) => {
                    entries.push(e);
                    done.push(p);
                }
                None => failed += 1,
            }
        }
        if !entries.is_empty() {
            self.transact(move |d, _| {
                for e in entries {
                    d.deleted.remove(&e.id);
                    match d.entries.iter().position(|x| x.id == e.id) {
                        Some(pos) => d.entries[pos] = e,
                        None => d.entries.push(e),
                    }
                }
                Ok(())
            })?;
        }
        // Erst nach dem Speichern löschen – bei einem Absturz dazwischen wird
        // derselbe Eintrag (gleiche ID) beim nächsten Mal nur ersetzt.
        for p in &done {
            let _ = fs::remove_file(p);
        }
        Ok((done.len(), failed))
    }

    /// Speichert eine Kopie der Datenbank an einem frei gewählten Ort.
    pub fn export_backup(&self, target: &Path) -> Result<()> {
        let _lock = FileLock::acquire(&self.dirs, &self.path)?;
        let bytes = fs::read(&self.path)?;
        atomic_write(target, &bytes)
    }
}

/// Ersetzt die Datenbank durch ein Backup (vorher Sicherheitskopie).
pub fn restore_from(backup: &Path, vault: &Path, dirs: &LocalDirs) -> Result<()> {
    let bytes = fs::read(backup)?;
    parse(&bytes)?;
    let _lock = FileLock::acquire(dirs, vault)?;
    safety_copy(dirs, vault, "vor-wiederherstellung")?;
    atomic_write(vault, &bytes)
}

/// Verschiebt die Datenbank an einen neuen Ort (z. B. in den Nextcloud-Ordner).
pub fn move_vault(from: &Path, to: &Path, dirs: &LocalDirs) -> Result<()> {
    if to.exists() {
        return Err(VaultError::Format("Am Ziel liegt bereits eine Datei.".into()));
    }
    let _lock = FileLock::acquire(dirs, from)?;
    let bytes = fs::read(from)?;
    atomic_write(to, &bytes)?;
    safety_copy(dirs, from, "vor-umzug")?;
    fs::remove_file(from)?;
    Ok(())
}

pub fn new_id() -> String {
    random::<8>().iter().map(|x| format!("{x:02x}")).collect()
}

/// Lokale Zeit formatiert (strftime-Format).
pub fn local_now(fmt: &str) -> String {
    jiff::ZonedDateTime::now().strftime(fmt).to_string()
}

pub fn now_string() -> String {
    local_now("%d.%m.%Y %H:%M")
}

pub fn now_ts() -> i64 {
    jiff::Timestamp::now().as_second()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    random()
}

// ---------------------------------------------------------------- Tests

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Kdf = Kdf { m: 1024, t: 1, p: 1 };

    fn dirs(root: &Path) -> LocalDirs {
        LocalDirs { locks: root.join("locks"), backups: root.join("backups"), inbox: root.join("inbox") }
    }

    fn create(path: &Path, d: &LocalDirs, pw: &str) -> Vault {
        Vault::create_with_kdf(path, d, pw, FAST).unwrap()
    }

    fn entry(id: &str, title: &str, secret: &str, ts: i64) -> Entry {
        Entry {
            id: id.into(),
            kind: "API-Key".into(),
            title: title.into(),
            secret: secret.into(),
            fields: BTreeMap::from([("dienst".into(), "OpenRouter".into())]),
            created: now_string(),
            updated: now_string(),
            updated_ts: ts,
        }
    }

    #[test]
    fn roundtrip() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.klv");
        let mut v = create(&p, &d, "geheim123");
        v.modify(|x| x.entries.push(entry("a", "Test", "sk-abc", 1))).unwrap();
        let v2 = Vault::open(&p, &d, Unlock::Password("geheim123")).unwrap();
        assert_eq!(v2.data.entries.len(), 1);
        assert_eq!(v2.data.entries[0].secret, "sk-abc");
    }

    #[test]
    fn wrong_password() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.klv");
        create(&p, &d, "richtig");
        assert!(matches!(Vault::open(&p, &d, Unlock::Password("falsch")), Err(VaultError::WrongPassword)));
    }

    #[test]
    fn nothing_in_plaintext_and_padded() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.klv");
        let mut v = create(&p, &d, "pw");
        v.modify(|x| x.entries.push(entry("a", "Sichtbar?", "sk-SUPERSECRET", 1))).unwrap();
        let raw = fs::read(&p).unwrap();
        let hay = String::from_utf8_lossy(&raw);
        assert!(!hay.contains("SUPERSECRET") && !hay.contains("Sichtbar") && !hay.contains("dienst"));
        let header = 11 + SLOT_LEN + NONCE_LEN;
        assert_eq!((raw.len() - header - TAG_LEN) % PAD_BLOCK, 0);
    }

    /// Jede einzelne Bit-Änderung im Header (Kennung, Version, Argon2-Werte,
    /// Salt, Nonces, Slots) muss erkannt werden.
    #[test]
    fn every_header_byte_is_authenticated() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.klv");
        let mut v = create(&p, &d, "pw");
        v.modify(|x| x.entries.push(entry("a", "a", "b", 1))).unwrap();
        let orig = fs::read(&p).unwrap();
        let header = 11 + SLOT_LEN + NONCE_LEN;
        for i in 0..header {
            let mut raw = orig.clone();
            raw[i] ^= 0x01;
            fs::write(&p, &raw).unwrap();
            assert!(Vault::open(&p, &d, Unlock::Password("pw")).is_err(), "Byte {i} nicht geschützt");
            // Auch mit bekanntem Datenschlüssel: Header ist AAD der Daten.
            // Auch mit bekanntem Datenschlüssel: der ganze Header ist AAD der Daten.
            assert!(Vault::peek(&p, Unlock::Key(v.dek())).is_err(), "Byte {i} nicht als AAD geschützt");
        }
        let mut raw = orig.clone();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        fs::write(&p, &raw).unwrap();
        assert!(Vault::open(&p, &d, Unlock::Password("pw")).is_err());
    }

    #[test]
    fn two_windows_do_not_lose_entries() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.klv");
        let mut a = create(&p, &d, "pw");
        let mut b = Vault::open(&p, &d, Unlock::Password("pw")).unwrap();
        a.modify(|x| x.entries.push(entry("1", "A", "1", 1))).unwrap();
        b.modify(|x| x.entries.push(entry("2", "B", "2", 1))).unwrap();
        assert_eq!(Vault::open(&p, &d, Unlock::Password("pw")).unwrap().data.entries.len(), 2);
    }

    #[test]
    fn atomic_write_leaves_no_temp_files() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.klv");
        let mut v = create(&p, &d, "pw");
        v.modify(|x| x.entries.push(entry("1", "A", "1", 1))).unwrap();
        let leftovers: Vec<_> = fs::read_dir(t.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn backup_codes_unlock_once() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.klv");
        let mut v = create(&p, &d, "altes-pw");
        v.modify(|x| x.entries.push(entry("1", "A", "geheim", 1))).unwrap();
        let codes: Vec<String> = (0..CODE_COUNT).map(|_| generate_code()).collect();
        v.set_codes(&codes).unwrap();
        assert_eq!(v.code_slots(), CODE_COUNT);

        // Mit Code (klein geschrieben, ohne Bindestriche) öffnen.
        let typed = codes[3].replace('-', " ").to_lowercase();
        let mut r = Vault::open(&p, &d, Unlock::Code(&typed)).unwrap();
        assert_eq!(r.data.entries[0].secret, "geheim");
        r.set_password("neues-pw-123").unwrap();
        r.consume_code(&typed).unwrap();
        assert_eq!(r.code_slots(), CODE_COUNT - 1);

        assert!(Vault::open(&p, &d, Unlock::Code(&typed)).is_err(), "Code darf nur einmal gehen");
        assert!(Vault::open(&p, &d, Unlock::Code(&codes[0])).is_ok());
        assert!(Vault::open(&p, &d, Unlock::Password("altes-pw")).is_err());
        assert!(Vault::open(&p, &d, Unlock::Password("neues-pw-123")).is_ok());
        assert!(Vault::open(&p, &d, Unlock::Code("AAAAA-BBBBB-CCCCC-DDDDD")).is_err());
    }

    #[test]
    fn code_format() {
        let c = generate_code();
        assert_eq!(c.len(), 23);
        assert_eq!(normalize_code(&c).len(), 20);
        assert_eq!(normalize_code("abcde-ilo00"), "ABCDE11000");
    }

    #[test]
    fn migrates_v1_fixture() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("alt.klv");
        fs::copy("tests/fixtures/v1.klv", &p).unwrap();
        assert!(Vault::open(&p, &d, Unlock::Password("falsch")).is_err());
        let v = Vault::open(&p, &d, Unlock::Password("TestPasswort-v1")).unwrap();
        assert_eq!(v.data.entries[0].secret, "sk-or-v1-FIXTURE");
        // Jetzt v2 auf der Platte, Sicherheitskopie vorhanden.
        let raw = fs::read(&p).unwrap();
        assert_eq!(u16::from_le_bytes([raw[8], raw[9]]), VERSION_V2);
        assert!(fs::read_dir(&d.backups).unwrap().count() >= 1);
        let again = Vault::open(&p, &d, Unlock::Password("TestPasswort-v1")).unwrap();
        assert_eq!(again.data.entries[0].title, "Fixture – OpenRouter");
    }

    #[test]
    fn merge_rules() {
        let mut a = VaultData::default();
        a.entries.push(entry("1", "alt", "x", 10));
        a.entries.push(entry("2", "bleibt", "y", 10));
        let mut b = VaultData::default();
        b.entries.push(entry("1", "neu", "x", 20));
        b.entries.push(entry("3", "nur in b", "z", 5));
        b.deleted.insert("2".into(), 15);
        a.merge(&b);
        let titles: Vec<_> = a.entries.iter().map(|e| e.title.as_str()).collect();
        assert!(titles.contains(&"neu") && titles.contains(&"nur in b") && !titles.contains(&"bleibt"));
    }

    #[test]
    fn merges_nextcloud_conflict_copy() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("keycatch.kcv");
        let mut v = create(&p, &d, "pw");
        v.modify(|x| x.entries.push(entry("1", "A", "1", 1))).unwrap();
        // Zweiter Rechner speichert parallel -> Konfliktkopie.
        let conflict = t.path().join("keycatch (conflicted copy 2026-11-22 101500).kcv");
        fs::copy(&p, &conflict).unwrap();
        let mut other = Vault::open(&conflict, &d, Unlock::Password("pw")).unwrap();
        other.modify(|x| x.entries.push(entry("2", "B", "2", 2))).unwrap();
        v.modify(|x| x.entries.push(entry("3", "C", "3", 3))).unwrap();

        assert_eq!(v.merge_conflicts().unwrap(), 1);
        assert!(!conflict.exists());
        let ids: Vec<_> = v.data.entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn restore_and_auto_backup() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.klv");
        let mut v = create(&p, &d, "pw");
        v.modify(|x| x.entries.push(entry("1", "A", "1", 1))).unwrap();
        let export = t.path().join("export.klv");
        v.export_backup(&export).unwrap();
        v.modify(|x| x.delete("1")).unwrap();
        assert!(v.data.entries.is_empty());
        assert!(fs::read_dir(&d.backups).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("auto-")));
        restore_from(&export, &p, &d).unwrap();
        assert_eq!(Vault::open(&p, &d, Unlock::Password("pw")).unwrap().data.entries.len(), 1);
    }

    #[test]
    fn inbox_capture_without_unlock() {
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let p = t.path().join("v.kcv");
        let mut v = create(&p, &d, "pw");
        let inbox = crate::inbox::dir_for(&d.inbox, &p);
        // Vor der Einrichtung gibt es keinen öffentlichen Schlüssel.
        assert!(crate::inbox::deposit(&inbox, &entry("x", "X", "geheim-x", 5)).is_err());
        assert!(!v.setup_inbox().unwrap());
        let first = v.data.inbox_keys[0].secret.clone();
        // Zweites Einrichten erzeugt keinen neuen Schlüssel.
        assert!(!v.setup_inbox().unwrap());
        assert_eq!(v.data.inbox_keys.len(), 1);
        assert_eq!(v.data.inbox_keys[0].secret, first);
        drop(v);

        // Erfassen bei gesperrter Datenbank.
        crate::inbox::deposit(&inbox, &entry("a", "A", "geheim-a", 5)).unwrap();
        crate::inbox::deposit(&inbox, &entry("b", "B", "geheim-b", 6)).unwrap();
        fs::write(inbox.join("kaputt.kci"), b"KCINBOX1 nicht lesbar").unwrap();

        let mut v = Vault::open(&p, &d, Unlock::Password("pw")).unwrap();
        assert_eq!(v.import_inbox().unwrap(), (2, 1));
        let titles: Vec<&str> = v.data.entries.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["A", "B"]);
        assert_eq!(crate::inbox::pending(&inbox).len(), 1);
        assert_eq!(v.import_inbox().unwrap(), (0, 1));
        // Auch nach dem erneuten Öffnen vorhanden.
        assert_eq!(Vault::open(&p, &d, Unlock::Password("pw")).unwrap().data.entries.len(), 2);

        // Manipulierte Schlüsseldatei wird beim Einrichten erkannt und ersetzt.
        crate::inbox::store_public(&inbox, &crate::inbox::public_of(&crate::inbox::new_secret())).unwrap();
        assert!(v.setup_inbox().unwrap());
        assert!(!v.setup_inbox().unwrap());
    }
}

#[cfg(test)]
mod default_kdf_tests {
    use super::*;

    #[test]
    fn date_format_check() {
        assert!(jiff::civil::Date::strptime("%d.%m.%Y", "05.03.2027").is_ok());
        assert!(jiff::civil::Date::strptime("%d.%m.%Y", "31.02.2027").is_err());
        assert!(jiff::civil::Date::strptime("%d.%m.%Y", "2027-03-05").is_err());
        assert_eq!(local_now("%d.%m.%Y %H:%M").len(), 16);
    }

    #[test]
    fn default_kdf_values() {
        assert_eq!(KDF_PASSWORD, Kdf { m: 131072, t: 3, p: 1 });
    }
}
