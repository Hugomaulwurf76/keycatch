//! PIN-Freigabe ohne Zeitlimit.
//!
//! Nach dem Entsperren mit Master-Passwort (oder Backup-Code) wird der
//! Datenschlüssel lokal abgelegt, bis die PIN gelöscht wird:
//!
//!   Schlüssel = HKDF-SHA256( Argon2id(PIN, salt) || Sitzungsgeheimnis )
//!
//! - Das Sitzungsgeheimnis (32 Byte Zufall) liegt nur im Schlüsselspeicher des
//!   Betriebssystems (Windows: Anmeldeinformationsverwaltung, Linux:
//!   Kernel-Schlüsselbund) und wird beim Löschen der PIN oder nach drei
//!   falschen PINs gelöscht – danach ist die Datei wertlos.
//! - Argon2id(PIN, salt) liegt dauerhaft nur verschlüsselt in der Datenbank.
//! - Datenbankpfad (und das Feld `expires`, hier ohne Ablauf) sind als AAD gebunden.

use std::fs;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::vault::{aead_decrypt, aead_encrypt, derive_key, hex, now_ts, random_bytes, unhex, Kdf, PinData};

const SERVICE: &str = "KeyCatch";
const ACCOUNT: &str = "pin-freigabe";
const KDF_PIN: Kdf = Kdf { m: 19 * 1024, t: 2, p: 1 };
const MAX_ATTEMPTS: u8 = 3;
// Kontext-Kennungen der Schlüsselableitung (unverändert seit KeyLock 0.2).
const HKDF_SALT: &[u8] = b"KeyLock PIN-Freigabe";
const HKDF_INFO: &[u8] = b"keylock pin-cache v1: dek wrap";

#[derive(Serialize, Deserialize)]
struct CacheFile {
    vault: String,
    expires: i64,
    attempts_left: u8,
    salt: String,
    nonce: String,
    wrapped: String,
}

pub enum PinError {
    Wrong(u8),
    Gone,
    Other(String),
}

fn cache_path(dir: &Path) -> PathBuf {
    dir.join("pin-freigabe.json")
}

fn entry() -> Result<keyring_core::Entry, String> {
    keyring_core::Entry::new(SERVICE, ACCOUNT).map_err(|e| format!("Schlüsselspeicher: {e}"))
}

/// Erzeugt die dauerhaften PIN-Daten (werden in der Datenbank gespeichert).
pub fn make_pin_data(pin: &str) -> Result<PinData, String> {
    let salt: [u8; 16] = random_bytes();
    let key = derive_key(pin.as_bytes(), &salt, KDF_PIN).map_err(|e| e.to_string())?;
    Ok(PinData { salt: hex(&salt), key: hex(key.as_ref()) })
}

/// Prüft eine PIN gegen die gespeicherten PIN-Daten (Vergleich in konstanter Zeit).
#[cfg(test)]
pub fn verify_pin(pd: &PinData, pin: &str) -> bool {
    let (Some(salt), Some(stored)) = (unhex(&pd.salt), unhex(&pd.key)) else { return false };
    let Ok(key) = derive_key(pin.as_bytes(), &salt, KDF_PIN) else { return false };
    let stored = Zeroizing::new(stored);
    stored.len() == key.len() && stored.iter().zip(key.iter()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn wrap_key(pin_key: &[u8], session: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(pin_key.len() + session.len()));
    ikm.extend_from_slice(pin_key);
    ikm.extend_from_slice(session);
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, out.as_mut()).expect("HKDF-Länge");
    out
}

fn aad(vault: &str, expires: i64) -> Vec<u8> {
    let mut a = b"KLPIN1".to_vec();
    a.extend_from_slice(vault.as_bytes());
    a.push(0);
    a.extend_from_slice(&expires.to_le_bytes());
    a
}

fn write_cache(dir: &Path, c: &CacheFile) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let json = serde_json::to_vec(c).map_err(|e| e.to_string())?;
    let path = cache_path(dir);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| e.to_string())?;
        f.write_all(&json).map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    fs::write(&path, &json).map_err(|e| e.to_string())?;
    Ok(())
}

/// Kennwert für „läuft nicht ab“.
const NO_EXPIRY: i64 = i64::MAX;

/// Startet die PIN-Freigabe (ohne Zeitlimit).
pub fn start(dir: &Path, vault: &Path, dek: &[u8; 32], pin: &PinData) -> Result<(), String> {
    let pin_key = Zeroizing::new(unhex(&pin.key).ok_or("PIN-Daten beschädigt")?);
    let session: Zeroizing<[u8; 32]> = Zeroizing::new(random_bytes());
    entry()?.set_secret(session.as_ref()).map_err(|e| format!("Schlüsselspeicher: {e}"))?;

    let vault_s = vault.to_string_lossy().to_string();
    let expires = NO_EXPIRY;
    let key = wrap_key(&pin_key, session.as_ref());
    let nonce: [u8; 24] = random_bytes();
    let wrapped = aead_encrypt(&key, &nonce, dek, &aad(&vault_s, expires));
    write_cache(
        dir,
        &CacheFile {
            vault: vault_s,
            expires,
            attempts_left: MAX_ATTEMPTS,
            salt: pin.salt.clone(),
            nonce: hex(&nonce),
            wrapped: hex(&wrapped),
        },
    )
}

/// Beendet die PIN-Freigabe sofort.
pub fn clear(dir: &Path) {
    let _ = fs::remove_file(cache_path(dir));
    if let Ok(e) = entry() {
        let _ = e.delete_credential();
    }
}

fn load(dir: &Path, vault: &Path) -> Option<CacheFile> {
    let c: CacheFile = serde_json::from_slice(&fs::read(cache_path(dir)).ok()?).ok()?;
    if c.vault != vault.to_string_lossy() || c.expires <= now_ts() || c.attempts_left == 0 {
        clear(dir);
        return None;
    }
    Some(c)
}

/// Läuft eine gültige PIN-Freigabe?
pub fn active(dir: &Path, vault: &Path) -> bool {
    load(dir, vault).is_some()
}

/// Entsperren mit PIN: liefert den Datenschlüssel.
pub fn unlock(dir: &Path, vault: &Path, pin: &str) -> Result<Zeroizing<[u8; 32]>, PinError> {
    let Some(mut c) = load(dir, vault) else { return Err(PinError::Gone) };
    let session = match entry().and_then(|e| e.get_secret().map_err(|e| e.to_string())) {
        Ok(s) => Zeroizing::new(s),
        Err(_) => {
            clear(dir);
            return Err(PinError::Gone);
        }
    };
    let salt = unhex(&c.salt).ok_or_else(|| PinError::Other("PIN-Daten beschädigt".into()))?;
    let nonce: [u8; 24] = unhex(&c.nonce)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| PinError::Other("PIN-Daten beschädigt".into()))?;
    let wrapped = unhex(&c.wrapped).ok_or_else(|| PinError::Other("PIN-Daten beschädigt".into()))?;

    let pin_key = derive_key(pin.as_bytes(), &salt, KDF_PIN).map_err(|e| PinError::Other(e.to_string()))?;
    let key = wrap_key(pin_key.as_ref(), &session);
    match aead_decrypt(&key, &nonce, &wrapped, &aad(&c.vault, c.expires)) {
        Some(plain) if plain.len() == 32 => {
            let mut dek = Zeroizing::new([0u8; 32]);
            dek.copy_from_slice(&plain);
            Ok(dek)
        }
        _ => {
            c.attempts_left = c.attempts_left.saturating_sub(1);
            if c.attempts_left == 0 {
                clear(dir);
                Err(PinError::Wrong(0))
            } else {
                let left = c.attempts_left;
                let _ = write_cache(dir, &c);
                Err(PinError::Wrong(left))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_cache_roundtrip_and_lockout() {
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let t = tempfile::tempdir().unwrap();
        let vault = t.path().join("v.kcv");
        let dek: [u8; 32] = random_bytes();
        let pd = make_pin_data("4711").unwrap();
        assert!(verify_pin(&pd, "4711"));
        assert!(!verify_pin(&pd, "4712"));
        start(t.path(), &vault, &dek, &pd).unwrap();
        assert!(active(t.path(), &vault));

        assert!(matches!(unlock(t.path(), &vault, "0000"), Err(PinError::Wrong(2))));
        assert_eq!(*unlock(t.path(), &vault, "4711").ok().unwrap(), dek);
        assert!(matches!(unlock(t.path(), &vault, "1111"), Err(PinError::Wrong(1))));
        assert!(matches!(unlock(t.path(), &vault, "2222"), Err(PinError::Wrong(0))));
        // Nach drei Fehlversuchen gelöscht – auch die richtige PIN hilft nicht mehr.
        assert!(matches!(unlock(t.path(), &vault, "4711"), Err(PinError::Gone)));
        assert!(!active(t.path(), &vault));

        // Ablauffeld ist per AAD gebunden (Manipulation fällt auf).
        start(t.path(), &vault, &dek, &pd).unwrap();
        let mut c: CacheFile = serde_json::from_slice(&fs::read(cache_path(t.path())).unwrap()).unwrap();
        c.expires -= 1;
        write_cache(t.path(), &c).unwrap();
        assert!(unlock(t.path(), &vault, "4711").is_err());

        // Ohne Sitzungsgeheimnis (z. B. nach Neustart) nutzlos.
        start(t.path(), &vault, &dek, &pd).unwrap();
        entry().unwrap().delete_credential().unwrap();
        assert!(matches!(unlock(t.path(), &vault, "4711"), Err(PinError::Gone)));
    }
}
