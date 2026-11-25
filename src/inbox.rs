//! Posteingang: Erfassen ohne Entsperren.
//!
//! Beim Erfassen ist die Datenbank gesperrt. Der neue Eintrag wird deshalb mit
//! dem öffentlichen Posteingang-Schlüssel (X25519) verschlüsselt und als eigene
//! Datei abgelegt. Der private Schlüssel liegt nur verschlüsselt in der
//! Datenbank. Beim nächsten Entsperren werden die Einträge übernommen und die
//! Posteingang-Dateien gelöscht.
//!
//! Dateiformat (*.kci):
//!   MAGIC "KCINBOX1" (8) | EPHEMERAL_PUB (32) | NONCE (24) | CIPHERTEXT (+16 Byte Tag)
//!
//! - Gemeinsamer Schlüssel: X25519(ephemeral, empfänger) -> HKDF-SHA256
//!   (salt = ephemeral_pub | empfänger_pub, info = "KeyCatch inbox v1").
//! - Verschlüsselung: XChaCha20-Poly1305, AAD = MAGIC | ephemeral_pub | empfänger_pub.
//! - Der Klartext (JSON des Eintrags) wird auf 1-KiB-Blöcke aufgefüllt.

use std::fs;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::vault::{aead_decrypt, aead_encrypt, atomic_write, hex, random_bytes, unhex, Entry};

const MAGIC: &[u8; 8] = b"KCINBOX1";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + KEY_LEN + NONCE_LEN;
const PAD_BLOCK: usize = 1024;
const INFO: &[u8] = b"KeyCatch inbox v1";
const PUB_FILE: &str = "posteingang.pub";
const EXT: &str = "kci";

/// Posteingang-Ordner einer bestimmten Datenbank (getrennt je Datenbankpfad).
pub fn dir_for(base: &Path, vault: &Path) -> PathBuf {
    let h = Sha256::digest(vault.to_string_lossy().as_bytes());
    base.join(hex(&h[..8]))
}

/// Öffentlicher Schlüssel zu einem privaten Schlüssel.
pub fn public_of(secret: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Neuer privater Posteingang-Schlüssel.
pub fn new_secret() -> Zeroizing<[u8; KEY_LEN]> {
    Zeroizing::new(random_bytes::<KEY_LEN>())
}

/// Liest den öffentlichen Schlüssel (ohne Entsperren).
pub fn load_public(dir: &Path) -> Option<[u8; KEY_LEN]> {
    let s = fs::read_to_string(dir.join(PUB_FILE)).ok()?;
    let b = unhex(s.trim())?;
    b.try_into().ok()
}

/// Schreibt den öffentlichen Schlüssel. Liefert `true`, wenn vorher ein
/// anderer (abweichender) Schlüssel in der Datei stand.
pub fn store_public(dir: &Path, public: &[u8; KEY_LEN]) -> Result<bool, String> {
    let old = load_public(dir);
    if old.as_ref() == Some(public) {
        return Ok(false);
    }
    atomic_write(&dir.join(PUB_FILE), hex(public).as_bytes()).map_err(|e| e.to_string())?;
    Ok(old.is_some())
}

fn derive(shared: &[u8; KEY_LEN], eph_pub: &[u8; KEY_LEN], recipient: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut salt = [0u8; 2 * KEY_LEN];
    salt[..KEY_LEN].copy_from_slice(eph_pub);
    salt[KEY_LEN..].copy_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO, key.as_mut()).expect("HKDF-Länge");
    key
}

fn aad(eph_pub: &[u8; KEY_LEN], recipient: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut a = Vec::with_capacity(8 + 2 * KEY_LEN);
    a.extend_from_slice(MAGIC);
    a.extend_from_slice(eph_pub);
    a.extend_from_slice(recipient);
    a
}

/// Verschlüsselt einen Eintrag für den Empfänger-Schlüssel.
pub fn seal(recipient: &[u8; KEY_LEN], entry: &Entry) -> Result<Vec<u8>, String> {
    let recipient_key = PublicKey::from(*recipient);
    let eph = StaticSecret::from(random_bytes::<KEY_LEN>());
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&recipient_key);
    if !shared.was_contributory() {
        return Err("Ungültiger Posteingang-Schlüssel.".into());
    }
    let key = derive(shared.as_bytes(), &eph_pub, recipient);

    let mut plain = Zeroizing::new(serde_json::to_vec(entry).map_err(|e| e.to_string())?);
    let padded = plain.len().div_ceil(PAD_BLOCK).max(1) * PAD_BLOCK;
    plain.resize(padded, b' ');

    let nonce: [u8; NONCE_LEN] = random_bytes();
    let mut out = Vec::with_capacity(HEADER_LEN + padded + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&aead_encrypt(&key, &nonce, &plain, &aad(&eph_pub, recipient)));
    Ok(out)
}

/// Entschlüsselt eine Posteingang-Datei mit einem privaten Schlüssel.
pub fn open(secret: &[u8; KEY_LEN], bytes: &[u8]) -> Option<Entry> {
    if bytes.len() < HEADER_LEN + TAG_LEN || &bytes[..8] != MAGIC {
        return None;
    }
    let mut eph_pub = [0u8; KEY_LEN];
    eph_pub.copy_from_slice(&bytes[8..8 + KEY_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[8 + KEY_LEN..HEADER_LEN]);
    let sk = StaticSecret::from(*secret);
    let recipient = PublicKey::from(&sk).to_bytes();
    let shared = sk.diffie_hellman(&PublicKey::from(eph_pub));
    if !shared.was_contributory() {
        return None;
    }
    let key = derive(shared.as_bytes(), &eph_pub, &recipient);
    let plain = aead_decrypt(&key, &nonce, &bytes[HEADER_LEN..], &aad(&eph_pub, &recipient))?;
    serde_json::from_slice(&plain).ok()
}

/// Legt einen erfassten Eintrag im Posteingang ab (ohne Entsperren).
pub fn deposit(dir: &Path, entry: &Entry) -> Result<(), String> {
    let public = load_public(dir).ok_or("Posteingang ist noch nicht eingerichtet.")?;
    let bytes = seal(&public, entry)?;
    // Zeitstempel in Nanosekunden vorn, damit die Dateien in Erfassungsreihenfolge sortiert sind.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let name = format!("{nanos:020}-{}.{EXT}", hex(&random_bytes::<8>()));
    atomic_write(&dir.join(name), &bytes).map_err(|e| e.to_string())
}

/// Alle Posteingang-Dateien (älteste zuerst).
pub fn pending(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == EXT))
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn entry() -> Entry {
        Entry {
            id: "abc".into(),
            kind: "API-Key".into(),
            title: "Test".into(),
            secret: "sk-geheim-123".into(),
            fields: BTreeMap::new(),
            created: "x".into(),
            updated: "x".into(),
            updated_ts: 1,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let sk = new_secret();
        let pk = public_of(&sk);
        let bytes = seal(&pk, &entry()).unwrap();
        assert!(!bytes.windows(13).any(|w| w == b"sk-geheim-123"));
        assert_eq!((bytes.len() - HEADER_LEN - TAG_LEN) % PAD_BLOCK, 0);
        assert_eq!(open(&sk, &bytes).unwrap(), entry());
    }

    #[test]
    fn wrong_key_and_tampering_fail() {
        let sk = new_secret();
        let bytes = seal(&public_of(&sk), &entry()).unwrap();
        assert!(open(&new_secret(), &bytes).is_none());
        for i in [0, 8, 40, HEADER_LEN + 3, bytes.len() - 1] {
            let mut b = bytes.clone();
            b[i] ^= 1;
            assert!(open(&sk, &b).is_none(), "Byte {i} nicht geschützt");
        }
    }

    #[test]
    fn deposit_needs_public_key() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("in");
        assert!(deposit(&dir, &entry()).is_err());
        let sk = new_secret();
        assert!(!store_public(&dir, &public_of(&sk)).unwrap());
        assert!(!store_public(&dir, &public_of(&sk)).unwrap());
        deposit(&dir, &entry()).unwrap();
        let files = pending(&dir);
        assert_eq!(files.len(), 1);
        assert_eq!(open(&sk, &fs::read(&files[0]).unwrap()).unwrap(), entry());
        // Abweichender Schlüssel in der Datei wird erkannt.
        assert!(store_public(&dir, &public_of(&new_secret())).unwrap());
    }
}
