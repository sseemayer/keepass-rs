#![cfg(feature = "save_kdbx4")]
#![forbid(unsafe_code)]

mod common;

use common::{combo_by_label, fast_combo, DEMO_PASSWORD};
use keepass::error::{DatabaseKeyError, DatabaseOpenError, DatabaseVersionParseError};
use keepass::{Database, DatabaseKey};

fn baseline_blob() -> (Vec<u8>, DatabaseKey) {
    let combo = fast_combo();
    let db = combo.minimal_database();
    let bytes = common::save_to_vec(&db, combo.get_key());
    (bytes, combo.get_key())
}

#[test]
fn mutation_bad_magic() {
    let (mut blob, key) = baseline_blob();
    blob[0] ^= 0xFF;
    let res = Database::open(&mut &blob[..], key);
    assert!(
        matches!(
            res,
            Err(DatabaseOpenError::VersionParse(
                DatabaseVersionParseError::InvalidKDBXIdentifier
            ))
        ),
        "BadMagic: unexpected result: {:?}",
        res
    );
}

#[test]
fn mutation_bad_kdbx_version() {
    let (mut blob, key) = baseline_blob();
    blob[10] = 5;
    blob[11] = 0;
    let res = Database::open(&mut &blob[..], key);
    assert!(
        matches!(
            res,
            Err(DatabaseOpenError::VersionParse(
                DatabaseVersionParseError::InvalidKDBXVersion { .. }
            ))
        ),
        "BadKdbxVersion: unexpected result: {:?}",
        res
    );
}

#[test]
fn mutation_truncated_at_header() {
    let (blob, key) = baseline_blob();
    let cut = (blob.len() / 4).clamp(20, 80);
    let truncated = &blob[..cut];
    let res = Database::open(&mut &truncated[..], key);
    assert!(res.is_err(), "TruncatedAtHeader: expected Err, got Ok");
}

#[test]
fn mutation_truncated_at_payload() {
    let (blob, key) = baseline_blob();
    let truncated = &blob[..blob.len() - 8];
    let res = Database::open(&mut &truncated[..], key);
    assert!(res.is_err(), "TruncatedAtPayload: expected Err, got Ok");
}

#[test]
fn mutation_bad_header_sha256() {
    let (mut blob, key) = baseline_blob();
    let header_end = locate_header_end(&blob).expect("locate header end");
    blob[header_end] ^= 0x01;
    let res = Database::open(&mut &blob[..], key);
    assert!(res.is_err(), "BadHeaderSha256: expected Err, got Ok");
}

#[test]
fn mutation_bad_header_hmac() {
    let (mut blob, key) = baseline_blob();
    let header_end = locate_header_end(&blob).expect("locate header end");
    blob[header_end + 32 + 1] ^= 0x80;
    let res = Database::open(&mut &blob[..], key);
    assert!(res.is_err(), "BadHeaderHmac: expected Err, got Ok");
}

#[test]
fn mutation_bad_inner_header() {
    let (mut blob, key) = baseline_blob();
    let header_end = locate_header_end(&blob).expect("locate header end");
    let target = header_end + 32 + 32 + 8;
    if target < blob.len() {
        blob[target] ^= 0xAA;
    }
    let res = Database::open(&mut &blob[..], key);
    assert!(res.is_err(), "BadInnerHeader: expected Err, got Ok");
}

#[test]
fn mutation_bad_cipher_id() {
    let (mut blob, key) = baseline_blob();
    let cipher_off = locate_header_field(&blob, 2).expect("locate cipher id");
    blob[cipher_off + 1] ^= 0xFF;
    let res = Database::open(&mut &blob[..], key);
    assert!(res.is_err(), "BadCipherId: expected Err, got Ok");
}

#[test]
fn mutation_bad_kdf_params() {
    let (mut blob, key) = baseline_blob();
    let kdf_off = locate_header_field(&blob, 11).expect("locate kdf params");
    blob[kdf_off] = 0xFF;
    blob[kdf_off + 1] = 0x7F;
    let res = Database::open(&mut &blob[..], key);
    assert!(res.is_err(), "BadKdfParams: expected Err, got Ok");
}

#[test]
fn mutation_data_after_end() {
    let (mut blob, key) = baseline_blob();
    blob.extend_from_slice(&[0u8; 64]);
    // Trailing-byte tolerance is reader-defined; either Ok or Err is fine,
    // we just don't want a panic. The test framework already fails on panic.
    let _ = Database::open(&mut &blob[..], key);
}

#[test]
fn mutation_wrong_password() {
    let (blob, _key) = baseline_blob();
    let wrong = DatabaseKey::new().with_password("not-the-password");
    let res = Database::open(&mut &blob[..], wrong);
    assert!(
        matches!(res, Err(DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey))),
        "WrongPassword: unexpected result: {:?}",
        res
    );
}

#[test]
fn mutation_keyfile_mismatch() {
    let combo = combo_by_label("aes256+gz+inner-chacha20+argon2d+pw+kf-raw32");
    let db = combo.minimal_database();
    let bytes = common::save_to_vec(&db, combo.get_key());

    let mut wrong_keyfile = vec![0u8; 32];
    wrong_keyfile[0] = 0xAA;
    let wrong = DatabaseKey::new()
        .with_password(DEMO_PASSWORD)
        .with_keyfile(&mut std::io::Cursor::new(wrong_keyfile))
        .expect("keyfile parse");

    let res = Database::open(&mut &bytes[..], wrong);
    assert!(
        matches!(res, Err(DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey))),
        "KeyfileMismatch: unexpected result: {:?}",
        res
    );
}

fn locate_header_end(blob: &[u8]) -> Option<usize> {
    let mut off = 12usize;
    while off + 5 <= blob.len() {
        let tag = blob[off];
        let len = u32::from_le_bytes([blob[off + 1], blob[off + 2], blob[off + 3], blob[off + 4]]) as usize;
        off += 5 + len;
        if tag == 0 {
            return Some(off);
        }
    }
    None
}

fn locate_header_field(blob: &[u8], tag_wanted: u8) -> Option<usize> {
    let mut off = 12usize;
    while off + 5 <= blob.len() {
        let tag = blob[off];
        let len = u32::from_le_bytes([blob[off + 1], blob[off + 2], blob[off + 3], blob[off + 4]]) as usize;
        if tag == tag_wanted {
            return Some(off + 5);
        }
        off += 5 + len;
        if tag == 0 {
            break;
        }
    }
    None
}
