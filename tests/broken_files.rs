#![forbid(unsafe_code)]

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use common::{combo_by_label, config_and_key_for, fast_combo, minimal_database, DEMO_PASSWORD};
use keepass::{Database, DatabaseKey};

fn baseline_blob() -> (Vec<u8>, DatabaseKey) {
    let combo = fast_combo();
    let (cfg, key) = config_and_key_for(&combo);
    let db = minimal_database(cfg);
    let bytes = common::save_to_vec(&db, key);
    (bytes, config_and_key_for(&combo).1)
}

fn assert_clean_error(blob: &[u8], key: DatabaseKey, label: &str) -> Result<(), String> {
    let res = catch_unwind(AssertUnwindSafe(|| Database::open(&mut &blob[..], key)));
    match res {
        Ok(Ok(_)) => Err(format!("{label}: parser returned Ok on broken input")),
        Ok(Err(_)) => Ok(()),
        Err(_) => Err(format!("{label}: parser PANICKED on broken input")),
    }
}

#[test]
fn mutation_bad_magic() {
    let (mut blob, key) = baseline_blob();
    blob[0] ^= 0xFF;
    assert_clean_error(&blob, key, "BadMagic").unwrap();
}

#[test]
fn mutation_bad_kdbx_version() {
    let (mut blob, key) = baseline_blob();
    blob[10] = 5;
    blob[11] = 0;
    assert_clean_error(&blob, key, "BadKdbxVersion").unwrap();
}

#[test]
fn mutation_truncated_at_header() {
    let (blob, key) = baseline_blob();
    let cut = (blob.len() / 4).clamp(20, 80);
    let truncated = &blob[..cut];
    assert_clean_error(truncated, key, "TruncatedAtHeader").unwrap();
}

#[test]
fn mutation_truncated_at_payload() {
    let (blob, key) = baseline_blob();
    let truncated = &blob[..blob.len() - 8];
    assert_clean_error(truncated, key, "TruncatedAtPayload").unwrap();
}

#[test]
fn mutation_bad_header_sha256() {
    let (mut blob, key) = baseline_blob();
    let header_end = locate_header_end(&blob).expect("locate header end");
    blob[header_end] ^= 0x01;
    assert_clean_error(&blob, key, "BadHeaderSha256").unwrap();
}

#[test]
fn mutation_bad_header_hmac() {
    let (mut blob, key) = baseline_blob();
    let header_end = locate_header_end(&blob).expect("locate header end");
    blob[header_end + 32 + 1] ^= 0x80;
    assert_clean_error(&blob, key, "BadHeaderHmac").unwrap();
}

#[test]
fn mutation_bad_inner_header() {
    let (mut blob, key) = baseline_blob();
    let header_end = locate_header_end(&blob).expect("locate header end");
    let target = header_end + 32 + 32 + 8;
    if target < blob.len() {
        blob[target] ^= 0xAA;
    }
    assert_clean_error(&blob, key, "BadInnerHeader").unwrap();
}

#[test]
fn mutation_bad_cipher_id() {
    let (mut blob, key) = baseline_blob();
    let cipher_off = locate_header_field(&blob, 2).expect("locate cipher id");
    blob[cipher_off + 1] ^= 0xFF;
    assert_clean_error(&blob, key, "BadCipherId").unwrap();
}

#[test]
fn mutation_bad_kdf_params() {
    let (mut blob, key) = baseline_blob();
    let kdf_off = locate_header_field(&blob, 11).expect("locate kdf params");
    blob[kdf_off] = 0xFF;
    blob[kdf_off + 1] = 0x7F;
    assert_clean_error(&blob, key, "BadKdfParams").unwrap();
}

#[test]
fn mutation_data_after_end() {
    let (mut blob, key) = baseline_blob();
    blob.extend_from_slice(&[0u8; 64]);
    let res = catch_unwind(AssertUnwindSafe(|| Database::open(&mut &blob[..], key)));
    if res.is_err() {
        panic!("DataAfterEnd: parser PANICKED on trailing bytes");
    }
}

#[test]
fn mutation_wrong_password() {
    let (blob, _key) = baseline_blob();
    let wrong = DatabaseKey::new().with_password("not-the-password");
    if Database::open(&mut &blob[..], wrong).is_ok() {
        panic!("WrongPassword: opened with wrong password");
    }
}

#[test]
fn mutation_keyfile_mismatch() {
    let combo = combo_by_label("aes256+gz+inner-chacha20+argon2d+pw+kf-raw32");
    let (cfg, key) = config_and_key_for(&combo);
    let db = minimal_database(cfg);
    let bytes = common::save_to_vec(&db, key);

    let mut wrong_keyfile = vec![0u8; 32];
    wrong_keyfile[0] = 0xAA;
    let wrong = DatabaseKey::new()
        .with_password(DEMO_PASSWORD)
        .with_keyfile(&mut std::io::Cursor::new(wrong_keyfile))
        .expect("keyfile parse");

    if Database::open(&mut &bytes[..], wrong).is_ok() {
        panic!("KeyfileMismatch: opened with wrong keyfile");
    }
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
