//! tests for keyfile format support
#![cfg(feature = "save_kdbx4")]
#![forbid(unsafe_code)]
#![allow(clippy::indexing_slicing, clippy::expect_used)]

mod common;

use std::io::Cursor;

use common::{baseline_combo, KeyfileKind};
use keepass::{Database, DatabaseKey};

fn drive(kind: KeyfileKind, label: &str) {
    let combo = baseline_combo();
    let bytes = kind.to_bytes();
    let key = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(bytes.clone()))
        .expect("keyfile parse");

    let db = combo.minimal_database();
    let saved = common::save_to_vec(&db, key);

    let reopen_key = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(bytes))
        .expect("keyfile parse 2");
    let parsed = Database::open(&mut saved.as_slice(), reopen_key)
        .unwrap_or_else(|e| panic!("{} reopen failed: {:?}", label, e));
    assert_eq!(parsed.root().entries().count(), 1);
    assert_eq!(parsed.root().groups().count(), 0);
}

#[test]
fn keyfile_raw32_round_trip() {
    drive(KeyfileKind::Raw32([7u8; 32]), "raw32");
}

#[test]
fn keyfile_hex_round_trip() {
    drive(KeyfileKind::Hex([0x42u8; 32]), "hex");
}

#[test]
fn keyfile_xml_v1_round_trip() {
    drive(KeyfileKind::XmlV1([0x33u8; 32]), "xml-v1");
}

#[test]
fn keyfile_xml_v2_round_trip() {
    drive(KeyfileKind::XmlV2([0x55u8; 32]), "xml-v2");
}

#[test]
fn keyfile_invalid_xml_falls_back_to_hash() {
    let combo = baseline_combo();
    let garbage = b"<not><a><keyfile></a></not>".to_vec();
    let key = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(garbage.clone()))
        .expect("garbage keyfile accepted");
    let db = combo.minimal_database();
    let saved = common::save_to_vec(&db, key);
    let reopen = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(garbage))
        .expect("garbage keyfile accepted 2");
    let parsed = Database::open(&mut saved.as_slice(), reopen).expect("garbage keyfile reopens");
    assert_eq!(parsed.root().entries().count(), 1);
    assert_eq!(parsed.root().groups().count(), 0);
}

#[test]
fn keyfile_empty_is_consistent() {
    let combo = baseline_combo();
    let key = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(Vec::<u8>::new()))
        .expect("empty keyfile accepted");
    let db = combo.minimal_database();
    let saved = common::save_to_vec(&db, key);
    let reopen = DatabaseKey::new()
        .with_keyfile(&mut Cursor::new(Vec::<u8>::new()))
        .expect("empty keyfile accepted");
    let parsed = Database::open(&mut saved.as_slice(), reopen).expect("empty keyfile reopens");
    assert_eq!(parsed.root().entries().count(), 1);
    assert_eq!(parsed.root().groups().count(), 0);
}
