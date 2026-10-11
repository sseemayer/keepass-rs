//! tests for binary attachment reading/writing
#![cfg(feature = "save_kdbx4")]
#![forbid(unsafe_code)]

mod common;

use common::combo_by_label;
use keepass::db::{Database, Value};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn drive(label: &str, payloads: Vec<Vec<u8>>) {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let mut db = Database::with_config(combo.get_config());

    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "attachments");
        for (i, content) in payloads.iter().enumerate() {
            e.add_attachment(format!("blob-{i}.bin"), Value::Unprotected(content.clone()));
        }
    }

    let bytes = common::save_to_vec(&db, combo.get_key());
    let parsed = Database::open(&mut bytes.as_slice(), combo.get_key())
        .unwrap_or_else(|err| panic!("{}: reopen failed: {:?}", label, err));

    assert_eq!(
        parsed.num_attachments(),
        payloads.len(),
        "{}: total attachments count",
        label
    );

    let root = parsed.root();
    let entry = root
        .entries()
        .next()
        .unwrap_or_else(|| panic!("{}: no entry under root", label));

    for (i, expected) in payloads.iter().enumerate() {
        let name = format!("blob-{i}.bin");
        let att = entry
            .attachment_by_name(&name)
            .unwrap_or_else(|| panic!("{}: missing attachment {}", label, name));
        assert_eq!(
            att.data.get().as_slice(),
            expected.as_slice(),
            "{}: payload {} differs",
            label,
            i
        );
    }
}

#[test]
fn binary_pool_sizes_zero_one_sixteen() {
    drive("sizes-tiny", vec![Vec::new(), vec![0x00], (0u8..16).collect()]);
}

#[test]
fn binary_pool_4kib_random() {
    let mut buf = vec![0u8; 4 * 1024];
    StdRng::seed_from_u64(0x1234_5678).fill_bytes(&mut buf);
    drive("sizes-4kib", vec![buf]);
}

#[test]
fn binary_pool_1mib_random() {
    let mut buf = vec![0u8; 1024 * 1024];
    StdRng::seed_from_u64(0x9876_5432).fill_bytes(&mut buf);
    drive("sizes-1mib", vec![buf]);
}

#[test]
fn binary_pool_byte_patterns() {
    drive(
        "byte-patterns",
        vec![
            vec![0u8; 256],
            vec![0xFFu8; 256],
            (0..=255u8).collect(),
            vec![
                0xC3, 0x28, 0xA0, 0xA1, 0xE2, 0x28, 0xA1, 0xE2, 0x82, 0x28, 0xF0, 0x28, 0x8C, 0xBC, 0xF0, 0x90,
                0x28, 0xBC, 0xF0, 0x28, 0x8C, 0x28,
            ],
        ],
    );
}

/// Removing an attachment leaves a gap in the attachment IDs; the file refers
/// to attachments by position, so every later attachment must still read back
/// as its own data — in entries and in their history.
#[test]
fn attachments_after_a_removed_one_keep_their_data() {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let mut db = Database::with_config(combo.get_config());

    let (first, second, third) = {
        let mut root = db.root_mut();
        let mut add = |title: &str, data: &[u8]| {
            let mut e = root.add_entry();
            e.set_unprotected("Title", title);
            e.add_attachment("file.bin", Value::Unprotected(data.to_vec()));
            e.id()
        };
        (
            add("first", b"one"),
            add("second", b"two"),
            add("third", b"three"),
        )
    };
    // The third entry also keeps an older version with an attachment of its own.
    db.entry_mut(third).unwrap().edit_tracking(|e| {
        e.add_attachment("new.bin", Value::Unprotected(b"four".to_vec()));
    });

    // The first attachment goes: ID 0 is free, 1..3 remain.
    db.entry_mut(first).unwrap().remove_attachment_by_name("file.bin");
    assert_eq!(db.num_attachments(), 3);

    let bytes = common::save_to_vec(&db, combo.get_key());
    let parsed = Database::open(&mut bytes.as_slice(), combo.get_key()).expect("reopen");

    let data = |entry: &keepass::db::EntryRef<'_>, name: &str| {
        entry.attachment_by_name(name).map(|a| a.data.get().clone())
    };
    assert_eq!(data(&parsed.entry(first).unwrap(), "file.bin"), None);
    assert_eq!(
        data(&parsed.entry(second).unwrap(), "file.bin"),
        Some(b"two".to_vec())
    );
    let third = parsed.entry(third).unwrap();
    assert_eq!(data(&third, "file.bin"), Some(b"three".to_vec()));
    assert_eq!(data(&third, "new.bin"), Some(b"four".to_vec()));
    let old = third.historical(0).expect("the older version");
    assert_eq!(data(&old, "file.bin"), Some(b"three".to_vec()));
}
