//! tests for binary attachment reading/writing
#![cfg(feature = "save_kdbx4")]
#![forbid(unsafe_code)]

mod common;

use common::combo_by_label;
use keepass::db::{Database, History, Value};
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

/// Removing an entry lets go of the files its older versions used too: a file
/// only the history refers to must leave the database and the saved file,
/// while other entries keep theirs.
#[test]
fn removing_an_entry_drops_the_files_only_its_history_used() {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let mut db = Database::with_config(combo.get_config());

    // The kept file comes first, so removing the other leaves no gap in the IDs.
    let (gone, kept) = {
        let mut root = db.root_mut();
        let mut k = root.add_entry();
        k.add_attachment("kept.bin", Value::Unprotected(b"kept".to_vec()));
        let kept = k.id();
        let mut e = root.add_entry();
        e.add_attachment("old.bin", Value::Unprotected(b"old".to_vec()));
        (e.id(), kept)
    };
    // An older version keeps the file; the current one no longer has it (as
    // a file saved by another client can be).
    db.entry_mut(gone)
        .unwrap()
        .edit_tracking(|e| e.set_unprotected("Title", "newer"));
    let mut without = db.clone();
    without
        .entry_mut(gone)
        .unwrap()
        .remove_attachment_by_name("old.bin");
    let current = (*without.entry(gone).unwrap()).clone();
    *db.entry_mut(gone).unwrap() = current;
    let bytes = common::save_to_vec(&db, combo.get_key());
    let mut db = Database::open(&mut bytes.as_slice(), combo.get_key()).expect("reopen");
    assert_eq!(db.entry(gone).unwrap().attachments().count(), 0);
    assert_eq!(
        db.entry(gone)
            .unwrap()
            .historical(0)
            .unwrap()
            .attachments()
            .count(),
        1
    );
    assert_eq!(db.num_attachments(), 2);

    db.entry_mut(gone).unwrap().track_changes().remove();
    assert_eq!(
        db.num_attachments(),
        1,
        "the file only the removed history used is gone"
    );

    let bytes = common::save_to_vec(&db, combo.get_key());
    let parsed = Database::open(&mut bytes.as_slice(), combo.get_key()).expect("reopen");
    assert_eq!(parsed.num_attachments(), 1);
    let kept = parsed.entry(kept).unwrap();
    assert_eq!(
        kept.attachment_by_name("kept.bin").map(|a| a.data.get().clone()),
        Some(b"kept".to_vec())
    );
}

/// Trimming an entry's history by replacing it leaves the files only the
/// dropped versions used; removing unused attachments takes them out of the
/// database and the saved file, and leaves references that later changes can
/// rely on.
#[test]
fn unused_attachments_leave_after_history_is_trimmed() {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let mut db = Database::with_config(combo.get_config());

    let id = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.add_attachment("old.bin", Value::Unprotected(b"old".to_vec()));
        e.id()
    };
    // The older version keeps old.bin; the current one has new.bin instead.
    db.entry_mut(id).unwrap().edit_tracking(|e| {
        e.add_attachment("new.bin", Value::Unprotected(b"new".to_vec()));
    });
    let mut without = db.clone();
    without
        .entry_mut(id)
        .unwrap()
        .remove_attachment_by_name("old.bin");
    let current = (*without.entry(id).unwrap()).clone();
    *db.entry_mut(id).unwrap() = current;
    assert_eq!(db.num_attachments(), 2);
    assert_eq!(db.remove_unused_attachments(), 0, "history still uses old.bin");

    // The history is trimmed away: old.bin is used by nothing now.
    db.entry_mut(id).unwrap().history = Some(History::default());
    assert_eq!(db.remove_unused_attachments(), 1);
    assert_eq!(db.num_attachments(), 1);

    let bytes = common::save_to_vec(&db, combo.get_key());
    let parsed = Database::open(&mut bytes.as_slice(), combo.get_key()).expect("reopen");
    assert_eq!(parsed.num_attachments(), 1);
    let entry = parsed.entry(id).unwrap();
    assert_eq!(
        entry.attachment_by_name("new.bin").map(|a| a.data.get().clone()),
        Some(b"new".to_vec())
    );

    // The rebuilt references hold: removing the last file empties the pool.
    db.entry_mut(id).unwrap().remove_attachment_by_name("new.bin");
    assert_eq!(db.num_attachments(), 0);
}
