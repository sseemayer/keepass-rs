//! Merging entries whose attachments changed.
#![cfg(all(feature = "_merge", feature = "save_kdbx4"))]
#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]

mod common;

use chrono::Duration;
use common::combo_by_label;
use keepass::db::{Database, EntryId, EntryRef, Times, Value};

fn data(entry: &EntryRef<'_>, name: &str) -> Option<Vec<u8>> {
    entry.attachment_by_name(name).map(|a| a.data.get().clone())
}

fn reopen(db: &Database) -> Database {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let bytes = common::save_to_vec(db, combo.get_key());
    Database::open(&mut bytes.as_slice(), combo.get_key()).expect("reopen")
}

/// Push an entry's modification time forward, as an edit made later would.
fn touch(db: &mut Database, id: EntryId, seconds: i64) {
    let mut entry = db.entry_mut(id).unwrap();
    entry.times.last_modification = Some(Times::now() + Duration::seconds(seconds));
}

/// A saved database with one entry holding `key.bin`.
fn base() -> (Database, EntryId) {
    let combo = combo_by_label("aes256+none+inner-chacha20+argon2d");
    let mut db = Database::with_config(combo.get_config());
    let id = {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "server");
        e.add_attachment("key.bin", Value::Unprotected(b"old key".to_vec()));
        e.id()
    };
    touch(&mut db, id, 0);
    (reopen(&db), id)
}

#[test]
fn an_attachment_changed_in_the_source_reaches_the_destination() {
    let (mut dest, id) = base();
    let mut source = dest.clone();
    source.entry_mut(id).unwrap().edit_tracking(|e| {
        e.add_attachment("key.bin", Value::Unprotected(b"new key".to_vec()));
    });
    touch(&mut source, id, 10);
    let source = reopen(&source);

    dest.merge(&source).unwrap();

    let entry = dest.entry(id).unwrap();
    assert_eq!(data(&entry, "key.bin"), Some(b"new key".to_vec()));
    let dest = reopen(&dest);
    let entry = dest.entry(id).unwrap();
    assert_eq!(data(&entry, "key.bin"), Some(b"new key".to_vec()));
    let history: Vec<_> = (0..entry.history.as_ref().unwrap().get_entries().len())
        .map(|i| data(&entry.historical(i).unwrap(), "key.bin"))
        .collect();
    assert!(history.contains(&Some(b"old key".to_vec())));
    assert!(!history.contains(&Some(b"new key".to_vec())));
    assert_eq!(dest.num_attachments(), 2);
}

#[test]
fn an_attachment_removed_in_the_source_is_removed_in_the_destination() {
    let (mut dest, id) = base();
    let mut source = dest.clone();
    source
        .entry_mut(id)
        .unwrap()
        .edit_tracking(|e| e.as_mut().remove_attachment_by_name("key.bin"));
    touch(&mut source, id, 10);
    let source = reopen(&source);

    dest.merge(&source).unwrap();

    let dest = reopen(&dest);
    let entry = dest.entry(id).unwrap();
    assert_eq!(data(&entry, "key.bin"), None);
    assert_eq!(
        data(&entry.historical(0).unwrap(), "key.bin"),
        Some(b"old key".to_vec())
    );
}

/// Attachment IDs are per database: the same ID can hold other data on each side.
#[test]
fn a_new_entry_brings_its_own_attachment_data() {
    let (mut dest, _) = base();
    let mut source = dest.clone();
    // each side adds a different entry and file; both get the next free ID
    dest.root_mut()
        .add_entry()
        .add_attachment("mine.bin", Value::Unprotected(b"dest data".to_vec()));
    let new = {
        let mut root = source.root_mut();
        let mut e = root.add_entry();
        e.add_attachment("theirs.bin", Value::Unprotected(b"source data".to_vec()));
        e.id()
    };
    touch(&mut source, new, 10);
    let mut dest = reopen(&dest);
    let source = reopen(&source);

    dest.merge(&source).unwrap();

    let dest = reopen(&dest);
    assert_eq!(
        data(&dest.entry(new).unwrap(), "theirs.bin"),
        Some(b"source data".to_vec())
    );
    let mine = dest
        .iter_all_entries()
        .find(|e| e.attachment_by_name("mine.bin").is_some())
        .unwrap();
    assert_eq!(data(&mine, "mine.bin"), Some(b"dest data".to_vec()));
    assert_eq!(dest.num_attachments(), 3);
}

#[test]
fn merging_an_unchanged_copy_adds_no_attachments() {
    let (mut dest, id) = base();
    dest.entry_mut(id).unwrap().edit_tracking(|e| {
        e.add_attachment("key.bin", Value::Unprotected(b"new key".to_vec()));
    });
    touch(&mut dest, id, 10);
    let mut dest = reopen(&dest);
    let source = dest.clone();

    dest.merge(&source).unwrap();
    assert_eq!(dest.num_attachments(), 2);
}

#[test]
fn an_older_source_leaves_the_destination_attachment_alone() {
    let (mut dest, id) = base();
    let mut source = dest.clone();
    source.entry_mut(id).unwrap().edit_tracking(|e| {
        e.add_attachment("key.bin", Value::Unprotected(b"stale key".to_vec()));
    });
    touch(&mut source, id, 5);
    dest.entry_mut(id).unwrap().edit_tracking(|e| {
        e.add_attachment("key.bin", Value::Unprotected(b"new key".to_vec()));
    });
    touch(&mut dest, id, 10);
    let mut dest = reopen(&dest);
    let source = reopen(&source);

    dest.merge(&source).unwrap();

    let dest = reopen(&dest);
    let entry = dest.entry(id).unwrap();
    assert_eq!(data(&entry, "key.bin"), Some(b"new key".to_vec()));
}
