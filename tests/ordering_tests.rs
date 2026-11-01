//! Regression test for preserving groups and entries order across save/open.
#![cfg(feature = "save_kdbx4")]

mod common;

use crate::common::{save_then_open, DEMO_PASSWORD};
use keepass::{db::fields, Database, DatabaseKey};

#[test]
fn group_and_entry_order_should_survive_round_trip() {
    let db = setup_database();
    let key = DatabaseKey::new().with_password(DEMO_PASSWORD);

    // Write database to byte array and read it
    let actual = save_then_open(&db, key);

    // Read entries and groups
    let root = actual.root();
    let actual_group_titles = root.groups().map(|g| g.name.to_string()).collect::<Vec<String>>();
    let actual_entry_titles = root
        .entries()
        .map(|e| e.get_title().unwrap_or("").to_string())
        .collect::<Vec<String>>();

    // Check titles are in correct order
    assert_eq!(actual_group_titles, generate_group_titles());
    assert_eq!(actual_entry_titles, generate_entry_titles());
}

#[test]
fn group_and_entry_order_should_survive_round_trip_after_deletion() {
    let mut db = setup_database();
    let key = DatabaseKey::new().with_password(DEMO_PASSWORD);

    // Delete some of the groups and entries
    let deleted_group_indexes = [0, 8, 19];
    let deleted_entry_indexes = [0, 7, 19];

    let group_ids = db.root().groups().map(|group| group.id()).collect::<Vec<_>>();
    let entry_ids = db.root().entries().map(|entry| entry.id()).collect::<Vec<_>>();

    for deleted_group_index in deleted_group_indexes {
        db.group_mut(group_ids[deleted_group_index])
            .expect("group should exist")
            .remove()
    }

    for deleted_entry_index in deleted_entry_indexes {
        db.entry_mut(entry_ids[deleted_entry_index])
            .expect("entry should exist")
            .remove();
    }

    // Write database to byte array and read it
    let actual = save_then_open(&db, key);

    // Read entries and groups
    let root = actual.root();
    let actual_group_titles = root.groups().map(|g| g.name.to_string()).collect::<Vec<String>>();
    let actual_entry_titles = root
        .entries()
        .map(|e| e.get_title().unwrap_or("").to_string())
        .collect::<Vec<String>>();

    // Check titles are in correct order
    assert_eq!(
        actual_group_titles,
        filter_indexes(generate_group_titles(), &deleted_group_indexes),
    );
    assert_eq!(
        actual_entry_titles,
        filter_indexes(generate_entry_titles(), &deleted_entry_indexes),
    );
}

fn generate_entry_titles() -> Vec<String> {
    (0..20)
        .into_iter()
        .map(|index| format!("Entry_{index}"))
        .collect()
}

fn generate_group_titles() -> Vec<String> {
    (0..20)
        .into_iter()
        .map(|index| format!("Group_{index}"))
        .collect()
}

fn setup_database() -> Database {
    let mut db = Database::new();
    let mut root = db.root_mut();

    let entry_titles = generate_entry_titles();
    let group_titles = generate_group_titles();

    for entry_title in &entry_titles {
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, entry_title);
    }
    for group_title in &group_titles {
        let mut group = root.add_group();
        group.name = group_title.to_string();
    }

    db
}

fn filter_indexes(titles: Vec<String>, indexes: &[usize]) -> Vec<String> {
    titles
        .into_iter()
        .enumerate()
        .filter_map(|(index, title)| (!indexes.contains(&index)).then_some(title))
        .collect()
}
