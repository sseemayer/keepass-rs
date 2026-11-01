//! Regression tests for empty entry fields.
//! Some KeePass implementations may add or remove empty entry fields.
//! To preserve the original database structure, a round trip should retain
//! explicitly present empty fields and shouldn't
//! add empty default fields (UserName, Password, etc.).
#![cfg(feature = "save_kdbx4")]

mod common;

use crate::common::{save_then_open, DEMO_PASSWORD};
use keepass::{db::fields, Database, DatabaseKey};

const ENTRY_TITLE: &str = "DemoEntry";

#[test]
fn empty_entry_fields_should_survive_round_trip() {
    let db = create_database_with_empty_fields();
    let key = DatabaseKey::new().with_password(DEMO_PASSWORD);

    // Write database to byte array and read it
    let actual = save_then_open(&db, key);

    // Empty standard and custom fields should be present after parsing
    let root = actual.root();
    let entry = root
        .entry_by_name(ENTRY_TITLE)
        .expect(format!("Entry '{ENTRY_TITLE}' should present in database").as_str());

    assert_eq!(entry.get(fields::USERNAME), Some(""));
    assert_eq!(entry.get("CustomField"), Some(""));
}

#[test]
fn empty_default_fields_should_not_be_added_after_round_trip() {
    let db = create_database_without_empty_fields();
    let key = DatabaseKey::new().with_password(DEMO_PASSWORD);

    // Write database to byte array and read it
    let actual = save_then_open(&db, key);

    // Entry should not have empty default fields
    let root = actual.root();
    let entry = root
        .entry_by_name(ENTRY_TITLE)
        .expect(format!("Entry '{ENTRY_TITLE}' should present in database").as_str());

    assert_eq!(entry.get(fields::USERNAME), None);
    assert_eq!(entry.get(fields::PASSWORD), None);
    assert_eq!(entry.get(fields::URL), None);
    assert_eq!(entry.get(fields::NOTES), None);
}

fn create_database_with_empty_fields() -> Database {
    let mut db = Database::new();
    let mut root = db.root_mut();
    let mut entry = root.add_entry();

    // Add standard KeePass field and custom field.
    entry.set_unprotected(fields::TITLE, ENTRY_TITLE);
    entry.set_unprotected(fields::USERNAME, "");
    entry.set_unprotected("CustomField", "");

    db
}

fn create_database_without_empty_fields() -> Database {
    let mut db = Database::new();
    let mut root = db.root_mut();
    let mut entry = root.add_entry();

    entry.set_unprotected(fields::TITLE, ENTRY_TITLE);

    db
}
