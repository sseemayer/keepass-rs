//! Types representing an opened KeePass database
//!
//! The main entry point is the [Database] struct, which can be created with [Database::new] or
//! loaded from a file using [Database::open]. The example uses explicit type annotations to show
//! what is happening, but these can be omitted in your own code.
//!
//! ```
//! use keepass::{Database, db::{fields, AttachmentMut, EntryMut, GroupMut, Value}};
//! # fn main() {
//! let mut db = Database::new();
//! let mut root: GroupMut<'_> = db.root_mut();
//!
//! // Add a new child group to the root group
//! let mut group: GroupMut<'_> = root.add_group();
//!
//! // GroupMut dereferences to &mut Group, so you can access most of its fields directly
//! group.name = "My Group".into();
//! group.notes = Some("This is an example group".into());
//!
//! // Add a new entry to the group
//! let mut entry: EntryMut<'_> = root.add_entry();
//!
//! // EntryMut dereferences to &mut Entry, so you can access most of its fields directly
//! entry.set_unprotected(fields::TITLE, "My Entry");
//! entry.set_unprotected(fields::USERNAME, "jdoe");
//! entry.set_protected(fields::PASSWORD, "hunter2");
//! entry.tags.push("example".into());
//!
//! // Adding the attachment to an entry will store it in the associated database and add a
//! // reference to the entry.
//! entry.add_attachment("myfile.txt", Value::unprotected(b"Hello, world!".to_vec()));
//!
//! // You can also use the fluent API to chain method calls together.
//! let entry_id = root.add_group()
//!     .edit(|g: &mut GroupMut| {
//!         g.name = "Another Group".into();
//!         g.notes = Some("This is another example group".into());
//!     })
//!     .add_entry()
//!     .edit(|e: &mut EntryMut<'_>| {
//!         e.set_unprotected(fields::TITLE, "Another Entry");
//!         e.set_unprotected(fields::USERNAME, "asmith");
//!         e.set_protected(fields::PASSWORD, "password123");
//!         e.tags.push("example".into());
//!     }).id();
//! # }
//! ```
pub mod fields;

mod open;
mod types;

#[cfg(feature = "_merge")]
mod merge;

#[cfg(feature = "totp")]
mod otp;

#[cfg(feature = "save_kdbx4")]
mod save;

#[cfg(feature = "save_kdbx4")]
pub use crate::db::save::DatabaseSaveError;

pub use crate::db::{
    open::{DatabaseFormatError, DatabaseOpenError},
    types::*,
};

#[cfg(feature = "totp")]
pub use crate::db::otp::{TOTPAlgorithm, TOTPError, TOTP};

#[cfg(test)]
mod database_tests {
    use std::fs::File;

    use crate::{db::DatabaseOpenError, Database, DatabaseKey};

    #[test]
    fn test_xml() -> Result<(), DatabaseOpenError> {
        let xml = Database::get_xml(
            &mut File::open("tests/resources/test_db_with_password.kdbx")?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert!(xml.len() > 100);

        Ok(())
    }

    #[test]
    fn test_open_invalid_version_header_size() {
        assert!(Database::parse(&[], DatabaseKey::new().with_password("testing")).is_err());
        assert!(Database::parse(
            &[0, 0, 0, 0, 0, 0, 0, 0],
            DatabaseKey::new().with_password("testing")
        )
        .is_err());
        assert!(Database::parse(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            DatabaseKey::new().with_password("testing")
        )
        .is_err());
    }

    #[cfg(feature = "save_kdbx4")]
    #[test]
    fn test_save() {
        use crate::format::variant_dictionary::VariantDictionary;
        let mut db = Database::new();

        let mut public_custom_data = VariantDictionary::new();
        public_custom_data.set("example", 42);

        db.config.public_custom_data = Some(public_custom_data);

        db.root_mut().add_entry();
        db.root_mut().add_entry();
        db.root_mut().add_entry();

        let mut buffer = Vec::new();

        db.save(&mut buffer, DatabaseKey::new().with_password("testing"))
            .unwrap();

        let db_loaded = Database::open(
            &mut buffer.as_slice(),
            DatabaseKey::new().with_password("testing"),
        )
        .unwrap();

        assert_eq!(db, db_loaded);
    }
}
