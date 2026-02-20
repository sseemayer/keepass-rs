//! Types for representing data contained in a KeePass database
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
        use crate::{db::Entry, format::variant_dictionary::VariantDictionary};
        let mut db = Database::new(Default::default());

        let mut public_custom_data = VariantDictionary::new();
        public_custom_data.set("example", 42);

        db.config.public_custom_data = Some(public_custom_data);

        db.root.entries.push(Entry::new());
        db.root.entries.push(Entry::new());
        db.root.entries.push(Entry::new());

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
