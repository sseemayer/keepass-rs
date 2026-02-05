use thiserror::Error;

use crate::{config::DatabaseVersion, Database, DatabaseKey};

impl Database {
    /// Save a database to a std::io::Write
    pub fn save(
        &self,
        destination: &mut dyn std::io::Write,
        key: DatabaseKey,
    ) -> Result<(), DatabaseSaveError> {
        use crate::format::kdbx4::dump_kdbx4;

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion),
            DatabaseVersion::KDB4(_) => Ok(dump_kdbx4(self, &key, destination)?),
        }
    }
}

#[derive(Debug, Error)]
pub enum DatabaseSaveError {
    #[error("Unsupported database version - can only save KDBX4 databases")]
    UnsupportedVersion,

    #[error(transparent)]
    SaveKdbx4Error(#[from] crate::format::kdbx4::SaveKdbx4Error),
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::{
        db::{fields, Times},
        Database, DatabaseKey, Value,
    };

    /// Test that a new database can be created and saved without errors, and loaded back correctly
    #[test]
    fn test_save() {
        let mut db = Database::new();

        // create an elaborate entry to test serialization and deserialization of all fields
        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Entry 1");
                e.set(fields::USERNAME, Value::String("user".to_string()));
                e.set_protected(fields::PASSWORD, "asdf");

                e.autotype = Some(crate::db::AutoType {
                    enabled: true,
                    default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string()),
                    data_transfer_obfuscation: None,
                    associations: vec![],
                });

                e.tags.insert("test".to_string());
                e.tags.insert("example".to_string());

                e.custom_data.insert(
                    "answer".to_string(),
                    crate::db::CustomDataItem {
                        value: Some(crate::db::CustomDataValue::String("42".to_string())),
                        last_modification_time: None,
                    },
                );

                e.custom_data.insert(
                    "binary".to_string(),
                    crate::db::CustomDataItem {
                        value: Some(crate::db::CustomDataValue::Binary(vec![1, 2, 3, 4])),
                        last_modification_time: Some(Times::now()),
                    },
                );

                e.icon_id = Some(5);

                e.foreground_color = Some(crate::db::Color { r: 255, g: 0, b: 0 });
                e.background_color = Some(crate::db::Color { r: 0, g: 255, b: 0 });

                e.override_url = Some("https://example.com/login".to_string());
            })
            .id();

        // make a tracking edit to test history serialization and deserialization
        db.entry_mut(entry_id).unwrap().edit_tracking(|e| {
            e.set_protected(fields::PASSWORD, "newpassword");
        });

        db.root_mut()
            .add_group()
            .edit(|g| {
                g.name = "Group 1".to_string();
                g.add_entry()
                    .edit(|e| e.set_unprotected(fields::TITLE, "Entry 2"));
            })
            .add_group()
            .edit(|g| {
                g.name = "Subgroup 1".to_string();
                g.add_entry()
                    .edit(|e| e.set_unprotected(fields::TITLE, "Entry 3"));
            });

        let key = DatabaseKey::new().with_password("testpass");
        let mut buffer: Vec<u8> = Vec::new();

        db.save(&mut buffer, key.clone())
            .expect("Failed to save database");

        let loaded_db = Database::open(&mut buffer.as_slice(), key).expect("Failed to load saved database");

        assert_eq!(db, loaded_db);
    }

    /// test that errors are thrown for invalid database versions
    #[test]
    fn test_save_unsupported_version() {
        let mut db = Database::new();
        db.config.version = crate::config::DatabaseVersion::KDB(1);

        let key = DatabaseKey::new().with_password("testpass");
        let mut buffer: Vec<u8> = Vec::new();

        let result = db.save(&mut buffer, key);

        assert!(matches!(
            result,
            Err(crate::db::save::DatabaseSaveError::UnsupportedVersion)
        ));

        let mut db = Database::new();
        db.config.version = crate::config::DatabaseVersion::KDB2(1);

        let key = DatabaseKey::new().with_password("testpass");
        let mut buffer: Vec<u8> = Vec::new();

        let result = db.save(&mut buffer, key);

        assert!(matches!(
            result,
            Err(crate::db::save::DatabaseSaveError::UnsupportedVersion)
        ));

        let mut db = Database::new();
        db.config.version = crate::config::DatabaseVersion::KDB3(1);

        let key = DatabaseKey::new().with_password("testpass");
        let mut buffer: Vec<u8> = Vec::new();

        let result = db.save(&mut buffer, key);

        assert!(matches!(
            result,
            Err(crate::db::save::DatabaseSaveError::UnsupportedVersion)
        ));
    }
}
