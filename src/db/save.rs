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

    use crate::{db::fields, Database, DatabaseKey};

    /// Test that a new database can be created and saved without errors, and loaded back correctly
    #[test]
    fn test_save() {
        let mut db = Database::new();

        db.root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "Entry 1"));

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
}
