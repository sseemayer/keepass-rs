use thiserror::Error;

use crate::{config::DatabaseVersion, db::Database, DatabaseKey, CURRENT_TARGET_DATABASE_VERSION};

impl Database {
    /// Upgrades the database to the current format version supported for saving.
    pub fn upgrade(&mut self) -> Result<(), DatabaseUpgradeError> {
        let can_upgrade = match (&self.config.version, &CURRENT_TARGET_DATABASE_VERSION) {
            (DatabaseVersion::KDB4(current), DatabaseVersion::KDB4(target)) => current < target,
            _ => false,
        };

        if can_upgrade {
            self.config.version = CURRENT_TARGET_DATABASE_VERSION;
            return Ok(());
        }

        if self.config.version == CURRENT_TARGET_DATABASE_VERSION {
            return Ok(());
        }

        Err(DatabaseUpgradeError {
            from_version: self.config.version.clone(),
            to_version: CURRENT_TARGET_DATABASE_VERSION,
        })
    }

    /// Saves the database to the given destination, using the provided key for encryption.
    pub fn save(
        &self,
        destination: &mut dyn std::io::Write,
        key: DatabaseKey,
    ) -> Result<(), DatabaseSaveError> {
        use crate::format::kdbx4::dump_kdbx4;

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion(self.config.version.clone())),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion(self.config.version.clone())),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion(self.config.version.clone())),
            DatabaseVersion::KDB4(_) => dump_kdbx4(self, &key, destination),
        }
    }
}

/// Error returned when a database cannot be upgraded to the current version.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("Upgrading database from {from_version} to {to_version} is not supported")]
pub struct DatabaseUpgradeError {
    /// Version of the database before the attempted upgrade.
    pub from_version: DatabaseVersion,

    /// Version to which the database would have been upgraded.
    pub to_version: DatabaseVersion,
}

/// Errors that can occur during saving of the database to a KDBX file
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseSaveError {
    /// I/O errors that can occur while writing the database to the destination, such as file system errors
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors related to XML serialization of the database
    #[error(transparent)]
    Serialization(#[from] quick_xml::SeError),

    /// Errors related to database key operations
    #[error(transparent)]
    Key(#[from] crate::key::DatabaseKeyError),

    /// Errors related to encryption operations
    #[error(transparent)]
    Cryptography(#[from] crate::crypt::CryptographyError),

    /// Errors related to random number generation
    #[error(transparent)]
    Random(#[from] getrandom::Error),

    /// Attempted to save a database with an unsupported version.
    #[error(
        "Saving database version {0} is not supported; call Database::upgrade before saving it as {CURRENT_TARGET_DATABASE_VERSION}"
    )]
    UnsupportedVersion(DatabaseVersion),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_version_error_suggests_kdbx41_upgrade() {
        let mut db = Database::new();
        db.config.version = DatabaseVersion::KDB4(0);

        let error = db
            .save(&mut Vec::new(), DatabaseKey::new().with_password("test"))
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "Saving database version KDBX4.0 is not supported; call Database::upgrade before saving it as KDBX4.1"
        );
    }

    #[test]
    fn kdbx40_database_can_be_upgraded_and_saved() {
        let mut db = Database::new();
        db.config.version = DatabaseVersion::KDB4(0);
        let key = DatabaseKey::new().with_password("test");
        let mut output = Vec::new();

        db.upgrade().unwrap();
        db.save(&mut output, key.clone()).unwrap();

        let reopened = Database::open(&mut output.as_slice(), key).unwrap();
        assert_eq!(reopened.config.version, CURRENT_TARGET_DATABASE_VERSION);
        assert_eq!(db.config.version, CURRENT_TARGET_DATABASE_VERSION);
    }

    #[test]
    fn upgrade_does_not_downgrade_a_newer_database() {
        let mut db = Database::new();
        db.config.version = DatabaseVersion::KDB4(2);

        let error = db.upgrade().unwrap_err();

        assert_eq!(error.from_version, DatabaseVersion::KDB4(2));
        assert_eq!(error.to_version, CURRENT_TARGET_DATABASE_VERSION);
        assert_eq!(db.config.version, DatabaseVersion::KDB4(2));
    }

    #[test]
    fn upgrading_current_database_is_a_noop() {
        let mut db = Database::new();

        db.upgrade().unwrap();

        assert_eq!(db.config.version, CURRENT_TARGET_DATABASE_VERSION);
    }

    #[test]
    fn upgrade_does_not_convert_older_major_versions() {
        let mut db = Database::new();
        db.config.version = DatabaseVersion::KDB3(1);

        let error = db.upgrade().unwrap_err();

        assert_eq!(error.from_version, DatabaseVersion::KDB3(1));
        assert_eq!(error.to_version, CURRENT_TARGET_DATABASE_VERSION);
        assert_eq!(db.config.version, DatabaseVersion::KDB3(1));
    }
}
