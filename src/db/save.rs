use thiserror::Error;

use crate::{config::DatabaseVersion, db::Database, DatabaseKey};

impl Database {
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
            DatabaseVersion::KDB4(_) => dump_kdbx4(self, &key, destination),
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseSaveError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Serialization(#[from] quick_xml::SeError),

    #[error(transparent)]
    Key(#[from] crate::key::DatabaseKeyError),

    #[error(transparent)]
    Cryptography(#[from] crate::crypt::CryptographyError),

    #[error(transparent)]
    Random(#[from] getrandom::Error),

    #[error("Unsupported database version")]
    UnsupportedVersion,
}
