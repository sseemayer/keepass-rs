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
