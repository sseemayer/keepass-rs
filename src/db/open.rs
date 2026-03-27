use thiserror::Error;

use crate::{
    config::DatabaseVersion,
    db::Database,
    format::{
        kdb::parse_kdb,
        kdbx3::{decrypt_kdbx3, parse_kdbx3},
        kdbx4::{decrypt_kdbx4, parse_kdbx4},
        DatabaseVersionParseError,
    },
    DatabaseKey,
};

impl Database {
    /// Parse a database from a std::io::Read
    pub fn open(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Database, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        Database::parse(data.as_ref(), key)
    }

    pub fn parse(data: &[u8], key: DatabaseKey) -> Result<Database, DatabaseOpenError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => parse_kdb(data, &key),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => parse_kdbx3(data, &key),
            DatabaseVersion::KDB4(_) => parse_kdbx4(data, &key),
        }
    }

    /// Helper function to load a database into its internal XML chunks
    pub fn get_xml(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Vec<u8>, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        let data = match database_version {
            DatabaseVersion::KDB(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => decrypt_kdbx3(data.as_ref(), &key)?.2,
            DatabaseVersion::KDB4(_) => decrypt_kdbx4(data.as_ref(), &key)?.3,
        };

        Ok(data)
    }

    /// Get the version of a database without decrypting it
    pub fn get_version(source: &mut dyn std::io::Read) -> Result<DatabaseVersion, DatabaseOpenError> {
        let mut data = vec![0; DatabaseVersion::get_version_header_size()];
        source.read_exact(&mut data)?;
        let version = DatabaseVersion::parse(data.as_ref())?;
        Ok(version)
    }
}

/// Errors that can occur when opening a database
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseOpenError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Unexpected end of file")]
    UnexpectedEof,

    #[error(transparent)]
    VersionParse(#[from] DatabaseVersionParseError),

    #[error("Unsupported database version")]
    UnsupportedVersion,

    #[error(transparent)]
    Key(#[from] crate::key::DatabaseKeyError),

    #[error(transparent)]
    Cryptography(#[from] crate::crypt::CryptographyError),

    #[error(transparent)]
    Format(#[from] DatabaseFormatError),
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseFormatError {
    #[error(transparent)]
    Kdb(#[from] crate::format::kdb::KdbOpenError),

    #[error(transparent)]
    Kdbx3(#[from] crate::format::kdbx3::Kdbx3OpenError),

    #[error(transparent)]
    Kdbx4(#[from] crate::format::kdbx4::Kdbx4OpenError),
}
