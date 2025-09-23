use thiserror::Error;

use crate::{
    format::{DatabaseVersion, DatabaseVersionParseError},
    DatabaseKey,
};

use crate::db::Database;

impl Database {
    /// Get the version of a database without decrypting it
    pub fn get_version(source: &mut dyn std::io::Read) -> Result<DatabaseVersion, GetDatabaseVersionError> {
        let mut data = vec![0; DatabaseVersion::get_version_header_size()];
        source.read_exact(&mut data)?;
        Ok(DatabaseVersion::parse(data.as_ref())?)
    }

    /// Load a database from a source implementing `std::io::Read`
    pub fn open(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Self, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        Ok(Database::parse(data.as_ref(), key)?)
    }

    pub fn get_xml(data: &[u8], key: DatabaseKey) -> Result<String, DatabaseParseError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => Err(DatabaseParseError::Unsupported(1)),
            DatabaseVersion::KDB2(_) => Err(DatabaseParseError::Unsupported(2)),
            DatabaseVersion::KDB3(_) => Ok(crate::format::kdbx3::get_xml(data, &key)?),
            DatabaseVersion::KDB4(_) => Ok(crate::format::kdbx4::get_xml(data, &key)?),
        }
    }

    /// Parse a database from a byte slice
    pub fn parse(data: &[u8], key: DatabaseKey) -> Result<Self, DatabaseParseError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => Ok(crate::format::kdb::parse_kdb(data, &key)?),
            DatabaseVersion::KDB2(_) => Err(DatabaseParseError::Unsupported(2)),
            DatabaseVersion::KDB3(_) => Ok(crate::format::kdbx3::parse_kdbx3(data, &key)?),
            DatabaseVersion::KDB4(_) => Ok(crate::format::kdbx4::parse_kdbx4(data, &key)?),
        }
    }
}

#[derive(Error, Debug)]
pub enum GetDatabaseVersionError {
    #[error("I/O error reading database version: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Parse(#[from] DatabaseVersionParseError),
}

#[derive(Error, Debug)]
pub enum DatabaseOpenError {
    #[error("I/O error reading database: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Parse(#[from] DatabaseParseError),
}

#[derive(Error, Debug)]
pub enum DatabaseParseError {
    #[error(transparent)]
    Version(#[from] DatabaseVersionParseError),

    #[error("Error parsing database: unsupported version {0}")]
    Unsupported(u8),

    #[error("Error parsing KDB v1 database: {0}")]
    KDB(#[from] crate::format::kdb::ParseKdbError),

    #[error("Error parsing KDB v3 database: {0}")]
    KDB3(#[from] crate::format::kdbx3::KDBX3ParseError),

    #[error("Error parsing KDB v4 database: {0}")]
    KDB4(#[from] crate::format::kdbx4::ParseKdbx4Error),
}
