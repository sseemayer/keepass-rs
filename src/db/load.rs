use thiserror::Error;

use crate::{
    format::{
        kdb::{parse_kdb, ParseKdbError},
        //kdbx3::parse_kdbx3,
        //kdbx4::parse_kdbx4,
    },
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
    pub fn load(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Self, DatabaseLoadError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        Ok(Database::parse(data.as_ref(), key)?)
    }

    /// Parse a database from a byte slice
    pub fn parse(data: &[u8], key: DatabaseKey) -> Result<Self, DatabaseParseError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => Ok(parse_kdb(data, &key)?),
            //DatabaseVersion::KDB2(_) => Err(DatabaseParseError::KDB2),
            //DatabaseVersion::KDB3(_) => Ok(parse_kdbx3(data, &key)?),
            //DatabaseVersion::KDB4(_) => Ok(parse_kdbx4(data, &key)?),
            _ => panic!("TODO implement"), // TODO: implement
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
pub enum DatabaseLoadError {
    #[error("I/O error reading database: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Parse(#[from] DatabaseParseError),
}

#[derive(Error, Debug)]
pub enum DatabaseParseError {
    #[error(transparent)]
    Version(#[from] DatabaseVersionParseError),

    #[error("Error parsing KDB v1 database: {0}")]
    KDB(#[from] ParseKdbError),

    #[error("Error parsing KDB v2 database: unsupported version")]
    KDB2,
    //#[error("Error parsing KDB v3 database: {0}")]
    //KDB3(#[from] ParseKdb3Error),

    //#[error("Error parsing KDB v4 database: {0}")]
    //KDB4(#[from] ParseKdb4Error),
}
