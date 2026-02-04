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

    /// Extract the inner XML from a database without fully parsing it
    pub fn get_xml(data: &[u8], key: DatabaseKey) -> Result<String, DatabaseParseError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => Err(DatabaseParseError::Unsupported(database_version)),
            DatabaseVersion::KDB2(_) => Err(DatabaseParseError::Unsupported(database_version)),
            DatabaseVersion::KDB3(_) => Ok(crate::format::kdbx3::get_xml(data, &key)?),
            DatabaseVersion::KDB4(_) => Ok(crate::format::kdbx4::get_xml(data, &key)?),
        }
    }

    /// Parse a database from a byte slice
    pub fn parse(data: &[u8], key: DatabaseKey) -> Result<Self, DatabaseParseError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => Ok(crate::format::kdb::parse_kdb(data, &key)?),
            DatabaseVersion::KDB2(_) => Err(DatabaseParseError::Unsupported(database_version)),
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
    Unsupported(DatabaseVersion),

    #[error("Error parsing KDB v1 database: {0}")]
    KDB(#[from] crate::format::kdb::ParseKdbError),

    #[error("Error parsing KDB v3 database: {0}")]
    KDB3(#[from] crate::format::kdbx3::KDBX3ParseError),

    #[error("Error parsing KDB v4 database: {0}")]
    KDB4(#[from] crate::format::kdbx4::ParseKdbx4Error),
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use crate::{db::Database, key::DatabaseKey};

    /// test that getting the version of an invalid file fails gracefully
    #[test]
    fn test_get_version_invalid_file() {
        let data = b"This is not a valid KeePass database";

        let result = Database::get_version(&mut std::io::Cursor::new(data));
        assert!(result.is_err());
    }

    /// test that getting the version of a valid KDB file works
    #[test]
    fn test_get_version_valid_kdb() {
        let mut file = File::open("tests/resources/test_db_kdb_with_password.kdb").unwrap();
        let version = Database::get_version(&mut file).unwrap();

        assert_eq!(version, crate::format::DatabaseVersion::KDB(3));
    }

    /// test that getting the version of a valid KDBX3 file works
    #[test]
    fn test_get_version_valid_kdbx3() {
        let mut file = File::open("tests/resources/test_db_with_password.kdbx").unwrap();
        let version = Database::get_version(&mut file).unwrap();

        assert_eq!(version, crate::format::DatabaseVersion::KDB3(1));
    }

    /// test that getting the version of a valid KDBX4 file works
    #[test]
    fn test_get_version_valid_kdbx4() {
        let mut file = File::open("tests/resources/test_db_kdbx4_with_password_aes.kdbx").unwrap();
        let version = Database::get_version(&mut file).unwrap();

        assert_eq!(version, crate::format::DatabaseVersion::KDB4(1));
    }

    /// test that opening an empty file fails gracefully
    #[test]
    fn test_open_empty_file() {
        let data = b"";
        let key = DatabaseKey::new().with_password("password");

        let result = Database::parse(data.as_ref(), key);
        assert!(result.is_err());
    }

    /// test that opening an invalid file fails gracefully
    #[test]
    fn test_open_invalid_file() {
        let data = b"This is not a valid KeePass database";
        let key = DatabaseKey::new().with_password("password");

        let result = Database::parse(data.as_ref(), key);
        assert!(result.is_err());
    }

    /// test that opening a valid KDBX4 file works
    // NOTE: more comprehensive tests for various database files are in tests/file_read_tests.rs
    #[test]
    fn test_open_valid_kdbx4_file() {
        let mut file = File::open("tests/resources/test_db_kdbx4_with_password_aes.kdbx").unwrap();
        let key = DatabaseKey::new().with_password("demopass");

        let db = Database::open(&mut file, key).unwrap();

        assert_eq!(db.meta.database_name.as_deref(), Some("Passwords"));
    }

    /// test that getting XML from a valid KDBX4 file works
    #[test]
    fn test_get_xml_valid_kdbx4_file() {
        let mut file = File::open("tests/resources/test_db_kdbx4_with_password_aes.kdbx").unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let key = DatabaseKey::new().with_password("demopass");

        let xml = Database::get_xml(&data, key).unwrap();

        assert!(xml.contains("<KeePassFile"));
    }
}
