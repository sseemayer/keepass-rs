//! Types for representing data contained in a KeePass database

pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod meta;
pub(crate) mod node;

#[cfg(feature = "totp")]
pub(crate) mod otp;

use std::collections::HashMap;

use chrono::NaiveDateTime;

pub use crate::db::{
    entry::{AutoType, AutoTypeAssociation, Entry, History, Value},
    group::Group,
    meta::{BinaryAttachment, BinaryAttachments, Meta},
    node::{Node, NodeIter, NodeRef, NodeRefMut},
};

#[cfg(feature = "totp")]
pub use crate::db::otp::{TOTPAlgorithm, TOTP};

use crate::{
    config::DatabaseConfig,
    error::{DatabaseIntegrityError, DatabaseOpenError},
    format::{
        kdb::parse_kdb,
        kdbx3::{decrypt_kdbx3, parse_kdbx3},
        kdbx4::{decrypt_kdbx4, parse_kdbx4},
        DatabaseVersion,
    },
    key::DatabaseKey,
};

/// A decrypted KeePass database
#[derive(Debug)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Database {
    /// Configuration settings of the database such as encryption and compression algorithms
    pub config: DatabaseConfig,

    /// Binary attachments in the inner header
    pub header_attachments: Vec<HeaderAttachment>,

    /// Root node of the KeePass database
    pub root: Group,

    /// Metadata of the KeePass database
    pub meta: Meta,
}

impl Database {
    /// Parse a database from a std::io::Read
    pub fn open(
        source: &mut dyn std::io::Read,
        key: DatabaseKey,
    ) -> Result<Database, DatabaseOpenError> {
        let key_elements = key.get_key_elements()?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        match database_version {
            DatabaseVersion::KDB(_) => parse_kdb(data.as_ref(), &key_elements),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion.into()),
            DatabaseVersion::KDB3(_) => parse_kdbx3(data.as_ref(), &key_elements),
            DatabaseVersion::KDB4(_) => parse_kdbx4(data.as_ref(), &key_elements),
        }
    }

    /// Save a database to a std::io::Write
    #[cfg(feature = "save_kdbx4")]
    pub fn save(
        &self,
        destination: &mut dyn std::io::Write,
        key: DatabaseKey,
    ) -> Result<(), crate::error::DatabaseSaveError> {
        use crate::error::DatabaseSaveError;
        use crate::format::kdbx4::dump_kdbx4;

        let key_elements = key.get_key_elements()?;

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB4(_) => dump_kdbx4(self, &key_elements, destination),
        }
    }

    /// Helper function to load a database into its internal XML chunks
    pub fn get_xml(
        source: &mut dyn std::io::Read,
        key: DatabaseKey,
    ) -> Result<Vec<u8>, DatabaseOpenError> {
        let key_elements = key.get_key_elements()?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        let data = match database_version {
            DatabaseVersion::KDB(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => decrypt_kdbx3(data.as_ref(), &key_elements)?.2,
            DatabaseVersion::KDB4(_) => decrypt_kdbx4(data.as_ref(), &key_elements)?.3,
        };

        Ok(data)
    }

    /// Get the version of a database without decrypting it
    pub fn get_version(
        source: &mut dyn std::io::Read,
    ) -> Result<DatabaseVersion, DatabaseIntegrityError> {
        let mut data = Vec::new();
        data.resize(DatabaseVersion::get_version_header_size(), 0);
        source.read(&mut data)?;
        DatabaseVersion::parse(data.as_ref())
    }

    /// Create a new, empty database
    pub fn new(config: DatabaseConfig) -> Database {
        Self {
            config,
            header_attachments: Vec::new(),
            root: Group::new("Root"),
            meta: Default::default(),
        }
    }
}

/// Timestamps for a Group or Entry
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Times {
    /// Does this node expire
    pub expires: bool,

    /// Number of usages
    pub usage_count: usize,

    /// Using chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub times: HashMap<String, NaiveDateTime>,
}

impl Times {
    fn get(&self, key: &str) -> Option<&NaiveDateTime> {
        self.times.get(key)
    }
}

/// Collection of custom data fields for an entry or metadata
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomData {
    pub items: Vec<CustomDataItem>,
}

/// Custom data field for an entry or metadata
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomDataItem {
    pub key: String,
    pub value: Option<Value>,
    pub last_modification_time: Option<NaiveDateTime>,
}

/// Binary attachments stored in a database inner header
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct HeaderAttachment {
    pub flags: u8,
    pub content: Vec<u8>,
}
