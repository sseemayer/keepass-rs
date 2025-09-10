//! Types for representing data contained in a KeePass database

pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod meta;
pub(crate) mod node;

#[cfg(feature = "_merge")]
pub(crate) mod merge;

#[cfg(feature = "totp")]
pub(crate) mod otp;

#[cfg(feature = "_merge")]
use std::collections::VecDeque;
use std::{collections::HashMap, str::FromStr};

use chrono::NaiveDateTime;
use uuid::Uuid;

pub use crate::db::{
    entry::{AutoType, AutoTypeAssociation, Entry, History, Value},
    group::Group,
    meta::{BinaryAttachment, BinaryAttachments, CustomIcons, Icon, MemoryProtection, Meta},
    node::{Node, NodeIter, NodeRef, NodeRefMut},
};

#[cfg(feature = "_merge")]
use crate::db::merge::{MergeError, MergeEvent, MergeEventType, MergeLog};

#[cfg(feature = "totp")]
pub use crate::db::otp::{TOTPAlgorithm, TOTP};

#[cfg(feature = "_merge")]
use crate::db::group::NodeLocation;
use crate::{
    config::DatabaseConfig,
    error::{DatabaseIntegrityError, DatabaseOpenError, ParseColorError},
    format::{
        kdb::parse_kdb,
        kdbx3::{decrypt_kdbx3, parse_kdbx3},
        kdbx4::{decrypt_kdbx4, parse_kdbx4},
        DatabaseVersion,
    },
    key::DatabaseKey,
};

/// A decrypted KeePass database
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Database {
    /// Configuration settings of the database such as encryption and compression algorithms
    pub config: DatabaseConfig,

    /// Binary attachments in the inner header
    pub header_attachments: Vec<HeaderAttachment>,

    /// Root node of the KeePass database
    pub root: Group,

    /// References to previously-deleted objects
    pub deleted_objects: DeletedObjects,

    /// Metadata of the KeePass database
    pub meta: Meta,
}

impl Database {
    /// Parse a database from a std::io::Read
    pub fn open(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Database, DatabaseOpenError> {}

    pub fn parse(data: &[u8], key: DatabaseKey) -> Result<Database, DatabaseOpenError> {}

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
    pub fn get_version(source: &mut dyn std::io::Read) -> Result<DatabaseVersion, DatabaseIntegrityError> {
        let mut data = vec![0; DatabaseVersion::get_version_header_size()];
        source.read_exact(&mut data)?;
        DatabaseVersion::parse(data.as_ref())
    }

    /// Create a new, empty database
    pub fn new(config: DatabaseConfig) -> Database {
        Self {
            config,
            header_attachments: Vec::new(),
            root: Group::new("Root"),
            deleted_objects: Default::default(),
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

pub const EXPIRY_TIME_TAG_NAME: &str = "ExpiryTime";
pub const LAST_MODIFICATION_TIME_TAG_NAME: &str = "LastModificationTime";
pub const CREATION_TIME_TAG_NAME: &str = "CreationTime";
pub const LAST_ACCESS_TIME_TAG_NAME: &str = "LastAccessTime";
pub const LOCATION_CHANGED_TAG_NAME: &str = "LocationChanged";

impl Times {
    fn get(&self, key: &str) -> Option<&NaiveDateTime> {
        self.times.get(key)
    }

    pub fn get_expiry(&self) -> Option<&NaiveDateTime> {
        self.times.get(EXPIRY_TIME_TAG_NAME)
    }

    pub fn set_expiry(&mut self, time: NaiveDateTime) {
        self.times.insert(EXPIRY_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_last_modification(&self) -> Option<&NaiveDateTime> {
        self.times.get(LAST_MODIFICATION_TIME_TAG_NAME)
    }

    pub fn set_last_modification(&mut self, time: NaiveDateTime) {
        self.times
            .insert(LAST_MODIFICATION_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_creation(&self) -> Option<&NaiveDateTime> {
        self.times.get(CREATION_TIME_TAG_NAME)
    }

    pub fn set_creation(&mut self, time: NaiveDateTime) {
        self.times.insert(CREATION_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_last_access(&self) -> Option<&NaiveDateTime> {
        self.times.get(LAST_ACCESS_TIME_TAG_NAME)
    }

    pub fn set_last_access(&mut self, time: NaiveDateTime) {
        self.times.insert(LAST_ACCESS_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_location_changed(&self) -> Option<&NaiveDateTime> {
        self.times.get(LOCATION_CHANGED_TAG_NAME)
    }

    pub fn set_location_changed(&mut self, time: NaiveDateTime) {
        self.times.insert(LOCATION_CHANGED_TAG_NAME.to_string(), time);
    }

    // Returns the current time, without the nanoseconds since
    // the last leap second.
    pub fn now() -> NaiveDateTime {
        let now = chrono::Utc::now().timestamp();
        chrono::DateTime::from_timestamp(now, 0).unwrap().naive_utc()
    }

    pub fn epoch() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }

    pub fn new() -> Times {
        let mut response = Times::default();
        let now = Times::now();
        response.set_creation(now);
        response.set_last_modification(now);
        response.set_last_access(now);
        response.set_location_changed(now);
        response.set_expiry(now);
        response.expires = false;
        response
    }
}

/// Binary attachments stored in a database inner header
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct HeaderAttachment {
    pub flags: u8,
    pub content: Vec<u8>,
}

/// Elements that have been previously deleted
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct DeletedObjects {
    pub objects: Vec<DeletedObject>,
}

impl DeletedObjects {
    pub fn contains(&self, uuid: Uuid) -> bool {
        for deleted_object in &self.objects {
            if deleted_object.uuid == uuid {
                return true;
            }
        }
        false
    }
}

/// A reference to a deleted element
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct DeletedObject {
    pub uuid: Uuid,
    pub deletion_time: NaiveDateTime,
}

#[cfg(test)]
mod database_tests {
    use std::fs::File;

    use crate::{error::DatabaseOpenError, Database, DatabaseKey};

    #[test]
    fn test_xml() -> Result<(), DatabaseOpenError> {
        let xml = Database::get_xml(
            &mut File::open("tests/resources/test_db_with_password.kdbx")?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert!(xml.len() > 100);

        Ok(())
    }

    #[test]
    fn test_open_invalid_version_header_size() {
        assert!(Database::parse(&[], DatabaseKey::new().with_password("testing")).is_err());
        assert!(Database::parse(
            &[0, 0, 0, 0, 0, 0, 0, 0],
            DatabaseKey::new().with_password("testing")
        )
        .is_err());
        assert!(Database::parse(
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            DatabaseKey::new().with_password("testing")
        )
        .is_err());
    }

    #[cfg(feature = "save_kdbx4")]
    #[test]
    fn test_save() {
        use crate::{db::Entry, variant_dictionary::VariantDictionary};
        let mut db = Database::new(Default::default());

        let mut public_custom_data = VariantDictionary::new();
        public_custom_data.set("example", 42);

        db.config.public_custom_data = Some(public_custom_data);

        db.root.add_child(Entry::new());
        db.root.add_child(Entry::new());
        db.root.add_child(Entry::new());

        let mut buffer = Vec::new();

        db.save(&mut buffer, DatabaseKey::new().with_password("testing"))
            .unwrap();

        let db_loaded = Database::open(
            &mut buffer.as_slice(),
            DatabaseKey::new().with_password("testing"),
        )
        .unwrap();

        assert_eq!(db, db_loaded);
    }
}
