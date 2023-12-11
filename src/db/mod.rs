//! Types for representing data contained in a KeePass database

pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod meta;
pub(crate) mod node;

#[cfg(feature = "totp")]
pub(crate) mod otp;

use std::{collections::HashMap, str::FromStr};

use chrono::NaiveDateTime;
use uuid::Uuid;

pub use crate::db::{
    entry::{AutoType, AutoTypeAssociation, Entry, History, Value},
    group::{Group, MergeEvent, MergeEventType, MergeLog},
    meta::{BinaryAttachment, BinaryAttachments, CustomIcons, Icon, MemoryProtection, Meta},
    node::{Node, NodeIter, NodeRef, NodeRefMut},
};

#[cfg(feature = "totp")]
pub use crate::db::otp::{TOTPAlgorithm, TOTP};

use crate::{
    config::DatabaseConfig,
    db::group::NodeLocation2,
    db::node::NodePath,
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
#[derive(Debug, PartialEq, Eq, Clone)]
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
    pub fn open(
        source: &mut dyn std::io::Read,
        key: DatabaseKey,
    ) -> Result<Database, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        match database_version {
            DatabaseVersion::KDB(_) => parse_kdb(data.as_ref(), &key),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion.into()),
            DatabaseVersion::KDB3(_) => parse_kdbx3(data.as_ref(), &key),
            DatabaseVersion::KDB4(_) => parse_kdbx4(data.as_ref(), &key),
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

        match self.config.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB4(_) => dump_kdbx4(self, &key, destination),
        }
    }

    /// Helper function to load a database into its internal XML chunks
    pub fn get_xml(
        source: &mut dyn std::io::Read,
        key: DatabaseKey,
    ) -> Result<Vec<u8>, DatabaseOpenError> {
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
            deleted_objects: Default::default(),
            meta: Default::default(),
        }
    }

    /// Merge this database with another version of this same database.
    /// This function will use the UUIDs to detect that entries and groups are
    /// the same.
    pub fn merge(&mut self, other: &Database) -> Result<MergeLog, String> {
        self.merge_group(vec![], &other.root)
    }

    fn merge_group(
        &mut self,
        current_group_path: NodePath,
        current_group: &Group,
    ) -> Result<MergeLog, String> {
        let mut log = MergeLog::default();

        let destination_group = match self.root.get_internal(&current_group_path).unwrap() {
            crate::db::NodeRef::Group(g) => g,
            _ => return Err("".to_string()),
        };
        // We don't need the original group here, only a copy so that we can do some
        // queries on it.
        let destination_group = destination_group.clone();
        let current_group_uuid = current_group.uuid;

        for other_entry in &current_group.entries() {
            // find the existing location
            let destination_entry_location = self.root.find_node_location_2(other_entry.uuid);

            // The group already exists in the destination database.
            if let Some(destination_entry_location) = destination_entry_location {
                let parent_group_uuid = destination_entry_location.last().unwrap();

                // The group already exists and is at the right location, so we can proceed and merge
                // the two groups.
                if parent_group_uuid == &current_group_uuid {
                    // let new_merge_log = self.merge_group(new_group_location, other_group)?;
                    // log = log.merge_with(&new_merge_log);
                    continue;
                }

                // TODO continue the merge logic for entries
            }
        }

        for other_group in &current_group.groups() {
            let mut new_group_location = current_group_path.clone();
            let other_group_uuid = other_group.uuid;
            let other_group_uuid_str = other_group.uuid.to_string();
            new_group_location.push(crate::db::node::NodePathElement::UUID(
                &other_group_uuid_str,
            ));

            let destination_group_location = self.root.find_node_location_2(other_group.uuid);
            // The group already exists in the destination database.
            if let Some(destination_group_location) = destination_group_location {
                let parent_group_uuid = destination_group_location.last().unwrap();

                // The group already exists and is at the right location, so we can proceed and merge
                // the two groups.
                if parent_group_uuid == &other_group_uuid {
                    let new_merge_log = self.merge_group(new_group_location, other_group)?;
                    log = log.merge_with(&new_merge_log);
                    continue;
                }

                // The group already exists but is not at the right location. We might have to
                // relocate it.
                // FIXME use the location to get the group!
                let existing_group = self
                    .root
                    .find_group(other_group.uuid.clone(), true)
                    .unwrap();
                let existing_group_location_changed =
                    match existing_group.times.get_location_changed() {
                        Some(t) => *t,
                        None => {
                            log.warnings.push(format!(
                                "Entry {} did not have a location changed timestamp",
                                existing_group.uuid
                            ));
                            Times::now()
                        }
                    };
                let other_group_location_changed = match other_group.times.get_location_changed() {
                    Some(t) => *t,
                    None => {
                        log.warnings.push(format!(
                            "Entry {} did not have a location changed timestamp",
                            other_group.uuid
                        ));
                        Times::epoch()
                    }
                };
                // The other group was moved after the current group, so we have to relocate it.
                if existing_group_location_changed < other_group_location_changed {
                    self.relocate_node(
                        &other_group.uuid,
                        &destination_group_location,
                        &current_group_path,
                    )?;

                    log.events.push(MergeEvent {
                        event_type: MergeEventType::GroupLocationUpdated,
                        node_uuid: other_group.uuid,
                    });

                    let new_merge_log = self.merge_group(new_group_location, other_group)?;
                    log = log.merge_with(&new_merge_log);
                    continue;
                }

                let new_merge_log = self.merge_group(new_group_location, other_group)?;
                log = log.merge_with(&new_merge_log);
                continue;
            }

            // The group doesn't exist in the destination, we create it
            let mut new_group = other_group.clone().to_owned();
            new_group.children = vec![];
            self.root.add_group(new_group, &new_group_location);
            let new_merge_log = self.merge_group(new_group_location, other_group)?;
            log = log.merge_with(&new_merge_log);
        }

        Ok(log)
    }

    fn relocate_node(
        &mut self,
        node_uuid: &Uuid,
        from: &NodeLocation2,
        to: &NodePath,
    ) -> Result<(), String> {
        // FIXME this isn't great. The new functions return the root node but not
        // the old search functions.
        let mut new_from = from.clone();
        new_from.remove(0);

        let source_group = match self.root.find_mut(&new_from).unwrap() {
            NodeRefMut::Group(g) => g,
            NodeRefMut::Entry(_) => panic!("".to_string()),
        };

        // FIXME this should work for entries too!!!
        // FIXME should we update the location changed timestamp??
        let relocated_group = source_group.remove_group(&node_uuid)?;

        let destination_group = match self.root.get_mut_internal(&to).unwrap() {
            NodeRefMut::Group(g) => g,
            NodeRefMut::Entry(_) => panic!("".to_string()),
        };
        destination_group
            .children
            .push(Node::Group(relocated_group));
        Ok(())
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
        self.times
            .insert(LAST_ACCESS_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_location_changed(&self) -> Option<&NaiveDateTime> {
        self.times.get(LOCATION_CHANGED_TAG_NAME)
    }

    pub fn set_location_changed(&mut self, time: NaiveDateTime) {
        self.times
            .insert(LOCATION_CHANGED_TAG_NAME.to_string(), time);
    }

    // Returns the current time, without the nanoseconds since
    // the last leap second.
    pub fn now() -> NaiveDateTime {
        let now = chrono::Utc::now().naive_utc().timestamp();
        chrono::NaiveDateTime::from_timestamp_opt(now, 0).unwrap()
    }

    pub fn epoch() -> NaiveDateTime {
        chrono::NaiveDateTime::from_timestamp_opt(0, 0).unwrap()
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

/// Collection of custom data fields for an entry or metadata
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomData {
    pub items: HashMap<String, CustomDataItem>,
}

/// Custom data field for an entry or metadata for internal use
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomDataItem {
    pub value: Option<Value>,
    pub last_modification_time: Option<NaiveDateTime>,
}

/// Custom data field for an entry or metadata from XML data
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomDataItemDenormalized {
    pub key: String,
    pub custom_data_item: CustomDataItem,
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

/// A reference to a deleted element
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct DeletedObject {
    pub uuid: Uuid,
    pub deletion_time: NaiveDateTime,
}

/// A color value for the Database, or Entry
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[cfg(feature = "serialization")]
impl serde::Serialize for Color {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl FromStr for Color {
    type Err = ParseColorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('#') || s.len() != 7 {
            return Err(ParseColorError(s.to_string()));
        }

        let v = u64::from_str_radix(s.trim_start_matches('#'), 16)
            .map_err(|_e| ParseColorError(s.to_string()))?;

        let r = ((v >> 16) & 0xff) as u8;
        let g = ((v >> 8) & 0xff) as u8;
        let b = (v & 0xff) as u8;

        Ok(Self { r, g, b })
    }
}

impl Color {
    pub fn to_string(&self) -> String {
        format!("#{:0x}{:0x}{:0x}", self.r, self.g, self.b)
    }
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

    #[cfg(feature = "save_kdbx4")]
    #[test]
    fn test_save() {
        use crate::db::Entry;
        let mut db = Database::new(Default::default());

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
