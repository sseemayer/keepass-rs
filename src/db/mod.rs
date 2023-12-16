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
    db::group::NodeLocation,
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
        current_group_path: NodeLocation,
        current_group: &Group,
    ) -> Result<MergeLog, String> {
        let mut log = MergeLog::default();

        let destination_group = match self.root.find_group(&current_group_path) {
            Some(g) => g,
            None => {
                return Err(format!(
                    "Could not find group at location {:?}",
                    current_group_path
                ))
            }
        };

        // We don't need the original group here, only a copy so that we can do some
        // queries on it.
        let destination_group = destination_group.clone();
        let current_group_uuid = current_group.uuid;

        for other_entry in &current_group.entries() {
            // find the existing location
            let destination_entry_location = self.root.find_node_location(other_entry.uuid);

            // The group already exists in the destination database.
            if let Some(destination_entry_location) = destination_entry_location {
                let parent_group_uuid = destination_entry_location.last().unwrap();

                let mut existing_entry_location = destination_entry_location.clone();
                // FIXME we shouldn't have to remove the root group.
                existing_entry_location.remove(0);
                existing_entry_location.push(other_entry.uuid);

                // The entry already exists but is not at the right location. We might have to
                // relocate it.
                let existing_entry = self
                    .root
                    .find_entry(&existing_entry_location)
                    .unwrap()
                    .clone();

                // The entry already exists and is at the right location, so we can proceed and merge
                // the two groups.
                if parent_group_uuid != &current_group_uuid {
                    let source_location_changed_time =
                        match other_entry.times.get_location_changed() {
                            Some(t) => *t,
                            None => {
                                log.warnings.push(format!(
                                    "Entry {} did not have a location updated timestamp",
                                    other_entry.uuid
                                ));
                                Times::epoch()
                            }
                        };
                    let destination_location_changed =
                        match existing_entry.times.get_location_changed() {
                            Some(t) => *t,
                            None => {
                                log.warnings.push(format!(
                                    "Entry {} did not have a location updated timestamp",
                                    other_entry.uuid
                                ));
                                Times::now()
                            }
                        };
                    if source_location_changed_time > destination_location_changed {
                        log.events.push(MergeEvent {
                            event_type: MergeEventType::EntryLocationUpdated,
                            node_uuid: other_entry.uuid,
                        });
                        self.relocate_node(
                            &other_entry.uuid,
                            &destination_entry_location,
                            &current_group_path,
                        )?;
                    }
                }

                if existing_entry == **other_entry {
                    continue;
                }

                let source_last_modification = match other_entry.times.get_last_modification() {
                    Some(t) => *t,
                    None => {
                        log.warnings.push(format!(
                            "Entry {} did not have a last modification timestamp",
                            other_entry.uuid
                        ));
                        Times::epoch()
                    }
                };
                let destination_last_modification =
                    match existing_entry.times.get_last_modification() {
                        Some(t) => *t,
                        None => {
                            log.warnings.push(format!(
                                "Entry {} did not have a last modification timestamp",
                                other_entry.uuid
                            ));
                            Times::now()
                        }
                    };

                if destination_last_modification == source_last_modification {
                    if !existing_entry.has_diverged_from(&other_entry) {
                        // This should never happen.
                        // This means that an entry was updated without updating the last modification
                        // timestamp.
                        return Err(
                            "Entries have the same modification time but are not the same!"
                                .to_string(),
                        );
                    }
                    continue;
                }

                let mut merged_entry: Entry = Entry::default();
                let mut entry_merge_log: MergeLog = MergeLog::default();

                if destination_last_modification > source_last_modification {
                    (merged_entry, entry_merge_log) = existing_entry.merge(other_entry)?;
                } else {
                    (merged_entry, entry_merge_log) = other_entry.clone().merge(&existing_entry)?;
                }

                if existing_entry.eq(&merged_entry) {
                    continue;
                }

                // The entry already exists but is not at the right location. We might have to
                // relocate it.
                let mut existing_entry =
                    self.root.find_entry_mut(&existing_entry_location).unwrap();
                *existing_entry = merged_entry.clone();

                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryUpdated,
                    node_uuid: merged_entry.uuid,
                });
                log.append(&entry_merge_log);
                continue;
            }

            if self.deleted_objects.contains(other_entry.uuid) {
                continue;
            }
            // The entry doesn't exist in the destination, we create it
            let mut new_entry = other_entry.clone().to_owned();

            let mut new_entry_parent_group = match self.root.find_group_mut(&current_group_path) {
                Some(g) => g,
                None => return Err(format!("Could not find group {:?}", current_group_path)),
            };
            new_entry_parent_group.add_child(new_entry.clone());

            // TODO should we update the time info for the entry?
            log.events.push(MergeEvent {
                event_type: MergeEventType::EntryCreated,
                node_uuid: new_entry.uuid,
            });
        }

        for other_group in &current_group.groups() {
            let mut new_group_location = current_group_path.clone();
            let other_group_uuid = other_group.uuid;
            new_group_location.push(other_group_uuid);

            let destination_group_location = self.root.find_node_location(other_group.uuid);
            // The group already exists in the destination database.
            if let Some(destination_group_location) = destination_group_location {
                let parent_group_uuid = destination_group_location.last().unwrap();

                // The group already exists and is at the right location, so we can proceed and merge
                // the two groups.
                if parent_group_uuid == &other_group_uuid {
                    let new_merge_log = self.merge_group(new_group_location, other_group)?;
                    log.append(&new_merge_log);
                    continue;
                }

                let mut existing_group_location = destination_group_location.clone();
                // FIXME we shouldn't have to remove the root group.
                existing_group_location.remove(0);
                existing_group_location.push(other_group_uuid);

                // The group already exists but is not at the right location. We might have to
                // relocate it.
                let existing_group = self.root.find_group(&existing_group_location).unwrap();
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
                    log.append(&new_merge_log);
                    continue;
                }

                let new_merge_log = self.merge_group(new_group_location, other_group)?;
                log.append(&new_merge_log);
                continue;
            }

            // The group doesn't exist in the destination, we create it
            let mut new_group = other_group.clone().to_owned();
            new_group.children = vec![];
            log.events.push(MergeEvent {
                event_type: MergeEventType::GroupCreated,
                node_uuid: new_group.uuid.clone(),
            });
            let mut new_group_parent_group = match self.root.find_group_mut(&current_group_path) {
                Some(g) => g,
                None => return Err(format!("Could not find group at {:?}", current_group_path)),
            };
            new_group_parent_group.add_child(new_group.clone());

            let new_merge_log = self.merge_group(new_group_location, other_group)?;
            log.append(&new_merge_log);
        }

        Ok(log)
    }

    fn relocate_node(
        &mut self,
        node_uuid: &Uuid,
        from: &NodeLocation,
        to: &NodeLocation,
    ) -> Result<(), String> {
        // FIXME this isn't great. The new functions return the root node but not
        // the old search functions.
        let mut new_from = from.clone();
        new_from.remove(0);

        let source_group = match self.root.find_mut(&new_from).unwrap() {
            NodeRefMut::Group(g) => g,
            NodeRefMut::Entry(_) => panic!("".to_string()),
        };

        // FIXME should we update the location changed timestamp??
        let relocated_node = source_group.remove_node(&node_uuid)?;

        let destination_group = match self.root.find_mut(&to).unwrap() {
            NodeRefMut::Group(g) => g,
            NodeRefMut::Entry(_) => panic!("".to_string()),
        };
        destination_group.children.push(relocated_node);
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
