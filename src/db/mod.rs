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
    pub fn open(source: &mut dyn std::io::Read, key: DatabaseKey) -> Result<Database, DatabaseOpenError> {
        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        Database::parse(data.as_ref(), key)
    }

    pub fn parse(data: &[u8], key: DatabaseKey) -> Result<Database, DatabaseOpenError> {
        let database_version = DatabaseVersion::parse(data)?;

        match database_version {
            DatabaseVersion::KDB(_) => parse_kdb(data, &key),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion.into()),
            DatabaseVersion::KDB3(_) => parse_kdbx3(data, &key),
            DatabaseVersion::KDB4(_) => parse_kdbx4(data, &key),
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
    #[cfg(feature = "_merge")]
    pub fn merge(&mut self, other: &Database) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();
        log.append(&self.merge_group(vec![], &other.root, false)?);
        log.append(&self.merge_deletions(&other)?);
        Ok(log)
    }

    #[cfg(feature = "_merge")]
    fn merge_deletions(&mut self, other: &Database) -> Result<MergeLog, MergeError> {
        // Utility function to search for a UUID in the VecDeque of deleted objects.
        let is_in_deleted_queue = |uuid: Uuid, deleted_groups_queue: &VecDeque<DeletedObject>| -> bool {
            for deleted_object in deleted_groups_queue {
                // This group still has a child group, but it is not going to be deleted.
                if deleted_object.uuid == uuid {
                    return true;
                }
            }
            false
        };

        let mut log = MergeLog::default();

        let mut new_deleted_objects = self.deleted_objects.clone();

        // We start by deleting the entries, since we will only remove groups if they are empty.
        for deleted_object in &other.deleted_objects.objects {
            if new_deleted_objects.contains(deleted_object.uuid) {
                continue;
            }
            let entry_location = match self.find_node_location(deleted_object.uuid) {
                Some(l) => l,
                None => continue,
            };

            let parent_group = match self.root.find_group_mut(&entry_location) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(entry_location)),
            };

            let entry = match parent_group.find_entry(&vec![deleted_object.uuid]) {
                Some(e) => e,
                // This uuid might refer to a group, which will be handled later.
                None => continue,
            };

            let entry_last_modification = match entry.times.get_last_modification() {
                Some(t) => *t,
                None => {
                    log.warnings.push(format!(
                        "Entry {} did not have a last modification timestamp",
                        entry.uuid
                    ));
                    Times::now()
                }
            };

            if entry_last_modification < deleted_object.deletion_time {
                parent_group.remove_node(&deleted_object.uuid)?;
                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryDeleted,
                    node_uuid: deleted_object.uuid,
                });

                new_deleted_objects.objects.push(deleted_object.clone());
            }
        }

        let mut deleted_groups_queue: VecDeque<DeletedObject> = vec![].into();
        for deleted_object in &other.deleted_objects.objects {
            if new_deleted_objects.contains(deleted_object.uuid) {
                continue;
            }
            deleted_groups_queue.push_back(deleted_object.clone());
        }

        while !deleted_groups_queue.is_empty() {
            let deleted_object = deleted_groups_queue.pop_front().unwrap();
            if new_deleted_objects.contains(deleted_object.uuid) {
                continue;
            }
            let group_location = match self.find_node_location(deleted_object.uuid) {
                Some(l) => l,
                None => continue,
            };

            let parent_group = match self.root.find_group_mut(&group_location) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(group_location)),
            };

            let group = match parent_group.find_group(&vec![deleted_object.uuid]) {
                Some(e) => e,
                None => {
                    // The node might be an entry, since we didn't necessarily removed all the
                    // entries that were in the deleted objects of the source database.
                    continue;
                }
            };

            // Not deleting a group if it still has entries.
            if !group.entries().is_empty() {
                continue;
            }

            // This group still has a child group that might get deleted in the future, so we delay
            // decision to delete it or not.
            if group
                .groups()
                .iter()
                .filter(|g| !is_in_deleted_queue(g.uuid, &deleted_groups_queue))
                .collect::<Vec<_>>()
                .len()
                != 0
            {
                deleted_groups_queue.push_back(deleted_object.clone());
                continue;
            }

            // This group still a groups that won't be deleted, so we don't delete it.
            if group.groups().len() != 0 {
                continue;
            }

            let group_last_modification = match group.times.get_last_modification() {
                Some(t) => *t,
                None => {
                    log.warnings.push(format!(
                        "Group {} did not have a last modification timestamp",
                        group.uuid
                    ));
                    Times::now()
                }
            };

            if group_last_modification < deleted_object.deletion_time {
                parent_group.remove_node(&deleted_object.uuid)?;
                log.events.push(MergeEvent {
                    event_type: MergeEventType::GroupDeleted,
                    node_uuid: deleted_object.uuid,
                });

                new_deleted_objects.objects.push(deleted_object.clone());
            }
        }

        self.deleted_objects = new_deleted_objects;
        Ok(log)
    }

    #[cfg(feature = "_merge")]
    pub(crate) fn find_node_location(&self, id: Uuid) -> Option<NodeLocation> {
        for node in &self.root.children {
            match node {
                Node::Entry(e) => {
                    if e.uuid == id {
                        return Some(vec![]);
                    }
                }
                Node::Group(g) => {
                    if g.uuid == id {
                        return Some(vec![]);
                    }
                    if let Some(location) = g.find_node_location(id) {
                        return Some(location);
                    }
                }
            }
        }
        None
    }

    #[cfg(feature = "_merge")]
    fn merge_group(
        &mut self,
        current_group_path: NodeLocation,
        current_group: &Group,
        is_in_deleted_group: bool,
    ) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();

        if let Some(destination_group_location) = self.find_node_location(current_group.uuid) {
            let mut destination_group_path = destination_group_location.clone();
            destination_group_path.push(current_group.uuid);
            let destination_group = match self.root.find_group_mut(&destination_group_path) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(destination_group_path)),
            };
            let group_update_merge_events = destination_group.merge_with(&current_group)?;
            log.append(&group_update_merge_events);
        }

        for other_entry in &current_group.entries() {
            // find the existing location
            let destination_entry_location = self.find_node_location(other_entry.uuid);

            // The group already exists in the destination database.
            if let Some(destination_entry_location) = destination_entry_location {
                let mut existing_entry_location = destination_entry_location.clone();
                existing_entry_location.push(other_entry.uuid);

                // The entry already exists but is not at the right location. We might have to
                // relocate it.
                let mut existing_entry = self.root.find_entry(&existing_entry_location).unwrap().clone();

                // The entry already exists but is not at the right location. We might have to
                // relocate it.
                if current_group_path.last() != destination_entry_location.last() && !is_in_deleted_group {
                    let source_location_changed_time = match other_entry.times.get_location_changed() {
                        Some(t) => *t,
                        None => {
                            log.warnings.push(format!(
                                "Entry {} did not have a location updated timestamp",
                                other_entry.uuid
                            ));
                            Times::epoch()
                        }
                    };
                    let destination_location_changed = match existing_entry.times.get_location_changed() {
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
                            source_location_changed_time,
                        )?;
                        // Update the location of the current entry in case we have to update it
                        // after.
                        existing_entry_location = current_group_path.clone();
                        existing_entry_location.push(other_entry.uuid);
                        existing_entry
                            .times
                            .set_location_changed(source_location_changed_time);
                    }
                }

                if !existing_entry.has_diverged_from(other_entry) {
                    continue;
                }

                // The entry already exists and is at the right location, so we can proceed and merge
                // the two entries.
                let (merged_entry, entry_merge_log) = existing_entry.merge(other_entry)?;
                let merged_entry = match merged_entry {
                    Some(m) => m,
                    None => continue,
                };

                if existing_entry.eq(&merged_entry) {
                    continue;
                }

                let existing_entry = match self.root.find_entry_mut(&existing_entry_location) {
                    Some(e) => e,
                    None => return Err(MergeError::FindEntryError(existing_entry_location)),
                };
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

            // We don't create new entries that exist under a deleted group.
            if is_in_deleted_group {
                continue;
            }

            // The entry doesn't exist in the destination, we create it
            let new_entry = other_entry.to_owned().clone();

            let new_entry_parent_group = match self.root.find_group_mut(&current_group_path) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(current_group_path)),
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

            if self.deleted_objects.contains(other_group.uuid) || is_in_deleted_group {
                let new_merge_log = self.merge_group(new_group_location, other_group, true)?;
                log.append(&new_merge_log);
                continue;
            }

            let destination_group_location = self.find_node_location(other_group.uuid);

            // The group already exists in the destination database.
            if let Some(destination_group_location) = destination_group_location {
                if current_group_path != destination_group_location {
                    let mut existing_group_location = destination_group_location.clone();
                    existing_group_location.push(other_group_uuid);

                    // The group already exists but is not at the right location. We might have to
                    // relocate it.
                    let existing_group = self.root.find_group(&existing_group_location).unwrap();
                    let existing_group_location_changed = match existing_group.times.get_location_changed() {
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
                            other_group_location_changed,
                        )?;

                        log.events.push(MergeEvent {
                            event_type: MergeEventType::GroupLocationUpdated,
                            node_uuid: other_group.uuid,
                        });

                        let new_merge_log =
                            self.merge_group(new_group_location, other_group, is_in_deleted_group)?;
                        log.append(&new_merge_log);
                        continue;
                    }
                }

                // The group already exists and is at the right location, so we can proceed and merge
                // the two groups.
                let new_merge_log = self.merge_group(new_group_location, other_group, is_in_deleted_group)?;
                log.append(&new_merge_log);
                continue;
            }

            // The group doesn't exist in the destination, we create it
            let mut new_group = other_group.to_owned().clone();
            new_group.children = vec![];
            log.events.push(MergeEvent {
                event_type: MergeEventType::GroupCreated,
                node_uuid: new_group.uuid.clone(),
            });
            let new_group_parent_group = match self.root.find_group_mut(&current_group_path) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(current_group_path)),
            };
            new_group_parent_group.add_child(new_group.clone());

            let new_merge_log = self.merge_group(new_group_location, other_group, is_in_deleted_group)?;
            log.append(&new_merge_log);
        }

        Ok(log)
    }

    #[cfg(feature = "_merge")]
    fn relocate_node(
        &mut self,
        node_uuid: &Uuid,
        from: &NodeLocation,
        to: &NodeLocation,
        new_location_changed_timestamp: NaiveDateTime,
    ) -> Result<(), MergeError> {
        let source_group = match self.root.find_group_mut(&from) {
            Some(g) => g,
            None => return Err(MergeError::FindGroupError(from.to_vec())),
        };

        let mut relocated_node = source_group.remove_node(&node_uuid)?;
        match relocated_node {
            Node::Group(ref mut g) => g.times.set_location_changed(new_location_changed_timestamp),
            Node::Entry(ref mut e) => e.times.set_location_changed(new_location_changed_timestamp),
        };

        let destination_group = match self.root.find_group_mut(&to) {
            Some(g) => g,
            None => return Err(MergeError::FindGroupError(to.to_vec())),
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

        let v =
            u64::from_str_radix(s.trim_start_matches('#'), 16).map_err(|_e| ParseColorError(s.to_string()))?;

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
