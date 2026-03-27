pub(crate) mod attachment;
pub(crate) mod autotype;
pub(crate) mod color;
pub(crate) mod custom_data;
pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod history;
pub(crate) mod icon;
pub(crate) mod meta;
pub(crate) mod times;
pub(crate) mod value;

use std::collections::HashMap;

pub use attachment::{Attachment, AttachmentId, AttachmentMut, AttachmentRef};
pub use autotype::{AutoType, AutoTypeAssociation};
pub use color::{Color, ParseColorError};
pub use custom_data::{CustomDataItem, CustomDataValue};
pub use entry::{DestinationGroupNotFoundError, Entry, EntryId, EntryMut, EntryRef, EntryTrack};
pub use group::{Group, GroupId, GroupMut, GroupRef, GroupTrack, MoveGroupError};
pub use history::History;
pub use icon::{CustomIcon, CustomIconId, CustomIconMut, CustomIconNotFoundError, CustomIconRef, Icon};
pub use meta::{MemoryProtection, Meta};
pub use times::Times;
pub use value::Value;

use crate::config::DatabaseConfig;

use chrono::NaiveDateTime;
use uuid::Uuid;

/// A decrypted KeePass database
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Database {
    /// Configuration settings of the database such as encryption and compression algorithms
    pub config: DatabaseConfig,

    /// Metadata of the KeePass database
    pub meta: Meta,

    /// Root node of the KeePass database
    pub(crate) root: GroupId,

    /// All attachments in the database, stored in a flat HashMap
    pub(crate) attachments: HashMap<AttachmentId, Attachment>,

    /// All custom icons in the database, stored in a flat HashMap
    pub(crate) custom_icons: HashMap<CustomIconId, CustomIcon>,

    /// All entries in the database, stored in a flat HashMap
    pub(crate) entries: HashMap<EntryId, Entry>,

    /// All groups in the database, stored in a flat HashMap
    pub(crate) groups: HashMap<GroupId, Group>,

    /// References to previously-deleted objects and their deletion times.
    pub deleted_objects: HashMap<Uuid, Option<NaiveDateTime>>,
}

impl Database {
    /// Create a new database with a single root group and no entries, groups, or attachments.
    ///
    /// The root group will be assigned a new random UUID.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::new_with_root_id(GroupId::new())
    }

    /// Create a new database with the given configuration and a single root group.
    ///
    /// The root group will be assigned a new random UUID.
    pub fn with_config(config: DatabaseConfig) -> Self {
        Self::with_data(config, GroupId::new())
    }

    pub(crate) fn new_with_root_id(root_id: GroupId) -> Self {
        let root = Group::with_id(root_id, None);

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config: DatabaseConfig::default(),
            meta: Meta::default(),
            root: root_id,
            attachments: HashMap::new(),
            custom_icons: HashMap::new(),
            entries: HashMap::new(),
            groups,
            deleted_objects: HashMap::new(),
        }
    }

    pub(crate) fn with_data(config: DatabaseConfig, root_id: GroupId) -> Self {
        let root = Group::with_id(root_id, None);

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config,
            meta: Meta::default(),
            root: root_id,
            attachments: HashMap::new(),
            custom_icons: HashMap::new(),
            entries: HashMap::new(),
            groups,
            deleted_objects: HashMap::new(),
        }
    }

    /// Get an immutable reference to the root group of the database.
    pub fn root(&self) -> GroupRef<'_> {
        GroupRef::new(self, self.root)
    }

    /// Get a mutable reference to the root group of the database.
    pub fn root_mut(&mut self) -> GroupMut<'_> {
        GroupMut::new(self, self.root)
    }

    /// Get an immutable reference to the recycle bin group, if it exists
    pub fn recycle_bin(&self) -> Option<GroupRef<'_>> {
        let recyclebin_id = self.meta.recyclebin_uuid.map(GroupId::from_uuid)?;
        self.group(recyclebin_id)
    }

    /// Get a mutable reference to the recycle bin group, if it exists
    pub fn recycle_bin_mut(&mut self) -> Option<GroupMut<'_>> {
        let recyclebin_id = self.meta.recyclebin_uuid.map(GroupId::from_uuid)?;
        self.group_mut(recyclebin_id)
    }

    /// Get the number of attachments in the database
    pub fn num_attachments(&self) -> usize {
        self.attachments.len()
    }

    /// Get the number of custom icons in the database
    pub fn num_custom_icons(&self) -> usize {
        self.custom_icons.len()
    }

    /// Get the number of entries in the database
    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    /// Get the number of groups in the database, including the root group and the recycle bin (if it exists)
    pub fn num_groups(&self) -> usize {
        self.groups.len()
    }

    /// Iterate over all attachments with immutable access.
    pub fn iter_all_attachments(&self) -> impl Iterator<Item = AttachmentRef<'_>> + '_ {
        self.attachments
            .keys()
            .map(move |id| AttachmentRef::new(self, *id))
    }

    /// Iterate over all attachments with mutable access. The provided closure is
    /// called for each `AttachmentMut` and borrows are limited to the closure body.
    pub fn foreach_attachment_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(AttachmentMut<'_>),
    {
        let ids: Vec<AttachmentId> = self.attachments.keys().copied().collect();
        for id in ids {
            f(AttachmentMut::new(self, id));
        }
    }

    /// Iterate over all entries with immutable access.
    pub fn iter_all_entries(&self) -> impl Iterator<Item = EntryRef<'_>> + '_ {
        self.entries.keys().map(move |id| EntryRef::new(self, *id))
    }

    /// Iterate over all entries with mutable access. The provided closure is
    /// called for each `EntryMut` and borrows are limited to the closure body.
    pub fn foreach_entry_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(EntryMut<'_>),
    {
        let ids: Vec<EntryId> = self.entries.keys().copied().collect();
        for id in ids {
            f(EntryMut::new(self, id));
        }
    }

    /// Iterate over all custom icons with immutable access.
    pub fn iter_all_custom_icons(&self) -> impl Iterator<Item = CustomIconRef<'_>> + '_ {
        self.custom_icons
            .keys()
            .map(move |id| CustomIconRef::new(self, *id))
    }

    /// Iterate over all custom icons with mutable access. The provided closure is
    /// called for each `CustomIconMut` and borrows are limited to the closure body.
    pub fn foreach_custom_icon_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(CustomIconMut<'_>),
    {
        let ids: Vec<CustomIconId> = self.custom_icons.keys().copied().collect();
        for id in ids {
            f(CustomIconMut::new(self, id));
        }
    }

    /// Iterate over all groups with immutable access. This includes the root group and the recycle
    /// bin (if it exists).
    pub fn iter_all_groups(&self) -> impl Iterator<Item = GroupRef<'_>> + '_ {
        self.groups.keys().map(move |id| GroupRef::new(self, *id))
    }

    /// Iterate over all groups with mutable access. The provided closure is
    /// called for each `GroupMut` and borrows are limited to the closure body.
    pub fn foreach_group_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(GroupMut<'_>),
    {
        let ids: Vec<GroupId> = self.groups.keys().copied().collect();
        for id in ids {
            f(GroupMut::new(self, id));
        }
    }

    /// Get an immutable reference to the attachment with the given ID, if it exists
    pub fn attachment(&self, id: AttachmentId) -> Option<AttachmentRef<'_>> {
        self.attachments
            .contains_key(&id)
            .then(move || AttachmentRef::new(self, id))
    }

    /// Get a mutable reference to the attachment with the given ID, if it exists
    pub fn attachment_mut(&mut self, id: AttachmentId) -> Option<AttachmentMut<'_>> {
        self.attachments
            .contains_key(&id)
            .then(move || AttachmentMut::new(self, id))
    }

    /// Get an immutable reference to the custom icon with the given ID, if it exists
    pub fn custom_icon(&self, id: CustomIconId) -> Option<CustomIconRef<'_>> {
        self.custom_icons
            .contains_key(&id)
            .then(move || CustomIconRef::new(self, id))
    }

    /// Get a mutable reference to the custom icon with the given ID, if it exists
    pub fn custom_icon_mut(&mut self, id: CustomIconId) -> Option<CustomIconMut<'_>> {
        self.custom_icons
            .contains_key(&id)
            .then(move || CustomIconMut::new(self, id))
    }

    /// Get an immutable reference to the entry with the given ID, if it exists
    pub fn entry(&self, id: EntryId) -> Option<EntryRef<'_>> {
        self.entries
            .contains_key(&id)
            .then(move || EntryRef::new(self, id))
    }

    /// Get a mutable reference to the entry with the given ID, if it exists
    pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>> {
        self.entries
            .contains_key(&id)
            .then(move || EntryMut::new(self, id))
    }

    /// Get an immutable reference to the group with the given ID, if it exists
    pub fn group(&self, id: GroupId) -> Option<GroupRef<'_>> {
        self.groups
            .contains_key(&id)
            .then(move || GroupRef::new(self, id))
    }

    /// Get a mutable reference to the group with the given ID, if it exists
    pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>> {
        self.groups
            .contains_key(&id)
            .then(move || GroupMut::new(self, id))
    }
}
