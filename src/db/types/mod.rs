mod attachment;
mod autotype;
mod color;
mod custom_data;
mod entry;
mod group;
mod history;
mod icon;
mod meta;
mod times;
mod value;

use std::collections::{HashMap, HashSet};

pub use attachment::{Attachment, AttachmentId, AttachmentMut, AttachmentRef};
pub use autotype::{AutoType, AutoTypeAssociation};
pub use color::Color;
pub use custom_data::{CustomDataItem, CustomDataValue};
pub use entry::{Entry, EntryId, EntryMut, EntryRef};
pub use group::{Group, GroupId, GroupMut, GroupRef};
pub use history::History;
pub use icon::{Icon, IconId, IconMut, IconRef};
pub use meta::{MemoryProtection, Meta};
pub use times::Times;
pub use value::Value;

use crate::config::DatabaseConfig;

/// In-memory representation of a KeePass Database.
///
/// This struct holds all data in a KeePass database within private fields, including [Group]s,
/// [Entry]s, and [Attachment]s, and provides access to them via [GroupRef], [EntryRef], and
/// [AttachmentRef] handles. Use e.g. [Database::root] to get a handle for the root group, and then
/// traverse the group hierarchy from there.
///
/// See the [module-level documentation](crate::db) for an example.
pub struct Database {
    pub config: DatabaseConfig,
    pub meta: Meta,

    pub(crate) root: GroupId,

    pub(crate) entries: HashMap<EntryId, Entry>,
    pub(crate) groups: HashMap<GroupId, Group>,

    pub(crate) custom_icons: HashMap<IconId, Icon>,

    pub(crate) attachments: HashMap<AttachmentId, Attachment>,

    pub(crate) deleted_entries: HashSet<EntryId>,
    pub(crate) deleted_groups: HashSet<GroupId>,
}

impl Database {
    pub fn new() -> Self {
        Self::new_with_root_id(GroupId::new())
    }

    pub(crate) fn new_with_root_id(root_id: GroupId) -> Self {
        let root = Group::with_id(root_id);

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config: DatabaseConfig::default(),
            meta: Meta::default(),
            root: root_id,
            entries: HashMap::new(),
            groups: groups,
            custom_icons: HashMap::new(),
            attachments: HashMap::new(),
            deleted_entries: HashSet::new(),
            deleted_groups: HashSet::new(),
        }
    }

    pub(crate) fn with_data(config: DatabaseConfig, root_id: GroupId) -> Self {
        let root = Group::with_id(root_id);

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config,
            meta: Meta::default(),
            root: root_id,
            entries: HashMap::new(),
            groups: groups,
            custom_icons: HashMap::new(),
            attachments: HashMap::new(),
            deleted_entries: HashSet::new(),
            deleted_groups: HashSet::new(),
        }
    }

    pub fn root(&self) -> GroupRef<'_> {
        GroupRef::new(self, self.root)
    }

    pub fn root_mut(&mut self) -> GroupMut<'_> {
        GroupMut::new(self, self.root)
    }

    pub fn recycle_bin(&self) -> Option<GroupRef<'_>> {
        let recyclebin_id = self.meta.recyclebin_uuid.map(GroupId::with_uuid)?;
        self.group(recyclebin_id)
    }

    pub fn recycle_bin_mut(&mut self) -> Option<GroupMut<'_>> {
        let recyclebin_id = self.meta.recyclebin_uuid.map(GroupId::with_uuid)?;
        self.group_mut(recyclebin_id)
    }

    pub fn num_attachments(&self) -> usize {
        self.attachments.len()
    }

    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    pub fn num_groups(&self) -> usize {
        self.groups.len()
    }

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

    pub fn entry(&self, id: EntryId) -> Option<EntryRef<'_>> {
        self.entries
            .contains_key(&id)
            .then(move || EntryRef::new(self, id))
    }

    pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>> {
        self.entries
            .contains_key(&id)
            .then(move || EntryMut::new(self, id))
    }

    pub fn group(&self, id: GroupId) -> Option<GroupRef<'_>> {
        self.groups
            .contains_key(&id)
            .then(move || GroupRef::new(self, id))
    }

    pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>> {
        self.groups
            .contains_key(&id)
            .then(move || GroupMut::new(self, id))
    }

    pub fn attachment(&self, id: AttachmentId) -> Option<AttachmentRef<'_>> {
        self.attachments
            .contains_key(&id)
            .then(move || AttachmentRef::new(self, id))
    }

    pub fn attachment_mut(&mut self, id: AttachmentId) -> Option<AttachmentMut<'_>> {
        self.attachments
            .contains_key(&id)
            .then(move || AttachmentMut::new(self, id))
    }

    pub fn custom_icon(&self, id: IconId) -> Option<IconRef<'_>> {
        self.custom_icons
            .contains_key(&id)
            .then(move || IconRef::new(self, id))
    }

    pub fn custom_icon_mut(&mut self, id: IconId) -> Option<IconMut<'_>> {
        self.custom_icons
            .contains_key(&id)
            .then(move || IconMut::new(self, id))
    }
}
