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

use std::collections::HashMap;

pub use attachment::{Attachment, AttachmentId, AttachmentMut, AttachmentRef};
pub use autotype::{AutoType, AutoTypeAssociation};
use chrono::NaiveDateTime;
pub use color::Color;
pub use custom_data::{CustomDataItem, CustomDataValue};
pub use entry::{DestinationGroupNotFoundError, Entry, EntryId, EntryMut, EntryRef, IconNotFoundError};
pub use group::{Group, GroupId, GroupMut, GroupRef, MoveGroupError};
pub use history::History;
pub use icon::{Icon, IconId, IconMut, IconRef};
pub use meta::{MemoryProtection, Meta};
pub use times::Times;
use uuid::Uuid;
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Database {
    pub config: DatabaseConfig,
    pub meta: Meta,

    pub(crate) root: GroupId,

    pub(crate) entries: HashMap<EntryId, Entry>,
    pub(crate) groups: HashMap<GroupId, Group>,

    pub(crate) custom_icons: HashMap<IconId, Icon>,

    pub(crate) attachments: HashMap<AttachmentId, Attachment>,

    /// Map of deleted object UUIDs to their deletion time (or None if unknown).
    ///
    /// These cannot be `EntryId`s or `GroupId`s because the internal XML representation uses raw
    /// UUIDs without specifying the type of object.
    pub(crate) deleted_objects: HashMap<Uuid, Option<NaiveDateTime>>,
}

impl Database {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::new_with_root_id(GroupId::new())
    }

    pub(crate) fn new_with_root_id(root_id: GroupId) -> Self {
        let root = Group::with_id(root_id, None);

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config: DatabaseConfig::default(),
            meta: Meta::default(),
            root: root_id,
            entries: HashMap::new(),
            groups,
            custom_icons: HashMap::new(),
            attachments: HashMap::new(),
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
            entries: HashMap::new(),
            groups,
            custom_icons: HashMap::new(),
            attachments: HashMap::new(),
            deleted_objects: HashMap::new(),
        }
    }

    pub fn root(&self) -> GroupRef<'_> {
        GroupRef::new(self, self.root)
    }

    pub fn root_mut(&mut self) -> GroupMut<'_> {
        GroupMut::new(self, self.root)
    }

    pub fn recycle_bin(&self) -> Option<GroupRef<'_>> {
        let recyclebin_id = self.meta.recyclebin_uuid.map(GroupId::from_uuid)?;
        self.group(recyclebin_id)
    }

    pub fn recycle_bin_mut(&mut self) -> Option<GroupMut<'_>> {
        let recyclebin_id = self.meta.recyclebin_uuid.map(GroupId::from_uuid)?;
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

    /// Iterate over all custom icons with immutable access.
    pub fn iter_all_icons(&self) -> impl Iterator<Item = IconRef<'_>> + '_ {
        self.custom_icons.keys().map(move |id| IconRef::new(self, *id))
    }

    /// Iterate over all custom icons with mutable access. The provided closure is
    /// called for each `IconMut` and borrows are limited to the closure body.
    pub fn foreach_icon_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(IconMut<'_>),
    {
        let ids: Vec<IconId> = self.custom_icons.keys().copied().collect();
        for id in ids {
            f(IconMut::new(self, id));
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

    /// Add a custom icon to the database, returning a mutable reference to it. The icon will be
    /// assigned a new random UUID, and the caller is responsible for ensuring that the data is
    /// valid (e.g. a valid PNG file).
    pub fn add_custom_icon(&mut self, data: Vec<u8>) -> IconMut<'_> {
        let id = IconId::new();
        let icon = Icon { id, data };
        self.custom_icons.insert(id, icon);
        IconMut::new(self, id)
    }
}

#[cfg(test)]
mod tests {
    use crate::{db::fields, Database};

    #[test]
    fn test_database_new() {
        let db = Database::new();
        assert_eq!(db.num_groups(), 1); // root group
        assert_eq!(db.num_entries(), 0);
        assert_eq!(db.num_attachments(), 0);
    }

    #[test]
    fn test_entry_iteration() {
        let mut db = Database::new();

        let mut root = db.root_mut();
        for i in 0..5 {
            root.add_entry().edit(|e| {
                e.set_unprotected(fields::TITLE, &format!("Entry {}", i));
            });
        }

        let mut count = 0;
        for entry in db.iter_all_entries() {
            assert!(entry.get_str(fields::TITLE).unwrap().starts_with("Entry "));
            count += 1;
        }
        assert_eq!(count, 5);

        db.foreach_entry_mut(|mut e| {
            let entry_title = e.get_str(fields::TITLE).unwrap().to_string();
            e.set_unprotected(fields::USERNAME, format!("User for {}", entry_title));
        });

        for entry in db.iter_all_entries() {
            let title = entry.get_str(fields::TITLE).unwrap();
            let username = entry.get_str(fields::USERNAME).unwrap();
            assert_eq!(username, format!("User for {}", title));
        }
    }

    #[test]
    fn test_group_iteration() {
        let mut db = Database::new();

        let mut root = db.root_mut();
        for i in 0..3 {
            root.add_group().edit(|g| {
                g.name = format!("Group {}", i);
            });
        }

        let mut count = 0;
        for group in db.iter_all_groups() {
            if group.id() == db.root().id() {
                continue; // skip root group
            }

            assert!(group.name.starts_with("Group "));
            count += 1;
        }
        assert_eq!(count, 3);

        db.foreach_group_mut(|mut g| {
            let group_name = g.name.to_string();
            g.name = format!("Renamed {}", group_name);
        });

        for group in db.iter_all_groups() {
            assert!(group.name.starts_with("Renamed ") || group.id() == db.root().id());
        }
    }
}
