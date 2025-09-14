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

pub use attachment::{
    BinaryAttachment, BinaryAttachmentId, BinaryAttachmentMut, BinaryAttachmentRef, HeaderAttachment,
    HeaderAttachmentId, HeaderAttachmentMut, HeaderAttachmentRef,
};
pub use autotype::{AutoType, AutoTypeAssociation};
pub use color::Color;
pub use custom_data::CustomDataItem;
pub use entry::{Entry, EntryId, EntryMut, EntryRef};
pub use group::{Group, GroupId, GroupMut, GroupRef};
pub use history::History;
pub use icon::{Icon, IconId, IconMut, IconRef};
pub use meta::{MemoryProtection, Meta};
pub use times::Times;
pub use value::Value;

use crate::config::DatabaseConfig;

pub struct Database {
    pub config: DatabaseConfig,
    pub(crate) root: GroupId,

    pub(crate) entries: HashMap<EntryId, Entry>,
    pub(crate) groups: HashMap<GroupId, Group>,

    pub(crate) custom_icons: HashMap<IconId, Icon>,
    pub(crate) binary_attachments: HashMap<BinaryAttachmentId, BinaryAttachment>,

    pub header_attachments: Vec<HeaderAttachment>,

    pub(crate) deleted_entries: HashSet<EntryId>,
    pub(crate) deleted_groups: HashSet<GroupId>,
    pub(crate) deleted_binary_attachments: HashSet<BinaryAttachmentId>,
    pub(crate) deleted_header_attachments: HashSet<HeaderAttachmentId>,

    pub meta: Meta,
}

impl Database {
    pub fn new() -> Self {
        let root = Group::new();
        let root_id = root.id();

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config: DatabaseConfig::default(),
            root: root_id,
            entries: HashMap::new(),
            groups: groups,
            custom_icons: HashMap::new(),
            binary_attachments: HashMap::new(),
            header_attachments: Vec::new(),
            deleted_entries: HashSet::new(),
            deleted_groups: HashSet::new(),
            deleted_binary_attachments: HashSet::new(),
            deleted_header_attachments: HashSet::new(),
            meta: Meta::default(),
        }
    }

    pub(crate) fn with_data(config: DatabaseConfig, root_id: GroupId) -> Self {
        let root = Group::with_id(root_id);

        let mut groups = HashMap::new();
        groups.insert(root_id, root);

        Database {
            config,
            root: root_id,
            entries: HashMap::new(),
            groups: groups,
            custom_icons: HashMap::new(),
            binary_attachments: HashMap::new(),
            header_attachments: Vec::new(),
            deleted_entries: HashSet::new(),
            deleted_groups: HashSet::new(),
            deleted_binary_attachments: HashSet::new(),
            deleted_header_attachments: HashSet::new(),
            meta: Meta::default(),
        }
    }

    pub fn root(&self) -> GroupRef<'_> {
        GroupRef::new(self, self.root)
    }

    pub fn root_mut(&mut self) -> GroupMut<'_> {
        GroupMut::new(self, self.root)
    }

    pub fn iter_all_entries(&self) -> impl Iterator<Item = EntryRef<'_>> + '_ {
        self.entries.keys().map(move |id| EntryRef::new(self, *id))
    }

    pub fn iter_all_groups(&self) -> impl Iterator<Item = GroupRef<'_>> + '_ {
        self.groups.keys().map(move |id| GroupRef::new(self, *id))
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
