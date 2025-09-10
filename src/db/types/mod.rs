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
    root: GroupId,

    entries: HashMap<EntryId, Entry>,
    groups: HashMap<GroupId, Group>,

    custom_icons: HashMap<IconId, Icon>,
    binary_attachments: HashMap<BinaryAttachmentId, BinaryAttachment>,
    header_attachments: HashMap<HeaderAttachmentId, HeaderAttachment>,

    deleted_entries: HashSet<EntryId>,
    deleted_groups: HashSet<GroupId>,
    deleted_binary_attachments: HashSet<BinaryAttachmentId>,
    deleted_header_attachments: HashSet<HeaderAttachmentId>,

    pub meta: Meta,
}

impl Database {
    pub fn new() -> Self {
        Database {
            config: DatabaseConfig::default(),
            root: GroupId::new(),
            entries: HashMap::new(),
            groups: HashMap::new(),
            custom_icons: HashMap::new(),
            binary_attachments: HashMap::new(),
            header_attachments: HashMap::new(),
            deleted_entries: HashSet::new(),
            deleted_groups: HashSet::new(),
            deleted_binary_attachments: HashSet::new(),
            deleted_header_attachments: HashSet::new(),
            meta: Meta::default(),
        }
    }

    pub(crate) fn with_data(config: DatabaseConfig, root: GroupId, meta: Meta) -> Self {
        Database {
            config,
            root,
            entries: HashMap::new(),
            groups: HashMap::new(),
            custom_icons: HashMap::new(),
            binary_attachments: HashMap::new(),
            header_attachments: HashMap::new(),
            deleted_entries: HashSet::new(),
            deleted_groups: HashSet::new(),
            deleted_binary_attachments: HashSet::new(),
            deleted_header_attachments: HashSet::new(),
            meta,
        }
    }

    pub fn root(&self) -> GroupRef {
        GroupRef::new(self, self.root)
    }

    pub fn root_mut(&mut self) -> GroupMut {
        GroupMut::new(self, self.root)
    }

    pub fn entry(&self, id: EntryId) -> Option<EntryRef> {
        self.entries
            .contains_key(&id)
            .then(move || EntryRef::new(self, id))
    }

    pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut> {
        self.entries
            .contains_key(&id)
            .then(move || EntryMut::new(self, id))
    }

    pub fn group(&self, id: GroupId) -> Option<GroupRef> {
        self.groups
            .contains_key(&id)
            .then(move || GroupRef::new(self, id))
    }

    pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut> {
        self.groups
            .contains_key(&id)
            .then(move || GroupMut::new(self, id))
    }

    pub fn custom_icon(&self, id: IconId) -> Option<IconRef> {
        self.custom_icons
            .contains_key(&id)
            .then(move || IconRef::new(self, id))
    }

    pub fn custom_icon_mut(&mut self, id: IconId) -> Option<IconMut> {
        self.custom_icons
            .contains_key(&id)
            .then(move || IconMut::new(self, id))
    }
}
