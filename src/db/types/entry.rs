use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::{Deref, DerefMut},
};

use uuid::Uuid;

use crate::db::{
    Attachment, AttachmentId, AttachmentMut, AutoType, Color, CustomDataItem, Database, History, IconId,
    IconRef, Times, Value,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct EntryId(Uuid);

impl EntryId {
    pub(crate) fn with_uuid(uuid: Uuid) -> EntryId {
        EntryId(uuid)
    }
}

impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Entry {
    id: EntryId,

    /// fields contained within the entry, such as title, username, password
    pub fields: HashMap<String, Value>,

    /// attachments associated with the entry
    pub attachments: HashSet<AttachmentId>,

    /// auto-type settings for the entry
    pub autotype: Option<AutoType>,

    /// tags associated with the entry
    pub tags: HashSet<String>,

    /// time fields for the entry
    pub times: Times,

    /// custom data associated with the entry
    pub custom_data: HashMap<String, CustomDataItem>,

    pub icon_id: Option<usize>,
    custom_icon_id: Option<IconId>,

    pub foreground_color: Option<Color>,
    pub background_color: Option<Color>,

    pub override_url: Option<String>,
    pub quality_check: Option<bool>,

    /// modification history of the entry
    pub history: Option<History>,
}

impl Entry {
    pub(crate) fn new() -> Entry {
        Entry {
            id: EntryId(Uuid::new_v4()),
            fields: HashMap::new(),
            attachments: HashSet::new(),
            autotype: None,
            tags: HashSet::new(),
            times: Times::default(),
            custom_data: HashMap::new(),
            icon_id: None,
            custom_icon_id: None,
            foreground_color: None,
            background_color: None,
            override_url: None,
            quality_check: None,
            history: None,
        }
    }

    pub(crate) fn with_id(id: Uuid) -> Entry {
        Entry {
            id: EntryId(id),
            fields: HashMap::new(),
            attachments: HashSet::new(),
            autotype: None,
            tags: HashSet::new(),
            times: Times::default(),
            custom_data: HashMap::new(),
            icon_id: None,
            custom_icon_id: None,
            foreground_color: None,
            background_color: None,
            override_url: None,
            quality_check: None,
            history: None,
        }
    }

    /// Get the unique identifier for the entry
    pub fn id(&self) -> EntryId {
        self.id
    }

    /// Get time fields for the entry (expiry, modification time, etc.)
    pub fn times(&self) -> &Times {
        &self.times
    }

    /// Get custom data fields for the entry
    pub fn custom_data(&self) -> &HashMap<String, CustomDataItem> {
        &self.custom_data
    }

    pub fn set(&mut self, key: impl Into<String>, value: Value) {
        self.fields.insert(key.into(), value);
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }

    // TODO: add ways to edit fields in need of protection
}

impl Deref for Entry {
    type Target = HashMap<String, Value>;

    fn deref(&self) -> &Self::Target {
        &self.fields
    }
}

impl DerefMut for Entry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.fields
    }
}

/// An immutable reference to a valid entry in the database. Implements Deref to Entry.
pub struct EntryRef<'a> {
    database: &'a Database,
    id: EntryId,
}

impl EntryRef<'_> {
    pub(crate) fn new(database: &Database, id: EntryId) -> EntryRef<'_> {
        EntryRef { database, id }
    }

    pub fn custom_icon_id(&self) -> Option<IconRef<'_>> {
        let icon_id = self.custom_icon_id?;
        self.database.custom_icon(icon_id)
    }
}

impl Deref for EntryRef<'_> {
    type Target = Entry;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: EntryRef can only be constructed with a valid EntryId
        self.database.entries.get(&self.id).expect("Entry not found")
    }
}

/// A mutable reference to a valid entry in the database. Implements Deref and DerefMut to Entry.
pub struct EntryMut<'a> {
    database: &'a mut Database,
    id: EntryId,
}

impl EntryMut<'_> {
    pub(crate) fn new(database: &mut Database, id: EntryId) -> EntryMut<'_> {
        EntryMut { database, id }
    }

    /// Add a new attachment to the entry, returning a mutable reference to it.
    pub fn add_attachment(&mut self) -> AttachmentMut<'_> {
        let attachment = Attachment::new();
        let id = attachment.id();
        self.database.attachments.insert(id, attachment);
        self.attachments.insert(id);

        AttachmentMut::new(self.database, id)
    }
}

impl Deref for EntryMut<'_> {
    type Target = Entry;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: EntryMut can only be constructed with a valid EntryId
        self.database.entries.get(&self.id).expect("Entry not found")
    }
}

impl DerefMut for EntryMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // UNWRAP safety: EntryMut can only be constructed with a valid EntryId
        self.database.entries.get_mut(&self.id).expect("Entry not found")
    }
}
