use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::{Deref, DerefMut},
};

use uuid::Uuid;

use crate::db::{
    Attachment, AttachmentId, AttachmentMut, AttachmentRef, AutoType, Color, CustomDataItem, Database, History,
    IconId, IconRef, Times, Value,
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

/// A KeePass database entry.
///
/// You will never construct or handle ownership of `Entry` objects directly, but will be handed
/// [EntryRef] and [EntryMut] handles through which you can access the entries.
///
/// See the [module-level documentation](crate::db) for an example.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Entry {
    id: EntryId,

    /// fields contained within the entry, such as title, username, password
    pub fields: HashMap<String, Value>,

    /// attachments associated with the entry
    attachments: HashSet<AttachmentId>,

    /// auto-type settings for the entry
    pub autotype: Option<AutoType>,

    /// tags associated with the entry
    pub tags: HashSet<String>,

    /// time fields for the entry
    pub times: Times,

    /// custom data associated with the entry
    pub custom_data: HashMap<String, CustomDataItem>,

    /// numerical icon index for the KeePass-provided icons
    pub icon_id: Option<usize>,

    /// UUID of a custom icon associated with the entry
    custom_icon_id: Option<IconId>,

    /// foreground color for the entry
    pub foreground_color: Option<Color>,

    /// background color for the entry
    pub background_color: Option<Color>,

    /// override URL for the entry
    pub override_url: Option<String>,

    /// unclear what a quality_check is; KeePass seems to use it for some kind of internal flagging
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

    pub(crate) fn with_id(id: EntryId) -> Entry {
        Entry {
            id,
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

    /// Set a field value. See [crate::db::fields] for common field names.
    pub fn set(&mut self, key: impl Into<String>, value: Value) {
        self.fields.insert(key.into(), value);
    }

    /// Set a protected field value. See [crate::db::fields] for common field names.
    pub fn set_protected(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields
            .insert(key.into(), Value::protected_string(value.into()));
    }

    /// Set an unprotected field value. See [crate::db::fields] for common field names.
    pub fn set_unprotected(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(key.into(), Value::string(value.into()));
    }

    /// Get a field value. See [crate::db::fields] for common field names.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.fields.get(key)
    }

    /// Get a field value as a string slice, if it exists.
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|v| v.as_str())
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

    pub fn attachment(&self, id: AttachmentId) -> Option<AttachmentRef<'_>> {
        if self.attachments.contains(&id) {
            Some(AttachmentRef::new(self.database, id))
        } else {
            None
        }
    }

    pub fn custom_icon(&self) -> Option<IconRef<'_>> {
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

    pub fn attachment_mut(&mut self, id: AttachmentId) -> Option<AttachmentMut<'_>> {
        if self.attachments.contains(&id) {
            Some(AttachmentMut::new(self.database, id))
        } else {
            None
        }
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
