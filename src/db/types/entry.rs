use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::{Deref, DerefMut},
};

use thiserror::Error;
use uuid::Uuid;

use crate::db::{
    Attachment, AttachmentId, AttachmentMut, AttachmentRef, AutoType, Color, CustomDataItem, Database, GroupId,
    GroupMut, GroupRef, History, IconId, IconRef, Times, Value,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct EntryId(Uuid);

impl EntryId {
    pub(crate) const fn with_uuid(uuid: Uuid) -> EntryId {
        EntryId(uuid)
    }

    pub fn uuid(&self) -> Uuid {
        self.0
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

    parent: GroupId,

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
    pub(crate) fn new(parent: GroupId) -> Entry {
        Entry {
            id: EntryId(Uuid::new_v4()),
            parent,
            fields: HashMap::new(),
            attachments: HashSet::new(),
            autotype: None,
            tags: HashSet::new(),
            times: Times::create_new(),
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

    pub(crate) fn with_id(id: EntryId, parent: GroupId) -> Entry {
        Entry {
            id,
            parent,
            fields: HashMap::new(),
            attachments: HashSet::new(),
            autotype: None,
            tags: HashSet::new(),
            times: Times::create_new(),
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

    /// Get an attachment of this entry by ID.
    pub fn attachment(&self, id: AttachmentId) -> Option<AttachmentRef<'_>> {
        if self.attachments.contains(&id) {
            Some(AttachmentRef::new(self.database, id))
        } else {
            None
        }
    }

    /// Get an iterator over all attachments of this entry.
    pub fn attachments(&self) -> impl Iterator<Item = AttachmentRef<'_>> {
        self.attachments
            .iter()
            .map(move |id| AttachmentRef::new(self.database, *id))
    }

    /// Get a reference to the parent group of this entry.
    pub fn parent(&self) -> GroupRef<'_> {
        self.database.group(self.parent).unwrap()
    }

    /// Get a reference to the icon associated with this entry, if any.
    pub fn custom_icon(&self) -> Option<IconRef<'_>> {
        let icon_id = self.custom_icon_id?;
        self.database.custom_icon(icon_id)
    }

    /// Get a reference to the underlying database
    pub fn database(&self) -> &Database {
        self.database
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

    pub fn as_ref(&self) -> EntryRef<'_> {
        EntryRef::new(self.database, self.id)
    }

    /// Convenience method to edit the entry in a closure.
    pub fn edit(&mut self, f: impl FnOnce(&mut EntryMut)) -> &mut Self {
        f(self);
        self
    }

    /// Convenience method to edit the entry in a closure, tracking changes.
    pub fn edit_tracking(&mut self, f: impl FnOnce(&mut EntryTrack)) -> &mut Self {
        {
            let mut tracked = self.track_changes();
            f(&mut tracked);
        }
        self
    }

    /// Convert this mutable reference into a history-tracking variant that will persist the
    /// current state of the entry into its history when dropped.
    pub fn track_changes(&mut self) -> EntryTrack<'_> {
        let mut historical: Entry = self.deref().deref().clone();

        // Remove history from the historical entry to avoid exponential growth
        historical.history = None;

        EntryTrack {
            database: self.database,
            id: self.id,
            historical,
        }
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

    /// Get a mutable reference to the parent group of this entry.
    pub fn parent_mut(&mut self) -> GroupMut<'_> {
        self.database.group_mut(self.parent).unwrap()
    }

    /// Move this entry to another group.
    pub fn move_to(&mut self, group_id: GroupId) -> Result<(), DestinationGroupNotFoundError> {
        if !self.database.groups.contains_key(&group_id) {
            return Err(DestinationGroupNotFoundError(group_id));
        }

        let my_id = self.id;

        let mut parent = self.parent_mut();
        parent.entries.remove(&my_id);

        let mut new_parent = self.database.group_mut(group_id).unwrap();
        new_parent.entries.insert(my_id);
        self.parent = group_id;

        Ok(())
    }

    /// Get a mutable reference to the underlying database
    pub fn database_mut(&mut self) -> &mut Database {
        self.database
    }

    /// Remove this entry from the database, including all its attachments.
    pub fn remove(self) {
        let entry = self.database.entries.remove(&self.id).expect("Entry not found");

        // Remove from parent group
        let mut parent = self
            .database
            .group_mut(entry.parent)
            .expect("Parent group not found");
        parent.entries.remove(&self.id);

        // Remove attachments
        for attachment_id in entry.attachments {
            self.database.attachments.remove(&attachment_id);
        }
    }
}

#[derive(Error, Debug)]
#[error("Destination group {0} not found")]
pub struct DestinationGroupNotFoundError(GroupId);

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

/// A variant of [EntryMut] that will persist the history of the entry when dropped.
pub struct EntryTrack<'a> {
    database: &'a mut Database,
    id: EntryId,

    historical: Entry,
}

impl EntryTrack<'_> {
    pub fn as_mut(&mut self) -> EntryMut<'_> {
        EntryMut::new(self.database, self.id)
    }

    pub fn move_to(&mut self, group_id: GroupId) -> Result<(), DestinationGroupNotFoundError> {
        self.as_mut().move_to(group_id)?;
        self.times.location_changed = Some(Times::now());
        Ok(())
    }

    pub fn remove(mut self) {
        let this = self.as_mut();
        this.database
            .deleted_objects
            .insert(this.id.uuid(), Some(Times::now()));

        this.remove();
    }

    /// Convenience method to edit the entry in a closure, tracking changes.
    pub fn edit(&mut self, f: impl FnOnce(&mut EntryTrack)) -> &mut Self {
        f(self);
        self.times.last_modification = Some(Times::now());
        self
    }

    /// Set a field value, tracking changes. See [crate::db::fields] for common field names.
    pub fn set(&mut self, key: impl Into<String>, value: Value) {
        let mut this = self.as_mut();
        this.set(key, value);
        this.times.last_modification = Some(Times::now());
    }

    /// Set a protected field value, tracking changes. See [crate::db::fields] for common field names.
    pub fn set_protected(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let mut this = self.as_mut();
        this.set_protected(key, value);
        this.times.last_modification = Some(Times::now());
    }

    /// Set an unprotected field value, tracking changes. See [crate::db::fields] for common field names.
    pub fn set_unprotected(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let mut this = self.as_mut();
        this.set_unprotected(key, value);
        this.times.last_modification = Some(Times::now());
    }
}

impl Deref for EntryTrack<'_> {
    type Target = Entry;

    fn deref(&self) -> &Self::Target {
        self.database.entries.get(&self.id).expect("Entry not found")
    }
}

impl DerefMut for EntryTrack<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let entry = self.database.entries.get_mut(&self.id).expect("Entry not found");
        entry
    }
}

impl Drop for EntryTrack<'_> {
    fn drop(&mut self) {
        // see if the entry is still there (it might have been removed)
        if let Some(entry) = self.database.entries.get_mut(&self.id) {
            let parent_id = entry.parent;

            let historical = std::mem::replace(&mut self.historical, Entry::new(parent_id));
            if entry.history.is_none() {
                entry.history = Some(History::default());
            }
            entry.history.as_mut().unwrap().entries.push(historical);
        }
    }
}
