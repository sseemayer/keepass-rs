use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    ops::{Deref, DerefMut},
};

use thiserror::Error;
use uuid::Uuid;

use crate::db::{
    types::history::{HistoryMut, HistoryRef},
    Attachment, AttachmentId, AttachmentMut, AttachmentRef, AutoType, Color, CustomDataItem, Database, GroupId,
    GroupMut, GroupRef, History, IconId, IconMut, IconRef, Times, Value,
};

/// Unique identifier for an [Entry]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct EntryId(Uuid);

impl EntryId {
    pub(crate) const fn from_uuid(uuid: Uuid) -> EntryId {
        EntryId(uuid)
    }

    /// Get the [Uuid] contained within
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
    pub(crate) attachments: HashSet<AttachmentId>,

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
    pub(crate) custom_icon_id: Option<IconId>,

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
            history: Some(History::default()),
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
            history: Some(History::default()),
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

/// An immutable reference to an [Entry]. Implements [Deref] to [&Entry][Entry].
pub struct EntryRef<'a> {
    database: &'a Database,
    id: EntryId,
}

impl EntryRef<'_> {
    pub(crate) fn new(database: &Database, id: EntryId) -> EntryRef<'_> {
        EntryRef { database, id }
    }

    /// Get an immutable reference of an attachment of this entry by ID.
    pub fn attachment(&self, id: AttachmentId) -> Option<AttachmentRef<'_>> {
        self.attachments
            .contains(&id)
            .then(move || AttachmentRef::new(self.database, id))
    }

    /// Get an iterator over all attachments of this entry.
    pub fn attachments(&self) -> impl Iterator<Item = AttachmentRef<'_>> {
        self.attachments
            .iter()
            .map(move |id| AttachmentRef::new(self.database, *id))
    }

    /// Get a reference to the history of this entry, if it exists.
    pub fn history(&self) -> Option<HistoryRef<'_>> {
        self.history
            .is_some()
            .then(|| HistoryRef::new(self.database, self.id))
    }

    /// Get a reference to the parent group of this entry.
    pub fn parent(&self) -> GroupRef<'_> {
        #[allow(clippy::unwrap_used, clippy::missing_panics_doc)] // parent always exists
        self.database.group(self.parent).unwrap()
    }

    /// Get a reference to the icon associated with this entnry, if any.
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

    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: EntryRef can only be constructed with a valid EntryId
        self.database.entries.get(&self.id).expect("Entry not found")
    }
}

/// A mutable reference to an [Entry]. Implements [DerefMut] to [&mut Entry][Entry].
pub struct EntryMut<'a> {
    database: &'a mut Database,
    id: EntryId,
}

impl EntryMut<'_> {
    pub(crate) fn new(database: &mut Database, id: EntryId) -> EntryMut<'_> {
        EntryMut { database, id }
    }

    /// Get an immutable reference to the entry.
    pub fn as_ref(&self) -> EntryRef<'_> {
        EntryRef::new(self.database, self.id)
    }

    /// Convenience method to edit the entry in a closure.
    pub fn edit(&mut self, f: impl FnOnce(&mut EntryMut<'_>)) -> &mut Self {
        f(self);
        self
    }

    /// Convenience method to edit the entry in a closure, tracking changes.
    pub fn edit_tracking(&mut self, f: impl FnOnce(&mut EntryTrack<'_>)) -> &mut Self {
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
        let id = AttachmentId::next_free(self.database);
        let attachment = Attachment::with_id(id);
        self.database.attachments.insert(id, attachment);
        self.attachments.insert(id);

        AttachmentMut::new(self.database, id)
    }

    /// Get a mutable reference to an attachment of this entry by ID.
    pub fn attachment_mut(&mut self, id: AttachmentId) -> Option<AttachmentMut<'_>> {
        self.attachments
            .contains(&id)
            .then(move || AttachmentMut::new(self.database, id))
    }

    /// Get a mutable reference to the history of this entry, if it exists, or create one.
    pub fn history_mut(&mut self) -> HistoryMut<'_> {
        self.history.get_or_insert_default();

        HistoryMut::new(self.database, self.id)
    }

    /// Get a mutable reference to the parent group of this entry.
    pub fn parent_mut(&mut self) -> GroupMut<'_> {
        #[allow(clippy::unwrap_used, clippy::missing_panics_doc)] // parent always exists
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

        #[allow(clippy::unwrap_used, clippy::missing_panics_doc)] // group existence is checked
        let mut new_parent = self.database.group_mut(group_id).unwrap();
        new_parent.entries.insert(my_id);
        self.parent = group_id;

        Ok(())
    }

    /// Get a mutable reference to the underlying database
    pub fn database_mut(&mut self) -> &mut Database {
        self.database
    }

    /// Set the custom icon for this entry.
    pub fn set_custom_icon(&mut self, icon_id: Option<IconId>) -> Result<(), IconNotFoundError> {
        if let Some(icon_id) = icon_id {
            if !self.database.custom_icons.contains_key(&icon_id) {
                return Err(IconNotFoundError(icon_id));
            }
        }

        self.custom_icon_id = icon_id;
        Ok(())
    }

    /// Get a mutable reference to the custom icon associated with this entry, if any.
    pub fn custom_icon_mut(&mut self) -> Option<IconMut<'_>> {
        let icon_id = self.custom_icon_id?;
        Some(IconMut::new(self.database, icon_id))
    }

    /// Remove this entry from the database, including all its attachments.
    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // the entry and parent should always be found
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

/// Error type for when a destination [GroupId] is provided that does not exist in the database
#[derive(Error, Debug)]
#[error("Destination group {0} not found")]
pub struct DestinationGroupNotFoundError(pub(crate) GroupId);

/// Error type for when an [IconId] is provided that does not exist in the database
#[derive(Error, Debug)]
#[error("Icon {0} not found")]
pub struct IconNotFoundError(IconId);

impl Deref for EntryMut<'_> {
    type Target = Entry;

    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: EntryMut can only be constructed with a valid EntryId
        self.database.entries.get(&self.id).expect("Entry not found")
    }
}

impl DerefMut for EntryMut<'_> {
    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
    fn deref_mut(&mut self) -> &mut Self::Target {
        // UNWRAP safety: EntryMut can only be constructed with a valid EntryId
        self.database.entries.get_mut(&self.id).expect("Entry not found")
    }
}

/// A variant of [EntryMut] that will persist the history of the entry when dropped.
#[clippy::has_significant_drop]
pub struct EntryTrack<'a> {
    database: &'a mut Database,
    id: EntryId,

    historical: Entry,
}

impl EntryTrack<'_> {
    pub fn as_mut(&mut self) -> EntryMut<'_> {
        EntryMut::new(self.database, self.id)
    }

    /// Move this entry to another group, tracking the change in history.
    pub fn move_to(&mut self, group_id: GroupId) -> Result<(), DestinationGroupNotFoundError> {
        self.as_mut().move_to(group_id)?;
        self.times.location_changed = Some(Times::now());
        Ok(())
    }

    /// Remove this entry from the database, tracking the change in history.
    pub fn remove(mut self) {
        let this = self.as_mut();
        this.database
            .deleted_objects
            .insert(this.id.uuid(), Some(Times::now()));

        // use EntryMut::remove to handle actual removal
        this.remove();
    }

    /// Convenience method to edit the entry in a closure, tracking changes.
    pub fn edit(&mut self, f: impl FnOnce(&mut EntryTrack<'_>)) -> &mut Self {
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

    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
    fn deref(&self) -> &Self::Target {
        self.database.entries.get(&self.id).expect("Entry not found")
    }
}

impl DerefMut for EntryTrack<'_> {
    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
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

            entry.history.get_or_insert_default().add_entry(historical);
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::{db::fields, Database};

    #[test]
    fn test_entry() {
        let mut db = Database::new();

        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Entry 1");
                e.set(fields::USERNAME, crate::db::Value::String("user".to_string()));
                e.set_protected(fields::PASSWORD, "asdf");
            })
            .id();

        assert_eq!(db.num_attachments(), 0);
        assert_eq!(db.num_entries(), 1);

        assert_eq!(
            db.entry(entry_id).unwrap().history.clone().unwrap().entries.len(),
            0
        );

        assert_eq!(
            db.entry(entry_id).unwrap().get_str(fields::TITLE).unwrap(),
            "Entry 1"
        );

        let attachment_id = db
            .entry_mut(entry_id)
            .unwrap()
            .edit_tracking(|e| {
                e.set_unprotected(fields::TITLE, "Modified Entry 1");
                e.set(
                    fields::USERNAME,
                    crate::db::Value::String(format!("modified_{}", e.get_str(fields::USERNAME).unwrap())),
                );
            })
            .add_attachment()
            .edit(|a| {
                a.name = "Attachment 1".to_string();
                a.set_data(b"Attachment data".to_vec());
                a.protected = !a.protected;
            })
            .id();

        assert_eq!(db.num_attachments(), 1);
        assert_eq!(db.num_entries(), 1);
        assert_eq!(
            db.entry(entry_id).unwrap().history.clone().unwrap().entries.len(),
            1
        );

        assert!(db.attachment(attachment_id).is_some());
        assert!(db.attachment_mut(attachment_id).is_some());

        assert!(db.entry(entry_id).unwrap().attachment(attachment_id).is_some());

        assert_eq!(
            db.entry(entry_id).unwrap().get_str(fields::TITLE).unwrap(),
            "Modified Entry 1"
        );

        // test moving to a non-existent group returns an error and does not modify the entry
        assert!(db
            .entry_mut(entry_id)
            .unwrap()
            .move_to(crate::db::GroupId::new())
            .is_err());

        db.entry_mut(entry_id)
            .unwrap()
            .attachment_mut(attachment_id)
            .unwrap()
            .edit(|a| a.protected = !a.protected);

        db.entry_mut(entry_id).unwrap().remove();

        assert_eq!(db.num_entries(), 0);
        assert_eq!(db.num_attachments(), 0);
    }
}
