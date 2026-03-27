use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
};

use thiserror::Error;
use uuid::Uuid;

use crate::{
    db::{
        attachment::{AttachmentMut, AttachmentRef},
        fields, Attachment, AttachmentId, AutoType, Color, CustomDataItem, CustomIcon, CustomIconId,
        CustomIconMut, CustomIconNotFoundError, CustomIconRef, GroupId, GroupMut, GroupRef, History, Icon,
        Times, Value,
    },
    Database,
};

/// Unique identifier for an [Entry]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct EntryId(Uuid);

impl EntryId {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub(crate) const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the Uuid contained inside
    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

/// A database entry containing several key-value fields.
#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Entry {
    pub(crate) id: EntryId,
    pub(crate) parent: GroupId,

    /// the key-value fields of this entry, such as username and password.
    ///
    /// Common field names are available in [crate::db::fields].
    pub fields: HashMap<String, Value<String>>,

    /// AutoType settings for this entry
    pub autotype: Option<AutoType>,

    /// tags associated with this entry
    pub tags: Vec<String>,

    /// timestamps for this entry
    pub times: Times,

    /// custom data items associated with this entry
    pub custom_data: HashMap<String, CustomDataItem>,

    pub(crate) icon: Option<Icon>,

    /// foreground color for this entry
    pub foreground_color: Option<Color>,

    /// background color for this entry
    pub background_color: Option<Color>,

    /// URL override for this entry
    pub override_url: Option<String>,

    /// whether to enable password quality check for this entry
    pub quality_check: Option<bool>,

    /// attachments associated with this entry, mapped by attachment name to attachment ID
    pub(crate) attachments: HashMap<String, AttachmentId>,

    /// history of this entry
    pub history: Option<History>,
}

impl Entry {
    pub(crate) fn new(parent: GroupId) -> Self {
        Entry::with_id(EntryId::new(), parent)
    }

    pub(crate) fn with_id(id: EntryId, parent: GroupId) -> Self {
        Entry {
            id,
            parent,
            fields: HashMap::new(),
            autotype: None,
            tags: Vec::new(),
            times: Times::new(),
            custom_data: HashMap::new(),
            icon: None,
            foreground_color: None,
            background_color: None,
            override_url: None,
            quality_check: None,
            attachments: HashMap::new(),
            history: Some(History::default()),
        }
    }

    /// Get the unique identifier for the [Entry]
    pub fn id(&self) -> EntryId {
        self.id
    }

    /// Get the icon of this entry, if it exists
    pub fn icon(&self) -> Option<&Icon> {
        self.icon.as_ref()
    }

    /// Get a field by name, taking care of unprotecting Protected values automatically
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|v| v.as_str())
    }

    /// Set a field's value by name
    pub fn set(&mut self, key: impl Into<String>, value: Value<String>) {
        self.fields.insert(key.into(), value);
    }

    /// Set a field's unprotected value by name
    pub fn set_unprotected(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.set(key, Value::unprotected(value));
    }

    /// Set a field's protected value by name
    pub fn set_protected(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.set(key, Value::protected(value));
    }

    /// Convenience method for getting the raw value of the 'otp' field
    pub fn get_raw_otp_value(&self) -> Option<&str> {
        self.get(fields::OTP)
    }

    /// Convenience method for getting the value of the 'Title' field
    pub fn get_title(&self) -> Option<&str> {
        self.get(fields::TITLE)
    }

    /// Convenience method for getting the value of the 'UserName' field
    pub fn get_username(&self) -> Option<&str> {
        self.get(fields::USERNAME)
    }

    /// Convenience method for getting the value of the 'Password' field
    pub fn get_password(&self) -> Option<&str> {
        self.get(fields::PASSWORD)
    }

    /// Convenience method for getting the value of the 'URL' field
    pub fn get_url(&self) -> Option<&str> {
        self.get(fields::URL)
    }
}

impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An immutable reference to an [Entry]. Implements [Deref] to [&Entry][Entry].
pub struct EntryRef<'a> {
    database: &'a Database,
    id: EntryId,
    history_index: Option<usize>,
}

impl EntryRef<'_> {
    pub(crate) fn new(database: &Database, id: EntryId) -> EntryRef<'_> {
        EntryRef {
            database,
            id,
            history_index: None,
        }
    }

    pub(crate) fn new_historical(
        database: &Database,
        id: EntryId,
        history_index: Option<usize>,
    ) -> EntryRef<'_> {
        EntryRef {
            database,
            id,
            history_index,
        }
    }

    /// Get a reference to the parent group of this entry.
    pub fn parent(&self) -> GroupRef<'_> {
        #[allow(clippy::unwrap_used, clippy::missing_panics_doc)] // parent always exists
        self.database.group(self.parent).unwrap()
    }

    /// Gets an [EntryRef] to a historical version of the [Entry], if it exists
    pub fn historical(&self, index: usize) -> Option<EntryRef<'_>> {
        if let Some(h) = &self.history {
            if index < h.entries.len() {
                Some(EntryRef {
                    database: self.database,
                    id: self.id,
                    history_index: Some(index),
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get a reference to the underlying database
    pub fn database(&self) -> &Database {
        self.database
    }

    /// Get a reference to an attachment by id, if it exists.
    pub fn attachment(&self, id: AttachmentId) -> Option<AttachmentRef<'_>> {
        self.attachments
            .values()
            .find(|&attachment_id| *attachment_id == id)
            .cloned()
            .map(move |attachment_id| AttachmentRef::new(self.database, attachment_id))
    }

    /// Get a reference to an attachment by name, if it exists.
    pub fn attachment_by_name(&self, name: &str) -> Option<AttachmentRef<'_>> {
        self.attachments
            .get(name)
            .cloned()
            .map(move |attachment_id| AttachmentRef::new(self.database, attachment_id))
    }

    /// Get an iterator over the attachments of this entry.
    pub fn attachments(&self) -> impl Iterator<Item = AttachmentRef<'_>> {
        self.attachments
            .values()
            .cloned()
            .map(move |attachment_id| AttachmentRef::new(self.database, attachment_id))
    }

    /// Get the custom icon of this entry, if it exists and is a custom icon.
    pub fn custom_icon(&self) -> Option<CustomIconRef<'_>> {
        if let Some(Icon::Custom(custom_icon_id)) = self.icon {
            Some(CustomIconRef::new(self.database, custom_icon_id))
        } else {
            None
        }
    }
}

impl Deref for EntryRef<'_> {
    type Target = Entry;

    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: EntryRef can only be constructed with a valid EntryId
        let entry = self.database.entries.get(&self.id).expect("Entry not found");

        if let Some(n) = self.history_index {
            // UNWRAP safety: history existance checked on EntryRef creation
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            &entry.history.as_ref().unwrap().entries[n]
        } else {
            entry
        }
    }
}

/// A mutable reference to an [Entry]. Implements [DerefMut] to [&mut Entry][Entry].
pub struct EntryMut<'a> {
    database: &'a mut Database,
    id: EntryId,
    history_index: Option<usize>,
}

impl EntryMut<'_> {
    pub(crate) fn new(database: &mut Database, id: EntryId) -> EntryMut<'_> {
        EntryMut {
            database,
            id,
            history_index: None,
        }
    }

    pub(crate) fn new_historical(
        database: &mut Database,
        id: EntryId,
        history_index: Option<usize>,
    ) -> EntryMut<'_> {
        EntryMut {
            database,
            id,
            history_index,
        }
    }

    /// Get an immutable reference to the entry.
    pub fn as_ref(&self) -> EntryRef<'_> {
        EntryRef {
            database: self.database,
            id: self.id,
            history_index: self.history_index,
        }
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
    ///
    /// NOTE: will always operate on the main Entry, not a historical version of it.
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

    /// Get a mutable reference to the parent group of this entry.
    pub fn parent_mut(&mut self) -> GroupMut<'_> {
        #[allow(clippy::unwrap_used, clippy::missing_panics_doc)] // parent always exists
        self.database.group_mut(self.parent).unwrap()
    }

    /// Get a mutable reference to an attachment by id, if it exists.
    pub fn attachment_mut(&mut self, id: AttachmentId) -> Option<AttachmentMut<'_>> {
        self.attachments
            .values()
            .find(|&attachment_id| *attachment_id == id)
            .cloned()
            .map(move |attachment_id| AttachmentMut::new(self.database, attachment_id))
    }

    /// Get a mutable reference to an attachment by name, if it exists.
    pub fn attachment_by_name_mut(&mut self, name: &str) -> Option<AttachmentMut<'_>> {
        self.attachments
            .get(name)
            .cloned()
            .map(move |attachment_id| AttachmentMut::new(self.database, attachment_id))
    }

    /// Apply a closure to each attachment of this entry, with mutable access.
    pub fn foreach_attachment_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(AttachmentMut<'_>),
    {
        let attachments: Vec<AttachmentId> = self.attachments.values().copied().collect();
        for attachment_id in attachments {
            f(AttachmentMut::new(self.database, attachment_id));
        }
    }

    /// Add an attachment to this entry with the given name and data.
    pub fn add_attachment(&mut self, name: impl Into<String>, data: Value<Vec<u8>>) -> AttachmentMut<'_> {
        let id = AttachmentId::next_free(self.database);

        let entries: HashSet<(EntryId, Option<usize>)> = vec![(self.id, None)].into_iter().collect();

        self.database
            .attachments
            .insert(id, Attachment { id, entries, data });

        if let Some(old_id) = self.attachments.insert(name.into(), id) {
            // if there was an old attachment with this name, remove it
            self.remove_attachment_by_id(old_id);
        }

        AttachmentMut::new(self.database, id)
    }

    /// Remove an attachment by name from this entry.
    ///
    /// If it was the last reference to the attachment, remove it from the database.
    pub fn remove_attachment_by_name(&mut self, name: &str) {
        let id = self.id;

        // remove the attachment reference from this entry
        if let Some(attachment_id) = self.attachments.remove(name) {
            if let Some(mut attachment) = self.database.attachment_mut(attachment_id) {
                attachment.entries.retain(|&(entry_id, _)| entry_id != id);

                // if this was the last entry referencing the attachment, remove it from the database
                if attachment.entries.is_empty() {
                    attachment.remove();
                }
            }
        }
    }

    /// Remove an attachment by id from this entry.
    ///
    /// If it was the last reference to the attachment, remove it from the database.
    pub fn remove_attachment_by_id(&mut self, attachment_id: AttachmentId) {
        let id = self.id;

        // remove the attachment reference from this entry
        let mut names_to_remove = Vec::new();
        for (name, &att_id) in &self.attachments {
            if att_id == attachment_id {
                names_to_remove.push(name.clone());
            }
        }

        for name in names_to_remove {
            self.attachments.remove(&name);
        }

        if let Some(mut attachment) = self.database.attachment_mut(attachment_id) {
            attachment.entries.retain(|&(entry_id, _)| entry_id != id);

            // if this was the last entry referencing the attachment, remove it from the database
            if attachment.entries.is_empty() {
                attachment.remove();
            }
        }
    }

    /// Remove the icon from this entry, if it exists.
    pub fn set_icon_none(&mut self) {
        let id = self.id;
        let history_index = self.history_index;

        if let Some(Icon::Custom(custom_icon_id)) = self.icon {
            // if this entry had a custom icon, remove this entry from the icon's reference list
            if let Some(mut custom_icon) = self.database.custom_icon_mut(custom_icon_id) {
                custom_icon.entries.retain(|&(entry_id, entry_history_index)| {
                    !(entry_id == id && entry_history_index == history_index)
                });
            }
        }

        self.icon = None;
    }

    /// Set a built-in icon for this entry by its ID, removing any existing icon.
    pub fn set_icon_builtin(&mut self, icon_id: usize) {
        self.set_icon_none();
        self.icon = Some(Icon::BuiltIn(icon_id));
    }

    /// Set a custom icon for this entry by its ID, removing any existing icon.
    pub fn set_icon_custom(&mut self, custom_icon_id: CustomIconId) -> Result<(), CustomIconNotFoundError> {
        self.set_icon_none();

        let id = self.id;
        let history_index = self.history_index;

        let mut custom_icon = self
            .database
            .custom_icon_mut(custom_icon_id)
            .ok_or(CustomIconNotFoundError(custom_icon_id))?;

        custom_icon.entries.insert((id, history_index));

        self.icon = Some(Icon::Custom(custom_icon_id));

        Ok(())
    }

    /// Set a custom icon for this entry by providing the raw data, removing any existing icon.
    /// Returns a mutable reference to the newly created custom icon.
    pub fn set_icon_custom_new(&mut self, data: Vec<u8>) -> CustomIconMut<'_> {
        self.set_icon_none();

        let custom_icon_id = CustomIconId::new();

        let id = self.id;
        let history_index = self.history_index;

        self.database.custom_icons.insert(
            custom_icon_id,
            CustomIcon {
                id: custom_icon_id,
                entries: vec![(id, history_index)].into_iter().collect(),
                groups: HashSet::new(),
                data,
            },
        );

        self.icon = Some(Icon::Custom(custom_icon_id));

        CustomIconMut::new(self.database, custom_icon_id)
    }

    /// Get a mutable reference to the custom icon of this entry, if it exists and is a custom
    /// icon.
    pub fn custom_icon_mut(&mut self) -> Option<CustomIconMut<'_>> {
        if let Some(Icon::Custom(custom_icon_id)) = self.icon {
            Some(CustomIconMut::new(self.database, custom_icon_id))
        } else {
            None
        }
    }

    /// Move this entry to another group.
    ///
    /// NOTE: will always operate on the main Entry, not a historical version of it.
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

    /// Remove this entry from the database, including all its attachments.
    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // the entry and parent should always be found
    pub fn remove(mut self) {
        let id = self.id;

        // remove references to this entry from attachments
        self.foreach_attachment_mut(|mut attachment| {
            attachment.entries.retain(|&(entry_id, _)| entry_id != id);

            // if this was the last entry referencing the attachment, remove it from the database
            if attachment.entries.is_empty() {
                attachment.remove();
            }
        });

        let entry = self.database.entries.remove(&self.id).expect("Entry not found");

        // Remove from parent group
        let mut parent = self
            .database
            .group_mut(entry.parent)
            .expect("Parent group not found");
        parent.entries.remove(&self.id);
    }
}

/// Error type for when a destination [GroupId] is provided that does not exist in the database
#[derive(Error, Debug)]
#[error("Destination group {0} not found")]
pub struct DestinationGroupNotFoundError(pub(crate) GroupId);

impl Deref for EntryMut<'_> {
    type Target = Entry;

    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: EntryMut can only be constructed with a valid EntryId
        let entry = self.database.entries.get(&self.id).expect("Entry not found");

        if let Some(n) = self.history_index {
            // UNWRAP safety: history existence checked on EntryMut creation
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            &entry.history.as_ref().unwrap().entries[n]
        } else {
            entry
        }
    }
}

impl DerefMut for EntryMut<'_> {
    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
    fn deref_mut(&mut self) -> &mut Self::Target {
        // UNWRAP safety: EntryMut can only be constructed with a valid EntryId
        let entry = self.database.entries.get_mut(&self.id).expect("Entry not found");

        if let Some(n) = self.history_index {
            // UNWRAP safety: history existence checked on EntryMut creation
            #[allow(clippy::unwrap_used, clippy::indexing_slicing)]
            &mut entry.history.as_mut().unwrap().entries[n]
        } else {
            entry
        }
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
    /// Turn this tracked entry into a normal mutable reference to the entry
    pub fn as_mut(&mut self) -> EntryMut<'_> {
        EntryMut {
            database: self.database,
            id: self.id,
            history_index: None,
        }
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
    pub fn set(&mut self, key: impl Into<String>, value: Value<String>) {
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

    /// Add an attachment, tracking changes.
    pub fn add_attachment(&mut self, name: impl Into<String>, data: Value<Vec<u8>>) -> AttachmentMut<'_> {
        self.times.last_modification = Some(Times::now());
        let mut this = self.as_mut();
        let id = this.add_attachment(name, data).id;

        AttachmentMut::new(self.database, id)
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
        self.database.entries.get_mut(&self.id).expect("Entry not found")
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

    use crate::{
        db::{fields, Value},
        Database,
    };

    #[test]
    fn test_entry() {
        let mut db = Database::new();

        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Entry 1");
                e.set(
                    fields::USERNAME,
                    crate::db::Value::unprotected("user".to_string()),
                );
                e.set_protected(fields::PASSWORD, "asdf");

                e.set_icon_custom_new(vec![1, 2, 3]);
            })
            .id();

        assert_eq!(db.num_attachments(), 0);
        assert_eq!(db.num_entries(), 1);

        assert_eq!(
            db.entry(entry_id).unwrap().history.clone().unwrap().entries.len(),
            0
        );

        assert_eq!(db.entry(entry_id).unwrap().get(fields::TITLE).unwrap(), "Entry 1");

        db.entry_mut(entry_id).unwrap().edit_tracking(|e| {
            e.set_unprotected(fields::TITLE, "Modified Entry 1");
            e.set(
                fields::USERNAME,
                crate::db::Value::unprotected(format!("modified_{}", e.get(fields::USERNAME).unwrap())),
            );

            e.add_attachment("Attachment 1", Value::protected(b"Attachment data".to_vec()));
        });

        assert_eq!(db.num_attachments(), 1);
        assert_eq!(db.num_entries(), 1);
        assert_eq!(
            db.entry(entry_id).unwrap().history.clone().unwrap().entries.len(),
            1
        );

        assert!(db
            .entry(entry_id)
            .unwrap()
            .attachments
            .get("Attachment 1")
            .is_some());

        assert_eq!(
            db.entry(entry_id).unwrap().get(fields::TITLE).unwrap(),
            "Modified Entry 1"
        );

        // test moving to a non-existent group returns an error and does not modify the entry
        assert!(db
            .entry_mut(entry_id)
            .unwrap()
            .move_to(crate::db::GroupId::new())
            .is_err());

        db.entry_mut(entry_id).unwrap().edit(|e| {
            let mut att = e.attachment_by_name_mut("Attachment 1").unwrap();

            att.data = Value::unprotected(b"Modified attachment data".to_vec());
        });

        db.entry_mut(entry_id).unwrap().remove();

        assert_eq!(db.num_entries(), 0);
        assert_eq!(db.num_attachments(), 0);
    }
}
