use std::ops::{Deref, DerefMut};

use thiserror::Error;

use crate::db::{Database, Entry, EntryId, EntryMut, GroupId};

/// History of an [Entry] containing previous versions.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct History {
    pub(crate) entries: Vec<Entry>,
}
impl History {
    /// Add a new entry to the history
    pub fn add_entry(&mut self, mut entry: Entry) {
        // DISCUSS: should we make sure that the last modification time is not the same
        // or older than the entry at the top of the history?

        // Remove the history from the new history entry to avoid having
        // an exponential number of history entries.
        entry.history.take();

        self.entries.insert(0, entry);
    }

    /// Get the history entries, ordered from most recent to oldest.
    pub fn entries(&self) -> &Vec<Entry> {
        &self.entries
    }
}

/// An immutable reference to the history of an [Entry]. Implements [Deref] to [&History][History]
pub struct HistoryRef<'a> {
    database: &'a Database,
    entry_id: EntryId,
}

impl<'a> HistoryRef<'a> {
    pub(crate) fn new(database: &'a Database, entry_id: EntryId) -> Self {
        Self { database, entry_id }
    }
}

impl Deref for HistoryRef<'_> {
    type Target = History;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: HistoryRef may only be constructed on valid entries that have a history
        self.database
            .entries
            .get(&self.entry_id)
            .unwrap()
            .history
            .as_ref()
            .unwrap()
    }
}

/// A mutable reference to the history of an [Entry]. Implements [DerefMut] to [&mut History][History]
pub struct HistoryMut<'a> {
    database: &'a mut Database,
    entry_id: EntryId,
}

#[derive(Debug, Error)]
pub enum RestoreEntryError {
    #[error("Entry with index {0} not found")]
    EntryNotFound(usize),

    #[error("Destination group with id {0} not found")]
    DestinationGroupNotFound(GroupId),
}

impl<'a> HistoryMut<'a> {
    pub(crate) fn new(database: &'a mut Database, entry_id: EntryId) -> Self {
        Self { database, entry_id }
    }

    /// Get an immutable reference to the history from this mutable reference.
    pub fn as_ref(&self) -> HistoryRef<'_> {
        HistoryRef {
            database: self.database,
            entry_id: self.entry_id,
        }
    }

    /// Restore a previous version of the entry from the history, creating a new entry with the
    /// same content as the historical entry and moving it to the specified destination group.
    pub fn restore_entry(
        &mut self,
        index: usize,
        destination: GroupId,
    ) -> Result<EntryMut<'_>, RestoreEntryError> {
        let this = self.as_ref();
        let history = this.deref();

        let entry_data = history
            .entries
            .get(index)
            .ok_or(RestoreEntryError::EntryNotFound(index))?
            .clone();

        let entry_history = History {
            entries: history.entries[..index].to_vec(),
        };

        let entry_id = self
            .database
            .group_mut(destination)
            .ok_or(RestoreEntryError::DestinationGroupNotFound(destination))?
            .add_entry()
            .edit(|e| {
                e.fields = entry_data.fields;
                e.attachments = entry_data.attachments;
                e.autotype = entry_data.autotype;
                e.tags = entry_data.tags;
                e.times = entry_data.times;
                e.custom_data = entry_data.custom_data;
                e.icon_id = entry_data.icon_id;
                e.custom_icon_id = entry_data.custom_icon_id;
                e.foreground_color = entry_data.foreground_color;
                e.background_color = entry_data.background_color;
                e.override_url = entry_data.override_url;
                e.quality_check = entry_data.quality_check;
                e.history = Some(entry_history);
            })
            .id();

        Ok(self.database.entry_mut(entry_id).unwrap())
    }
}

impl Deref for HistoryMut<'_> {
    type Target = History;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: HistoryMut may only be constructed on valid entries that have a history
        self.database
            .entries
            .get(&self.entry_id)
            .unwrap()
            .history
            .as_ref()
            .unwrap()
    }
}

impl DerefMut for HistoryMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // UNWRAP safety: HistoryMut may only be constructed on valid entries that have a history
        self.database
            .entries
            .get_mut(&self.entry_id)
            .unwrap()
            .history
            .as_mut()
            .unwrap()
    }
}
