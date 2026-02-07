use crate::db::Entry;

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
