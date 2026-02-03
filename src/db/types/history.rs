use crate::db::Entry;

/// An entry's history
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct History {
    pub(crate) entries: Vec<Entry>,
}
impl History {
    pub fn add_entry(&mut self, mut entry: Entry) {
        // DISCUSS: should we make sure that the last modification time is not the same
        // or older than the entry at the top of the history?
        if entry.history.is_some() {
            // Remove the history from the new history entry to avoid having
            // an exponential number of history entries.
            entry.history.take().unwrap();
        }
        self.entries.insert(0, entry);
    }

    pub fn get_entries(&self) -> &Vec<Entry> {
        &self.entries
    }

    // Determines if the entries of the history are
    // ordered by last modification time.
    #[cfg(test)]
    pub(crate) fn is_ordered(&self) -> bool {
        let mut last_modification_time: Option<&chrono::NaiveDateTime> = None;
        for entry in &self.entries {
            if last_modification_time.is_none() {
                last_modification_time = entry.times.last_modification.as_ref();
            }

            if let Some(entry_modification_time) = entry.times.last_modification.as_ref() {
                if last_modification_time.unwrap() < entry_modification_time {
                    return false;
                }
                last_modification_time = Some(entry_modification_time);
                continue;
            }
        }
        true
    }
}
