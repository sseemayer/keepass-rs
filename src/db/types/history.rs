use crate::db::Entry;

/// An entry's history
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct History {
    pub(crate) entries: Vec<Entry>,
}
impl History {
    pub(crate) fn new() -> History {
        History { entries: Vec::new() }
    }

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

    #[cfg(all(test, feature = "_merge"))]
    // Determines if the entries of the history are
    // ordered by last modification time.
    pub(crate) fn is_ordered(&self) -> bool {
        let mut last_modification_time: Option<&chrono::NaiveDateTime> = None;
        for entry in &self.entries {
            if last_modification_time.is_none() {
                last_modification_time = entry.times.get_last_modification();
            }

            let entry_modification_time = entry.times.get_last_modification().unwrap();
            // FIXME should we also handle equal modification times??
            if last_modification_time.unwrap() < entry_modification_time {
                return false;
            }
            last_modification_time = Some(entry_modification_time);
        }
        true
    }

    // Merge both histories together.
    #[cfg(feature = "_merge")]
    pub(crate) fn merge_with(&mut self, other: &History) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();
        let mut new_history_entries: HashMap<chrono::NaiveDateTime, Entry> = HashMap::new();

        for history_entry in &self.entries {
            let modification_time = history_entry.times.get_last_modification().unwrap();
            if new_history_entries.contains_key(modification_time) {
                return Err(MergeError::DuplicateHistoryEntries(
                    modification_time.to_string(),
                    history_entry.uuid.to_string(),
                ));
            }
            new_history_entries.insert(*modification_time, history_entry.clone());
        }

        for history_entry in &other.entries {
            let modification_time = history_entry.times.get_last_modification().unwrap();
            let existing_history_entry = new_history_entries.get(modification_time);
            if let Some(existing_history_entry) = existing_history_entry {
                if existing_history_entry.has_diverged_from(history_entry) {
                    log.warnings.push(format!(
                        "History entries for {} have the same modification timestamp but were not the same.",
                        existing_history_entry.uuid
                    ));
                }
            } else {
                new_history_entries.insert(*modification_time, history_entry.clone());
            }
        }

        let mut all_modification_times: Vec<&chrono::NaiveDateTime> = new_history_entries.keys().collect();
        all_modification_times.sort();
        all_modification_times.reverse();
        let mut new_entries: Vec<Entry> = vec![];
        for modification_time in &all_modification_times {
            new_entries.push(new_history_entries.get(modification_time).unwrap().clone());
        }

        self.entries = new_entries;
        Ok(log)
    }
}
