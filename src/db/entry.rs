use std::collections::HashMap;

use secstr::SecStr;
use uuid::Uuid;

#[cfg(feature = "_merge")]
use crate::db::merge::{MergeError, MergeLog};
#[cfg(all(test, feature = "_merge"))]
use std::{thread, time};

use crate::db::{Color, CustomData, Times};

#[cfg(feature = "totp")]
use crate::db::otp::{TOTPError, TOTP};

/// A database entry containing several key-value fields.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Entry {
    pub uuid: Uuid,
    pub fields: HashMap<String, Value>,
    pub autotype: Option<AutoType>,
    pub tags: Vec<String>,

    pub times: Times,

    pub custom_data: CustomData,

    pub icon_id: Option<usize>,
    pub custom_icon_uuid: Option<Uuid>,

    pub foreground_color: Option<Color>,
    pub background_color: Option<Color>,

    pub override_url: Option<String>,
    pub quality_check: Option<bool>,

    pub history: Option<History>,
}
impl Entry {
    pub fn new() -> Entry {
        Entry {
            uuid: Uuid::new_v4(),
            times: Times::new(),
            ..Default::default()
        }
    }

    #[cfg(feature = "_merge")]
    pub(crate) fn merge(&self, other: &Entry) -> Result<(Option<Entry>, MergeLog), MergeError> {
        let mut log = MergeLog::default();

        let source_last_modification = match other.times.get_last_modification() {
            Some(t) => *t,
            None => {
                log.warnings.push(format!(
                    "Entry {} did not have a last modification timestamp",
                    other.uuid
                ));
                Times::epoch()
            }
        };
        let destination_last_modification = match self.times.get_last_modification() {
            Some(t) => *t,
            None => {
                log.warnings.push(format!(
                    "Entry {} did not have a last modification timestamp",
                    self.uuid
                ));
                Times::now()
            }
        };

        if destination_last_modification == source_last_modification {
            if !self.has_diverged_from(&other) {
                // This should never happen.
                // This means that an entry was updated without updating the last modification
                // timestamp.
                return Err(MergeError::EntryModificationTimeNotUpdated(
                    other.uuid.to_string(),
                ));
            }
            return Ok((None, log));
        }

        let (mut merged_entry, entry_merge_log) = match destination_last_modification > source_last_modification
        {
            true => self.merge_history(other)?,
            false => other.clone().merge_history(&self)?,
        };

        // The location changed timestamp is handled separately when merging two databases.
        if let Some(location_changed_timestamp) = self.times.get_location_changed() {
            merged_entry
                .times
                .set_location_changed(*location_changed_timestamp);
        }

        return Ok((Some(merged_entry), entry_merge_log));
    }

    #[cfg(feature = "_merge")]
    pub(crate) fn merge_history(&self, other: &Entry) -> Result<(Entry, MergeLog), MergeError> {
        let mut log = MergeLog::default();

        let mut source_history = match &other.history {
            Some(h) => h.clone(),
            None => {
                log.warnings.push(format!(
                    "Entry {} from source database had no history.",
                    self.uuid
                ));
                History::default()
            }
        };
        let mut destination_history = match &self.history {
            Some(h) => h.clone(),
            None => {
                log.warnings.push(format!(
                    "Entry {} from destination database had no history.",
                    self.uuid
                ));
                History::default()
            }
        };
        let mut response = self.clone();

        if other.has_uncommitted_changes() {
            log.warnings.push(format!(
                "Entry {} from source database has uncommitted changes.",
                self.uuid
            ));
            source_history.add_entry(other.clone());
        }

        // TODO we should probably check for uncommitted changes in the destination
        // database here too for consistency.

        let history_merge_log = destination_history.merge_with(&source_history)?;
        response.history = Some(destination_history);

        Ok((response, log.merge_with(&history_merge_log)))
    }

    #[cfg(all(test, feature = "_merge"))]
    // Convenience function used in unit tests, to make sure that:
    // 1. The history gets updated after changing a field
    // 2. We wait a second before commiting the changes so that the timestamp is not the same
    //    as it previously was. This is necessary since the timestamps in the KDBX format
    //    do not preserve the msecs.
    pub(crate) fn set_field_and_commit(&mut self, field_name: &str, field_value: &str) {
        self.fields.insert(
            field_name.to_string(),
            Value::Unprotected(field_value.to_string()),
        );
        thread::sleep(time::Duration::from_secs(1));
        self.update_history();
    }

    #[cfg(feature = "_merge")]
    // Convenience function used in when merging two entries
    pub(crate) fn has_diverged_from(&self, other_entry: &Entry) -> bool {
        let new_times = Times::default();

        let mut self_without_times = self.clone();
        self_without_times.times = new_times.clone();

        let mut other_without_times = other_entry.clone();
        other_without_times.times = new_times.clone();

        !self_without_times.eq(&other_without_times)
    }
}

impl<'a> Entry {
    /// Get a field by name, taking care of unprotecting Protected values automatically
    pub fn get(&'a self, key: &str) -> Option<&'a str> {
        match self.fields.get(key) {
            Some(&Value::Bytes(_)) => None,
            Some(&Value::Protected(ref pv)) => std::str::from_utf8(pv.unsecure()).ok(),
            Some(&Value::Unprotected(ref uv)) => Some(&uv),
            None => None,
        }
    }

    /// Get a bytes field by name
    pub fn get_bytes(&'a self, key: &str) -> Option<&'a [u8]> {
        match self.fields.get(key) {
            Some(&Value::Bytes(ref b)) => Some(&b),
            _ => None,
        }
    }

    pub fn get_uuid(&'a self) -> &'a Uuid {
        &self.uuid
    }

    /// Get a timestamp field by name
    ///
    /// Returning the chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub fn get_time(&self, key: &str) -> Option<&chrono::NaiveDateTime> {
        self.times.get(key)
    }

    /// Convenience method for getting the time that the entry expires.
    /// This value is usually only meaningful/useful when expires == true
    pub fn get_expiry_time(&self) -> Option<&chrono::NaiveDateTime> {
        self.times.get_expiry()
    }

    /// Convenience method for getting a TOTP from this entry
    #[cfg(feature = "totp")]
    pub fn get_otp(&'a self) -> Result<TOTP, TOTPError> {
        self.get_raw_otp_value().ok_or(TOTPError::NoRecord)?.parse()
    }

    /// Convenience method for getting the raw value of the 'otp' field
    pub fn get_raw_otp_value(&'a self) -> Option<&'a str> {
        self.get("otp")
    }

    /// Convenience method for getting the value of the 'Title' field
    pub fn get_title(&'a self) -> Option<&'a str> {
        self.get("Title")
    }

    /// Convenience method for getting the value of the 'UserName' field
    pub fn get_username(&'a self) -> Option<&'a str> {
        self.get("UserName")
    }

    /// Convenience method for getting the value of the 'Password' field
    pub fn get_password(&'a self) -> Option<&'a str> {
        self.get("Password")
    }

    /// Convenience method for getting the value of the 'URL' field
    pub fn get_url(&'a self) -> Option<&'a str> {
        self.get("URL")
    }

    /// Adds the current version of the entry to the entry's history
    /// and updates the last modification timestamp.
    /// The history will only be updated if the entry has
    /// uncommitted changes.
    ///
    /// Returns whether or not a new history entry was added.
    pub fn update_history(&mut self) -> bool {
        if self.history.is_none() {
            self.history = Some(History::default());
        }

        if !self.has_uncommitted_changes() {
            return false;
        }

        self.times.set_last_modification(Times::now());

        let mut new_history_entry = self.clone();
        new_history_entry.history.take().unwrap();

        // TODO should we validate that the history is enabled?
        // TODO should we validate the maximum size of the history?
        self.history.as_mut().unwrap().add_entry(new_history_entry);

        true
    }

    /// Determines if the entry was modified since the last
    /// history update.
    fn has_uncommitted_changes(&self) -> bool {
        if let Some(history) = self.history.as_ref() {
            if history.entries.len() == 0 {
                return true;
            }

            let new_times = Times::default();

            let mut sanitized_entry = self.clone();
            sanitized_entry.times = new_times.clone();
            sanitized_entry.history.take();

            let mut last_history_entry = history.entries.get(0).unwrap().clone();
            last_history_entry.times = new_times.clone();
            last_history_entry.history.take();

            if sanitized_entry.eq(&last_history_entry) {
                return false;
            }
        }
        true
    }
}

/// A value that can be a raw string, byte array, or protected memory region
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Value {
    Bytes(Vec<u8>),
    Unprotected(String),
    Protected(SecStr),
}

impl Value {
    pub fn is_empty(&self) -> bool {
        match self {
            Value::Bytes(b) => b.is_empty(),
            Value::Unprotected(u) => u.is_empty(),
            Value::Protected(p) => p.unsecure().is_empty(),
        }
    }
}

#[cfg(feature = "serialization")]
impl serde::Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Value::Bytes(b) => serializer.serialize_bytes(b),
            Value::Unprotected(u) => serializer.serialize_str(u),
            Value::Protected(p) => serializer.serialize_str(String::from_utf8_lossy(p.unsecure()).as_ref()),
        }
    }
}

/// An AutoType setting associated with an Entry
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AutoType {
    pub enabled: bool,
    pub sequence: Option<String>,
    pub associations: Vec<AutoTypeAssociation>,
}

/// A window association associated with an AutoType setting
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AutoTypeAssociation {
    pub window: Option<String>,
    pub sequence: Option<String>,
}

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
            new_history_entries.insert(modification_time.clone(), history_entry.clone());
        }

        for history_entry in &other.entries {
            let modification_time = history_entry.times.get_last_modification().unwrap();
            let existing_history_entry = new_history_entries.get(modification_time);
            if let Some(existing_history_entry) = existing_history_entry {
                if existing_history_entry.has_diverged_from(&history_entry) {
                    log.warnings.push(format!(
                        "History entries for {} have the same modification timestamp but were not the same.",
                        existing_history_entry.uuid
                    ));
                }
            } else {
                new_history_entries.insert(modification_time.clone(), history_entry.clone());
            }
        }

        let mut all_modification_times: Vec<&chrono::NaiveDateTime> = new_history_entries.keys().collect();
        all_modification_times.sort();
        all_modification_times.reverse();
        let mut new_entries: Vec<Entry> = vec![];
        for modification_time in &all_modification_times {
            new_entries.push(new_history_entries.get(&modification_time).unwrap().clone());
        }

        self.entries = new_entries;
        Ok(log)
    }
}

#[cfg(test)]
mod entry_tests {
    use std::{thread, time};

    use secstr::SecStr;

    use super::{Entry, Value};

    #[test]
    fn byte_values() {
        let mut entry = Entry::new();
        entry
            .fields
            .insert("a-bytes".to_string(), Value::Bytes(vec![1, 2, 3]));

        entry.fields.insert(
            "a-unprotected".to_string(),
            Value::Unprotected("asdf".to_string()),
        );

        entry.fields.insert(
            "a-protected".to_string(),
            Value::Protected(SecStr::new("asdf".as_bytes().to_vec())),
        );

        assert_eq!(entry.get_bytes("a-bytes"), Some(&[1, 2, 3][..]));
        assert_eq!(entry.get_bytes("a-unprotected"), None);
        assert_eq!(entry.get_bytes("a-protected"), None);

        assert_eq!(entry.get("a-bytes"), None);

        assert_eq!(entry.fields["a-bytes"].is_empty(), false);
    }

    #[test]
    fn update_history() {
        let mut entry = Entry::new();
        let mut last_modification_time = entry.times.get_last_modification().unwrap().clone();

        entry
            .fields
            .insert("Username".to_string(), Value::Unprotected("user".to_string()));
        // Making sure to wait 1 sec before update the history, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));

        assert!(entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 1);
        assert_ne!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );
        last_modification_time = entry.times.get_last_modification().unwrap().clone();
        thread::sleep(time::Duration::from_secs(1));

        // Updating the history without making any changes
        // should not do anything.
        assert!(!entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 1);
        assert_eq!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );

        entry
            .fields
            .insert("Title".to_string(), Value::Unprotected("first title".to_string()));

        assert!(entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 2);
        assert_ne!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );
        last_modification_time = entry.times.get_last_modification().unwrap().clone();
        thread::sleep(time::Duration::from_secs(1));

        assert!(!entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 2);
        assert_eq!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );

        entry.fields.insert(
            "Title".to_string(),
            Value::Unprotected("second title".to_string()),
        );

        assert!(entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 3);
        assert_ne!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );
        last_modification_time = entry.times.get_last_modification().unwrap().clone();
        thread::sleep(time::Duration::from_secs(1));

        assert!(!entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 3);
        assert_eq!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );

        let last_history_entry = entry.history.as_ref().unwrap().entries.get(0).unwrap();
        assert_eq!(last_history_entry.get_title().unwrap(), "second title");

        for history_entry in &entry.history.unwrap().entries {
            assert!(history_entry.history.is_none());
        }
    }

    #[cfg(feature = "totp")]
    #[test]
    fn totp() {
        let mut entry = Entry::new();
        entry.fields.insert("otp".to_string(), Value::Unprotected("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30".to_string()));

        assert!(entry.get_otp().is_ok());
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn serialization() {
        assert_eq!(
            serde_json::to_string(&Value::Bytes(vec![65, 66, 67])).unwrap(),
            "[65,66,67]".to_string()
        );

        assert_eq!(
            serde_json::to_string(&Value::Unprotected("ABC".to_string())).unwrap(),
            "\"ABC\"".to_string()
        );

        assert_eq!(
            serde_json::to_string(&Value::Protected(SecStr::new("ABC".as_bytes().to_vec()))).unwrap(),
            "\"ABC\"".to_string()
        );
    }
}
