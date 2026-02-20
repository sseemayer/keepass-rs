use std::collections::HashMap;

use uuid::Uuid;

use crate::db::{fields, Attachment, AutoType, Color, CustomDataItem, History, Times, Value};

/// A database entry containing several key-value fields.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Entry {
    pub uuid: Uuid,
    pub fields: HashMap<String, Value>,
    pub autotype: Option<AutoType>,
    pub tags: Vec<String>,

    pub times: Times,

    pub custom_data: HashMap<String, CustomDataItem>,

    pub icon_id: Option<usize>,
    pub custom_icon: Option<(Uuid, Vec<u8>)>,

    pub foreground_color: Option<Color>,
    pub background_color: Option<Color>,

    pub override_url: Option<String>,
    pub quality_check: Option<bool>,

    pub attachments: HashMap<String, Attachment>,

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
}

impl<'a> Entry {
    /// Get a field by name, taking care of unprotecting Protected values automatically
    pub fn get(&'a self, key: &str) -> Option<&'a str> {
        self.fields.get(key).map(|v| v.as_str())
    }

    /// Convenience method for getting the raw value of the 'otp' field
    pub fn get_raw_otp_value(&'a self) -> Option<&'a str> {
        self.get(fields::OTP)
    }

    /// Convenience method for getting the value of the 'Title' field
    pub fn get_title(&'a self) -> Option<&'a str> {
        self.get(fields::TITLE)
    }

    /// Convenience method for getting the value of the 'UserName' field
    pub fn get_username(&'a self) -> Option<&'a str> {
        self.get(fields::USERNAME)
    }

    /// Convenience method for getting the value of the 'Password' field
    pub fn get_password(&'a self) -> Option<&'a str> {
        self.get(fields::PASSWORD)
    }

    /// Convenience method for getting the value of the 'URL' field
    pub fn get_url(&'a self) -> Option<&'a str> {
        self.get(fields::URL)
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

        self.times.last_modification = Some(Times::now());

        let mut new_history_entry = self.clone();
        new_history_entry.history.take().unwrap();

        // TODO should we validate that the history is enabled?
        // TODO should we validate the maximum size of the history?
        self.history.as_mut().unwrap().add_entry(new_history_entry);

        true
    }

    /// Determines if the entry was modified since the last
    /// history update.
    pub(crate) fn has_uncommitted_changes(&self) -> bool {
        if let Some(history) = self.history.as_ref() {
            if history.entries.is_empty() {
                return true;
            }

            let new_times = Times::default();

            let mut sanitized_entry = self.clone();
            sanitized_entry.times = new_times.clone();
            sanitized_entry.history.take();

            let mut last_history_entry = history.entries.first().unwrap().clone();
            last_history_entry.times = new_times.clone();
            last_history_entry.history.take();

            if sanitized_entry.eq(&last_history_entry) {
                return false;
            }
        }
        true
    }

    pub fn set(&mut self, key: impl Into<String>, value: Value) {
        self.fields.insert(key.into(), value);
    }

    pub fn set_unprotected(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.set(key, Value::string(value.into()));
    }

    pub fn set_protected(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.set(key, Value::protected_string(value.into()));
    }
}

#[cfg(test)]
mod entry_tests {
    use std::{thread, time};

    use crate::db::{fields, Entry, Value};

    #[test]
    fn update_history() {
        let mut entry = Entry::new();
        let mut last_modification_time = entry.times.last_modification.unwrap();

        entry.set_unprotected(fields::USERNAME, "user");

        // Making sure to wait 1 sec before update the history, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));

        assert!(entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 1);
        assert_ne!(entry.times.last_modification.unwrap(), last_modification_time);
        last_modification_time = entry.times.last_modification.unwrap();
        thread::sleep(time::Duration::from_secs(1));

        // Updating the history without making any changes
        // should not do anything.
        assert!(!entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 1);
        assert_eq!(entry.times.last_modification.unwrap(), last_modification_time);

        entry.set_unprotected(fields::TITLE, "first title");

        assert!(entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 2);
        assert_ne!(entry.times.last_modification.unwrap(), last_modification_time);
        last_modification_time = entry.times.last_modification.unwrap();
        thread::sleep(time::Duration::from_secs(1));

        assert!(!entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 2);
        assert_eq!(entry.times.last_modification.unwrap(), last_modification_time);

        entry
            .fields
            .insert(fields::TITLE.to_string(), Value::string("second title"));

        assert!(entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 3);
        assert_ne!(entry.times.last_modification.unwrap(), last_modification_time);
        last_modification_time = entry.times.last_modification.unwrap();
        thread::sleep(time::Duration::from_secs(1));

        assert!(!entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 3);
        assert_eq!(entry.times.last_modification.unwrap(), last_modification_time);

        let last_history_entry = entry.history.as_ref().unwrap().entries.first().unwrap();
        assert_eq!(last_history_entry.get_title().unwrap(), "second title");

        for history_entry in &entry.history.unwrap().entries {
            assert!(history_entry.history.is_none());
        }
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn serialization() {
        assert_eq!(
            serde_json::to_string(&Value::string("ABC")).unwrap(),
            "\"ABC\"".to_string()
        );

        assert_eq!(
            serde_json::to_string(&Value::protected_string("ABC")).unwrap(),
            "\"ABC\"".to_string()
        );
    }
}
