use std::collections::HashMap;

use chrono::NaiveDateTime;
use secstr::SecStr;
use uuid::Uuid;

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
        let mut times = Times::default();
        let now = Times::now();
        times.set_creation(now);
        times.set_last_modification(now);
        Entry {
            uuid: Uuid::new_v4(),
            times,
            ..Default::default()
        }
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
    /// uncommited changes.
    ///
    /// Returns whether or not a new history entry was added.
    pub fn update_history(&mut self) -> bool {
        if self.history.is_none() {
            self.history = Some(History::default());
        }

        if !self.has_uncommited_changes() {
            return false;
        }

        let mut new_history_entry = self.clone();
        new_history_entry.history.take().unwrap();

        // TODO should we validate that the history is enabled?
        // TODO should we validate the maximum size of the history?
        self.history.as_mut().unwrap().add_entry(new_history_entry);

        self.times
            .set_last_modification(chrono::Utc::now().naive_utc());
        true
    }

    /// Determines if the entry was modified since the last
    /// history update.
    fn has_uncommited_changes(&self) -> bool {
        if let Some(history) = self.history.as_ref() {
            if history.entries.len() == 0 {
                return true;
            }

            let mut sanitized_entry = self.clone();
            sanitized_entry
                .times
                .set_last_modification(NaiveDateTime::default());
            sanitized_entry.history.take();

            let mut last_history_entry = history.entries.get(0).unwrap().clone();
            last_history_entry
                .times
                .set_last_modification(NaiveDateTime::default());
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
            Value::Protected(p) => {
                serializer.serialize_str(String::from_utf8_lossy(p.unsecure()).as_ref())
            }
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
}

#[cfg(test)]
mod entry_tests {
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

        entry.fields.insert(
            "Username".to_string(),
            Value::Unprotected("user".to_string()),
        );

        assert!(entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 1);
        assert_ne!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );
        last_modification_time = entry.times.get_last_modification().unwrap().clone();

        // Updating the history without making any changes
        // should not do anything.
        assert!(!entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 1);
        assert_eq!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );

        entry.fields.insert(
            "Title".to_string(),
            Value::Unprotected("first title".to_string()),
        );

        assert!(entry.update_history());
        assert!(entry.history.is_some());
        assert_eq!(entry.history.as_ref().unwrap().entries.len(), 2);
        assert_ne!(
            entry.times.get_last_modification().unwrap(),
            &last_modification_time
        );
        last_modification_time = entry.times.get_last_modification().unwrap().clone();

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
            serde_json::to_string(&Value::Protected(SecStr::new("ABC".as_bytes().to_vec())))
                .unwrap(),
            "\"ABC\"".to_string()
        );
    }
}
