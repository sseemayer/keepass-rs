use std::collections::HashMap;

use chrono::NaiveDateTime;

/// Timestamps for a Group or Entry
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Times {
    /// Does this node expire
    pub expires: bool,

    /// Number of usages
    pub usage_count: usize,

    /// Using chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub times: HashMap<String, NaiveDateTime>,
}

pub const EXPIRY_TIME_TAG_NAME: &str = "ExpiryTime";
pub const LAST_MODIFICATION_TIME_TAG_NAME: &str = "LastModificationTime";
pub const CREATION_TIME_TAG_NAME: &str = "CreationTime";
pub const LAST_ACCESS_TIME_TAG_NAME: &str = "LastAccessTime";
pub const LOCATION_CHANGED_TAG_NAME: &str = "LocationChanged";

impl Times {
    fn get(&self, key: &str) -> Option<&NaiveDateTime> {
        self.times.get(key)
    }

    pub fn get_expiry(&self) -> Option<&NaiveDateTime> {
        self.times.get(EXPIRY_TIME_TAG_NAME)
    }

    pub fn set_expiry(&mut self, time: NaiveDateTime) {
        self.times.insert(EXPIRY_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_last_modification(&self) -> Option<&NaiveDateTime> {
        self.times.get(LAST_MODIFICATION_TIME_TAG_NAME)
    }

    pub fn set_last_modification(&mut self, time: NaiveDateTime) {
        self.times
            .insert(LAST_MODIFICATION_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_creation(&self) -> Option<&NaiveDateTime> {
        self.times.get(CREATION_TIME_TAG_NAME)
    }

    pub fn set_creation(&mut self, time: NaiveDateTime) {
        self.times.insert(CREATION_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_last_access(&self) -> Option<&NaiveDateTime> {
        self.times.get(LAST_ACCESS_TIME_TAG_NAME)
    }

    pub fn set_last_access(&mut self, time: NaiveDateTime) {
        self.times.insert(LAST_ACCESS_TIME_TAG_NAME.to_string(), time);
    }

    pub fn get_location_changed(&self) -> Option<&NaiveDateTime> {
        self.times.get(LOCATION_CHANGED_TAG_NAME)
    }

    pub fn set_location_changed(&mut self, time: NaiveDateTime) {
        self.times.insert(LOCATION_CHANGED_TAG_NAME.to_string(), time);
    }

    // Returns the current time, without the nanoseconds since
    // the last leap second.
    pub fn now() -> NaiveDateTime {
        let now = chrono::Utc::now().timestamp();
        chrono::DateTime::from_timestamp(now, 0).unwrap().naive_utc()
    }

    pub fn epoch() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }

    pub fn new() -> Times {
        let mut response = Times::default();
        let now = Times::now();
        response.set_creation(now);
        response.set_last_modification(now);
        response.set_last_access(now);
        response.set_location_changed(now);
        response.set_expiry(now);
        response.expires = false;
        response
    }

    pub fn times(&self) -> &HashMap<String, NaiveDateTime> {
        &self.times
    }
}
