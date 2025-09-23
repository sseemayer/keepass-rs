use chrono::NaiveDateTime;

/// Timestamps for a Group or Entry
///
/// NaiveDateTime is used because KeePass does not store timezone information
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Times {
    pub creation: Option<NaiveDateTime>,
    pub last_modification: Option<NaiveDateTime>,
    pub last_access: Option<NaiveDateTime>,
    pub expiry: Option<NaiveDateTime>,
    pub location_changed: Option<NaiveDateTime>,

    pub expires: Option<bool>,
    pub usage_count: Option<usize>,
}

impl Times {
    /// Returns the current time, without nanoseconds since the last leap second
    pub fn now() -> NaiveDateTime {
        let now = chrono::Utc::now().timestamp();
        chrono::DateTime::from_timestamp(now, 0).unwrap().naive_utc()
    }

    /// Returns the Unix epoch time: 1970-01-01 00:00:00
    pub fn epoch() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }
}
