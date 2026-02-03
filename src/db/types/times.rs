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
    pub(crate) fn create_new() -> Self {
        let now = Times::now();
        Times {
            creation: Some(now),
            last_modification: Some(now),
            last_access: Some(now),
            expiry: None,
            location_changed: Some(now),
            expires: Some(false),
            usage_count: Some(0),
        }
    }
}

impl Times {
    /// Returns the current time since the last leap second
    #[cfg(target_arch = "wasm32")]
    pub fn now() -> NaiveDateTime {
        // Use JS Date.now() to get the current time in milliseconds,
        // then convert it to seconds and nanoseconds
        let millis = js_sys::Date::now();
        let secs = (millis / 1000.0) as i64;
        let nanosecs = ((millis % 1000.0) * 1_000_000.0) as u32;

        chrono::DateTime::from_timestamp(secs, nanosecs)
            .unwrap()
            .naive_utc()
    }

    /// Returns the current time since the last leap second
    #[cfg(not(target_arch = "wasm32"))]
    pub fn now() -> NaiveDateTime {
        chrono::Utc::now().naive_utc()
    }

    /// Returns the Unix epoch time: 1970-01-01 00:00:00
    pub fn epoch() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }
}
