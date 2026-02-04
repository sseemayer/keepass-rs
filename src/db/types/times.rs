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

#[cfg(target_arch = "wasm32")]
fn now_timestamp() -> i64 {
    // Use JS Date.now() to get the current time in milliseconds, then convert it to seconds.
    let millis = js_sys::Date::now();
    (millis / 1000.0) as i64
}

#[cfg(not(target_arch = "wasm32"))]
fn now_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Times {
    /// Returns the current time since the last leap second
    ///
    /// Times are rounded to the nearest second because KeePass only stores second precision
    /// timestamps, so serialization/deserialization would lose precision otherwise.
    pub fn now() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(now_timestamp(), 0)
            .unwrap()
            .naive_utc()
    }

    /// Returns the Unix epoch time: 1970-01-01 00:00:00
    pub fn epoch() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }
}
