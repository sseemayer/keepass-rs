use chrono::NaiveDateTime;

/// Timestamps for a [Group][crate::db::Group] or [Entry][crate::db::Entry]
///
/// As the KeePass file format does not store time zone information and does not store sub-second
/// precision, all times are stored as [NaiveDateTime] with second precision.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Times {
    /// The time of creation
    pub creation: Option<NaiveDateTime>,

    /// The time of the last modification
    pub last_modification: Option<NaiveDateTime>,

    /// The time of the last access
    pub last_access: Option<NaiveDateTime>,

    /// The time of expiration
    pub expiry: Option<NaiveDateTime>,

    /// The time of the last location change, which is updated when an entry is moved to a different group.
    pub location_changed: Option<NaiveDateTime>,

    /// Whether the entry or group expires.
    ///
    /// A `None` value indicates that the expiration status is not set
    pub expires: Option<bool>,

    /// The number of times the entry or group has been accessed.
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
    // a 64-bit timestamp will not overflow until the year 292 billion, so we can safely unwrap
    // here.
    #[allow(clippy::missing_panics_doc, clippy::expect_used)]
    pub fn now() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(now_timestamp(), 0)
            .expect("We are before the year 292 billion")
            .naive_utc()
    }

    /// Returns the Unix epoch time: 1970-01-01 00:00:00
    #[allow(clippy::missing_panics_doc, clippy::unwrap_used)] // will not panic from constant input
    pub fn epoch() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }
}
