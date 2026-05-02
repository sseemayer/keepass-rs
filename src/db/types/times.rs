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

// On non-browser targets — including wasm32-wasip1 and wasm32-wasip2 —
// chrono::Utc::now() works (wasi clocks via WASI 0.1+ are supported by
// chrono's `clock` feature).  The `js_sys::Date::now()` path is only
// usable in true browser contexts (target_arch = "wasm32" with target_os
// = "unknown"), where wasm-bindgen post-processes the binary to resolve
// the placeholder imports.  Targeting "wasm32" alone unintentionally
// catches WASI builds and breaks linking.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now_timestamp() -> i64 {
    // Use JS Date.now() to get the current time in milliseconds, then convert it to seconds.
    let millis = js_sys::Date::now();
    (millis / 1000.0) as i64
}

impl Times {
    // Returns the current time, without the nanoseconds since
    // the last leap second.
    pub fn now() -> NaiveDateTime {
        let now = now_timestamp();
        chrono::DateTime::from_timestamp(now, 0).unwrap().naive_utc()
    }

    pub fn epoch() -> NaiveDateTime {
        chrono::DateTime::from_timestamp(0, 0).unwrap().naive_utc()
    }

    pub fn new() -> Self {
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
