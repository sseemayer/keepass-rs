use chrono::NaiveDateTime;

/// Timestamps for a Group or Entry
///
/// NaiveDateTime is used because KeePass does not store timezone information
#[derive(Debug, Default, PartialEq, Eq, Clone)]
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
