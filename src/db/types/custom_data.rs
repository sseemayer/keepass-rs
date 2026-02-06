use chrono::NaiveDateTime;

/// Custom data field for an [Entry][crate::db::Entry] or [Meta][crate::db::Meta] for database-wide
/// custom data
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomDataItem {
    pub value: Option<CustomDataValue>,
    pub last_modification_time: Option<NaiveDateTime>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum CustomDataValue {
    String(String),
    Binary(Vec<u8>),
}
