use chrono::NaiveDateTime;

/// Custom data field for an [Entry][crate::db::Entry] or [Meta][crate::db::Meta] for database-wide
/// custom data
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomDataItem {
    /// Value of the custom data item.
    pub value: Option<CustomDataValue>,

    /// Time the custom data item was last modified
    pub last_modification_time: Option<NaiveDateTime>,
}

/// Value of a [CustomDataItem]
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum CustomDataValue {
    /// String custom data value
    String(String),

    /// Binary custom data value
    Binary(Vec<u8>),
}
