use uuid::Uuid;

/// Collection of custom icons
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomIcons {
    pub icons: Vec<Icon>,
}

/// A custom icon
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Icon {
    /// UUID, to reference the icon
    pub uuid: Uuid,

    /// Image data
    pub data: Vec<u8>,
}
