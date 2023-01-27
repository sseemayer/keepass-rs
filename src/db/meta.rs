use chrono::NaiveDateTime;

use crate::db::CustomData;

/// Database metadata
#[derive(Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Meta {
    /// the program that generated the database file.
    pub generator: Option<String>,

    /// name of the database
    pub database_name: Option<String>,

    /// time the database name was last changed
    pub database_name_changed: Option<NaiveDateTime>,

    /// description of the database
    pub database_description: Option<String>,

    /// time the database description was last changed
    pub database_description_changed: Option<NaiveDateTime>,

    /// default username
    pub default_username: Option<String>,

    /// time the default username was last changed
    pub default_username_changed: Option<NaiveDateTime>,

    pub maintenance_history_days: Option<usize>,

    pub color: Option<String>,

    /// time the master key was last changed
    pub master_key_changed: Option<NaiveDateTime>,

    pub master_key_change_rec: Option<isize>,

    pub master_key_change_force: Option<isize>,

    pub memory_protection: Option<MemoryProtection>,

    pub custom_icons: CustomIcons,

    pub recyclebin_enabled: Option<bool>,

    /// A UUID for the recycle bin group
    pub recyclebin_uuid: String,

    pub recyclebin_changed: Option<NaiveDateTime>,

    pub entry_templates_group: Option<String>,

    pub entry_templates_group_changed: Option<NaiveDateTime>,

    pub last_selected_group: Option<String>,

    pub last_top_visible_group: Option<String>,

    pub history_max_items: Option<usize>,

    pub history_max_size: Option<usize>,

    pub settings_changed: Option<NaiveDateTime>,

    pub binaries: BinaryAttachments,

    pub custom_data: CustomData,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct MemoryProtection {
    pub protect_title: bool,
    pub protect_username: bool,
    pub protect_password: bool,
    pub protect_url: bool,
    pub protect_notes: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CustomIcons {
    pub icons: Vec<Icon>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Icon {
    pub uuid: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BinaryAttachments {
    pub binaries: Vec<BinaryAttachment>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct BinaryAttachment {
    pub identifier: Option<String>,
    pub flags: u8,
    pub content: Vec<u8>,
}
