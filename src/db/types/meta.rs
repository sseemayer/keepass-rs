use std::collections::HashMap;

use chrono::NaiveDateTime;
use uuid::Uuid;

use crate::db::{Color, CustomDataItem};

/// Database metadata
#[derive(Debug, Default, Eq, PartialEq, Clone)]
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

    /// number of days of maintenance history to keep
    pub maintenance_history_days: Option<usize>,

    /// color code for the database
    pub color: Option<Color>,

    /// time the master key was last changed
    pub master_key_changed: Option<NaiveDateTime>,

    pub master_key_change_rec: Option<isize>,

    pub master_key_change_force: Option<isize>,

    /// memory protection settings
    pub memory_protection: Option<MemoryProtection>,

    /// whether the recycle bin is enabled
    pub recyclebin_enabled: Option<bool>,

    /// A UUID for the recycle bin group
    pub recyclebin_uuid: Option<Uuid>,

    /// last time the recycle bin was changed
    pub recyclebin_changed: Option<NaiveDateTime>,

    /// UUID of the group containing entry templates
    pub entry_templates_group: Option<Uuid>,

    /// last time the group containing entry templates was changed
    pub entry_templates_group_changed: Option<NaiveDateTime>,

    /// UUID of the last selected group
    pub last_selected_group: Option<Uuid>,

    /// UUID of the last top-visible group
    pub last_top_visible_group: Option<Uuid>,

    /// Maximum number of items of history to keep
    pub history_max_items: Option<usize>,

    /// Maximum size of the history to keep
    pub history_max_size: Option<usize>,

    /// Last time the settings were changed
    pub settings_changed: Option<NaiveDateTime>,

    /// Additional custom data fields
    pub custom_data: HashMap<String, CustomDataItem>,
}

/// Database memory protection settings
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct MemoryProtection {
    /// Whether titles should be protected
    pub protect_title: bool,

    /// Whether user names should be protected
    pub protect_username: bool,

    /// Whether passwords should be protected
    pub protect_password: bool,

    /// Whether URLs should be protected
    pub protect_url: bool,

    /// Whether notes should be protected
    pub protect_notes: bool,
}

impl Default for MemoryProtection {
    fn default() -> Self {
        Self {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        }
    }
}
