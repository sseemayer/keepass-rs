pub(crate) mod attachment;
pub(crate) mod autotype;
pub(crate) mod color;
pub(crate) mod custom_data;
pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod history;
pub(crate) mod meta;
pub(crate) mod times;
pub(crate) mod value;

use std::collections::HashMap;

pub use attachment::Attachment;
pub use autotype::{AutoType, AutoTypeAssociation};
pub use color::{Color, ParseColorError};
pub use custom_data::{CustomDataItem, CustomDataValue};
pub use entry::Entry;
pub use group::Group;
pub use history::History;
pub use meta::{MemoryProtection, Meta};
pub use times::Times;
pub use value::Value;

use crate::config::DatabaseConfig;

use chrono::NaiveDateTime;
use uuid::Uuid;

/// A decrypted KeePass database
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Database {
    /// Configuration settings of the database such as encryption and compression algorithms
    pub config: DatabaseConfig,

    /// Root node of the KeePass database
    pub root: Group,

    /// References to previously-deleted objects and their deletion times.
    pub deleted_objects: HashMap<Uuid, Option<NaiveDateTime>>,

    /// Metadata of the KeePass database
    pub meta: Meta,
}

impl Database {
    /// Create a new, empty database
    pub fn new(config: DatabaseConfig) -> Database {
        Self {
            config,
            root: Group::new("Root"),
            deleted_objects: Default::default(),
            meta: Default::default(),
        }
    }
}
