use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::{
    db::{CustomDataItem, IconId, Times},
    Database,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(Uuid);

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Group {
    /// The unique identifier for the group
    id: GroupId,

    /// The name of the group
    name: String,

    /// The icon ID for the group
    icon_id: Option<usize>,

    /// The unique identifier for a custom icon, if any
    custom_icon_id: Option<IconId>,

    /// Unique identifiers for child groups
    groups: HashSet<GroupId>,

    /// Time fields for the group
    times: Times,

    /// Custom data associated with the group
    custom_data: HashMap<String, CustomDataItem>,

    /// Whether the group is expanded in the user interface
    is_expanded: bool,

    /// Default autotype sequence
    default_autotype_sequence: Option<String>,

    /// Whether autotype is enabled by default for entries in this group
    /// TODO: in example XML files, this is "null" - what should the type be?
    enable_autotype: Option<String>,

    /// Whether searching is enabled by default for entries in this group
    enable_searching: Option<String>,

    /// UUID for the last top visible entry
    // TODO figure out what that is supposed to mean. According to the KeePass sourcecode, it has
    // something to do with restoring selected items when re-opening a database.
    last_top_visible_entry: Option<Uuid>,
}

pub struct GroupRef<'a> {
    database: &'a crate::db::Database,
    id: GroupId,
}

impl GroupRef<'_> {
    pub(crate) fn new(database: &Database, id: GroupId) -> GroupRef {
        GroupRef { database, id }
    }
}

pub struct GroupMut<'a> {
    database: &'a mut crate::db::Database,
    id: GroupId,
}

impl GroupMut<'_> {
    pub(crate) fn new(database: &mut Database, id: GroupId) -> GroupMut {
        GroupMut { database, id }
    }
}
