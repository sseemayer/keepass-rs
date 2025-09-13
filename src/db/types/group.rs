use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
};

use uuid::Uuid;

use crate::{
    db::{CustomDataItem, Entry, EntryId, EntryMut, IconId, Times},
    Database,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(Uuid);

impl GroupId {
    pub fn new() -> GroupId {
        GroupId(Uuid::new_v4())
    }

    pub fn with_uuid(uuid: Uuid) -> GroupId {
        GroupId(uuid)
    }
}

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
    pub name: String,

    /// The icon ID for the group
    pub icon_id: Option<usize>,

    /// The unique identifier for a custom icon, if any
    custom_icon_id: Option<IconId>,

    /// Unique identifiers for child groups
    groups: HashSet<GroupId>,

    /// Unique identifiers for entries in the group
    entries: HashSet<EntryId>,

    /// Time fields for the group
    pub times: Times,

    /// Custom data associated with the group
    pub custom_data: HashMap<String, CustomDataItem>,

    /// Whether the group is expanded in the user interface
    pub is_expanded: bool,

    /// Default autotype sequence
    pub default_autotype_sequence: Option<String>,

    /// Whether autotype is enabled by default for entries in this group
    /// TODO: in example XML files, this is "null" - what should the type be?
    pub enable_autotype: Option<String>,

    /// Whether searching is enabled by default for entries in this group
    pub enable_searching: Option<String>,

    /// UUID for the last top visible entry
    // TODO figure out what that is supposed to mean. According to the KeePass sourcecode, it has
    // something to do with restoring selected items when re-opening a database.
    last_top_visible_entry: Option<Uuid>,
}

impl Group {
    pub fn id(&self) -> GroupId {
        self.id
    }

    pub(crate) fn new() -> Group {
        Group {
            id: GroupId::new(),
            name: String::new(),
            icon_id: None,
            custom_icon_id: None,
            groups: HashSet::new(),
            entries: HashSet::new(),
            times: Times::new(),
            custom_data: HashMap::new(),
            is_expanded: true,
            default_autotype_sequence: None,
            enable_autotype: None,
            enable_searching: None,
            last_top_visible_entry: None,
        }
    }

    pub(crate) fn with_id(id: GroupId) -> Group {
        Group {
            id,
            name: String::new(),
            icon_id: None,
            custom_icon_id: None,
            groups: HashSet::new(),
            entries: HashSet::new(),
            times: Times::new(),
            custom_data: HashMap::new(),
            is_expanded: true,
            default_autotype_sequence: None,
            enable_autotype: None,
            enable_searching: None,
            last_top_visible_entry: None,
        }
    }
}

pub struct GroupRef<'a> {
    database: &'a crate::db::Database,
    id: GroupId,
}

impl GroupRef<'_> {
    pub(crate) fn new(database: &Database, id: GroupId) -> GroupRef<'_> {
        GroupRef { database, id }
    }
}

impl Deref for GroupRef<'_> {
    type Target = Group;

    fn deref(&self) -> &Self::Target {
        self.database
            .groups
            .get(&self.id)
            .expect("GroupRef points to a non-existing group")
    }
}

pub struct GroupMut<'a> {
    database: &'a mut crate::db::Database,
    id: GroupId,
}

impl GroupMut<'_> {
    pub(crate) fn new(database: &mut Database, id: GroupId) -> GroupMut<'_> {
        GroupMut { database, id }
    }

    /// Adds a new subgroup to this group and returns a mutable reference to it.
    pub fn add_group(&mut self) -> GroupMut<'_> {
        let new_group = Group::new();
        let id = new_group.id;

        self.groups.insert(id);
        self.database.groups.insert(id, new_group);

        GroupMut::new(self.database, id)
    }

    pub fn add_entry(&mut self) -> EntryMut<'_> {
        let new_entry = Entry::new();
        let id = new_entry.id();

        self.entries.insert(id);
        self.database.entries.insert(id, new_entry);

        EntryMut::new(self.database, id)
    }
}

impl Deref for GroupMut<'_> {
    type Target = Group;

    fn deref(&self) -> &Self::Target {
        self.database
            .groups
            .get(&self.id)
            .expect("GroupMut points to a non-existing group")
    }
}

impl DerefMut for GroupMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.database
            .groups
            .get_mut(&self.id)
            .expect("GroupMut points to a non-existing group")
    }
}
