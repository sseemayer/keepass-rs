use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
};

use uuid::Uuid;

use crate::{
    db::{CustomDataItem, Entry, EntryId, EntryMut, EntryRef, IconId, Times},
    Database,
};

/// Unique identifier for a [Group]. Stores [Uuid]s internally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct GroupId(Uuid);

impl GroupId {
    pub(crate) fn new() -> GroupId {
        GroupId(Uuid::new_v4())
    }

    pub(crate) fn with_uuid(uuid: Uuid) -> GroupId {
        GroupId(uuid)
    }

    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A KeePass database group.
///
/// You will never construct or handle ownership of `Group` objects directly, but will be handed
/// [GroupRef] and [GroupMut] handles through which you can access the entries.
///
/// See the [module-level documentation](crate::db) for an example.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Group {
    /// The unique identifier for the group
    id: GroupId,

    /// The name of the group
    pub name: String,

    /// Notes associated with the group
    pub notes: Option<String>,

    /// The icon ID for the group
    pub icon_id: Option<usize>,

    /// The unique identifier for a custom icon, if any
    pub(crate) custom_icon_id: Option<IconId>,

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
    pub enable_autotype: Option<bool>,

    /// Whether searching is enabled by default for entries in this group
    pub enable_searching: Option<bool>,

    /// UUID for the last top visible entry
    pub(crate) last_top_visible_entry: Option<EntryId>,
}

impl Group {
    pub fn id(&self) -> GroupId {
        self.id
    }

    pub(crate) fn new() -> Group {
        Group {
            id: GroupId::new(),
            name: String::new(),
            notes: None,
            icon_id: None,
            custom_icon_id: None,
            groups: HashSet::new(),
            entries: HashSet::new(),
            times: Times::default(),
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
            notes: None,
            icon_id: None,
            custom_icon_id: None,
            groups: HashSet::new(),
            entries: HashSet::new(),
            times: Times::default(),
            custom_data: HashMap::new(),
            is_expanded: true,
            default_autotype_sequence: None,
            enable_autotype: None,
            enable_searching: None,
            last_top_visible_entry: None,
        }
    }
}

/// Immutable reference to a [Group]. Can be dereferenced to get a [`&Group`][Group]
#[derive(Clone)]
pub struct GroupRef<'a> {
    database: &'a crate::db::Database,
    id: GroupId,
}

impl GroupRef<'_> {
    pub(crate) fn new(database: &Database, id: GroupId) -> GroupRef<'_> {
        GroupRef { database, id }
    }

    pub fn groups(&self) -> impl Iterator<Item = GroupRef<'_>> + '_ {
        self.groups
            .iter()
            .map(move |id| GroupRef::new(self.database, *id))
    }

    pub fn entries(&self) -> impl Iterator<Item = EntryRef<'_>> + '_ {
        self.entries
            .iter()
            .map(move |id| EntryRef::new(self.database, *id))
    }

    /// Find a subgroup by name, case-insensitively.
    pub fn group_by_name(&self, name: &str) -> Option<GroupRef<'_>> {
        self.groups().find(|g| g.name.eq_ignore_ascii_case(name))
    }

    /// Find an entry by title, case-insensitively.
    pub fn entry_by_name(&self, title: &str) -> Option<EntryRef<'_>> {
        self.entries().find(|e| {
            e.get(crate::db::fields::TITLE)
                .map_or(false, |t| t.as_str().eq_ignore_ascii_case(title))
        })
    }

    /// Find a subgroup by a path of names, case-insensitively.
    pub fn group_by_path(&self, path: &[&str]) -> Option<GroupRef<'_>> {
        let mut current = self.id;

        for part in path {
            current = self
                .database
                .groups
                .get(&current)?
                .groups
                .iter()
                .filter_map(|id| self.database.groups.get(id))
                .find(|g| g.name.eq_ignore_ascii_case(part))?
                .id;
        }

        Some(GroupRef::new(self.database, current))
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

/// Mutable reference to a [Group]. Can be dereferenced to get a [`&mut Group`][Group]
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

    pub(crate) fn add_entry_with_id(&mut self, id: EntryId) -> EntryMut<'_> {
        if self.database.entries.contains_key(&id) {
            panic!("Entry with ID {} already exists", id);
        }

        let new_entry = Entry::with_id(id);
        self.entries.insert(id);
        self.database.entries.insert(id, new_entry);

        EntryMut::new(self.database, id)
    }

    pub(crate) fn add_group_with_id(&mut self, id: GroupId) -> GroupMut<'_> {
        if self.database.groups.contains_key(&id) {
            panic!("Group with ID {} already exists", id);
        }

        let new_group = Group::with_id(id);
        self.groups.insert(id);
        self.database.groups.insert(id, new_group);

        GroupMut::new(self.database, id)
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
