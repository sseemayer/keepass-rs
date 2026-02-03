use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
};

use thiserror::Error;
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

    pub(crate) const fn with_uuid(uuid: Uuid) -> GroupId {
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

    /// The unique identifier for the parent group
    parent: Option<GroupId>,

    /// The name of the group
    pub name: String,

    /// Notes associated with the group
    pub notes: Option<String>,

    /// The icon ID for the group
    pub icon_id: Option<usize>,

    /// The unique identifier for a custom icon, if any
    pub(crate) custom_icon_id: Option<IconId>,

    /// Unique identifiers for child groups
    pub(crate) groups: HashSet<GroupId>,

    /// Unique identifiers for entries in the group
    pub(crate) entries: HashSet<EntryId>,

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

    pub(crate) fn new(parent: Option<GroupId>) -> Group {
        Group {
            id: GroupId::new(),
            parent,
            name: String::new(),
            notes: None,
            icon_id: None,
            custom_icon_id: None,
            groups: HashSet::new(),
            entries: HashSet::new(),
            times: Times::create_new(),
            custom_data: HashMap::new(),
            is_expanded: true,
            default_autotype_sequence: None,
            enable_autotype: None,
            enable_searching: None,
            last_top_visible_entry: None,
        }
    }

    pub(crate) fn with_id(id: GroupId, parent: Option<GroupId>) -> Group {
        Group {
            id,
            parent,
            name: String::new(),
            notes: None,
            icon_id: None,
            custom_icon_id: None,
            groups: HashSet::new(),
            entries: HashSet::new(),
            times: Times::create_new(),
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

    /// Get a contained group by ID
    pub fn group(&self, id: GroupId) -> Option<GroupRef<'_>> {
        if self.groups.contains(&id) {
            Some(GroupRef::new(self.database, id))
        } else {
            None
        }
    }

    /// Get a contained entry by ID
    pub fn entry(&self, id: EntryId) -> Option<EntryRef<'_>> {
        if self.entries.contains(&id) {
            Some(EntryRef::new(self.database, id))
        } else {
            None
        }
    }

    /// Get an iterator over all contained groups
    pub fn groups(&self) -> impl Iterator<Item = GroupRef<'_>> + '_ {
        self.groups
            .iter()
            .map(move |id| GroupRef::new(self.database, *id))
    }

    /// Get an iterator over all contained entries
    pub fn entries(&self) -> impl Iterator<Item = EntryRef<'_>> + '_ {
        self.entries
            .iter()
            .map(move |id| EntryRef::new(self.database, *id))
    }

    /// Find a contained group by name, case-insensitively.
    pub fn group_by_name(&self, name: &str) -> Option<GroupRef<'_>> {
        self.groups().find(|g| g.name.eq_ignore_ascii_case(name))
    }

    /// Find a contained entry by title, case-insensitively.
    pub fn entry_by_name(&self, title: &str) -> Option<EntryRef<'_>> {
        self.entries().find(|e| {
            e.get(crate::db::fields::TITLE)
                .map_or(false, |t| t.as_str().eq_ignore_ascii_case(title))
        })
    }

    /// Find a contained group by a path of names, case-insensitively.
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

    /// Get the database this group belongs to
    pub fn database(&self) -> &Database {
        self.database
    }

    pub fn parent(&self) -> Option<GroupRef<'_>> {
        self.parent.map(|id| GroupRef::new(self.database, id))
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

    pub fn as_ref(&self) -> GroupRef<'_> {
        GroupRef::new(self.database, self.id)
    }

    pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>> {
        if self.groups.contains(&id) {
            Some(GroupMut::new(self.database, id))
        } else {
            None
        }
    }

    pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>> {
        if self.entries.contains(&id) {
            Some(EntryMut::new(self.database, id))
        } else {
            None
        }
    }

    /// Convenience method to edit the group in a closure.
    pub fn edit(&mut self, f: impl FnOnce(&mut GroupMut)) -> &mut Self {
        f(self);
        self
    }

    /// Convenience method to edit the group in a closure that tracks changes.
    pub fn edit_tracking(&mut self, f: impl FnOnce(&mut GroupTrack)) -> &mut Self {
        let mut tracker = self.track_changes();
        f(&mut tracker);
        tracker.as_mut().times.last_modification = Some(Times::now());
        self
    }

    /// Adds a new subgroup to this group and returns a mutable reference to it.
    pub fn add_group(&mut self) -> GroupMut<'_> {
        let new_group = Group::new(Some(self.id));
        let id = new_group.id;

        self.groups.insert(id);
        self.database.groups.insert(id, new_group);

        GroupMut::new(self.database, id)
    }

    pub fn add_entry(&mut self) -> EntryMut<'_> {
        let new_entry = Entry::new(self.id);
        let id = new_entry.id();

        self.entries.insert(id);
        self.database.entries.insert(id, new_entry);

        EntryMut::new(self.database, id)
    }

    pub(crate) fn add_entry_with_id(&mut self, id: EntryId) -> EntryMut<'_> {
        if self.database.entries.contains_key(&id) {
            panic!("Entry with ID {} already exists", id);
        }

        let new_entry = Entry::with_id(id, self.id);
        self.entries.insert(id);
        self.database.entries.insert(id, new_entry);

        EntryMut::new(self.database, id)
    }

    pub(crate) fn add_group_with_id(&mut self, id: GroupId) -> GroupMut<'_> {
        if self.database.groups.contains_key(&id) {
            panic!("Group with ID {} already exists", id);
        }

        let new_group = Group::with_id(id, Some(self.id));
        self.groups.insert(id);
        self.database.groups.insert(id, new_group);

        GroupMut::new(self.database, id)
    }

    pub fn database_mut(&mut self) -> &mut Database {
        self.database
    }

    pub fn parent_mut(&mut self) -> Option<GroupMut<'_>> {
        if let Some(parent_id) = self.parent {
            if self.database.groups.contains_key(&parent_id) {
                return Some(GroupMut::new(self.database, parent_id));
            }
        }
        None
    }

    pub fn move_to(&mut self, new_parent_id: GroupId) -> Result<(), MoveGroupError> {
        let old_parent_id = self.parent.ok_or(MoveGroupError::CannotMoveRoot)?;

        if !self.database.groups.contains_key(&new_parent_id) {
            return Err(MoveGroupError::NotFound(new_parent_id));
        }

        // Check for cycles
        let mut current = Some(new_parent_id);
        while let Some(curr_id) = current {
            if curr_id == self.id {
                return Err(MoveGroupError::WouldCreateCycle);
            }
            current = self.database.groups.get(&curr_id).and_then(|g| g.parent);
        }

        // Remove from old parent
        let mut old_parent = self.database.group_mut(old_parent_id).unwrap();
        old_parent.groups.remove(&self.id);

        let mut new_parent = self.database.group_mut(new_parent_id).unwrap();
        new_parent.groups.insert(self.id);

        // Update parent reference
        self.parent = Some(new_parent_id);

        Ok(())
    }

    /// Deletes this group and all its child groups and entries from the database.
    pub fn remove(mut self) {
        // Remove from parent
        if let Some(parent_id) = self.parent {
            if let Some(mut parent) = self.database.group_mut(parent_id) {
                parent.groups.remove(&self.id);
            }
        }

        // Delete entries
        let entry_ids: Vec<EntryId> = self.entries.iter().cloned().collect();
        for entry_id in entry_ids {
            self.entry_mut(entry_id).unwrap().remove();
        }

        // Recursively delete child groups
        let child_group_ids: Vec<GroupId> = self.groups.iter().cloned().collect();
        for child_id in child_group_ids {
            if let Some(child_group) = self.database.group_mut(child_id) {
                child_group.remove();
            }
        }

        // Finally, remove this group from the database
        self.database.groups.remove(&self.id);
    }

    /// Convert this mutable group reference into a history-tracking variant that will record
    /// changes such as deletions and moves.
    pub fn track_changes(&mut self) -> GroupTrack<'_> {
        GroupTrack {
            database: self.database,
            id: self.id,
        }
    }
}

#[derive(Debug, Error)]
pub enum MoveGroupError {
    #[error("Cannot move the root group")]
    CannotMoveRoot,

    #[error("Destination group with ID {0} not found")]
    NotFound(GroupId),

    #[error("Cannot move a group into itself or one of its descendants")]
    WouldCreateCycle,
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

pub struct GroupTrack<'a> {
    database: &'a mut crate::db::Database,
    id: GroupId,
}

impl GroupTrack<'_> {
    pub fn as_mut(&mut self) -> GroupMut<'_> {
        GroupMut::new(self.database, self.id)
    }

    /// Move this group to a new parent group, updating the location changed time.
    pub fn move_to(&mut self, new_parent_id: GroupId) -> Result<(), MoveGroupError> {
        self.as_mut().move_to(new_parent_id)?;
        self.times.location_changed = Some(Times::now());
        Ok(())
    }

    /// Deletes this group and all its child groups and entries from the database,
    /// adding them to the deleted entries and groups sets.
    pub fn remove(mut self) {
        // Remove from parent
        if let Some(parent_id) = self.parent {
            if let Some(mut parent) = self.database.group_mut(parent_id) {
                parent.groups.remove(&self.id);
            }
        }

        // Delete entries
        let entry_ids: Vec<EntryId> = self.entries.iter().cloned().collect();
        for entry_id in entry_ids {
            self.as_mut().entry_mut(entry_id).unwrap().remove();
        }

        // Recursively delete child groups
        let child_group_ids: Vec<GroupId> = self.groups.iter().cloned().collect();
        for child_id in child_group_ids {
            if let Some(child_group) = self.database.group_mut(child_id) {
                child_group.remove();
            }
        }

        // Finally, remove this group from the database and add to deleted groups
        self.database.groups.remove(&self.id);
        self.database
            .deleted_objects
            .insert(self.id.uuid(), Some(Times::now()));
    }

    /// Convenience method to edit the group in a closure, updating the last modification time.
    pub fn edit(&mut self, f: impl FnOnce(&mut GroupTrack)) -> &mut Self {
        f(self);
        self.as_mut().times.last_modification = Some(Times::now());
        self
    }
}

impl Deref for GroupTrack<'_> {
    type Target = Group;

    fn deref(&self) -> &Self::Target {
        self.database.groups.get(&self.id).expect("Group not found")
    }
}

impl DerefMut for GroupTrack<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.database.groups.get_mut(&self.id).expect("Group not found")
    }
}
