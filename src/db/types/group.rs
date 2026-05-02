use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
};

use thiserror::Error;
use uuid::Uuid;

use crate::{
    db::{
        CustomDataItem, CustomIcon, CustomIconId, CustomIconMut, CustomIconNotFoundError, CustomIconRef, Entry,
        EntryId, EntryMut, EntryRef, Icon, Times,
    },
    Database,
};

/// Unique identifier for a [Group]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct GroupId(Uuid);

impl GroupId {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub(crate) const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the Uuid contained inside
    pub fn uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A database group with child groups and entries
#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Group {
    /// The unique identifier of the group
    pub(crate) id: GroupId,

    /// The unique identifier for the parent group
    pub(crate) parent: Option<GroupId>,

    /// The name of the group
    pub name: String,

    /// Notes for the group
    pub notes: Option<String>,

    /// The list of tags for this group
    pub tags: Vec<String>,

    /// Icon for the group
    pub(crate) icon: Option<Icon>,

    /// The list of child group identifiers
    pub(crate) groups: HashSet<GroupId>,

    /// The list of entry identifiers directly under this group
    pub(crate) entries: HashSet<EntryId>,

    /// The list of time fields for this group
    pub times: Times,

    // Custom Data
    pub custom_data: HashMap<String, CustomDataItem>,

    /// Whether the group is expanded in the user interface
    pub is_expanded: bool,

    /// Default autotype sequence
    pub default_autotype_sequence: Option<String>,

    /// Whether autotype is enabled
    pub enable_autotype: Option<bool>,

    /// Whether searching is enabled
    pub enable_searching: Option<bool>,

    /// UUID for the last top visible entry
    pub(crate) last_top_visible_entry: Option<EntryId>,

    pub(crate) previous_parent_group: Option<GroupId>,
}

impl Group {
    /// Get the unique identifier for this group
    pub fn id(&self) -> GroupId {
        self.id
    }

    pub(crate) fn new(parent: Option<GroupId>) -> Group {
        Group {
            id: GroupId::new(),
            parent,
            name: String::new(),
            notes: None,
            tags: Vec::new(),
            icon: None,
            groups: HashSet::new(),
            entries: HashSet::new(),
            times: Times::new(),
            custom_data: HashMap::new(),
            is_expanded: true,
            default_autotype_sequence: None,
            enable_autotype: None,
            enable_searching: None,
            last_top_visible_entry: None,
            previous_parent_group: None,
        }
    }

    pub(crate) fn with_id(id: GroupId, parent: Option<GroupId>) -> Group {
        Group {
            id,
            parent,
            name: String::new(),
            notes: None,
            tags: Vec::new(),
            icon: None,
            groups: HashSet::new(),
            entries: HashSet::new(),
            times: Times::new(),
            custom_data: HashMap::new(),
            is_expanded: true,
            default_autotype_sequence: None,
            enable_autotype: None,
            enable_searching: None,
            last_top_visible_entry: None,
            previous_parent_group: None,
        }
    }

    /// Get an iterator over the IDs of all contained groups
    pub fn group_ids(&self) -> impl Iterator<Item = GroupId> + '_ {
        self.groups.iter().cloned()
    }

    /// Get an iterator over the IDs of all contained entries
    pub fn entry_ids(&self) -> impl Iterator<Item = EntryId> + '_ {
        self.entries.iter().cloned()
    }

    /// Get a reference to the icon of this group, if any
    pub fn icon(&self) -> Option<&Icon> {
        self.icon.as_ref()
    }
}

/// Immutable reference to a [Group]. Implements [Deref] to [&Group][Group].
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
        self.groups
            .contains(&id)
            .then(move || GroupRef::new(self.database, id))
    }

    /// Get a contained entry by ID
    pub fn entry(&self, id: EntryId) -> Option<EntryRef<'_>> {
        self.entries
            .contains(&id)
            .then(move || EntryRef::new(self.database, id))
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
                .is_some_and(|t| t.eq_ignore_ascii_case(title))
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

    /// Get a reference to the parent group, if any
    pub fn parent(&self) -> Option<GroupRef<'_>> {
        self.parent.map(|id| GroupRef::new(self.database, id))
    }

    /// Get a reference to the previous parent group, if any
    pub fn previous_parent(&self) -> Option<GroupRef<'_>> {
        self.previous_parent_group
            .and_then(|id| self.database().group(id))
    }

    /// Get a reference to the custom icon of this group, if it has one and it is a custom icon
    pub fn custom_icon(&self) -> Option<CustomIconRef<'_>> {
        if let Some(Icon::Custom(cid)) = self.icon {
            Some(CustomIconRef::new(self.database, cid))
        } else {
            None
        }
    }
}

impl Deref for GroupRef<'_> {
    type Target = Group;

    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // group existence is guaranteed
    fn deref(&self) -> &Self::Target {
        self.database
            .groups
            .get(&self.id)
            .expect("GroupRef points to a non-existing group")
    }
}

/// Mutable reference to a [Group]. Implements [DerefMut] to [&mut Group][Group]
pub struct GroupMut<'a> {
    database: &'a mut crate::db::Database,
    id: GroupId,
}

impl GroupMut<'_> {
    pub(crate) fn new(database: &mut Database, id: GroupId) -> GroupMut<'_> {
        GroupMut { database, id }
    }

    /// Get an immutable reference to this group
    pub fn as_ref(&self) -> GroupRef<'_> {
        GroupRef::new(self.database, self.id)
    }

    /// Get a mutable reference to a contained group by ID
    pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>> {
        self.groups
            .contains(&id)
            .then(move || GroupMut::new(self.database, id))
    }

    /// Get a mutable reference to a contained entry by ID
    pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>> {
        self.entries
            .contains(&id)
            .then(move || EntryMut::new(self.database, id))
    }

    /// Convenience method to edit the group in a closure.
    pub fn edit(&mut self, f: impl FnOnce(&mut GroupMut<'_>)) -> &mut Self {
        f(self);
        self
    }

    /// Convenience method to edit the group in a closure that tracks changes.
    pub fn edit_tracking(&mut self, f: impl FnOnce(&mut GroupTrack<'_>)) -> &mut Self {
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

    /// Adds a new entry to this group and returns a mutable reference to it.
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

    /// Get a mutable reference to the database this group belongs to
    pub fn database_mut(&mut self) -> &mut Database {
        self.database
    }

    /// Get a mutable reference to the parent group, if any
    pub fn parent_mut(&mut self) -> Option<GroupMut<'_>> {
        self.parent.map(move |id| GroupMut::new(self.database, id))
    }

    /// Get a mutable reference to the previous parent group, if any
    pub fn previous_parent_mut(&mut self) -> Option<GroupMut<'_>> {
        self.previous_parent_group
            .and_then(move |id| self.database_mut().group_mut(id))
    }

    /// Find a contained group by name, case-insensitively, and return a mutable reference to it.
    pub fn group_by_name_mut(&mut self, name: &str) -> Option<GroupMut<'_>> {
        let gid = self.as_ref().groups().find_map(|g| {
            if g.name.eq_ignore_ascii_case(name) {
                Some(g.id)
            } else {
                None
            }
        });

        gid.map(move |id| GroupMut::new(self.database, id))
    }

    /// Find a contained entry by title, case-insensitively, and return a mutable reference to it.
    pub fn entry_by_name_mut(&mut self, title: &str) -> Option<EntryMut<'_>> {
        let eid = self.as_ref().entries().find_map(|e| {
            e.get(crate::db::fields::TITLE)
                .is_some_and(|t| t.eq_ignore_ascii_case(title))
                .then(|| e.id())
        });

        eid.map(move |id| EntryMut::new(self.database, id))
    }

    /// Find a contained group by a path of names, case-insensitively, and return a mutable
    /// reference to it.
    pub fn group_by_path_mut(&mut self, path: &[&str]) -> Option<GroupMut<'_>> {
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

        Some(GroupMut::new(self.database, current))
    }

    /// Remove the icon from this group, if it exists.
    pub fn set_icon_none(&mut self) {
        let id = self.id;

        if let Some(Icon::Custom(custom_icon_id)) = self.icon {
            // if this group had a custom icon, remove this group from the icon's reference list
            if let Some(mut custom_icon) = self.database.custom_icon_mut(custom_icon_id) {
                custom_icon.groups.retain(|&group_id| group_id != id);
            }
        }

        self.icon = None;
    }

    /// Set a built-in icon for this group by its ID, removing any existing icon.
    pub fn set_icon_builtin(&mut self, icon_id: usize) {
        self.set_icon_none();
        self.icon = Some(Icon::BuiltIn(icon_id));
    }

    /// Set a custom icon for this group by its ID, removing any existing icon.
    pub fn set_icon_custom(&mut self, custom_icon_id: CustomIconId) -> Result<(), CustomIconNotFoundError> {
        self.set_icon_none();

        let id = self.id;

        let mut custom_icon = self
            .database
            .custom_icon_mut(custom_icon_id)
            .ok_or(CustomIconNotFoundError(custom_icon_id))?;

        custom_icon.groups.insert(id);

        self.icon = Some(Icon::Custom(custom_icon_id));

        Ok(())
    }

    /// Set a custom icon for this group by providing the raw data, removing any existing icon.
    /// Returns a mutable reference to the newly created custom icon.
    pub fn set_icon_custom_new(&mut self, data: Vec<u8>) -> CustomIconMut<'_> {
        self.set_icon_none();

        let custom_icon_id = CustomIconId::new();

        let id = self.id;

        self.database.custom_icons.insert(
            custom_icon_id,
            CustomIcon {
                id: custom_icon_id,
                entries: HashSet::new(),
                groups: vec![id].into_iter().collect(),
                name: None,
                last_modification_time: Some(Times::now()),
                data,
            },
        );

        self.icon = Some(Icon::Custom(custom_icon_id));

        CustomIconMut::new(self.database, custom_icon_id)
    }

    /// Get a mutable reference to the custom icon of this group, if it exists and is a custom
    /// icon.
    pub fn custom_icon_mut(&mut self) -> Option<CustomIconMut<'_>> {
        if let Some(Icon::Custom(custom_icon_id)) = self.icon {
            Some(CustomIconMut::new(self.database, custom_icon_id))
        } else {
            None
        }
    }

    /// Move this group to a new parent group.
    ///
    /// Performs sanity checking and will return an error if the destination does not exist,
    /// belongs to a different database, or if the move would create a cycle in the group
    /// hierarchy.
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
        #[allow(clippy::unwrap_used, clippy::missing_panics_doc)] // we checked that old_parent_id exists
        let mut old_parent = self.database.group_mut(old_parent_id).unwrap();
        old_parent.groups.remove(&self.id);

        // Insert into new parent
        #[allow(clippy::unwrap_used, clippy::missing_panics_doc)] // we checked that new_parent_id exists
        let mut new_parent = self.database.group_mut(new_parent_id).unwrap();
        new_parent.groups.insert(self.id);

        // Update parent reference
        self.parent = Some(new_parent_id);
        self.previous_parent_group = Some(old_parent_id);

        Ok(())
    }

    /// Deletes this group and all its child groups and entries from the database.
    pub fn remove(self) {
        // Remove from parent
        if let Some(parent_id) = self.parent {
            if let Some(mut parent) = self.database.group_mut(parent_id) {
                parent.groups.remove(&self.id);
            }
        }

        // Delete entries
        let entry_ids: Vec<EntryId> = self.entries.iter().cloned().collect();
        for entry_id in entry_ids {
            if let Some(entry) = self.database.entry_mut(entry_id) {
                entry.remove();
            }
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

/// Errors that can occur when moving a group to a new parent.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MoveGroupError {
    /// The root group cannot be moved
    #[error("Cannot move the root group")]
    CannotMoveRoot,

    /// The destination group was not found in the database.
    ///
    /// This error can also occur if the destination group belongs to a different database.
    #[error("Destination group with ID {0} not found")]
    NotFound(GroupId),

    /// Moving the group would create a cycle in the group hierarchy, which is not allowed.
    #[error("Cannot move a group into itself or one of its descendants")]
    WouldCreateCycle,
}

impl Deref for GroupMut<'_> {
    type Target = Group;

    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // group existence is guaranteed
    fn deref(&self) -> &Self::Target {
        self.database
            .groups
            .get(&self.id)
            .expect("GroupMut points to a non-existing group")
    }
}

impl DerefMut for GroupMut<'_> {
    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // group existence is guaranteed
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.database
            .groups
            .get_mut(&self.id)
            .expect("GroupMut points to a non-existing group")
    }
}

/// A variant of [GroupMut] that tracks changes to the group, such as deletions and moves, and
/// updates the location changed time when the group is moved.
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
    pub fn remove(self) -> Result<(), CannotDeleteRootError> {
        if self.id() == self.database.root().id() {
            return Err(CannotDeleteRootError);
        }

        // Remove from parent
        if let Some(parent_id) = self.parent {
            if let Some(mut parent) = self.database.group_mut(parent_id) {
                parent.groups.remove(&self.id);
            }
        }

        // Delete entries
        let entry_ids: Vec<EntryId> = self.entries.iter().cloned().collect();

        for entry_id in entry_ids {
            if let Some(mut entry) = self.database.entry_mut(entry_id) {
                entry.track_changes().remove();
            }
        }

        // Recursively delete child groups
        let child_group_ids: Vec<GroupId> = self.groups.iter().cloned().collect();
        for child_id in child_group_ids {
            if let Some(mut child_group) = self.database.group_mut(child_id) {
                child_group.track_changes().remove()?;
            }
        }

        // Finally, remove this group from the database and add to deleted groups
        self.database.groups.remove(&self.id);
        self.database
            .deleted_objects
            .insert(self.id.uuid(), Some(Times::now()));

        Ok(())
    }

    /// Convenience method to edit the group in a closure, updating the last modification time.
    pub fn edit(&mut self, f: impl FnOnce(&mut GroupTrack<'_>)) -> &mut Self {
        f(self);
        self.as_mut().times.last_modification = Some(Times::now());
        self
    }
}

impl Deref for GroupTrack<'_> {
    type Target = Group;

    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // group existence is guaranteed
    fn deref(&self) -> &Self::Target {
        self.database.groups.get(&self.id).expect("Group not found")
    }
}

impl DerefMut for GroupTrack<'_> {
    #[allow(clippy::expect_used, clippy::missing_panics_doc)] // group existence is guaranteed
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.database.groups.get_mut(&self.id).expect("Group not found")
    }
}

/// Error returned when attempting to delete the root group, which is not allowed.
#[derive(Debug, Error)]
#[error("Cannot delete the root group")]
pub struct CannotDeleteRootError;

#[cfg(test)]
mod group_tests {
    use crate::db::fields;
    use crate::Database;

    #[test]
    fn get() {
        let mut db = Database::new();

        let general_group_id = db.root_mut().add_group().edit(|g| g.name = "General".into()).id();

        let sample_entry_id = db
            .group_mut(general_group_id)
            .unwrap()
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Sample Entry #2");
            })
            .id();

        assert_eq!(
            db.entry(sample_entry_id).unwrap().get(fields::TITLE),
            Some("Sample Entry #2")
        );

        let root = db.root();

        assert!(root.group(general_group_id).is_some());
        assert!(db
            .group(general_group_id)
            .unwrap()
            .entry(sample_entry_id)
            .is_some());

        let grp = root.group_by_path(&["General"]).unwrap();

        assert!(grp.entry_by_name("Sample Entry #2").is_some());

        assert!(root.group_by_name("General").is_some());

        assert!(root.group_by_name("Invalid Group").is_none());

        assert!(root.group_by_path(&[]).is_some());
    }

    #[test]
    fn get_mut() {
        let mut db = Database::new();

        let general_group_id = db.root_mut().add_group().edit(|g| g.name = "General".into()).id();

        let sample_entry_id = db
            .group_mut(general_group_id)
            .unwrap()
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Sample Entry #2");
            })
            .id();

        assert_eq!(
            db.entry_mut(sample_entry_id).unwrap().get(fields::TITLE),
            Some("Sample Entry #2")
        );

        let mut root = db.root_mut();
        assert!(root.group_mut(general_group_id).is_some());

        let mut grp = root.group_by_path_mut(&["General"]).unwrap();

        assert!(grp.entry_by_name_mut("Sample Entry #2").is_some());

        assert!(root.group_by_name_mut("General").is_some());
        assert!(root.group_by_name_mut("Invalid Group").is_none());
        assert!(root.group_by_path_mut(&[]).is_some());

        assert!(db
            .group_mut(general_group_id)
            .unwrap()
            .entry_mut(sample_entry_id)
            .is_some());
    }
}
