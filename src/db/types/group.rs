use std::collections::HashMap;

use uuid::Uuid;

use crate::db::{CustomDataItem, Entry, Times};

/// A database group with child groups and entries
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Group {
    /// The unique identifier of the group
    pub uuid: Uuid,

    /// The name of the group
    pub name: String,

    /// Notes for the group
    pub notes: Option<String>,

    /// ID of the group's icon
    pub icon_id: Option<usize>,

    /// UUID for a custom group icon
    pub custom_icon_uuid: Option<Uuid>,

    /// The list of child groups
    pub groups: Vec<Group>,

    /// The list of entries directly under this group
    pub entries: Vec<Entry>,

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
    // TODO figure out what that is supposed to mean. According to the KeePass sourcecode, it has
    // something to do with restoring selected items when re-opening a database.
    pub last_top_visible_entry: Option<Uuid>,
}

impl Group {
    pub fn new(name: &str) -> Group {
        Group {
            name: name.to_string(),
            times: Times::new(),
            uuid: Uuid::new_v4(),
            ..Default::default()
        }
    }

    /// Get a reference to a child group by name. This will only search the immediate child groups
    /// of the current group, not any descendant groups.
    pub fn group_by_name(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|g| g.name == name)
    }

    /// Get a mutable reference to a child group by name. This will only search the immediate child
    /// groups of the current group, not any descendant groups.
    pub fn group_by_name_mut(&mut self, name: &str) -> Option<&mut Group> {
        self.groups.iter_mut().find(|g| g.name == name)
    }

    /// Recursively get a group reference by specifying a path of group names relative to the
    /// current Group
    pub fn group_by_path(&self, path: &[&str]) -> Option<&Group> {
        if path.is_empty() {
            return Some(self);
        }

        self.groups.iter().find(|g| g.name == path[0]).and_then(|g| {
            if path.len() > 1 {
                g.group_by_path(&path[1..])
            } else {
                Some(g)
            }
        })
    }

    /// Recursively get a mutable group reference by specifying a path of group names relative to
    /// the current Group
    pub fn group_by_path_mut(&mut self, path: &[&str]) -> Option<&mut Group> {
        if path.is_empty() {
            return Some(self);
        }

        self.groups.iter_mut().find(|g| g.name == path[0]).and_then(|g| {
            if path.len() > 1 {
                g.group_by_path_mut(&path[1..])
            } else {
                Some(g)
            }
        })
    }

    /// Get a group reference by specifying a UUID. This will search the current group and all
    /// descendant groups for a matching UUID.
    pub fn group_by_uuid(&self, uuid: Uuid) -> Option<&Group> {
        if self.uuid == uuid {
            return Some(self);
        }

        for g in &self.groups {
            if let Some(group) = g.group_by_uuid(uuid) {
                return Some(group);
            }
        }

        None
    }

    /// Get a mutable group reference by specifying a UUID. This will search the current group and
    /// all descendant groups for a matching UUID.
    pub fn group_by_uuid_mut(&mut self, uuid: Uuid) -> Option<&mut Group> {
        if self.uuid == uuid {
            return Some(self);
        }

        for g in &mut self.groups {
            if let Some(group) = g.group_by_uuid_mut(uuid) {
                return Some(group);
            }
        }

        None
    }

    /// Get an entry by name. This will only search the immediate child entries of the current
    /// group, not any descendant entries in child groups.
    pub fn entry_by_name(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.get_title() == Some(name))
    }

    /// Get a mutable entry by name. This will only search the immediate child entries of the
    /// current group, not any descendant entries in child groups.
    pub fn entry_by_name_mut(&mut self, name: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.get_title() == Some(name))
    }

    /// Get an entry by UUID. This will search the immediate child entries of the current group and
    /// all descendant entries in child groups for a matching UUID.
    pub fn entry_by_uuid(&self, uuid: Uuid) -> Option<&Entry> {
        for e in &self.entries {
            if e.uuid == uuid {
                return Some(e);
            }
        }

        for g in &self.groups {
            if let Some(e) = g.entry_by_uuid(uuid) {
                return Some(e);
            }
        }

        None
    }

    /// Get a mutable entry by UUID. This will search the immediate child entries of the current
    /// group and all descendant entries in child groups for a matching UUID.
    pub fn entry_by_uuid_mut(&mut self, uuid: Uuid) -> Option<&mut Entry> {
        for e in &mut self.entries {
            if e.uuid == uuid {
                return Some(e);
            }
        }

        for g in &mut self.groups {
            if let Some(e) = g.entry_by_uuid_mut(uuid) {
                return Some(e);
            }
        }

        None
    }

    /// Convenience method for getting the name of the Group
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod group_tests {
    use super::Group;
    use crate::db::{fields, Entry};
    use crate::Database;

    #[test]
    fn get() {
        let mut db = Database::new(Default::default());

        let mut general_group = Group::new("General");
        let mut sample_entry = Entry::new();
        sample_entry.set_unprotected(fields::TITLE, "Sample Entry #2");
        general_group.entries.push(sample_entry);
        db.root.groups.push(general_group);

        assert!(db
            .root
            .group_by_path(&["General"])
            .and_then(|g| g.entry_by_name("Sample Entry #2"))
            .is_some());

        assert!(db.root.group_by_name("General").is_some());

        assert!(db.root.group_by_name("Invalid Group").is_none());

        assert!(db.root.group_by_path(&[]).is_some());
    }

    #[test]
    fn get_mut() {
        let mut db = Database::new(Default::default());

        let mut general_group = Group::new("General");
        let mut sample_entry = Entry::new();
        sample_entry.set_unprotected(fields::TITLE, "Sample Entry #2");
        general_group.entries.push(sample_entry);
        db.root.groups.push(general_group);

        assert!(db
            .root
            .group_by_path_mut(&["General"])
            .and_then(|g| g.entry_by_name_mut("Sample Entry #2"))
            .is_some());

        assert!(db.root.group_by_name_mut("General").is_some());
        assert!(db.root.group_by_name_mut("Invalid Group").is_none());
        assert!(db.root.group_by_path_mut(&[]).is_some());
    }

    #[test]
    fn get_by_uuid() {
        let mut db = Database::new(Default::default());

        let mut general_group = Group::new("General");
        let mut sample_entry = Entry::new();
        sample_entry.set_unprotected(fields::TITLE, "Sample Entry #2");
        general_group.entries.push(sample_entry.clone());
        db.root.groups.push(general_group.clone());

        let general_group_uuid = general_group.uuid;
        let sample_entry_uuid = sample_entry.uuid;
        let invalid_uuid = uuid::Uuid::new_v4();

        assert!(db.root.group_by_uuid(general_group_uuid).is_some());
        assert!(db.root.group_by_uuid(sample_entry_uuid).is_none());
        assert!(db.root.group_by_uuid(invalid_uuid).is_none());

        assert!(db.root.entry_by_uuid(general_group_uuid).is_none());
        assert!(db.root.entry_by_uuid(sample_entry_uuid).is_some());
        assert!(db.root.entry_by_uuid(invalid_uuid).is_none());
    }

    #[test]
    fn get_by_uuid_mut() {
        let mut db = Database::new(Default::default());

        let mut general_group = Group::new("General");
        let mut sample_entry = Entry::new();
        sample_entry.set_unprotected(fields::TITLE, "Sample Entry #2");
        general_group.entries.push(sample_entry.clone());
        db.root.groups.push(general_group.clone());

        let general_group_uuid = general_group.uuid;
        let sample_entry_uuid = sample_entry.uuid;
        let invalid_uuid = uuid::Uuid::new_v4();

        assert!(db.root.group_by_uuid_mut(general_group_uuid).is_some());
        assert!(db.root.group_by_uuid_mut(sample_entry_uuid).is_none());
        assert!(db.root.group_by_uuid_mut(invalid_uuid).is_none());

        assert!(db.root.entry_by_uuid_mut(general_group_uuid).is_none());
        assert!(db.root.entry_by_uuid_mut(sample_entry_uuid).is_some());
        assert!(db.root.entry_by_uuid_mut(invalid_uuid).is_none());
    }
}
