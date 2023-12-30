use std::collections::VecDeque;

use uuid::Uuid;

use crate::db::{
    node::{Node, NodeIter, NodeRef, NodeRefMut},
    CustomData, Times,
};

pub enum SearchField {
    UUID,
    Title,
}

impl SearchField {
    pub(crate) fn matches(&self, node: &Node, field_value: &str) -> bool {
        let uuid = match node {
            Node::Entry(e) => e.uuid,
            Node::Group(g) => g.uuid,
        };
        let title = match node {
            Node::Entry(e) => e.get_title(),
            Node::Group(g) => Some(g.get_name()),
        };
        match self {
            SearchField::UUID => uuid.to_string() == field_value,
            SearchField::Title => {
                if let Some(title) = title {
                    return title == field_value;
                }
                return false;
            }
        }
    }
}

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

    /// The list of child nodes (Groups or Entries)
    pub children: Vec<Node>,

    /// The list of time fields for this group
    pub times: Times,

    // Custom Data
    pub custom_data: CustomData,

    /// Whether the group is expanded in the user interface
    pub is_expanded: bool,

    /// Default autotype sequence
    pub default_autotype_sequence: Option<String>,

    /// Whether autotype is enabled
    // TODO: in example XML files, this is "null" - what should the type be?
    pub enable_autotype: Option<String>,

    /// Whether searching is enabled
    // TODO: in example XML files, this is "null" - what should the type be?
    pub enable_searching: Option<String>,

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

    /// Add a child node (an entry or a group) to this group.
    pub fn add_child(&mut self, node: impl Into<Node>) {
        self.children.push(node.into());
    }

    /// Recursively get a Group or Entry reference by specifying a path relative to the current Group
    /// ```
    /// use keepass::{Database, DatabaseKey, db::NodeRef};
    /// use std::fs::File;
    ///
    /// let mut file = File::open("tests/resources/test_db_with_password.kdbx").unwrap();
    /// let db = Database::open(
    ///     &mut file,
    ///     DatabaseKey::new().with_password("demopass")
    /// ).unwrap();
    ///
    /// if let Some(NodeRef::Entry(e)) = db.root.get(&["General", "Sample Entry #2"]) {
    ///     println!("User: {}", e.get_username().unwrap());
    /// }
    ///
    /// if let Some(NodeRef::Group(e)) = db.root.get(&["General"]) {
    ///    println!("Group: {}", e.name);
    /// }
    /// ```
    pub fn get<'a>(&'a self, path: &[&str]) -> Option<NodeRef<'a>> {
        self.get_internal(&path, SearchField::Title)
    }

    pub(crate) fn get_by_uuid<'a, T: AsRef<str>>(&'a self, path: &[T]) -> Option<NodeRef<'a>> {
        self.get_internal(&path, SearchField::UUID)
    }

    fn get_internal<'a, T: AsRef<str>>(&'a self, path: &[T], search_field: SearchField) -> Option<NodeRef<'a>> {
        if path.is_empty() {
            Some(NodeRef::Group(self))
        } else {
            if path.len() == 1 {
                let head = &path[0];
                self.children.iter().find_map(|n| {
                    if search_field.matches(n, head.as_ref()) {
                        return Some(n.as_ref());
                    }
                    return None;
                })
            } else {
                let head = &path[0];
                let tail = &path[1..path.len()];

                let head_group = self.children.iter().find_map(|n| match n {
                    Node::Group(g) if search_field.matches(n, head.as_ref()) => Some(g),
                    _ => None,
                })?;

                head_group.get_internal(&tail, search_field)
            }
        }
    }

    /// Recursively get a mutable reference to a Group or Entry by specifying a path relative to
    /// the current Group
    pub fn get_mut<'a>(&'a mut self, path: &[&str]) -> Option<NodeRefMut<'a>> {
        self.get_mut_internal(path, SearchField::Title)
    }

    pub(crate) fn get_by_uuid_mut<'a, T: AsRef<str>>(&'a mut self, path: &[T]) -> Option<NodeRefMut<'a>> {
        self.get_mut_internal(path, SearchField::UUID)
    }

    fn get_mut_internal<'a, T: AsRef<str>>(
        &'a mut self,
        path: &[T],
        search_field: SearchField,
    ) -> Option<NodeRefMut<'a>> {
        if path.is_empty() {
            Some(NodeRefMut::Group(self))
        } else {
            if path.len() == 1 {
                let head = &path[0];
                self.children
                    .iter_mut()
                    .filter(|n| search_field.matches(n, head.as_ref()))
                    .map(|t| t.as_mut())
                    .next()
            } else {
                let head = &path[0];
                let tail = &path[1..path.len()];

                let head_group: &mut Group = self.children.iter_mut().find_map(|n| {
                    let node_matches = search_field.matches(n, head.as_ref());
                    match n {
                        Node::Group(g) if node_matches => Some(g),
                        _ => None,
                    }
                })?;

                head_group.get_mut_internal(&tail, search_field)
            }
        }
    }

    /// Convenience method for getting the name of the Group
    pub fn get_name<'a>(&'a self) -> &'a str {
        &self.name
    }

    /// Get a timestamp field by name
    ///
    /// Returning the chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub fn get_time(&self, key: &str) -> Option<&chrono::NaiveDateTime> {
        self.times.get(key)
    }

    /// Convenience method for getting the time that the group expires
    pub fn get_expiry_time(&self) -> Option<&chrono::NaiveDateTime> {
        self.times.get_expiry()
    }
}

impl<'a> Group {
    pub fn iter(&'a self) -> NodeIter<'a> {
        (&self).into_iter()
    }
}

impl<'a> IntoIterator for &'a Group {
    type Item = NodeRef<'a>;
    type IntoIter = NodeIter<'a>;

    fn into_iter(self) -> NodeIter<'a> {
        let mut queue: VecDeque<NodeRef> = VecDeque::new();
        queue.push_back(NodeRef::Group(self));

        NodeIter::new(queue)
    }
}

#[cfg(test)]
mod group_tests {
    use super::Group;
    use crate::db::Entry;
    use crate::Database;

    #[test]
    fn get() {
        let mut db = Database::new(Default::default());

        let mut general_group = Group::new("General");
        let mut sample_entry = Entry::new();
        sample_entry.fields.insert(
            "Title".to_string(),
            crate::db::Value::Unprotected("Sample Entry #2".to_string()),
        );
        general_group.add_child(sample_entry);
        db.root.add_child(general_group);

        assert!(db.root.get(&["General", "Sample Entry #2"]).is_some());
        assert!(db.root.get(&["General"]).is_some());
        assert!(db.root.get(&["Invalid Group"]).is_none());
        assert!(db.root.get(&[]).is_some());
    }

    #[test]
    fn get_mut() {
        let mut db = Database::new(Default::default());

        let mut general_group = Group::new("General");
        let mut sample_entry = Entry::new();
        sample_entry.fields.insert(
            "Title".to_string(),
            crate::db::Value::Unprotected("Sample Entry #2".to_string()),
        );
        general_group.add_child(sample_entry);
        db.root.add_child(general_group);

        assert!(db.root.get_mut(&["General", "Sample Entry #2"]).is_some());
        assert!(db.root.get_mut(&["General"]).is_some());
        assert!(db.root.get_mut(&["Invalid Group"]).is_none());
        assert!(db.root.get_mut(&[]).is_some());
    }

    #[test]
    fn get_by_uuid() {
        let mut db = Database::new(Default::default());

        let mut general_group = Group::new("General");
        let mut sample_entry = Entry::new();
        sample_entry.fields.insert(
            "Title".to_string(),
            crate::db::Value::Unprotected("Sample Entry #2".to_string()),
        );
        general_group.add_child(sample_entry.clone());
        db.root.add_child(general_group.clone());

        let general_group_uuid = general_group.uuid.to_string();
        let sample_entry_uuid = sample_entry.uuid.to_string();
        let invalid_uuid = uuid::Uuid::new_v4().to_string();

        // Testing with references to the UUIDs
        let group_path: [&str; 1] = [general_group_uuid.as_ref()];
        let entry_path: [&str; 2] = [general_group_uuid.as_ref(), sample_entry_uuid.as_ref()];
        let invalid_path: [&str; 1] = [invalid_uuid.as_ref()];
        let empty_path: [&str; 0] = [];

        assert!(db.root.get_by_uuid(&group_path).is_some());
        assert!(db.root.get_by_uuid(&entry_path).is_some());
        assert!(db.root.get_by_uuid(&invalid_path).is_none());
        assert!(db.root.get_by_uuid(&empty_path).is_some());

        // Testing with owned versions of the UUIDs.
        let group_path = vec![general_group_uuid.clone()];
        let entry_path = vec![general_group_uuid.clone(), sample_entry_uuid.clone()];
        let invalid_path = vec![invalid_uuid.clone()];
        let empty_path: Vec<String> = vec![];

        assert!(db.root.get_by_uuid(&group_path).is_some());
        assert!(db.root.get_by_uuid(&entry_path).is_some());
        assert!(db.root.get_by_uuid(&invalid_path).is_none());
        assert!(db.root.get_by_uuid(&empty_path).is_some());
    }

    #[test]
    fn get_by_uuid_mut() {
        let mut db = Database::new(Default::default());

        let mut general_group = Group::new("General");
        let mut sample_entry = Entry::new();
        sample_entry.fields.insert(
            "Title".to_string(),
            crate::db::Value::Unprotected("Sample Entry #2".to_string()),
        );
        general_group.add_child(sample_entry.clone());
        db.root.add_child(general_group.clone());

        let general_group_uuid = general_group.uuid.to_string();
        let sample_entry_uuid = sample_entry.uuid.to_string();
        let invalid_uuid = uuid::Uuid::new_v4().to_string();

        // Testing with references to the UUIDs
        let group_path: [&str; 1] = [general_group_uuid.as_ref()];
        let entry_path: [&str; 2] = [general_group_uuid.as_ref(), sample_entry_uuid.as_ref()];
        let invalid_path: [&str; 1] = [invalid_uuid.as_ref()];
        let empty_path: [&str; 0] = [];

        assert!(db.root.get_by_uuid_mut(&group_path).is_some());
        assert!(db.root.get_by_uuid_mut(&entry_path).is_some());
        assert!(db.root.get_by_uuid_mut(&invalid_path).is_none());
        assert!(db.root.get_by_uuid_mut(&empty_path).is_some());

        // Testing with owned versions of the UUIDs.
        let group_path = vec![general_group_uuid.clone()];
        let entry_path = vec![general_group_uuid.clone(), sample_entry_uuid.clone()];
        let invalid_path = vec![invalid_uuid.clone()];
        let empty_path: Vec<String> = vec![];

        assert!(db.root.get_by_uuid_mut(&group_path).is_some());
        assert!(db.root.get_by_uuid_mut(&entry_path).is_some());
        assert!(db.root.get_by_uuid_mut(&invalid_path).is_none());
        assert!(db.root.get_by_uuid_mut(&empty_path).is_some());
    }
}
