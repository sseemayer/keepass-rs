use std::collections::VecDeque;

use uuid::Uuid;

use crate::db::{
    entry::{Entry, Value},
    node::{Node, NodeIter, NodePath, NodePathElement, NodeRef, NodeRefMut},
    CustomData, Times,
};

#[cfg(feature = "merge")]
use crate::db::merge::{MergeError, MergeEvent, MergeEventType, MergeLog};

pub(crate) type NodeLocation = Vec<Uuid>;

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
        let node_path = NodePathElement::wrap_titles(path);
        self.get_internal(&node_path)
    }

    pub(crate) fn get_internal<'a>(&'a self, path: &NodePath) -> Option<NodeRef<'a>> {
        if path.is_empty() {
            Some(NodeRef::Group(self))
        } else {
            if path.len() == 1 {
                let head = &path[0];
                self.children.iter().find_map(|n| {
                    if head.matches(&n) {
                        return Some(n.as_ref());
                    }
                    return None;
                })
            } else {
                let head = &path[0];
                let tail = path[1..path.len()].to_owned();

                let head_group = self.children.iter().find_map(|n| match n {
                    Node::Group(g) if head.matches(&n) => Some(g),
                    _ => None,
                })?;

                head_group.get_internal(&tail)
            }
        }
    }

    /// Recursively get a mutable reference to a Group or Entry by specifying a path relative to
    /// the current Group
    pub fn get_mut<'a>(&'a mut self, path: &[&str]) -> Option<NodeRefMut<'a>> {
        let node_path = NodePathElement::wrap_titles(path);
        self.get_mut_internal(&node_path)
    }

    pub(crate) fn get_mut_internal<'a>(&'a mut self, path: &NodePath) -> Option<NodeRefMut<'a>> {
        if path.is_empty() {
            Some(NodeRefMut::Group(self))
        } else {
            if path.len() == 1 {
                let head = &path[0];
                self.children
                    .iter_mut()
                    .filter(|n| head.matches(n))
                    .map(|t| t.as_mut())
                    .next()
            } else {
                let head = &path[0];
                let tail = path[1..path.len()].to_owned();

                let head_group: &mut Group = self.children.iter_mut().find_map(|n| {
                    let title_matches = head.matches(&n);
                    match n {
                        Node::Group(g) if title_matches => Some(g),
                        _ => None,
                    }
                })?;

                head_group.get_mut_internal(&tail)
            }
        }
    }

    pub(crate) fn find_group<'a>(&'a self, path: &Vec<Uuid>) -> Option<&Group> {
        let node_ref = match self.find(path) {
            Some(n) => n,
            None => return None,
        };
        match node_ref {
            NodeRef::Group(g) => Some(g),
            NodeRef::Entry(_) => None,
        }
    }

    pub(crate) fn find_entry<'a>(&'a self, path: &Vec<Uuid>) -> Option<&Entry> {
        let node_ref = match self.find(path) {
            Some(n) => n,
            None => return None,
        };
        match node_ref {
            NodeRef::Entry(e) => Some(e),
            NodeRef::Group(_) => None,
        }
    }

    pub(crate) fn find<'a>(&'a self, path: &Vec<Uuid>) -> Option<NodeRef<'a>> {
        let node_path = NodePathElement::wrap_ids(path);
        self.get_internal(&node_path)
    }

    pub(crate) fn find_entry_mut<'a>(&'a mut self, path: &Vec<Uuid>) -> Option<&mut Entry> {
        let node_ref = match self.find_mut(path) {
            Some(n) => n,
            None => return None,
        };
        match node_ref {
            NodeRefMut::Entry(e) => Some(e),
            NodeRefMut::Group(_) => None,
        }
    }

    pub(crate) fn find_group_mut<'a>(&'a mut self, path: &Vec<Uuid>) -> Option<&mut Group> {
        let node_ref = match self.find_mut(path) {
            Some(n) => n,
            None => return None,
        };
        match node_ref {
            NodeRefMut::Group(g) => Some(g),
            NodeRefMut::Entry(_) => None,
        }
    }

    pub(crate) fn find_mut<'a>(&'a mut self, path: &Vec<Uuid>) -> Option<NodeRefMut<'a>> {
        let node_path = NodePathElement::wrap_ids(path);
        self.get_mut_internal(&node_path)
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

    pub fn entries(&self) -> Vec<&Entry> {
        let mut response: Vec<&Entry> = vec![];
        for node in &self.children {
            if let Node::Entry(e) = node {
                response.push(e)
            }
        }
        response
    }

    pub fn entries_mut(&mut self) -> Vec<&mut Entry> {
        let mut response: Vec<&mut Entry> = vec![];
        for node in &mut self.children {
            if let Node::Entry(e) = node {
                response.push(e)
            }
        }
        response
    }

    pub fn groups(&self) -> Vec<&Group> {
        let mut response: Vec<&Group> = vec![];
        for node in &self.children {
            if let Node::Group(g) = node {
                response.push(g);
            }
        }
        response
    }

    pub fn groups_mut(&mut self) -> Vec<&mut Group> {
        let mut response: Vec<&mut Group> = vec![];
        for node in &mut self.children {
            if let Node::Group(g) = node {
                response.push(g);
            }
        }
        response
    }

    #[cfg(feature = "merge")]
    pub(crate) fn remove_node(&mut self, uuid: &Uuid) -> Result<Node, MergeError> {
        let mut removed_node: Option<Node> = None;
        let mut new_nodes: Vec<Node> = vec![];
        for node in &self.children {
            match node {
                Node::Entry(e) => {
                    if &e.uuid != uuid {
                        new_nodes.push(node.clone());
                        continue;
                    }
                    removed_node = Some(node.clone());
                }
                Node::Group(g) => {
                    if &g.uuid != uuid {
                        new_nodes.push(node.clone());
                        continue;
                    }
                    removed_node = Some(node.clone());
                }
            }
        }

        if let Some(node) = removed_node {
            self.children = new_nodes;
            return Ok(node);
        }

        return Err(MergeError::GenericError(format!(
            "Could not find node {} in group {}.",
            uuid, self.name
        )));
    }

    pub(crate) fn find_node_location(&self, id: Uuid) -> Option<NodeLocation> {
        let mut current_location = vec![self.uuid];
        for node in &self.children {
            match node {
                Node::Entry(e) => {
                    if e.uuid == id {
                        return Some(current_location);
                    }
                }
                Node::Group(g) => {
                    if g.uuid == id {
                        return Some(current_location);
                    }
                    if let Some(mut location) = g.find_node_location(id) {
                        current_location.append(&mut location);
                        return Some(current_location);
                    }
                }
            }
        }
        None
    }

    #[cfg(feature = "merge")]
    pub(crate) fn merge_with(&mut self, other: &Group) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();

        let source_last_modification = match other.times.get_last_modification() {
            Some(t) => *t,
            None => {
                log.warnings.push(format!(
                    "Group {} did not have a last modification timestamp",
                    self.uuid
                ));
                Times::epoch()
            }
        };
        let destination_last_modification = match self.times.get_last_modification() {
            Some(t) => *t,
            None => {
                log.warnings.push(format!(
                    "Group {} did not have a last modification timestamp",
                    self.uuid
                ));
                Times::now()
            }
        };

        if destination_last_modification == source_last_modification {
            if self.has_diverged_from(&other) {
                // This should never happen.
                // This means that a group was updated without updating the last modification
                // timestamp.
                return Err(MergeError::GroupModificationTimeNotUpdated(
                    other.uuid.to_string(),
                ));
            }
            return Ok(log);
        }

        if destination_last_modification > source_last_modification {
            return Ok(log);
        }

        self.name = other.name.clone();
        self.notes = other.notes.clone();
        self.icon_id = other.icon_id.clone();
        self.custom_icon_uuid = other.custom_icon_uuid.clone();
        self.custom_data = other.custom_data.clone();

        // The location changed timestamp is handled separately when merging two databases.
        let current_times = self.times.clone();
        self.times = other.times.clone();
        if let Some(t) = current_times.get_location_changed() {
            self.times.set_location_changed(t.clone());
        }

        self.is_expanded = other.is_expanded;
        self.default_autotype_sequence = other.default_autotype_sequence.clone();
        self.enable_autotype = other.enable_autotype.clone();
        self.enable_searching = other.enable_searching.clone();
        self.last_top_visible_entry = other.last_top_visible_entry.clone();

        log.events.push(MergeEvent {
            event_type: MergeEventType::GroupUpdated,
            node_uuid: self.uuid,
        });

        Ok(log)
    }

    pub(crate) fn has_diverged_from(&self, other: &Group) -> bool {
        let new_times = Times::new();
        let mut self_purged = self.clone();
        self_purged.times = new_times.clone();
        self_purged.children = vec![];

        let mut other_purged = other.clone();
        other_purged.times = new_times.clone();
        other_purged.children = vec![];
        !self_purged.eq(&other_purged)
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
    use super::NodePathElement;
    use super::{Entry, Group, Value};
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
    fn get_internal() {
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

        let group_path = vec![NodePathElement::UUID(general_group_uuid.clone())];
        let entry_path = vec![
            NodePathElement::UUID(general_group_uuid),
            NodePathElement::UUID(sample_entry_uuid),
        ];
        let invalid_path = vec![NodePathElement::UUID(invalid_uuid)];

        assert!(db.root.get_internal(&group_path).is_some());
        assert!(db.root.get_internal(&entry_path).is_some());
        assert!(db.root.get_internal(&invalid_path).is_none());
        assert!(db.root.get_internal(&vec![]).is_some());
    }

    #[test]
    fn get_mut_internal() {
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

        let group_path = vec![NodePathElement::UUID(general_group_uuid.clone())];
        let entry_path = vec![
            NodePathElement::UUID(general_group_uuid),
            NodePathElement::UUID(sample_entry_uuid),
        ];
        let invalid_path = vec![NodePathElement::UUID(invalid_uuid)];

        assert!(db.root.get_mut_internal(&group_path).is_some());
        assert!(db.root.get_mut_internal(&entry_path).is_some());
        assert!(db.root.get_mut_internal(&invalid_path).is_none());
        assert!(db.root.get_mut_internal(&vec![]).is_some());
    }
}
