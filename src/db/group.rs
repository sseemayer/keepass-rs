use std::collections::VecDeque;

use uuid::Uuid;

use crate::db::{
    entry::{Entry, Value},
    node::{Node, NodeIter, NodePath, NodePathElement, NodeRef, NodeRefMut},
    CustomData, Times,
};

#[derive(Debug, Clone)]
pub enum MergeEventType {
    EntryCreated,
    EntryLocationUpdated,
    EntryUpdated,
    GroupCreated,
    GroupLocationUpdated,
}

#[derive(Debug, Clone)]
pub struct MergeEvent {
    /// The uuid of the node (entry or group) affected by
    /// the merge event.
    pub node_uuid: Uuid,

    pub event_type: MergeEventType,
}

// FIXME this should be moved to Database
#[derive(Debug, Default, Clone)]
pub struct MergeLog {
    pub warnings: Vec<String>,
    pub events: Vec<MergeEvent>,
}

impl MergeLog {
    pub fn merge_with(&self, other: &MergeLog) -> MergeLog {
        let mut response = MergeLog::default();
        response.warnings.append(self.warnings.clone().as_mut());
        response.warnings.append(other.warnings.clone().as_mut());
        response.events.append(self.events.clone().as_mut());
        response.events.append(other.events.clone().as_mut());
        response
    }
}

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

    pub(crate) fn find<'a>(&'a self, path: &Vec<Uuid>) -> Option<NodeRef<'a>> {
        if path.is_empty() {
            Some(NodeRef::Group(self))
        } else {
            if path.len() == 1 {
                let head = &path[0];
                self.children.iter().find_map(|n| {
                    if head == &n.get_uuid() {
                        return Some(n.as_ref());
                    }
                    return None;
                })
            } else {
                let head = &path[0];
                let tail = path[1..path.len()].to_owned();

                let head_group = self.children.iter().find_map(|n| match n {
                    Node::Group(g) if head == &n.get_uuid() => Some(g),
                    _ => None,
                })?;

                head_group.find(&tail)
            }
        }
    }

    pub(crate) fn find_mut<'a>(&'a mut self, path: &Vec<Uuid>) -> Option<NodeRefMut<'a>> {
        if path.is_empty() {
            Some(NodeRefMut::Group(self))
        } else {
            if path.len() == 1 {
                let head = &path[0];
                self.children
                    .iter_mut()
                    .filter(|n| head == &n.get_uuid())
                    .map(|t| t.as_mut())
                    .next()
            } else {
                let head = &path[0];
                let tail = path[1..path.len()].to_owned();

                let head_group: &mut Group = self.children.iter_mut().find_map(|n| {
                    let uuid_matches = head == &n.get_uuid();
                    match n {
                        Node::Group(g) if uuid_matches => Some(g),
                        _ => None,
                    }
                })?;

                head_group.find_mut(&tail)
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

    pub(crate) fn replace_entry(&mut self, entry: &Entry) {
        for node in &mut self.children {
            match node {
                Node::Group(g) => {
                    g.replace_entry(entry);
                }
                Node::Entry(e) => {
                    if e.uuid == entry.uuid {
                        *e = entry.clone();
                    }
                }
            }
        }
    }

    pub(crate) fn remove_node(&mut self, uuid: &Uuid) -> Result<Node, String> {
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

        return Err(format!(
            "Could not find node {} in group {}.",
            uuid, self.name
        ));
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

    pub fn find_entry_by_uuid(&self, id: Uuid) -> Option<&Entry> {
        for node in &self.children {
            match node {
                Node::Group(g) => {
                    if let Some(e) = g.find_entry_by_uuid(id) {
                        return Some(e);
                    }
                }
                Node::Entry(e) => {
                    if e.uuid == id {
                        return Some(e);
                    }
                }
            }
        }
        None
    }

    pub fn find_group(&self, id: Uuid) -> Option<&Group> {
        for node in &self.children {
            match node {
                Node::Group(g) => {
                    if g.uuid == id {
                        return Some(g);
                    }
                    if let Some(g) = g.find_group(id) {
                        return Some(g);
                    }
                }
                Node::Entry(e) => continue,
            }
        }
        None
    }

    pub(crate) fn add_group_or_entry(
        &mut self,
        node: impl Into<Node> + Clone,
        path: &NodeLocation,
    ) {
        if path.len() == 0 {
            self.add_child(node.clone());
            return;
        }
        println!("Searching for {:?}", path);

        let next_path_uuid = &path[0];

        let mut remaining_path = path.clone();
        remaining_path.remove(0);

        println!("Searching for group {}", next_path_uuid);
        for n in &mut self.children {
            if let Node::Group(g) = n {
                if &g.uuid != next_path_uuid {
                    continue;
                }
                g.add_group_or_entry(node, &remaining_path);
                return;
            }
        }

        panic!("TODO handle this with a response");
    }

    // Recursively get all the entries in the group, along with their
    // location.
    pub(crate) fn get_all_entries(
        &self,
        current_location: &NodeLocation,
    ) -> Vec<(&Entry, NodeLocation)> {
        let mut response: Vec<(&Entry, NodeLocation)> = vec![];
        let mut new_location = current_location.clone();
        new_location.push(self.uuid.clone());

        for node in &self.children {
            match node {
                Node::Entry(e) => {
                    response.push((&e, new_location.clone()));
                }
                Node::Group(g) => {
                    let mut new_entries = g.get_all_entries(&new_location);
                    response.append(&mut new_entries);
                }
            }
        }
        response
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

        let group_path = vec![NodePathElement::UUID(&general_group_uuid)];
        let entry_path = vec![
            NodePathElement::UUID(&general_group_uuid),
            NodePathElement::UUID(&sample_entry_uuid),
        ];
        let invalid_path = vec![NodePathElement::UUID(&invalid_uuid)];

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

        let group_path = vec![NodePathElement::UUID(&general_group_uuid)];
        let entry_path = vec![
            NodePathElement::UUID(&general_group_uuid),
            NodePathElement::UUID(&sample_entry_uuid),
        ];
        let invalid_path = vec![NodePathElement::UUID(&invalid_uuid)];

        assert!(db.root.get_mut_internal(&group_path).is_some());
        assert!(db.root.get_mut_internal(&entry_path).is_some());
        assert!(db.root.get_mut_internal(&invalid_path).is_none());
        assert!(db.root.get_mut_internal(&vec![]).is_some());
    }
}

#[cfg(test)]
mod merge_tests {
    use std::{fs::File, path::Path};
    use std::{thread, time};
    use uuid::Uuid;

    use super::{Entry, Group, Node, Times};
    use crate::Database;

    const ROOT_GROUP_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6a";
    const GROUP1_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6b";
    const GROUP2_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6c";
    const SUBGROUP1_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d";
    const SUBGROUP2_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6e";

    fn get_entry_mut<'a>(db: &'a mut Database, path: &[&str]) -> &'a mut Entry {
        match db.root.get_mut(path).unwrap() {
            crate::db::NodeRefMut::Entry(e) => e,
            crate::db::NodeRefMut::Group(g) => panic!("An entry was expected."),
        }
    }

    fn get_group_mut<'a>(db: &'a mut Database, path: &[&str]) -> &'a mut Group {
        match db.root.get_mut(path).unwrap() {
            crate::db::NodeRefMut::Group(g) => g,
            crate::db::NodeRefMut::Entry(e) => panic!("A group was expected."),
        }
    }

    fn create_test_database() -> Database {
        let mut db = Database::new(Default::default());
        let mut root_group = Group::new("root");
        root_group.uuid = Uuid::parse_str(ROOT_GROUP_ID).unwrap();

        let mut group1 = Group::new("group1");
        group1.uuid = Uuid::parse_str(GROUP1_ID).unwrap();
        let mut group2 = Group::new("group2");
        group2.uuid = Uuid::parse_str(GROUP2_ID).unwrap();

        let mut subgroup1 = Group::new("subgroup1");
        subgroup1.uuid = Uuid::parse_str(SUBGROUP1_ID).unwrap();
        let mut subgroup2 = Group::new("subgroup2");
        subgroup2.uuid = Uuid::parse_str(SUBGROUP2_ID).unwrap();

        group1.add_child(subgroup1);
        group2.add_child(subgroup2);

        root_group.add_child(group1);
        root_group.add_child(group2);

        db.root = root_group;
        db
    }

    #[test]
    fn test_idempotence() {
        let mut destination_db = create_test_database();
        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_db.root.add_child(entry);

        let mut source_db = destination_db.clone();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_db.root.children.len(), 3);
        // The 2 groups should be exactly the same after merging, since
        // nothing was performed during the merge.
        assert_eq!(destination_db, source_db);

        let mut entry = &mut destination_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        let destination_db_just_after_merge = destination_db.clone();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        // Merging twice in a row, even if the first merge updated the destination group,
        // should not create more changes.
        assert_eq!(destination_db_just_after_merge, destination_db);
    }

    #[test]
    fn test_add_new_entry() {
        let mut destination_db = create_test_database();

        let mut source_db = destination_db.clone();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_db.root.add_child(entry);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);
        assert_eq!(destination_db.root.children.len(), 3);
        let new_entry = destination_db.root.find_entry_by_uuid(entry_uuid);
        assert!(new_entry.is_some());
        assert_eq!(
            new_entry.unwrap().get_title().unwrap(),
            "entry1".to_string()
        );

        // Merging the same group again should not create a duplicate entry.
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_db.root.children.len(), 3);
    }

    #[test]
    fn test_deleted_entry_in_destination() {
        let mut destination_db = create_test_database();

        let mut source_db = destination_db.clone();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_db.root.add_child(entry);

        destination_db
            .deleted_objects
            .objects
            .push(crate::db::DeletedObject {
                uuid: entry_uuid.clone(),
                deletion_time: Times::now(),
            });

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_db.root.children.len(), 2);
        let new_entry = destination_db.root.find_entry_by_uuid(entry_uuid);
        assert!(new_entry.is_none());
    }

    #[test]
    fn test_add_new_non_root_entry() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let mut source_sub_group = &mut source_db.root.groups_mut()[0];

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_sub_group.add_child(entry);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);
        let destination_entries = destination_db.root.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (created_entry, created_entry_location) = destination_entries.get(0).unwrap();
        assert_eq!(created_entry_location.len(), 2);
    }

    #[test]
    fn test_add_new_entry_new_group() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let mut source_group = Group::new("group2");
        let mut source_sub_group = Group::new("subgroup2");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_sub_group.add_child(entry);
        source_group.add_child(source_sub_group);
        source_db.root.add_child(source_group);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 3);
        let destination_entries = destination_db.root.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (created_entry, created_entry_location) = destination_entries.get(0).unwrap();
        assert_eq!(created_entry_location.len(), 3);
    }

    #[test]
    fn test_entry_relocation_existing_group() {
        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        let mut destination_db = create_test_database();
        let mut destination_sub_group1 =
            get_group_mut(&mut destination_db, &["group1", "subgroup1"]);

        destination_sub_group1.add_child(entry.clone());

        let mut source_db = destination_db.clone();
        assert!(source_db.root.get_all_entries(&vec![]).len() == 1);

        let mut relocated_entry = get_entry_mut(&mut source_db, &["group1", "subgroup1", "entry1"]);
        relocated_entry.times.set_location_changed(Times::now());
        // FIXME we should not have to update the history here. We should
        // have a better compare function in the merge function instead.
        relocated_entry.update_history();
        drop(&relocated_entry);

        source_db
            .relocate_node(
                &entry_uuid,
                &vec![
                    Uuid::parse_str(ROOT_GROUP_ID).unwrap(),
                    Uuid::parse_str(GROUP1_ID).unwrap(),
                    Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                ],
                &vec![Uuid::parse_str(GROUP2_ID).unwrap()],
            )
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let destination_entries = destination_db.root.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (moved_entry, moved_entry_location) = destination_entries.get(0).unwrap();
        assert_eq!(moved_entry_location.len(), 2);
        assert_eq!(
            moved_entry_location[0],
            Uuid::parse_str(ROOT_GROUP_ID).unwrap()
        );
        assert_eq!(moved_entry_location[1], Uuid::parse_str(GROUP2_ID).unwrap());
    }

    #[test]
    fn test_entry_relocation_new_group() {
        let mut destination_db = create_test_database();

        let mut source_db = destination_db.clone();
        let mut new_group = Group::new("subgroup3");
        let new_group_uuid = new_group.uuid.clone();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        thread::sleep(time::Duration::from_secs(1));
        entry.times.set_location_changed(Times::now());
        // FIXME we should not have to update the history here. We should
        // have a better compare function in the merge function instead.
        entry.update_history();
        new_group.add_child(entry.clone());
        source_db.root.add_child(new_group);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let destination_entries = destination_db.root.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (created_entry, created_entry_location) = destination_entries.get(0).unwrap();
        assert_eq!(created_entry_location.len(), 2);
        assert_eq!(
            created_entry_location[0],
            Uuid::parse_str(ROOT_GROUP_ID).unwrap()
        );
        assert_eq!(created_entry_location[1], new_group_uuid);
    }

    #[test]
    fn test_group_relocation() {
        let mut destination_db = create_test_database();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        let mut destination_sub_group1 = match destination_db
            .root
            .get_mut(&["group1", "subgroup1"])
            .unwrap()
        {
            crate::db::NodeRefMut::Group(g) => g,
            _ => panic!("This should never happen."),
        };
        destination_sub_group1.add_child(entry.clone());

        let mut source_db = destination_db.clone();

        let mut source_group_1 = match source_db.root.get_mut(&["group1"]).unwrap() {
            crate::db::NodeRefMut::Group(g) => g,
            _ => panic!("This should never happen."),
        };
        let mut source_sub_group_1 = match source_group_1
            .remove_node(&Uuid::parse_str(SUBGROUP1_ID).unwrap())
            .unwrap()
        {
            Node::Group(g) => g,
            _ => panic!("This should not happen."),
        };
        thread::sleep(time::Duration::from_secs(1));
        source_sub_group_1.times.set_location_changed(Times::now());

        drop(source_group_1);
        let mut source_group_2 = match source_db.root.get_mut(&["group2"]).unwrap() {
            crate::db::NodeRefMut::Group(g) => g,
            _ => panic!("This should never happen."),
        };

        source_group_2.add_child(source_sub_group_1);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let destination_entries = destination_db.root.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (created_entry, created_entry_location) = destination_entries.get(0).unwrap();
        assert_eq!(created_entry_location.len(), 3);
        assert_eq!(created_entry_location[0], destination_db.root.uuid);
        assert_eq!(
            created_entry_location[1],
            Uuid::parse_str(GROUP2_ID).unwrap()
        );
        assert_eq!(
            created_entry_location[2],
            Uuid::parse_str(SUBGROUP1_ID).unwrap()
        );
    }

    #[test]
    fn test_update_in_destination_no_conflict() {
        let mut destination_db = Database::new(Default::default());
        let mut destination_group = Group::new("root");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        destination_group.add_child(entry);
        destination_db.root = destination_group.clone();

        let mut source_db = destination_db.clone();

        let mut entry = &mut destination_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_in_source_no_conflict() {
        let mut destination_db = Database::new(Default::default());
        let mut destination_group = Group::new("root");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_group.add_child(entry);
        destination_db.root = destination_group.clone();

        let mut source_db = destination_db.clone();

        let mut entry = &mut source_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_with_conflicts() {
        let mut destination_db = Database::new(Default::default());
        let mut destination_group = Group::new("root");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_group.add_child(entry);
        destination_db.root = destination_group.clone();

        let mut source_db = destination_db.clone();

        let mut entry = &mut destination_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated_from_destination");

        let mut entry = &mut source_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated_from_source");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated_from_source"));

        let merged_history = entry.history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 3);
        let merged_entry = &merged_history.entries[1];
        assert_eq!(
            merged_entry.get_title(),
            Some("entry1_updated_from_destination")
        );

        // Merging again should not result in any additional change.
        let merge_result = destination_db.merge(&destination_db.clone()).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
    }
}
