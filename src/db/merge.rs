use std::collections::{HashMap, VecDeque};

use crate::db::{Database, DeletedObject, Entry, Group, History, Node, NodeRef, NodeRefMut, Times};
use chrono::NaiveDateTime;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum MergeEventType {
    EntryCreated,
    EntryDeleted,
    EntryLocationUpdated,
    EntryUpdated,

    GroupCreated,
    GroupDeleted,
    GroupLocationUpdated,
    GroupUpdated,
}

#[derive(Debug, Clone)]
pub struct MergeEvent {
    /// The uuid of the node (entry or group) affected by
    /// the merge event.
    pub node_uuid: Uuid,

    pub event_type: MergeEventType,
}

#[derive(Debug, Default, Clone)]
pub struct MergeLog {
    pub warnings: Vec<String>,
    pub events: Vec<MergeEvent>,
}

/// Errors while merge two databases
#[derive(Error, Debug)]
pub enum MergeError {
    #[error("{0}")]
    GenericError(String),

    #[error("Could not find group at {0:?}")]
    FindGroupError(NodeLocation),

    #[error("Could not find entry at {0:?}")]
    FindEntryError(NodeLocation),

    #[error("Entries with UUID {0} have the same modification time but have diverged.")]
    EntryModificationTimeNotUpdated(String),

    #[error("Groups with UUID {0} have the same modification time but have diverged.")]
    GroupModificationTimeNotUpdated(String),

    #[error("Found history entries with the same timestamp ({0}) for entry {1}.")]
    DuplicateHistoryEntries(String, String),
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

    pub fn append(&mut self, other: &MergeLog) {
        self.warnings.append(other.warnings.clone().as_mut());
        self.events.append(other.events.clone().as_mut());
    }
}

pub(crate) type NodeLocation = Vec<Uuid>;

impl Database {
    /// Merge this database with another version of this same database.
    /// This function will use the UUIDs to detect that entries and groups are
    /// the same.
    pub fn merge(&mut self, other: &Database) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();
        log.append(&self.merge_group(vec![], &other.root, false)?);
        log.append(&self.merge_deletions(other)?);
        Ok(log)
    }

    fn merge_deletions(&mut self, other: &Database) -> Result<MergeLog, MergeError> {
        // Utility function to search for a UUID in the VecDeque of deleted objects.
        let is_in_deleted_queue = |uuid: Uuid, deleted_groups_queue: &VecDeque<DeletedObject>| -> bool {
            for deleted_object in deleted_groups_queue {
                // This group still has a child group, but it is not going to be deleted.
                if deleted_object.uuid == uuid {
                    return true;
                }
            }
            false
        };

        let mut log = MergeLog::default();

        let mut new_deleted_objects = self.deleted_objects.clone();

        // We start by deleting the entries, since we will only remove groups if they are empty.
        for deleted_object in &other.deleted_objects.objects {
            if new_deleted_objects.contains(deleted_object.uuid) {
                continue;
            }
            let entry_location = match self.find_node_location(deleted_object.uuid) {
                Some(l) => l,
                None => continue,
            };

            let parent_group = match self.root.find_group_mut(&entry_location) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(entry_location)),
            };

            let entry = match parent_group.find_entry(&[deleted_object.uuid]) {
                Some(e) => e,
                // This uuid might refer to a group, which will be handled later.
                None => continue,
            };

            let entry_last_modification = match entry.times.get_last_modification() {
                Some(t) => *t,
                None => {
                    log.warnings.push(format!(
                        "Entry {} did not have a last modification timestamp",
                        entry.uuid
                    ));
                    Times::now()
                }
            };

            if entry_last_modification < deleted_object.deletion_time {
                parent_group.remove_node(&deleted_object.uuid)?;
                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryDeleted,
                    node_uuid: deleted_object.uuid,
                });

                new_deleted_objects.objects.push(deleted_object.clone());
            }
        }

        let mut deleted_groups_queue: VecDeque<DeletedObject> = vec![].into();
        for deleted_object in &other.deleted_objects.objects {
            if new_deleted_objects.contains(deleted_object.uuid) {
                continue;
            }
            deleted_groups_queue.push_back(deleted_object.clone());
        }

        while !deleted_groups_queue.is_empty() {
            let deleted_object = deleted_groups_queue.pop_front().unwrap();
            if new_deleted_objects.contains(deleted_object.uuid) {
                continue;
            }
            let group_location = match self.find_node_location(deleted_object.uuid) {
                Some(l) => l,
                None => continue,
            };

            let parent_group = match self.root.find_group_mut(&group_location) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(group_location)),
            };

            let group = match parent_group.find_group(&[deleted_object.uuid]) {
                Some(e) => e,
                None => {
                    // The node might be an entry, since we didn't necessarily removed all the
                    // entries that were in the deleted objects of the source database.
                    continue;
                }
            };

            // Not deleting a group if it still has entries.
            if !group.entries().is_empty() {
                continue;
            }

            // This group still has a child group that might get deleted in the future, so we delay
            // decision to delete it or not.
            if !group
                .groups()
                .iter()
                .filter(|g| !is_in_deleted_queue(g.uuid, &deleted_groups_queue))
                .collect::<Vec<_>>()
                .is_empty()
            {
                deleted_groups_queue.push_back(deleted_object.clone());
                continue;
            }

            // This group still a groups that won't be deleted, so we don't delete it.
            if !group.groups().is_empty() {
                continue;
            }

            let group_last_modification = match group.times.get_last_modification() {
                Some(t) => *t,
                None => {
                    log.warnings.push(format!(
                        "Group {} did not have a last modification timestamp",
                        group.uuid
                    ));
                    Times::now()
                }
            };

            if group_last_modification < deleted_object.deletion_time {
                parent_group.remove_node(&deleted_object.uuid)?;
                log.events.push(MergeEvent {
                    event_type: MergeEventType::GroupDeleted,
                    node_uuid: deleted_object.uuid,
                });

                new_deleted_objects.objects.push(deleted_object.clone());
            }
        }

        self.deleted_objects = new_deleted_objects;
        Ok(log)
    }

    pub(crate) fn find_node_location(&self, id: Uuid) -> Option<NodeLocation> {
        for node in &self.root.children {
            match node {
                Node::Entry(e) => {
                    if e.uuid == id {
                        return Some(vec![]);
                    }
                }
                Node::Group(g) => {
                    if g.uuid == id {
                        return Some(vec![]);
                    }
                    if let Some(location) = g.find_node_location(id) {
                        return Some(location);
                    }
                }
            }
        }
        None
    }

    fn merge_group(
        &mut self,
        current_group_path: NodeLocation,
        current_group: &Group,
        is_in_deleted_group: bool,
    ) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();

        if let Some(destination_group_location) = self.find_node_location(current_group.uuid) {
            let mut destination_group_path = destination_group_location.clone();
            destination_group_path.push(current_group.uuid);
            let destination_group = match self.root.find_group_mut(&destination_group_path) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(destination_group_path)),
            };
            let group_update_merge_events = destination_group.merge_with(current_group)?;
            log.append(&group_update_merge_events);
        }

        for other_entry in &current_group.entries() {
            // find the existing location
            let destination_entry_location = self.find_node_location(other_entry.uuid);

            // The group already exists in the destination database.
            if let Some(destination_entry_location) = destination_entry_location {
                let mut existing_entry_location = destination_entry_location.clone();
                existing_entry_location.push(other_entry.uuid);

                // The entry already exists but is not at the right location. We might have to
                // relocate it.
                let mut existing_entry = self.root.find_entry(&existing_entry_location).unwrap().clone();

                // The entry already exists but is not at the right location. We might have to
                // relocate it.
                if current_group_path.last() != destination_entry_location.last() && !is_in_deleted_group {
                    let source_location_changed_time = match other_entry.times.get_location_changed() {
                        Some(t) => *t,
                        None => {
                            log.warnings.push(format!(
                                "Entry {} did not have a location updated timestamp",
                                other_entry.uuid
                            ));
                            Times::epoch()
                        }
                    };
                    let destination_location_changed = match existing_entry.times.get_location_changed() {
                        Some(t) => *t,
                        None => {
                            log.warnings.push(format!(
                                "Entry {} did not have a location updated timestamp",
                                other_entry.uuid
                            ));
                            Times::now()
                        }
                    };
                    if source_location_changed_time > destination_location_changed {
                        log.events.push(MergeEvent {
                            event_type: MergeEventType::EntryLocationUpdated,
                            node_uuid: other_entry.uuid,
                        });
                        self.relocate_node(
                            &other_entry.uuid,
                            &destination_entry_location,
                            &current_group_path,
                            source_location_changed_time,
                        )?;
                        // Update the location of the current entry in case we have to update it
                        // after.
                        existing_entry_location = current_group_path.clone();
                        existing_entry_location.push(other_entry.uuid);
                        existing_entry
                            .times
                            .set_location_changed(source_location_changed_time);
                    }
                }

                if !existing_entry.has_diverged_from(other_entry) {
                    continue;
                }

                // The entry already exists and is at the right location, so we can proceed and merge
                // the two entries.
                let (merged_entry, entry_merge_log) = existing_entry.merge(other_entry)?;
                let merged_entry = match merged_entry {
                    Some(m) => m,
                    None => continue,
                };

                if existing_entry.eq(&merged_entry) {
                    continue;
                }

                let existing_entry = match self.root.find_entry_mut(&existing_entry_location) {
                    Some(e) => e,
                    None => return Err(MergeError::FindEntryError(existing_entry_location)),
                };
                *existing_entry = merged_entry.clone();

                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryUpdated,
                    node_uuid: merged_entry.uuid,
                });
                log.append(&entry_merge_log);
                continue;
            }

            if self.deleted_objects.contains(other_entry.uuid) {
                continue;
            }

            // We don't create new entries that exist under a deleted group.
            if is_in_deleted_group {
                continue;
            }

            // The entry doesn't exist in the destination, we create it
            let new_entry = other_entry.to_owned().clone();

            let new_entry_parent_group = match self.root.find_group_mut(&current_group_path) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(current_group_path)),
            };
            new_entry_parent_group.add_child(new_entry.clone());

            // TODO should we update the time info for the entry?
            log.events.push(MergeEvent {
                event_type: MergeEventType::EntryCreated,
                node_uuid: new_entry.uuid,
            });
        }

        for other_group in &current_group.groups() {
            let mut new_group_location = current_group_path.clone();
            let other_group_uuid = other_group.uuid;
            new_group_location.push(other_group_uuid);

            if self.deleted_objects.contains(other_group.uuid) || is_in_deleted_group {
                let new_merge_log = self.merge_group(new_group_location, other_group, true)?;
                log.append(&new_merge_log);
                continue;
            }

            let destination_group_location = self.find_node_location(other_group.uuid);

            // The group already exists in the destination database.
            if let Some(destination_group_location) = destination_group_location {
                if current_group_path != destination_group_location {
                    let mut existing_group_location = destination_group_location.clone();
                    existing_group_location.push(other_group_uuid);

                    // The group already exists but is not at the right location. We might have to
                    // relocate it.
                    let existing_group = self.root.find_group(&existing_group_location).unwrap();
                    let existing_group_location_changed = match existing_group.times.get_location_changed() {
                        Some(t) => *t,
                        None => {
                            log.warnings.push(format!(
                                "Entry {} did not have a location changed timestamp",
                                existing_group.uuid
                            ));
                            Times::now()
                        }
                    };
                    let other_group_location_changed = match other_group.times.get_location_changed() {
                        Some(t) => *t,
                        None => {
                            log.warnings.push(format!(
                                "Entry {} did not have a location changed timestamp",
                                other_group.uuid
                            ));
                            Times::epoch()
                        }
                    };
                    // The other group was moved after the current group, so we have to relocate it.
                    if existing_group_location_changed < other_group_location_changed {
                        self.relocate_node(
                            &other_group.uuid,
                            &destination_group_location,
                            &current_group_path,
                            other_group_location_changed,
                        )?;

                        log.events.push(MergeEvent {
                            event_type: MergeEventType::GroupLocationUpdated,
                            node_uuid: other_group.uuid,
                        });

                        let new_merge_log =
                            self.merge_group(new_group_location, other_group, is_in_deleted_group)?;
                        log.append(&new_merge_log);
                        continue;
                    }
                }

                // The group already exists and is at the right location, so we can proceed and merge
                // the two groups.
                let new_merge_log = self.merge_group(new_group_location, other_group, is_in_deleted_group)?;
                log.append(&new_merge_log);
                continue;
            }

            // The group doesn't exist in the destination, we create it
            let mut new_group = other_group.to_owned().clone();
            new_group.children = vec![];
            log.events.push(MergeEvent {
                event_type: MergeEventType::GroupCreated,
                node_uuid: new_group.uuid,
            });
            let new_group_parent_group = match self.root.find_group_mut(&current_group_path) {
                Some(g) => g,
                None => return Err(MergeError::FindGroupError(current_group_path)),
            };
            new_group_parent_group.add_child(new_group.clone());

            let new_merge_log = self.merge_group(new_group_location, other_group, is_in_deleted_group)?;
            log.append(&new_merge_log);
        }

        Ok(log)
    }

    fn relocate_node(
        &mut self,
        node_uuid: &Uuid,
        from: &NodeLocation,
        to: &NodeLocation,
        new_location_changed_timestamp: NaiveDateTime,
    ) -> Result<(), MergeError> {
        let source_group = match self.root.find_group_mut(from) {
            Some(g) => g,
            None => return Err(MergeError::FindGroupError(from.to_vec())),
        };

        let mut relocated_node = source_group.remove_node(node_uuid)?;
        match relocated_node {
            Node::Group(ref mut g) => g.times.set_location_changed(new_location_changed_timestamp),
            Node::Entry(ref mut e) => e.times.set_location_changed(new_location_changed_timestamp),
        };

        let destination_group = match self.root.find_group_mut(to) {
            Some(g) => g,
            None => return Err(MergeError::FindGroupError(to.to_vec())),
        };
        destination_group.children.push(relocated_node);
        Ok(())
    }
}

impl Group {
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

        Err(MergeError::GenericError(format!(
            "Could not find node {} in group {}.",
            uuid, self.name
        )))
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
            if self.has_diverged_from(other) {
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
        self.icon_id = other.icon_id;
        self.custom_icon_uuid = other.custom_icon_uuid;
        self.custom_data = other.custom_data.clone();

        // The location changed timestamp is handled separately when merging two databases.
        let current_times = self.times.clone();
        self.times = other.times.clone();
        if let Some(t) = current_times.get_location_changed() {
            self.times.set_location_changed(*t);
        }

        self.is_expanded = other.is_expanded;
        self.default_autotype_sequence = other.default_autotype_sequence.clone();
        self.enable_autotype = other.enable_autotype.clone();
        self.enable_searching = other.enable_searching.clone();
        self.last_top_visible_entry = other.last_top_visible_entry;

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

    pub(crate) fn find_group(&self, path: &[Uuid]) -> Option<&Group> {
        let path: Vec<String> = path.iter().map(|p| p.to_string()).collect();
        let node_ref = self.get_by_uuid(&path)?;
        match node_ref {
            NodeRef::Group(g) => Some(g),
            NodeRef::Entry(_) => None,
        }
    }

    pub(crate) fn find_entry(&self, path: &[Uuid]) -> Option<&Entry> {
        let path: Vec<String> = path.iter().map(|p| p.to_string()).collect();
        let node_ref = self.get_by_uuid(&path)?;
        match node_ref {
            NodeRef::Entry(e) => Some(e),
            NodeRef::Group(_) => None,
        }
    }

    pub(crate) fn find_entry_mut(&mut self, path: &[Uuid]) -> Option<&mut Entry> {
        let path: Vec<String> = path.iter().map(|p| p.to_string()).collect();
        let node_ref = self.get_by_uuid_mut(&path)?;
        match node_ref {
            NodeRefMut::Entry(e) => Some(e),
            NodeRefMut::Group(_) => None,
        }
    }

    pub(crate) fn find_group_mut(&mut self, path: &[Uuid]) -> Option<&mut Group> {
        let path: Vec<String> = path.iter().map(|p| p.to_string()).collect();
        let node_ref = self.get_by_uuid_mut(&path)?;
        match node_ref {
            NodeRefMut::Group(g) => Some(g),
            NodeRefMut::Entry(_) => None,
        }
    }
}

impl Entry {
    pub(crate) fn merge(&self, other: &Entry) -> Result<(Option<Entry>, MergeLog), MergeError> {
        let mut log = MergeLog::default();

        let source_last_modification = match other.times.get_last_modification() {
            Some(t) => *t,
            None => {
                log.warnings.push(format!(
                    "Entry {} did not have a last modification timestamp",
                    other.uuid
                ));
                Times::epoch()
            }
        };
        let destination_last_modification = match self.times.get_last_modification() {
            Some(t) => *t,
            None => {
                log.warnings.push(format!(
                    "Entry {} did not have a last modification timestamp",
                    self.uuid
                ));
                Times::now()
            }
        };

        if destination_last_modification == source_last_modification {
            if !self.has_diverged_from(other) {
                // This should never happen.
                // This means that an entry was updated without updating the last modification
                // timestamp.
                return Err(MergeError::EntryModificationTimeNotUpdated(
                    other.uuid.to_string(),
                ));
            }
            return Ok((None, log));
        }

        let (mut merged_entry, entry_merge_log) = match destination_last_modification > source_last_modification
        {
            true => self.merge_history(other)?,
            false => other.clone().merge_history(self)?,
        };

        // The location changed timestamp is handled separately when merging two databases.
        if let Some(location_changed_timestamp) = self.times.get_location_changed() {
            merged_entry
                .times
                .set_location_changed(*location_changed_timestamp);
        }

        Ok((Some(merged_entry), entry_merge_log))
    }

    pub(crate) fn merge_history(&self, other: &Entry) -> Result<(Entry, MergeLog), MergeError> {
        let mut log = MergeLog::default();

        let mut source_history = match &other.history {
            Some(h) => h.clone(),
            None => {
                log.warnings.push(format!(
                    "Entry {} from source database had no history.",
                    self.uuid
                ));
                History::default()
            }
        };
        let mut destination_history = match &self.history {
            Some(h) => h.clone(),
            None => {
                log.warnings.push(format!(
                    "Entry {} from destination database had no history.",
                    self.uuid
                ));
                History::default()
            }
        };
        let mut response = self.clone();

        if other.has_uncommitted_changes() {
            log.warnings.push(format!(
                "Entry {} from source database has uncommitted changes.",
                self.uuid
            ));
            source_history.add_entry(other.clone());
        }

        // TODO we should probably check for uncommitted changes in the destination
        // database here too for consistency.

        let history_merge_log = destination_history.merge_with(&source_history)?;
        response.history = Some(destination_history);

        Ok((response, log.merge_with(&history_merge_log)))
    }

    // Convenience function used in unit tests, to make sure that:
    // 1. The history gets updated after changing a field
    // 2. We wait a second before committing the changes so that the timestamp is not the same
    //    as it previously was. This is necessary since the timestamps in the KDBX format
    //    do not preserve the msecs.
    #[cfg(test)]
    pub(crate) fn set_field_and_commit(&mut self, field_name: &str, field_value: &str) {
        use crate::db::Value;

        self.fields.insert(
            field_name.to_string(),
            Value::Unprotected(field_value.to_string()),
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
        self.update_history();
    }

    // Convenience function used in when merging two entries
    pub(crate) fn has_diverged_from(&self, other_entry: &Entry) -> bool {
        let new_times = Times::default();

        let mut self_without_times = self.clone();
        self_without_times.times = new_times.clone();

        let mut other_without_times = other_entry.clone();
        other_without_times.times = new_times.clone();

        !self_without_times.eq(&other_without_times)
    }
}

impl History {
    // Determines if the entries of the history are
    // ordered by last modification time.
    #[cfg(test)]
    pub(crate) fn is_ordered(&self) -> bool {
        let mut last_modification_time: Option<&chrono::NaiveDateTime> = None;
        for entry in &self.entries {
            if last_modification_time.is_none() {
                last_modification_time = entry.times.get_last_modification();
            }

            let entry_modification_time = entry.times.get_last_modification().unwrap();
            // FIXME should we also handle equal modification times??
            if last_modification_time.unwrap() < entry_modification_time {
                return false;
            }
            last_modification_time = Some(entry_modification_time);
        }
        true
    }

    // Merge both histories together.
    pub(crate) fn merge_with(&mut self, other: &History) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();
        let mut new_history_entries: HashMap<chrono::NaiveDateTime, Entry> = HashMap::new();

        for history_entry in &self.entries {
            let modification_time = history_entry.times.get_last_modification().unwrap();
            if new_history_entries.contains_key(modification_time) {
                return Err(MergeError::DuplicateHistoryEntries(
                    modification_time.to_string(),
                    history_entry.uuid.to_string(),
                ));
            }
            new_history_entries.insert(*modification_time, history_entry.clone());
        }

        for history_entry in &other.entries {
            let modification_time = history_entry.times.get_last_modification().unwrap();
            let existing_history_entry = new_history_entries.get(modification_time);
            if let Some(existing_history_entry) = existing_history_entry {
                if existing_history_entry.has_diverged_from(history_entry) {
                    log.warnings.push(format!(
                        "History entries for {} have the same modification timestamp but were not the same.",
                        existing_history_entry.uuid
                    ));
                }
            } else {
                new_history_entries.insert(*modification_time, history_entry.clone());
            }
        }

        let mut all_modification_times: Vec<&chrono::NaiveDateTime> = new_history_entries.keys().collect();
        all_modification_times.sort();
        all_modification_times.reverse();
        let mut new_entries: Vec<Entry> = vec![];
        for modification_time in &all_modification_times {
            new_entries.push(new_history_entries.get(modification_time).unwrap().clone());
        }

        self.entries = new_entries;
        Ok(log)
    }
}

#[cfg(test)]
mod merge_tests {
    use std::{thread, time};
    use uuid::Uuid;

    use crate::db::{Entry, Group, Node, Times};
    use crate::Database;

    fn get_entry<'a>(db: &'a Database, path: &[&str]) -> &'a Entry {
        match db.root.get(path).unwrap() {
            crate::db::NodeRef::Entry(e) => e,
            crate::db::NodeRef::Group(_) => panic!("An entry was expected."),
        }
    }

    fn get_group_mut<'a>(db: &'a mut Database, path: &[&str]) -> &'a mut Group {
        match db.root.get_mut(path).unwrap() {
            crate::db::NodeRefMut::Group(g) => g,
            crate::db::NodeRefMut::Entry(_) => panic!("A group was expected."),
        }
    }

    fn get_group<'a>(db: &'a Database, path: &[&str]) -> &'a Group {
        match db.root.get(path).unwrap() {
            crate::db::NodeRef::Group(g) => g,
            crate::db::NodeRef::Entry(_) => panic!("A group was expected."),
        }
    }

    fn get_all_groups(group: &Group) -> Vec<&Group> {
        let mut response: Vec<&Group> = vec![];
        for node in &group.children {
            match node {
                Node::Group(g) => {
                    let mut new_groups = get_all_groups(g);
                    response.append(&mut new_groups);
                    response.push(g);
                }
                _ => continue,
            }
        }
        response
    }

    fn get_all_entries(group: &Group) -> Vec<&Entry> {
        let mut response: Vec<&Entry> = vec![];
        for node in &group.children {
            match node {
                Node::Group(g) => {
                    let mut new_entries = get_all_entries(g);
                    response.append(&mut new_entries);
                }
                Node::Entry(e) => {
                    response.push(e);
                }
            }
        }
        response
    }

    const ROOT_GROUP_ID: &str = "00000000-0000-0000-0000-000000000001";
    const GROUP1_ID: &str = "00000000-0000-0000-0000-000000000002";
    const GROUP2_ID: &str = "00000000-0000-0000-0000-000000000003";
    const SUBGROUP1_ID: &str = "00000000-0000-0000-0000-000000000004";
    const SUBGROUP2_ID: &str = "00000000-0000-0000-0000-000000000005";

    const ENTRY1_ID: &str = "00000000-0000-0000-0000-000000000006";
    const ENTRY2_ID: &str = "00000000-0000-0000-0000-000000000007";

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

        // Placing the first entry in the root group
        let mut entry1 = Entry::new();
        entry1.uuid = Uuid::parse_str(ENTRY1_ID).unwrap();
        entry1.set_field_and_commit("Title", "entry1");
        root_group.add_child(entry1);

        // Placing the second entry in a subgroup
        let mut entry2 = Entry::new();
        entry2.uuid = Uuid::parse_str(ENTRY2_ID).unwrap();
        entry2.set_field_and_commit("Title", "entry2");
        subgroup1.add_child(entry2);

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
        let source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_db.root.children.len(), 3);
        // The 2 groups should be exactly the same after merging, since
        // nothing was performed during the merge.
        assert_eq!(destination_db, source_db);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let entry = &mut destination_db.root.entries_mut()[0];
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

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let mut new_entry = Entry::new();
        new_entry.set_field_and_commit("Title", "new_entry");
        source_db.root.add_child(new_entry);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);

        let root_entries = destination_db.root.entries();
        assert_eq!(root_entries.len(), 2);

        let new_entry = get_entry(&destination_db, &["new_entry"]);
        assert_eq!(new_entry.get_title().unwrap(), "new_entry".to_string());

        // Merging the same group again should not create a duplicate entry.
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);
    }

    #[test]
    fn test_deleted_entry_in_destination() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let mut deleted_entry = Entry::new();
        let deleted_entry_uuid = deleted_entry.uuid;
        deleted_entry.set_field_and_commit("Title", "deleted_entry");
        source_db.root.add_child(deleted_entry);

        destination_db
            .deleted_objects
            .objects
            .push(crate::db::DeletedObject {
                uuid: deleted_entry_uuid,
                deletion_time: Times::now(),
            });

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let new_entry = destination_db.root.find_node_location(deleted_entry_uuid);
        assert!(new_entry.is_none());
    }

    #[test]
    fn test_updated_entry_under_deleted_group() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let mut modified_entry = Entry::new();
        modified_entry.set_field_and_commit("Title", "original_title");
        destination_db.root.add_child(modified_entry.clone());

        let mut deleted_group = Group::new("deleted_group");
        let deleted_group_uuid = deleted_group.uuid;
        let modified_entry_uuid = modified_entry.uuid;
        modified_entry.set_field_and_commit("Title", "modified_title");
        deleted_group.add_child(modified_entry);
        source_db.root.add_child(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        destination_db
            .deleted_objects
            .objects
            .push(crate::db::DeletedObject {
                uuid: deleted_group_uuid,
                deletion_time: Times::now(),
            });

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let deleted_group = destination_db.root.find_node_location(deleted_group_uuid);
        assert!(deleted_group.is_none());

        let modified_entry_location = destination_db.root.find_node_location(modified_entry_uuid);
        assert!(modified_entry_location.is_some());

        let modified_entry = destination_db.root.find_entry(&[modified_entry_uuid]).unwrap();
        assert_eq!(modified_entry.get_title(), Some("modified_title"));
    }

    #[test]
    fn test_deleted_group_in_destination() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let deleted_group = Group::new("deleted_group");
        let deleted_group_uuid = deleted_group.uuid;
        source_db.root.add_child(deleted_group);

        destination_db
            .deleted_objects
            .objects
            .push(crate::db::DeletedObject {
                uuid: deleted_group_uuid,
                deletion_time: Times::now(),
            });

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let deleted_group = destination_db.root.find_node_location(deleted_group_uuid);
        assert!(deleted_group.is_none());
    }

    #[test]
    fn test_deleted_entry_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let mut deleted_entry = Entry::new();
        let deleted_entry_uuid = deleted_entry.uuid;
        deleted_entry.set_field_and_commit("Title", "deleted_entry");
        destination_db.root.add_child(deleted_entry);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        thread::sleep(time::Duration::from_secs(1));
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_entry_uuid,
            deletion_time: Times::now(),
        });

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before);

        let new_entry = destination_db.root.find_node_location(deleted_entry_uuid);
        assert!(new_entry.is_none());

        assert!(destination_db.deleted_objects.contains(deleted_entry_uuid));
    }

    #[test]
    fn test_deleted_group_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let deleted_group = Group::new("deleted_group");
        let deleted_group_uuid = deleted_group.uuid;
        destination_db.root.add_child(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        thread::sleep(time::Duration::from_secs(1));
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_group_uuid,
            deletion_time: Times::now(),
        });

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before - 1);

        let deleted_group = destination_db.root.find_node_location(deleted_group_uuid);
        assert!(deleted_group.is_none());

        assert!(destination_db.deleted_objects.contains(deleted_group_uuid));
    }

    #[test]
    fn test_deleted_entry_in_source_modified_in_destination() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let deleted_entry_uuid = Uuid::new_v4();

        thread::sleep(time::Duration::from_secs(1));
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_entry_uuid,
            deletion_time: Times::now(),
        });

        thread::sleep(time::Duration::from_secs(1));
        let mut deleted_entry = Entry::new();
        deleted_entry.uuid = deleted_entry_uuid;
        deleted_entry.set_field_and_commit("Title", "deleted_entry");
        destination_db.root.add_child(deleted_entry);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let new_entry = destination_db.root.find_node_location(deleted_entry_uuid);
        assert!(new_entry.is_some());

        assert!(!destination_db.deleted_objects.contains(deleted_entry_uuid));
    }

    #[test]
    fn test_group_subtree_deletion() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let deleted_entry_uuid = Uuid::new_v4();
        let deleted_group_uuid = Uuid::new_v4();
        let deleted_subgroup_uuid = Uuid::new_v4();

        thread::sleep(time::Duration::from_secs(1));
        let mut deleted_entry = Entry::new();
        deleted_entry.uuid = deleted_entry_uuid;
        deleted_entry.set_field_and_commit("Title", "deleted_entry");

        let mut deleted_subgroup = Group::new("deleted_subgroup");
        deleted_subgroup.uuid = deleted_subgroup_uuid;
        deleted_subgroup.add_child(deleted_entry);

        let mut deleted_group = Group::new("deleted_group");
        deleted_group.uuid = deleted_group_uuid;
        deleted_group.add_child(deleted_subgroup);

        destination_db.root.add_child(deleted_group);

        thread::sleep(time::Duration::from_secs(1));
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_entry_uuid,
            deletion_time: Times::now(),
        });
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_subgroup_uuid,
            deletion_time: Times::now(),
        });
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_group_uuid,
            deletion_time: Times::now(),
        });

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 3);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before - 2);

        let deleted_entry = destination_db.root.find_node_location(deleted_entry_uuid);
        assert!(deleted_entry.is_none());
        let deleted_subgroup = destination_db.root.find_node_location(deleted_subgroup_uuid);
        assert!(deleted_subgroup.is_none());
        let deleted_group = destination_db.root.find_node_location(deleted_group_uuid);
        assert!(deleted_group.is_none());

        assert!(destination_db.deleted_objects.contains(deleted_entry_uuid));
        assert!(destination_db.deleted_objects.contains(deleted_subgroup_uuid));
        assert!(destination_db.deleted_objects.contains(deleted_group_uuid));
    }

    #[test]
    fn test_group_subtree_partial_deletion() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let deleted_entry_uuid = Uuid::new_v4();
        let deleted_group_uuid = Uuid::new_v4();
        let deleted_subgroup_uuid = Uuid::new_v4();

        thread::sleep(time::Duration::from_secs(1));
        let mut deleted_entry = Entry::new();
        deleted_entry.uuid = deleted_entry_uuid;
        deleted_entry.set_field_and_commit("Title", "deleted_entry");

        let mut deleted_subgroup = Group::new("deleted_subgroup");
        deleted_subgroup.uuid = deleted_subgroup_uuid;
        deleted_subgroup.add_child(deleted_entry);

        thread::sleep(time::Duration::from_secs(1));
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_entry_uuid,
            deletion_time: Times::now(),
        });
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_subgroup_uuid,
            deletion_time: Times::now(),
        });
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_group_uuid,
            deletion_time: Times::now(),
        });

        thread::sleep(time::Duration::from_secs(1));
        let mut deleted_group = Group::new("deleted_group");
        deleted_group.uuid = deleted_group_uuid;
        deleted_group.add_child(deleted_subgroup);

        destination_db.root.add_child(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before - 1);

        let deleted_entry = destination_db.root.find_node_location(deleted_entry_uuid);
        assert!(deleted_entry.is_none());
        let deleted_subgroup = destination_db.root.find_node_location(deleted_subgroup_uuid);
        assert!(deleted_subgroup.is_none());
        let deleted_group = destination_db.root.find_node_location(deleted_group_uuid);
        assert!(deleted_group.is_some());

        assert!(destination_db.deleted_objects.contains(deleted_entry_uuid));
        assert!(destination_db.deleted_objects.contains(deleted_subgroup_uuid));
        assert!(!destination_db.deleted_objects.contains(deleted_group_uuid));
    }

    #[test]
    fn test_deleted_group_in_source_modified_in_destination() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let deleted_group_uuid = Uuid::new_v4();

        thread::sleep(time::Duration::from_secs(1));
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_group_uuid,
            deletion_time: Times::now(),
        });

        thread::sleep(time::Duration::from_secs(1));
        let mut deleted_group = Group::new("deleted_group");
        deleted_group.uuid = deleted_group_uuid;
        destination_db.root.add_child(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let deleted_group = destination_db.root.find_node_location(deleted_group_uuid);
        assert!(deleted_group.is_some());

        assert!(!destination_db.deleted_objects.contains(deleted_group_uuid));
    }

    #[test]
    fn test_deleted_group_has_new_entries() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let mut deleted_group = Group::new("deleted_group");
        let deleted_group_uuid = deleted_group.uuid;

        let mut new_entry = Entry::new();
        let new_entry_uuid = new_entry.uuid;
        new_entry.set_field_and_commit("Title", "new_entry");
        deleted_group.add_child(new_entry);
        destination_db.root.add_child(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        thread::sleep(time::Duration::from_secs(1));
        source_db.deleted_objects.objects.push(crate::db::DeletedObject {
            uuid: deleted_group_uuid,
            deletion_time: Times::now(),
        });

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let deleted_group = destination_db.root.find_node_location(deleted_group_uuid);
        assert!(deleted_group.is_some());
        let new_entry = destination_db.root.find_node_location(new_entry_uuid);
        assert!(new_entry.is_some());

        assert!(!destination_db.deleted_objects.contains(deleted_group_uuid));
        assert!(!destination_db.deleted_objects.contains(new_entry_uuid));
    }

    #[test]
    fn test_add_new_non_root_entry() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let source_sub_group = &mut source_db.root.groups_mut()[0];

        let mut new_entry = Entry::new();
        let new_entry_uuid = new_entry.uuid;
        new_entry.set_field_and_commit("Title", "new_entry");
        source_sub_group.add_child(new_entry);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);

        let created_entry_location = destination_db.root.find_node_location(new_entry_uuid).unwrap();
        assert_eq!(created_entry_location.len(), 2);
    }

    #[test]
    fn test_add_new_entry_new_group() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let group_count_before = get_all_groups(&destination_db.root).len();
        let entry_count_before = get_all_entries(&destination_db.root).len();

        let mut source_group = Group::new("new_group");
        let mut source_sub_group = Group::new("new_subgroup");

        let mut new_entry = Entry::new();
        let new_entry_uuid = new_entry.uuid;
        new_entry.set_field_and_commit("Title", "new_entry");
        source_sub_group.add_child(new_entry);
        source_group.add_child(source_sub_group);
        source_db.root.add_child(source_group);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 3);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before + 2);

        let created_entry_location = destination_db.root.find_node_location(new_entry_uuid).unwrap();
        assert_eq!(created_entry_location.len(), 3);
    }

    #[test]
    fn test_entry_relocation_existing_group() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let group_count_before = get_all_groups(&destination_db.root).len();
        let entry_count_before = get_all_entries(&destination_db.root).len();

        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();

        source_db
            .relocate_node(
                &Uuid::parse_str(ENTRY2_ID).unwrap(),
                &vec![
                    Uuid::parse_str(GROUP1_ID).unwrap(),
                    Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                ],
                &vec![Uuid::parse_str(GROUP2_ID).unwrap()],
                new_location_changed_timestamp,
            )
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        let moved_entry_location = destination_db
            .root
            .find_node_location(Uuid::parse_str(ENTRY2_ID).unwrap())
            .unwrap();
        assert_eq!(moved_entry_location.len(), 2);
        assert_eq!(&moved_entry_location[0].to_string(), ROOT_GROUP_ID);
        assert_eq!(&moved_entry_location[1].to_string(), GROUP2_ID);

        let moved_entry = get_entry(&destination_db, &["group2", "entry2"]);
        assert_eq!(
            *moved_entry.times.get_location_changed().unwrap(),
            new_location_changed_timestamp
        );
    }

    #[test]
    fn test_entry_relocation_and_update() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let group_count_before = get_all_groups(&destination_db.root).len();
        let entry_count_before = get_all_entries(&destination_db.root).len();

        let entry2 = source_db
            .root
            .find_entry_mut(&[
                Uuid::parse_str(GROUP1_ID).unwrap(),
                Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                Uuid::parse_str(ENTRY2_ID).unwrap(),
            ])
            .unwrap();
        entry2.set_field_and_commit("Title", "entry2_modified_in_source");

        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();
        source_db
            .relocate_node(
                &Uuid::parse_str(ENTRY2_ID).unwrap(),
                &vec![
                    Uuid::parse_str(GROUP1_ID).unwrap(),
                    Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                ],
                &vec![Uuid::parse_str(GROUP2_ID).unwrap()],
                new_location_changed_timestamp,
            )
            .unwrap();

        let entry2 = destination_db
            .root
            .find_entry_mut(&[
                Uuid::parse_str(GROUP1_ID).unwrap(),
                Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                Uuid::parse_str(ENTRY2_ID).unwrap(),
            ])
            .unwrap();
        entry2.set_field_and_commit("Title", "entry2_modified_in_destination");
        let entry_modified_timestamp = *entry2.times.get_last_modification().unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        let moved_entry_location = destination_db
            .root
            .find_node_location(Uuid::parse_str(ENTRY2_ID).unwrap())
            .unwrap();
        assert_eq!(moved_entry_location.len(), 2);
        assert_eq!(&moved_entry_location[0].to_string(), ROOT_GROUP_ID);
        assert_eq!(&moved_entry_location[1].to_string(), GROUP2_ID);

        let moved_entry = get_entry(&destination_db, &["group2", "entry2_modified_in_destination"]);
        assert_eq!(
            *moved_entry.times.get_last_modification().unwrap(),
            entry_modified_timestamp,
        );
        assert_eq!(
            *moved_entry.times.get_location_changed().unwrap(),
            new_location_changed_timestamp
        );
    }

    #[test]
    fn test_entry_relocation_in_destination_and_update() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let group_count_before = get_all_groups(&destination_db.root).len();
        let entry_count_before = get_all_entries(&destination_db.root).len();

        let entry2 = source_db
            .root
            .find_entry_mut(&[
                Uuid::parse_str(GROUP1_ID).unwrap(),
                Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                Uuid::parse_str(ENTRY2_ID).unwrap(),
            ])
            .unwrap();
        entry2.set_field_and_commit("Title", "entry2_modified_in_source");
        let entry_modified_timestamp = *entry2.times.get_last_modification().unwrap();

        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();
        destination_db
            .relocate_node(
                &Uuid::parse_str(ENTRY2_ID).unwrap(),
                &vec![
                    Uuid::parse_str(GROUP1_ID).unwrap(),
                    Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                ],
                &vec![Uuid::parse_str(GROUP2_ID).unwrap()],
                new_location_changed_timestamp,
            )
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        let moved_entry_location = destination_db
            .root
            .find_node_location(Uuid::parse_str(ENTRY2_ID).unwrap())
            .unwrap();
        assert_eq!(moved_entry_location.len(), 2);
        assert_eq!(&moved_entry_location[0].to_string(), ROOT_GROUP_ID);
        assert_eq!(&moved_entry_location[1].to_string(), GROUP2_ID);

        let moved_entry = get_entry(&destination_db, &["group2", "entry2_modified_in_source"]);
        assert_eq!(
            *moved_entry.times.get_last_modification().unwrap(),
            entry_modified_timestamp,
        );
        assert_eq!(
            *moved_entry.times.get_location_changed().unwrap(),
            new_location_changed_timestamp
        );
    }

    #[test]
    fn test_entry_relocation_new_group() {
        let mut destination_db = create_test_database();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let mut source_db = destination_db.clone();
        let mut new_group = Group::new("new_group");
        let new_group_uuid = new_group.uuid;

        let mut new_entry = Entry::new();
        let entry_uuid = new_entry.uuid;
        new_entry.set_field_and_commit("Title", "entry1");

        thread::sleep(time::Duration::from_secs(1));
        new_entry.times.set_location_changed(Times::now());
        // FIXME we should not have to update the history here. We should
        // have a better compare function in the merge function instead.
        new_entry.update_history();
        new_group.add_child(new_entry.clone());
        source_db.root.add_child(new_group);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before + 1);

        let created_entry_location = destination_db.root.find_node_location(entry_uuid).unwrap();
        assert_eq!(created_entry_location.len(), 2);
        assert_eq!(&created_entry_location[0].to_string(), ROOT_GROUP_ID);
        assert_eq!(created_entry_location[1], new_group_uuid);
    }

    #[test]
    fn test_group_relocation() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let source_group_1 = get_group_mut(&mut source_db, &["group1"]);
        let mut source_sub_group_1 = match source_group_1
            .remove_node(&Uuid::parse_str(SUBGROUP1_ID).unwrap())
            .unwrap()
        {
            Node::Group(g) => g,
            _ => panic!("This should not happen."),
        };
        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();
        source_sub_group_1
            .times
            .set_location_changed(new_location_changed_timestamp);

        let source_group_2 = get_group_mut(&mut source_db, &["group2"]);
        source_group_2.add_child(source_sub_group_1);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let created_entry_location = destination_db
            .root
            .find_node_location(Uuid::parse_str(ENTRY2_ID).unwrap())
            .unwrap();
        assert_eq!(created_entry_location.len(), 3);
        assert_eq!(created_entry_location[0], destination_db.root.uuid);
        assert_eq!(&created_entry_location[1].to_string(), GROUP2_ID);
        assert_eq!(&created_entry_location[2].to_string(), SUBGROUP1_ID);

        let relocated_group = get_group(&destination_db, &["group2", "subgroup1"]);
        assert_eq!(
            *relocated_group.times.get_location_changed().unwrap(),
            new_location_changed_timestamp
        );
    }

    #[test]
    fn test_update_in_destination_no_conflict() {
        let mut destination_db = create_test_database();
        let source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let entry = &mut destination_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry = &mut destination_db.root.entries()[0];
        let merged_history = entry.history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 2);
        let merged_entry = &merged_history.entries[1];
        assert_eq!(merged_entry.get_title(), Some("entry1"));

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_in_source_no_conflict() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let entry = &mut source_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry = &mut destination_db.root.entries()[0];
        let merged_history = entry.history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 2);
        let merged_entry = &merged_history.entries[1];
        assert_eq!(merged_entry.get_title(), Some("entry1"));

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_with_conflicts() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let entry = &mut destination_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated_from_destination");

        let entry = &mut source_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated_from_source");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated_from_source"));

        let merged_history = entry.history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 3);
        let merged_entry = &merged_history.entries[1];
        assert_eq!(merged_entry.get_title(), Some("entry1_updated_from_destination"));

        // Merging again should not result in any additional change.
        let merge_result = destination_db.merge(&destination_db.clone()).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
    }

    #[test]
    fn test_group_update_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let group = get_group_mut(&mut source_db, &["group1", "subgroup1"]);
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group.times.set_last_modification(new_modification_timestamp);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let modified_group = get_group(&destination_db, &["group1", "subgroup1_updated_name"]);
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.get_last_modification(),
            Some(new_modification_timestamp).as_ref(),
        );
    }

    #[test]
    fn test_group_update_in_destination() {
        let mut destination_db = create_test_database();
        let source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let group = get_group_mut(&mut destination_db, &["group1", "subgroup1"]);
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group.times.set_last_modification(new_modification_timestamp);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let modified_group = get_group(&destination_db, &["group1", "subgroup1_updated_name"]);
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.get_last_modification(),
            Some(new_modification_timestamp).as_ref(),
        );
    }

    #[test]
    fn test_group_update_and_relocation() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let group = get_group_mut(&mut source_db, &["group1", "subgroup1"]);
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group.times.set_last_modification(new_modification_timestamp);

        source_db
            .relocate_node(
                &Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                &vec![Uuid::parse_str(GROUP1_ID).unwrap()],
                &vec![Uuid::parse_str(GROUP2_ID).unwrap()],
                new_modification_timestamp,
            )
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let modified_group = get_group(&destination_db, &["group2", "subgroup1_updated_name"]);
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.get_last_modification(),
            Some(new_modification_timestamp).as_ref(),
        );
    }

    #[test]
    fn test_group_update_in_destination_and_relocation_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let group = get_group_mut(&mut source_db, &["group1", "subgroup1"]);
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group.times.set_last_modification(new_modification_timestamp);

        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();
        destination_db
            .relocate_node(
                &Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                &vec![Uuid::parse_str(GROUP1_ID).unwrap()],
                &vec![Uuid::parse_str(GROUP2_ID).unwrap()],
                new_location_changed_timestamp,
            )
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let modified_group = get_group(&destination_db, &["group2", "subgroup1_updated_name"]);
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.get_last_modification(),
            Some(new_modification_timestamp).as_ref(),
        );
        assert_eq!(
            modified_group.times.get_location_changed(),
            Some(new_location_changed_timestamp).as_ref(),
        );
    }
}
