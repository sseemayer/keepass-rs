use std::collections::{HashMap, VecDeque};

use crate::db::{Database, Entry, Group, History, Times};
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

    #[error("Could not find group {0}")]
    FindGroupError(Uuid),

    #[error("Could not find entry {0}")]
    FindEntryError(Uuid),

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

impl Database {
    /// Merge this database with another version of this same database.
    /// This function will use the UUIDs to detect that entries and groups are
    /// the same.
    pub fn merge(&mut self, other: &Database) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();
        log.append(&self.merge_group(&other.root, false)?);
        log.append(&self.merge_deletions(other)?);
        Ok(log)
    }

    fn merge_deletions(&mut self, other: &Database) -> Result<MergeLog, MergeError> {
        // Utility function to search for a UUID in the VecDeque of deleted objects.
        let is_in_deleted_queue =
            |uuid: Uuid, deleted_groups_queue: &VecDeque<(Uuid, Option<NaiveDateTime>)>| -> bool {
                for (deleted_uuid, _) in deleted_groups_queue {
                    // This group still has a child group, but it is not going to be deleted.
                    if *deleted_uuid == uuid {
                        return true;
                    }
                }
                false
            };

        let mut log = MergeLog::default();

        let mut new_deleted_objects = self.deleted_objects.clone();

        // We start by deleting the entries, since we will only remove groups if they are empty.
        for (&other_uuid, &other_time) in &other.deleted_objects {
            if new_deleted_objects.contains_key(&other_uuid) {
                continue;
            }

            let Some(entry) = self.root.entry_by_uuid(other_uuid) else {
                // This uuid might refer to a group, which will be handled later.
                continue;
            };

            let parent_uuid = self
                .root
                .find_entry_parent(other_uuid)
                .ok_or(MergeError::FindEntryError(other_uuid))?;

            let entry_last_modification = match entry.times.last_modification {
                Some(t) => t,
                None => {
                    log.warnings.push(format!(
                        "Entry {} did not have a last modification timestamp",
                        entry.uuid
                    ));
                    Times::now()
                }
            };

            let other_time = other_time.unwrap_or_else(|| {
                log.warnings.push(format!(
                    "Entry {} did not have a last modification timestamp",
                    other_uuid
                ));
                Times::epoch()
            });

            let parent_group = self
                .root
                .group_by_uuid_mut(parent_uuid)
                .ok_or(MergeError::FindGroupError(parent_uuid))?;

            if entry_last_modification < other_time {
                parent_group.remove_entry(other_uuid)?;
                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryDeleted,
                    node_uuid: other_uuid,
                });

                new_deleted_objects.insert(other_uuid, Some(other_time));
            }
        }

        let mut deleted_groups_queue: VecDeque<(Uuid, Option<NaiveDateTime>)> = VecDeque::new();
        for (&deleted_uuid, &deleted_time) in &other.deleted_objects {
            if new_deleted_objects.contains_key(&deleted_uuid) {
                continue;
            }
            deleted_groups_queue.push_back((deleted_uuid, deleted_time));
        }

        while !deleted_groups_queue.is_empty() {
            let (deleted_uuid, deleted_time) = deleted_groups_queue.pop_front().unwrap();
            if new_deleted_objects.contains_key(&deleted_uuid) {
                continue;
            }

            let Some(parent_uuid) = self.root.find_group_parent(deleted_uuid) else {
                // The node might be an entry, since we didn't necessarily removed all the
                // entries that were in the deleted objects of the source database.
                continue;
            };

            let Some(group) = self.root.group_by_uuid_mut(deleted_uuid) else {
                // The node might be an entry, since we didn't necessarily removed all the
                // entries that were in the deleted objects of the source database.
                continue;
            };

            // Not deleting a group if it still has entries.
            if !group.entries.is_empty() {
                continue;
            }

            // This group still has a child group that might get deleted in the future, so we delay
            // decision to delete it or not.
            if !group
                .groups
                .iter()
                .filter(|g| is_in_deleted_queue(g.uuid, &deleted_groups_queue))
                .collect::<Vec<_>>()
                .is_empty()
            {
                deleted_groups_queue.push_back((deleted_uuid, deleted_time));
                continue;
            }

            // This group still a groups that won't be deleted, so we don't delete it.
            if !group.groups.is_empty() {
                continue;
            }

            let group_last_modification = match group.times.last_modification {
                Some(t) => t,
                None => {
                    log.warnings.push(format!(
                        "Group {} did not have a last modification timestamp",
                        group.uuid
                    ));
                    Times::now()
                }
            };

            let deleted_time = deleted_time.unwrap_or_else(|| {
                log.warnings.push(format!(
                    "Group {} did not have a deletion timestamp",
                    deleted_uuid
                ));
                Times::epoch()
            });

            if group_last_modification < deleted_time {
                let parent_group = self
                    .root
                    .group_by_uuid_mut(parent_uuid)
                    .ok_or(MergeError::FindGroupError(parent_uuid))?;

                parent_group.remove_group(deleted_uuid)?;
                log.events.push(MergeEvent {
                    event_type: MergeEventType::GroupDeleted,
                    node_uuid: deleted_uuid,
                });

                new_deleted_objects.insert(deleted_uuid, Some(deleted_time));
            }
        }

        self.deleted_objects = new_deleted_objects;
        Ok(log)
    }

    fn merge_group(
        &mut self,
        current_group: &Group,
        is_in_deleted_group: bool,
    ) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();

        // shallow merge the current group's data
        if let Some(destination_group) = self.root.group_by_uuid_mut(current_group.uuid) {
            let group_update_merge_events = destination_group.merge_with(current_group)?;
            log.append(&group_update_merge_events);
        }

        // merge entries by iterating over entries in source (aka current_group)
        for other_entry in &current_group.entries {
            // does the entry exist in the destination database?
            if let Some(existing_entry) = self.root.entry_by_uuid(other_entry.uuid).cloned() {
                let existing_parent = self.root.find_entry_parent(other_entry.uuid).unwrap();
                let mut existing_time = existing_entry.times.location_changed.clone();

                // is the location of the entry the same in both databases?
                if current_group.uuid != existing_parent && !is_in_deleted_group {
                    // we might have to relocate the entry, but we first check timestamps

                    let source_location_changed =
                        other_entry.times.location_changed.clone().unwrap_or_else(|| {
                            log.warnings.push(format!(
                                "Entry {} did not have a location updated timestamp",
                                other_entry.uuid
                            ));
                            Times::epoch()
                        });

                    let destination_location_changed =
                        existing_entry.times.location_changed.clone().unwrap_or_else(|| {
                            log.warnings.push(format!(
                                "Entry {} did not have a location updated timestamp",
                                other_entry.uuid
                            ));
                            Times::now()
                        });

                    // check location change timestamps to see if we need to relocate the entry
                    if source_location_changed > destination_location_changed {
                        // The entry was moved in the source database after it was moved in the
                        // destination database, so we have to move it to the new location.

                        log.events.push(MergeEvent {
                            event_type: MergeEventType::EntryLocationUpdated,
                            node_uuid: other_entry.uuid,
                        });

                        self.relocate_entry(
                            other_entry.uuid,
                            existing_parent,
                            current_group.uuid,
                            source_location_changed,
                        )?;

                        existing_time = Some(source_location_changed);
                    }
                }

                // skip updating entry data if it still matches
                if !existing_entry.has_diverged_from(other_entry) {
                    continue;
                }

                let (merged_entry, entry_merge_log) = existing_entry.merge(other_entry)?;
                let Some(merged_entry) = merged_entry else {
                    continue;
                };

                if existing_entry == merged_entry {
                    continue;
                }

                let existing_entry = self.root.entry_by_uuid_mut(other_entry.uuid).unwrap();
                *existing_entry = merged_entry.clone();

                if let Some(et) = existing_time {
                    existing_entry.times.location_changed = Some(et);
                }

                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryUpdated,
                    node_uuid: merged_entry.uuid,
                });

                log.append(&entry_merge_log);

                // the entry is now merged, we can skip the rest of the loop which is for processing new entries
                continue;
            }

            if self.deleted_objects.contains_key(&other_entry.uuid) {
                continue;
            }

            // We don't create new entries that exist under a deleted group.
            if is_in_deleted_group {
                continue;
            }

            // The entry doesn't exist in the destination, we create it
            let new_entry = other_entry.to_owned().clone();

            let new_entry_parent_group = self
                .root
                .group_by_uuid_mut(current_group.uuid)
                .ok_or(MergeError::FindGroupError(current_group.uuid))?;

            new_entry_parent_group.entries.push(new_entry.clone());

            // TODO should we update the time info for the entry?
            log.events.push(MergeEvent {
                event_type: MergeEventType::EntryCreated,
                node_uuid: new_entry.uuid,
            });
        }

        // merge groups by iterating over groups in source (aka current_group)
        for other_group in &current_group.groups {
            if self.deleted_objects.contains_key(&other_group.uuid) || is_in_deleted_group {
                let new_merge_log = self.merge_group(other_group, true)?;
                log.append(&new_merge_log);
                continue;
            }

            // does the group exist in the destination database?
            if let Some(existing_group) = self.root.group_by_uuid(other_group.uuid) {
                let existing_parent = self.root.find_group_parent(other_group.uuid).unwrap();

                if current_group.uuid != existing_parent {
                    // we might have to relocate the entry, but we first check timestamps

                    let source_location_changed_time =
                        other_group.times.location_changed.clone().unwrap_or_else(|| {
                            log.warnings.push(format!(
                                "Group {} did not have a location updated timestamp",
                                other_group.uuid
                            ));
                            Times::epoch()
                        });

                    let destination_location_changed_time =
                        existing_group.times.location_changed.clone().unwrap_or_else(|| {
                            log.warnings.push(format!(
                                "Group {} did not have a location updated timestamp",
                                other_group.uuid
                            ));
                            Times::now()
                        });

                    // check location change timestamps to see if we need to relocate the group
                    if source_location_changed_time > destination_location_changed_time {
                        log.events.push(MergeEvent {
                            event_type: MergeEventType::GroupLocationUpdated,
                            node_uuid: other_group.uuid,
                        });

                        self.relocate_group(
                            other_group.uuid,
                            existing_parent,
                            current_group.uuid,
                            source_location_changed_time,
                        )?;
                    }
                }

                // the group is now in the correct location, we can merge it with the current group
                let new_merge_log = self.merge_group(other_group, is_in_deleted_group)?;
                log.append(&new_merge_log);

                // the group is now merged, we can skip the rest of the loop which is for processing new groups
                continue;
            }

            // The group doesn't exist in the destination, we create it
            let mut new_group = other_group.to_owned().clone();
            new_group.groups.clear();
            new_group.entries.clear();
            log.events.push(MergeEvent {
                event_type: MergeEventType::GroupCreated,
                node_uuid: new_group.uuid,
            });

            let new_group_parent_group = self
                .root
                .group_by_uuid_mut(current_group.uuid)
                .ok_or(MergeError::FindGroupError(current_group.uuid))?;

            new_group_parent_group.groups.push(new_group.clone());

            let new_merge_log = self.merge_group(other_group, is_in_deleted_group)?;
            log.append(&new_merge_log);
        }

        Ok(log)
    }

    fn relocate_entry(
        &mut self,
        entry_uuid: Uuid,
        from_parent: Uuid,
        to_parent: Uuid,
        new_location_changed_timestamp: NaiveDateTime,
    ) -> Result<(), MergeError> {
        let from_parent = self
            .root
            .group_by_uuid_mut(from_parent)
            .ok_or(MergeError::FindGroupError(from_parent))?;

        let mut relocated_entry = from_parent.remove_entry(entry_uuid)?;
        relocated_entry.times.location_changed = Some(new_location_changed_timestamp);

        let to_parent = self
            .root
            .group_by_uuid_mut(to_parent)
            .ok_or(MergeError::FindGroupError(to_parent))?;

        to_parent.entries.push(relocated_entry);

        Ok(())
    }

    fn relocate_group(
        &mut self,
        group_uuid: Uuid,
        from_parent: Uuid,
        to_parent: Uuid,
        new_location_changed_timestamp: NaiveDateTime,
    ) -> Result<(), MergeError> {
        let from_parent = self
            .root
            .group_by_uuid_mut(from_parent)
            .ok_or(MergeError::FindGroupError(from_parent))?;

        let mut relocated_group = from_parent.remove_group(group_uuid)?;
        relocated_group.times.location_changed = Some(new_location_changed_timestamp);

        let to_parent = self
            .root
            .group_by_uuid_mut(to_parent)
            .ok_or(MergeError::FindGroupError(to_parent))?;

        to_parent.groups.push(relocated_group);
        Ok(())
    }
}

impl Group {
    pub(crate) fn remove_entry(&mut self, uuid: Uuid) -> Result<Entry, MergeError> {
        for i in 0..self.entries.len() {
            if self.entries[i].uuid == uuid {
                return Ok(self.entries.remove(i));
            }
        }

        Err(MergeError::GenericError(format!(
            "Could not find entry {} in group {}.",
            uuid, self.name
        )))
    }

    pub(crate) fn remove_group(&mut self, uuid: Uuid) -> Result<Group, MergeError> {
        for i in 0..self.groups.len() {
            if self.groups[i].uuid == uuid {
                return Ok(self.groups.remove(i));
            }

            if let Ok(removed_group) = self.groups[i].remove_group(uuid) {
                return Ok(removed_group);
            }
        }

        Err(MergeError::GenericError(format!(
            "Could not find group {} in group {}.",
            uuid, self.name
        )))
    }

    pub(crate) fn find_entry_parent(&self, entry_uuid: Uuid) -> Option<Uuid> {
        for entry in &self.entries {
            if entry.uuid == entry_uuid {
                return Some(self.uuid);
            }
        }

        for group in &self.groups {
            if let Some(parent) = group.find_entry_parent(entry_uuid) {
                return Some(parent);
            }
        }

        None
    }

    pub(crate) fn find_group_parent(&self, group_uuid: Uuid) -> Option<Uuid> {
        for group in &self.groups {
            if group.uuid == group_uuid {
                return Some(self.uuid);
            }

            if let Some(parent) = group.find_group_parent(group_uuid) {
                return Some(parent);
            }
        }

        None
    }

    pub(crate) fn merge_with(&mut self, other: &Group) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();

        let source_last_modification = match other.times.last_modification {
            Some(t) => t,
            None => {
                log.warnings.push(format!(
                    "Group {} did not have a last modification timestamp",
                    self.uuid
                ));
                Times::epoch()
            }
        };
        let destination_last_modification = match self.times.last_modification {
            Some(t) => t,
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
        if let Some(t) = current_times.location_changed {
            self.times.location_changed = Some(t);
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
        self_purged.groups.clear();
        self_purged.entries.clear();

        let mut other_purged = other.clone();
        other_purged.times = new_times.clone();
        other_purged.groups.clear();
        other_purged.entries.clear();
        !self_purged.eq(&other_purged)
    }
}

impl Entry {
    pub(crate) fn merge(&self, other: &Entry) -> Result<(Option<Entry>, MergeLog), MergeError> {
        let mut log = MergeLog::default();

        let source_last_modification = match other.times.last_modification {
            Some(t) => t,
            None => {
                log.warnings.push(format!(
                    "Entry {} did not have a last modification timestamp",
                    other.uuid
                ));
                Times::epoch()
            }
        };
        let destination_last_modification = match self.times.last_modification {
            Some(t) => t,
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
        if let Some(location_changed_timestamp) = self.times.location_changed {
            merged_entry.times.location_changed = Some(location_changed_timestamp);
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
        self.set_unprotected(field_name, field_value);

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
        let mut last_modification_time: Option<chrono::NaiveDateTime> = None;
        for entry in &self.entries {
            if last_modification_time.is_none() {
                last_modification_time = entry.times.last_modification;
            }

            let entry_modification_time = entry.times.last_modification.unwrap();
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
            let modification_time = history_entry.times.last_modification.unwrap_or_else(|| {
                log.warnings.push(format!(
                    "Destination history entry {} did not have a last modification timestamp",
                    history_entry.uuid
                ));
                Times::epoch()
            });

            if new_history_entries.contains_key(&modification_time) {
                return Err(MergeError::DuplicateHistoryEntries(
                    modification_time.to_string(),
                    history_entry.uuid.to_string(),
                ));
            }
            new_history_entries.insert(modification_time, history_entry.clone());
        }

        for history_entry in &other.entries {
            let modification_time = history_entry.times.last_modification.unwrap();
            let existing_history_entry = new_history_entries.get(&modification_time);
            if let Some(existing_history_entry) = existing_history_entry {
                if existing_history_entry.has_diverged_from(history_entry) {
                    log.warnings.push(format!(
                        "History entries for {} have the same modification timestamp but were not the same.",
                        existing_history_entry.uuid
                    ));
                }
            } else {
                new_history_entries.insert(modification_time, history_entry.clone());
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
    use uuid::{uuid, Uuid};

    use crate::db::{fields, Entry, Group, Times};
    use crate::Database;

    fn get_all_groups(parent: &Group) -> Vec<&Group> {
        let mut response: Vec<&Group> = vec![];
        for child_group in &parent.groups {
            response.extend(get_all_groups(child_group));
            response.push(child_group);
        }
        response
    }

    fn get_all_entries(parent: &Group) -> Vec<&Entry> {
        let mut response: Vec<&Entry> = vec![];
        response.extend(parent.entries.iter());

        for child_group in &parent.groups {
            response.extend(get_all_entries(child_group));
        }

        response
    }

    const ROOT_GROUP_ID: Uuid = uuid!("00000000-0000-0000-0000-000000000001");
    const GROUP1_ID: Uuid = uuid!("00000000-0000-0000-0000-000000000002");
    const GROUP2_ID: Uuid = uuid!("00000000-0000-0000-0000-000000000003");
    const SUBGROUP1_ID: Uuid = uuid!("00000000-0000-0000-0000-000000000004");
    const SUBGROUP2_ID: Uuid = uuid!("00000000-0000-0000-0000-000000000005");

    const ENTRY1_ID: Uuid = uuid!("00000000-0000-0000-0000-000000000006");
    const ENTRY2_ID: Uuid = uuid!("00000000-0000-0000-0000-000000000007");

    /// Creates a test database with the following structure:
    /// - root
    ///  - entry1
    ///  - group1
    ///   - subgroup1
    ///    - entry2
    ///
    ///  - group2
    ///   - subgroup2
    fn create_test_database() -> Database {
        let mut db = Database::new(Default::default());
        let mut root_group = Group::new("root");
        root_group.uuid = ROOT_GROUP_ID;

        let mut group1 = Group::new("group1");
        group1.uuid = GROUP1_ID;
        let mut group2 = Group::new("group2");
        group2.uuid = GROUP2_ID;

        let mut subgroup1 = Group::new("subgroup1");
        subgroup1.uuid = SUBGROUP1_ID;
        let mut subgroup2 = Group::new("subgroup2");
        subgroup2.uuid = SUBGROUP2_ID;

        // Placing the first entry in the root group
        let mut entry1 = Entry::new();
        entry1.uuid = ENTRY1_ID;
        entry1.set_field_and_commit(fields::TITLE, "entry1");
        root_group.entries.push(entry1);

        // Placing the second entry in a subgroup
        let mut entry2 = Entry::new();
        entry2.uuid = ENTRY2_ID;
        entry2.set_field_and_commit(fields::TITLE, "entry2");
        subgroup1.entries.push(entry2);

        group1.groups.push(subgroup1);
        group2.groups.push(subgroup2);

        root_group.groups.push(group1);
        root_group.groups.push(group2);

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
        assert_eq!(destination_db.root.groups.len(), 2);
        assert_eq!(destination_db.root.entries.len(), 1);

        // The 2 groups should be exactly the same after merging, since
        // nothing was performed during the merge.
        assert_eq!(destination_db, source_db);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let entry = &mut destination_db.root.entries[0];
        entry.set_field_and_commit(fields::TITLE, "entry1_updated");

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
        new_entry.set_field_and_commit(fields::TITLE, "new_entry");
        source_db.root.entries.push(new_entry);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);

        assert_eq!(destination_db.root.entries.len(), 2);

        let new_entry = destination_db.root.entry_by_name("new_entry").unwrap();
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
        deleted_entry.set_field_and_commit(fields::TITLE, "deleted_entry");
        source_db.root.entries.push(deleted_entry);

        destination_db
            .deleted_objects
            .insert(deleted_entry_uuid, Some(Times::now()));

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let new_entry = destination_db.root.entry_by_uuid(deleted_entry_uuid);
        assert!(new_entry.is_none());
    }

    #[test]
    fn test_updated_entry_under_deleted_group() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let mut modified_entry = Entry::new();
        modified_entry.set_field_and_commit(fields::TITLE, "original_title");
        destination_db.root.entries.push(modified_entry.clone());

        let mut deleted_group = Group::new("deleted_group");
        let deleted_group_uuid = deleted_group.uuid;
        let modified_entry_uuid = modified_entry.uuid;
        modified_entry.set_field_and_commit(fields::TITLE, "modified_title");
        deleted_group.entries.push(modified_entry);
        source_db.root.groups.push(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        destination_db
            .deleted_objects
            .insert(deleted_group_uuid, Some(Times::now()));

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let deleted_group = destination_db.root.group_by_uuid(deleted_group_uuid);
        assert!(deleted_group.is_none());

        let modified_entry_location = destination_db.root.entry_by_uuid(modified_entry_uuid);
        assert!(modified_entry_location.is_some());

        let modified_entry = destination_db.root.entry_by_uuid(modified_entry_uuid).unwrap();
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
        source_db.root.groups.push(deleted_group);

        destination_db
            .deleted_objects
            .insert(deleted_group_uuid, Some(Times::now()));

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let deleted_group = destination_db.root.group_by_uuid(deleted_group_uuid);
        assert!(deleted_group.is_none());
    }

    #[test]
    fn test_deleted_entry_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let mut deleted_entry = Entry::new();
        let deleted_entry_uuid = deleted_entry.uuid;
        deleted_entry.set_field_and_commit(fields::TITLE, "deleted_entry");
        destination_db.root.entries.push(deleted_entry);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        thread::sleep(time::Duration::from_secs(1));
        source_db
            .deleted_objects
            .insert(deleted_entry_uuid, Some(Times::now()));

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before);

        let new_entry = destination_db.root.entry_by_uuid(deleted_entry_uuid);
        assert!(new_entry.is_none());

        assert!(destination_db.deleted_objects.contains_key(&deleted_entry_uuid));
    }

    #[test]
    fn test_deleted_group_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let deleted_group = Group::new("deleted_group");
        let deleted_group_uuid = deleted_group.uuid;
        destination_db.root.groups.push(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        thread::sleep(time::Duration::from_secs(1));
        source_db
            .deleted_objects
            .insert(deleted_group_uuid, Some(Times::now()));

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before - 1);

        let deleted_group = destination_db.root.group_by_uuid(deleted_group_uuid);
        assert!(deleted_group.is_none());

        assert!(destination_db.deleted_objects.contains_key(&deleted_group_uuid));
    }

    #[test]
    fn test_deleted_entry_in_source_modified_in_destination() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let deleted_entry_uuid = Uuid::new_v4();

        thread::sleep(time::Duration::from_secs(1));
        source_db
            .deleted_objects
            .insert(deleted_entry_uuid, Some(Times::now()));

        thread::sleep(time::Duration::from_secs(1));
        let mut deleted_entry = Entry::new();
        deleted_entry.uuid = deleted_entry_uuid;
        deleted_entry.set_field_and_commit(fields::TITLE, "deleted_entry");
        destination_db.root.entries.push(deleted_entry);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let new_entry = destination_db.root.entry_by_uuid(deleted_entry_uuid);
        assert!(new_entry.is_some());

        assert!(!destination_db.deleted_objects.contains_key(&deleted_entry_uuid));
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
        deleted_entry.set_field_and_commit(fields::TITLE, "deleted_entry");

        let mut deleted_subgroup = Group::new("deleted_subgroup");
        deleted_subgroup.uuid = deleted_subgroup_uuid;
        deleted_subgroup.entries.push(deleted_entry);

        let mut deleted_group = Group::new("deleted_group");
        deleted_group.uuid = deleted_group_uuid;
        deleted_group.groups.push(deleted_subgroup);

        destination_db.root.groups.push(deleted_group);

        thread::sleep(time::Duration::from_secs(1));
        source_db
            .deleted_objects
            .insert(deleted_entry_uuid, Some(Times::now()));
        source_db
            .deleted_objects
            .insert(deleted_subgroup_uuid, Some(Times::now()));
        source_db
            .deleted_objects
            .insert(deleted_group_uuid, Some(Times::now()));

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 3);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before - 2);

        let deleted_entry = destination_db.root.entry_by_uuid(deleted_entry_uuid);
        assert!(deleted_entry.is_none());
        let deleted_subgroup = destination_db.root.group_by_uuid(deleted_subgroup_uuid);
        assert!(deleted_subgroup.is_none());
        let deleted_group = destination_db.root.group_by_uuid(deleted_group_uuid);
        assert!(deleted_group.is_none());

        assert!(destination_db.deleted_objects.contains_key(&deleted_entry_uuid));
        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_subgroup_uuid));
        assert!(destination_db.deleted_objects.contains_key(&deleted_group_uuid));
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
        deleted_entry.set_field_and_commit(fields::TITLE, "deleted_entry");

        let mut deleted_subgroup = Group::new("deleted_subgroup");
        deleted_subgroup.uuid = deleted_subgroup_uuid;
        deleted_subgroup.entries.push(deleted_entry);

        thread::sleep(time::Duration::from_secs(1));
        source_db
            .deleted_objects
            .insert(deleted_entry_uuid, Some(Times::now()));
        source_db
            .deleted_objects
            .insert(deleted_subgroup_uuid, Some(Times::now()));
        source_db
            .deleted_objects
            .insert(deleted_group_uuid, Some(Times::now()));

        thread::sleep(time::Duration::from_secs(1));
        let mut deleted_group = Group::new("deleted_group");
        deleted_group.uuid = deleted_group_uuid;
        deleted_group.groups.push(deleted_subgroup);

        destination_db.root.groups.push(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before - 1);

        let deleted_entry = destination_db.root.entry_by_uuid(deleted_entry_uuid);
        assert!(deleted_entry.is_none());
        let deleted_subgroup = destination_db.root.group_by_uuid(deleted_subgroup_uuid);
        assert!(deleted_subgroup.is_none());
        let deleted_group = destination_db.root.group_by_uuid(deleted_group_uuid);
        assert!(deleted_group.is_some());

        assert!(destination_db.deleted_objects.contains_key(&deleted_entry_uuid));
        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_subgroup_uuid));
        assert!(!destination_db.deleted_objects.contains_key(&deleted_group_uuid));
    }

    #[test]
    fn test_deleted_group_in_source_modified_in_destination() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let deleted_group_uuid = Uuid::new_v4();

        thread::sleep(time::Duration::from_secs(1));
        source_db
            .deleted_objects
            .insert(deleted_group_uuid, Some(Times::now()));

        thread::sleep(time::Duration::from_secs(1));
        let mut deleted_group = Group::new("deleted_group");
        deleted_group.uuid = deleted_group_uuid;
        destination_db.root.groups.push(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let deleted_group = destination_db.root.group_by_uuid(deleted_group_uuid);
        assert!(deleted_group.is_some());

        assert!(!destination_db.deleted_objects.contains_key(&deleted_group_uuid));
    }

    #[test]
    fn test_deleted_group_has_new_entries() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let mut deleted_group = Group::new("deleted_group");
        let deleted_group_uuid = deleted_group.uuid;

        let mut new_entry = Entry::new();
        let new_entry_uuid = new_entry.uuid;
        new_entry.set_field_and_commit(fields::TITLE, "new_entry");
        deleted_group.entries.push(new_entry);
        destination_db.root.groups.push(deleted_group);

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        thread::sleep(time::Duration::from_secs(1));
        source_db
            .deleted_objects
            .insert(deleted_group_uuid, Some(Times::now()));

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let deleted_group = destination_db.root.group_by_uuid(deleted_group_uuid);
        assert!(deleted_group.is_some());
        let new_entry = destination_db.root.entry_by_uuid(new_entry_uuid);
        assert!(new_entry.is_some());

        assert!(!destination_db.deleted_objects.contains_key(&deleted_group_uuid));
        assert!(!destination_db.deleted_objects.contains_key(&new_entry_uuid));
    }

    #[test]
    fn test_add_new_non_root_entry() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let source_sub_group = &mut source_db.root.groups[0];
        let source_sub_group_uuid = source_sub_group.uuid;

        let mut new_entry = Entry::new();
        let new_entry_uuid = new_entry.uuid;
        new_entry.set_field_and_commit(fields::TITLE, "new_entry");
        source_sub_group.entries.push(new_entry);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);

        let created_entry_parent = destination_db.root.find_entry_parent(new_entry_uuid).unwrap();
        assert_eq!(created_entry_parent, source_sub_group_uuid);
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
        new_entry.set_field_and_commit(fields::TITLE, "new_entry");
        source_sub_group.entries.push(new_entry);
        source_group.groups.push(source_sub_group.clone());
        source_db.root.groups.push(source_group);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 3);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before + 2);

        let created_entry_parent = destination_db.root.find_entry_parent(new_entry_uuid).unwrap();
        assert_eq!(created_entry_parent, source_sub_group.uuid);
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
            .relocate_entry(ENTRY2_ID, SUBGROUP1_ID, GROUP2_ID, new_location_changed_timestamp)
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        let moved_entry_parent = destination_db.root.find_entry_parent(ENTRY2_ID).unwrap();
        assert_eq!(moved_entry_parent, GROUP2_ID);

        let moved_entry = destination_db
            .root
            .group_by_name("group2")
            .and_then(|g| g.entry_by_name("entry2"))
            .unwrap();

        assert_eq!(
            moved_entry.times.location_changed.unwrap(),
            new_location_changed_timestamp
        );
    }

    #[test]
    fn test_entry_relocation_and_update() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let group_count_before = get_all_groups(&destination_db.root).len();
        let entry_count_before = get_all_entries(&destination_db.root).len();

        let entry2 = source_db.root.entry_by_uuid_mut(ENTRY2_ID).unwrap();
        entry2.set_field_and_commit(fields::TITLE, "entry2_modified_in_source");

        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();
        source_db
            .relocate_entry(ENTRY2_ID, SUBGROUP1_ID, GROUP2_ID, new_location_changed_timestamp)
            .unwrap();

        let entry2 = destination_db.root.entry_by_uuid_mut(ENTRY2_ID).unwrap();
        entry2.set_field_and_commit(fields::TITLE, "entry2_modified_in_destination");
        let entry_modified_timestamp = entry2.times.last_modification.unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        let moved_entry_parent = destination_db.root.find_entry_parent(ENTRY2_ID).unwrap();
        assert_eq!(moved_entry_parent, GROUP2_ID);

        let moved_entry = destination_db
            .root
            .group_by_name("group2")
            .and_then(|g| g.entry_by_name("entry2_modified_in_destination"))
            .unwrap();

        assert_eq!(
            moved_entry.times.last_modification.unwrap(),
            entry_modified_timestamp,
        );
        assert_eq!(
            moved_entry.times.location_changed.unwrap(),
            new_location_changed_timestamp
        );
    }

    #[test]
    fn test_entry_relocation_in_destination_and_update() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let group_count_before = get_all_groups(&destination_db.root).len();
        let entry_count_before = get_all_entries(&destination_db.root).len();

        let entry2 = source_db.root.entry_by_uuid_mut(ENTRY2_ID).unwrap();
        entry2.set_field_and_commit(fields::TITLE, "entry2_modified_in_source");

        let entry_modified_timestamp = entry2.times.last_modification.unwrap();

        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();
        destination_db
            .relocate_entry(ENTRY2_ID, SUBGROUP1_ID, GROUP2_ID, new_location_changed_timestamp)
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        let moved_entry_parent = destination_db.root.find_entry_parent(ENTRY2_ID).unwrap();
        assert_eq!(moved_entry_parent, GROUP2_ID);

        let moved_entry = destination_db
            .root
            .group_by_name("group2")
            .and_then(|g| g.entry_by_name("entry2_modified_in_source"))
            .unwrap();

        assert_eq!(
            moved_entry.times.last_modification.unwrap(),
            entry_modified_timestamp,
        );
        assert_eq!(
            moved_entry.times.location_changed.unwrap(),
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
        new_entry.set_field_and_commit(fields::TITLE, "entry1");

        thread::sleep(time::Duration::from_secs(1));
        new_entry.times.location_changed = Some(Times::now());
        // FIXME we should not have to update the history here. We should
        // have a better compare function in the merge function instead.
        new_entry.update_history();
        new_group.entries.push(new_entry.clone());
        source_db.root.groups.push(new_group);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before + 1);

        let created_entry_parent = destination_db.root.find_entry_parent(entry_uuid).unwrap();
        assert_eq!(created_entry_parent, new_group_uuid);
    }

    #[test]
    fn test_group_relocation() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let source_group_1 = source_db.root.group_by_name_mut("group1").unwrap();
        let mut source_sub_group_1 = source_group_1.remove_group(SUBGROUP1_ID).unwrap();

        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();
        source_sub_group_1.times.location_changed = Some(new_location_changed_timestamp);

        let source_group_2 = source_db.root.group_by_name_mut("group2").unwrap();
        source_group_2.groups.push(source_sub_group_1);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let created_entry_parent = destination_db.root.find_entry_parent(ENTRY2_ID).unwrap();
        assert_eq!(created_entry_parent, SUBGROUP1_ID);

        let relocated_group = destination_db
            .root
            .group_by_path(&["group2", "subgroup1"])
            .unwrap();

        assert_eq!(
            relocated_group.times.location_changed.unwrap(),
            new_location_changed_timestamp
        );
    }

    #[test]
    fn test_update_in_destination_no_conflict() {
        let mut destination_db = create_test_database();
        let source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let entry = &mut destination_db.root.entries[0];
        entry.set_field_and_commit(fields::TITLE, "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry = &mut destination_db.root.entries[0];
        let merged_history = entry.history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 2);
        let merged_entry = &merged_history.entries[1];
        assert_eq!(merged_entry.get_title(), Some("entry1"));

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let entry = &destination_db.root.entries[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_in_source_no_conflict() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let entry = &mut source_db.root.entries[0];
        entry.set_field_and_commit(fields::TITLE, "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry = &mut destination_db.root.entries[0];
        let merged_history = entry.history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 2);
        let merged_entry = &merged_history.entries[1];
        assert_eq!(merged_entry.get_title(), Some("entry1"));

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let entry = &destination_db.root.entries[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_with_conflicts() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let entry = &mut destination_db.root.entries[0];
        entry.set_field_and_commit(fields::TITLE, "entry1_updated_from_destination");

        let entry = &mut source_db.root.entries[0];
        entry.set_field_and_commit(fields::TITLE, "entry1_updated_from_source");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let entry = &destination_db.root.entries[0];
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

        let group = source_db
            .root
            .group_by_path_mut(&["group1", "subgroup1"])
            .unwrap();
        group.name = "subgroup1_updated_name".to_string();

        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group.times.last_modification = Some(new_modification_timestamp);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let modified_group = destination_db
            .root
            .group_by_path(&["group1", "subgroup1_updated_name"])
            .unwrap();

        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.last_modification,
            Some(new_modification_timestamp),
        );
    }

    #[test]
    fn test_group_update_in_destination() {
        let mut destination_db = create_test_database();
        let source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let group = destination_db
            .root
            .group_by_path_mut(&["group1", "subgroup1"])
            .unwrap();
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group.times.last_modification = Some(new_modification_timestamp);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let modified_group = destination_db
            .root
            .group_by_path(&["group1", "subgroup1_updated_name"])
            .unwrap();
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.last_modification,
            Some(new_modification_timestamp),
        );
    }

    #[test]
    fn test_group_update_and_relocation() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let group = source_db
            .root
            .group_by_path_mut(&["group1", "subgroup1"])
            .unwrap();
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group.times.last_modification = Some(new_modification_timestamp);

        source_db
            .relocate_group(SUBGROUP1_ID, GROUP1_ID, GROUP2_ID, new_modification_timestamp)
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let modified_group = destination_db
            .root
            .group_by_path(&["group2", "subgroup1_updated_name"])
            .unwrap();
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.last_modification,
            Some(new_modification_timestamp),
        );
    }

    #[test]
    fn test_group_update_in_destination_and_relocation_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let group = source_db
            .root
            .group_by_path_mut(&["group1", "subgroup1"])
            .unwrap();
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group.times.last_modification = Some(new_modification_timestamp);

        thread::sleep(time::Duration::from_secs(1));
        let new_location_changed_timestamp = Times::now();
        destination_db
            .relocate_group(SUBGROUP1_ID, GROUP1_ID, GROUP2_ID, new_location_changed_timestamp)
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let modified_group = destination_db
            .root
            .group_by_path(&["group2", "subgroup1_updated_name"])
            .unwrap();
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.last_modification,
            Some(new_modification_timestamp),
        );
        assert_eq!(
            modified_group.times.location_changed,
            Some(new_location_changed_timestamp),
        );
    }
}
