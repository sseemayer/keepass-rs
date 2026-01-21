use std::{collections::HashSet, ops::Deref};

use chrono::NaiveDateTime;
use thiserror::Error;

use crate::{
    db::{
        Entry, EntryId, EntryMut, EntryRef, Group, GroupId, GroupMut, GroupRef, History, MoveGroupError, Times,
    },
    Database,
};

#[derive(Debug, Clone)]
pub enum MergeEventType {
    Created,
    Deleted,
    LocationUpdated,
    Updated,
}

#[derive(Debug, Clone)]
pub enum MergeEventTarget {
    Entry(EntryId),
    Group(GroupId),
}

#[derive(Debug, Clone)]
pub struct MergeEvent {
    pub target: MergeEventTarget,
    pub event_type: MergeEventType,
}

/// Errors while merge two databases
#[derive(Error)]
#[derive(Debug)]
pub enum MergeError {
    #[error("{0}")]
    GenericError(String),

    #[error("Could not find group {0}")]
    FindGroupError(GroupId),

    #[error("Could not find entry {0}")]
    FindEntryError(EntryId),

    #[error("Entries with UUID {0} have the same modification time but have diverged.")]
    EntryModificationTimeNotUpdated(EntryId),

    #[error("Groups with UUID {0} have the same modification time but have diverged.")]
    GroupModificationTimeNotUpdated(GroupId),

    #[error("Found history entries with the same timestamp ({0}) for entry {1}.")]
    DuplicateHistoryEntries(NaiveDateTime, EntryId),

    #[error(transparent)]
    MoveGroupError(#[from] MoveGroupError),
}

#[derive(Debug, Default, Clone)]
pub struct MergeLog {
    pub warnings: Vec<String>,
    pub events: Vec<MergeEvent>,
}

impl Database {
    /// Merge a database with another version of the same database, applying the changes to self.
    ///
    /// This function will use the UUIDs to detect what entries and groups are the same.
    pub fn merge(&mut self, other: &Database) -> Result<MergeLog, MergeError> {
        let mut log = MergeLog::default();
        merge_group(self.root_mut(), other.root(), &mut log)?;
        merge_deletions(self, other, &mut log)?;

        Ok(log)
    }
}

/// Merge deletions from `source` into `dest`, appending to a log of the merge process.
fn merge_deletions(dest: &mut Database, source: &Database, log: &mut MergeLog) -> Result<(), MergeError> {
    for &deleted_group_id in source.deleted_groups.iter() {
        if !dest.deleted_groups.contains(&deleted_group_id) {
            if let Some(group) = dest.group_mut(deleted_group_id) {
                group.remove();
                log.events.push(MergeEvent {
                    target: MergeEventTarget::Group(deleted_group_id),
                    event_type: MergeEventType::Deleted,
                });
            }

            dest.deleted_groups.insert(deleted_group_id);
        }
    }

    for &deleted_entry_id in source.deleted_entries.iter() {
        if !dest.deleted_entries.contains(&deleted_entry_id) {
            if let Some(entry) = dest.entry_mut(deleted_entry_id) {
                entry.remove();
                log.events.push(MergeEvent {
                    target: MergeEventTarget::Entry(deleted_entry_id),
                    event_type: MergeEventType::Deleted,
                });
            }

            dest.deleted_entries.insert(deleted_entry_id);
        }
    }

    Ok(())
}

/// Merge child entries of a group from `source` into `dest`, appending to a log of the merge process.
fn merge_group_entries(dest: &mut GroupMut, source: &GroupRef, log: &mut MergeLog) -> Result<(), MergeError> {
    let dest_entries = dest.as_ref().entries().map(|e| e.id()).collect::<HashSet<_>>();
    let source_entries = source.entries().map(|e| e.id()).collect::<HashSet<_>>();

    // Handle entries that exist in both source and destination - this might mean moving them to a
    // new location.
    for &id in dest_entries.intersection(&source_entries) {
        let dest_entry = dest.entry_mut(id).unwrap();
        let source_entry = source.entry(id).unwrap();
        merge_entry(dest_entry, source_entry, log)?;
    }

    // Handle entries that exist only in source.
    for &id in source_entries.difference(&dest_entries) {
        // was the entry deleted in dest? then do not re-add it
        if dest.as_ref().database().deleted_entries.contains(&id) {
            continue;
        }

        let source_entry = source.entry(id).unwrap();

        let mut entry = dest.add_entry_with_id(id);
        *entry = source_entry.deref().clone();

        log.events.push(MergeEvent {
            target: MergeEventTarget::Entry(id),
            event_type: MergeEventType::Created,
        });
    }

    // Handle entries that exist only in destination.
    for &id in dest_entries.difference(&source_entries) {
        // was the entry deleted in source? then delete it from dest
        if source.database().deleted_entries.contains(&id) {
            let db = dest.database_mut();
            db.deleted_entries.insert(id);
            db.entry_mut(id).expect("Entry must exist").remove();

            log.events.push(MergeEvent {
                target: MergeEventTarget::Entry(id),
                event_type: MergeEventType::Deleted,
            });
        }
    }

    Ok(())
}

/// Merge child entries of a group from `source` into `dest`, appending to a log of the merge process.
fn merge_group_groups(dest: &mut GroupMut, source: &GroupRef, log: &mut MergeLog) -> Result<(), MergeError> {
    let dest_groups = dest.as_ref().groups().map(|g| g.id()).collect::<HashSet<_>>();
    let source_groups = source.groups().map(|g| g.id()).collect::<HashSet<_>>();

    // Handle groups that exist in both source and destination.
    for &id in dest_groups.intersection(&source_groups) {
        let dest_group = dest.group_mut(id).unwrap();
        let source_group = source.group(id).unwrap();
        merge_group(dest_group, source_group, log)?;
    }

    // Handle groups that exist only in source.
    for &id in source_groups.difference(&dest_groups) {
        // was the group deleted in dest? then do not re-add it
        if dest.as_ref().database().deleted_groups.contains(&id) {
            continue;
        }

        let source_group = source.group(id).unwrap();
        let mut group = dest.add_group_with_id(id);
        *group = source_group.deref().clone();

        log.events.push(MergeEvent {
            target: MergeEventTarget::Group(id),
            event_type: MergeEventType::Created,
        });
    }

    // Handle groups that exist only in destination.
    for &id in dest_groups.difference(&source_groups) {
        // was the group deleted in source? then delete it from dest
        if source.database().deleted_groups.contains(&id) {
            let db = dest.database_mut();
            db.deleted_groups.insert(id);
            db.group_mut(id).expect("Group must exist").remove();

            log.events.push(MergeEvent {
                target: MergeEventTarget::Group(id),
                event_type: MergeEventType::Deleted,
            });
        }
    }

    Ok(())
}

/// Perform merge on just the data of the group itself, not its children.
fn merge_group_itself(dest: &mut GroupMut, source: &GroupRef, log: &mut MergeLog) -> Result<(), MergeError> {
    // check if the group has moved location
    let dest_parent = dest.as_ref().parent().map(|p| p.id());
    let source_parent = source.parent().map(|p| p.id());
    if dest_parent != source_parent {
        // can we determine which change is more recent?
        if let (Some(dest_location_changed), Some(source_location_changed)) =
            (dest.times.location_changed, source.times.location_changed)
        {
            if source_location_changed > dest_location_changed {
                // the source group has been moved more recently than the destination group.
                // try to move the destination group to the new location.
                if let Some(source_parent) = source_parent {
                    if dest.as_ref().database().group(source_parent).is_none() {
                        log.warnings.push(format!(
                            "Cannot move group {} to group {} because the group does not exist in the destination database.",
                            dest.id(),
                            source_parent,
                        ));
                    } else {
                        log.events.push(MergeEvent {
                            target: MergeEventTarget::Group(dest.id()),
                            event_type: MergeEventType::LocationUpdated,
                        });
                        dest.move_to(source_parent)?;
                        dest.times.location_changed = Some(source_location_changed)
                    }
                } else {
                    log.warnings.push(format!(
                        "Cannot move group {} to root because moving groups to root is not supported.",
                        dest.id(),
                    ));
                }
            }
        } else {
            log.warnings.push(format!(
                "Cannot determine which group {} move is more recent because one of the groups does not have a location changed timestamp.",
                dest.id(),
            ));
        }
    }

    let dest_last_modification = dest.times.last_modification.unwrap_or_else(|| {
        log.warnings.push(format!(
            "Destination group {} did not have a last modification timestamp",
            dest.id()
        ));
        Times::now()
    });

    let source_last_modification = source.times.last_modification.unwrap_or_else(|| {
        log.warnings.push(format!(
            "Source group {} did not have a last modification timestamp",
            source.id()
        ));
        Times::epoch()
    });

    if dest_last_modification == source_last_modification {
        if !have_groups_diverged(&dest, &source) {
            // This should never happen.
            //
            // A group was updated without updating the last modification timestamp.
            return Err(MergeError::GroupModificationTimeNotUpdated(source.id()));
        }
        return Ok(());
    }

    if dest_last_modification > source_last_modification {
        // The destination group is more recent than the source group. Nothing to do.
        return Ok(());
    }

    // The source group is more recent than the destination group. Update dest with source.
    dest.name = source.name.clone();
    dest.notes = source.notes.clone();
    dest.icon_id = source.icon_id;
    dest.custom_data = source.custom_data.clone();
    dest.times.last_modification = source.times.last_modification.or(dest.times.last_modification);
    dest.is_expanded = source.is_expanded;
    dest.default_autotype_sequence = source.default_autotype_sequence.clone();
    dest.enable_autotype = source.enable_autotype;
    dest.enable_searching = source.enable_searching;
    dest.last_top_visible_entry = source.last_top_visible_entry;

    log.events.push(MergeEvent {
        target: MergeEventTarget::Group(dest.id()),
        event_type: MergeEventType::Updated,
    });

    Ok(())
}

/// Merge group data from `source` into `dest`, appending to a log of the merge process.
fn merge_group(mut dest: GroupMut, source: GroupRef, log: &mut MergeLog) -> Result<(), MergeError> {
    merge_group_groups(&mut dest, &source, log)?;
    merge_group_entries(&mut dest, &source, log)?;
    merge_group_itself(&mut dest, &source, log)?;
    Ok(())
}

/// Merge entry data from `source` into `dest`, appending to a log of the merge process.
fn merge_entry(mut dest: EntryMut, source: EntryRef, log: &mut MergeLog) -> Result<(), MergeError> {
    // check whether the entries are still in the same parent group
    if dest.as_ref().parent().id() != source.parent().id() {
        // can we determine which change is more recent?
        if let (Some(dest_location_changed), Some(source_location_changed)) =
            (dest.times.location_changed, source.times.location_changed)
        {
            if source_location_changed > dest_location_changed {
                // the source entry has been moved more recently than the destination entry.
                // try to move the destination entry to the new location.
                let source_parent = source.parent().id();
                if dest.as_ref().database().group(source_parent).is_none() {
                    log.warnings.push(format!(
                            "Cannot move entry {} to group {} because the group does not exist in the destination database.",
                            dest.id(),
                            source_parent,
                        ));
                } else {
                    log.events.push(MergeEvent {
                        target: MergeEventTarget::Entry(dest.id()),
                        event_type: MergeEventType::LocationUpdated,
                    });
                    dest.move_to(source_parent)
                        .expect("We checked that destination exists");
                    dest.times.location_changed = Some(source_location_changed)
                }
            }
        } else {
            log.warnings.push(format!(
                "Cannot determine which entry {} move is more recent because one of the entries does not have a location changed timestamp.",
                dest.id(),
            ));
        }
    }

    let source_last_modification = source.times.last_modification.unwrap_or_else(|| {
        log.warnings.push(format!(
            "Source entry {} did not have a last modification timestamp",
            source.id()
        ));
        Times::epoch()
    });

    let dest_last_modification = dest.times.last_modification.unwrap_or_else(|| {
        log.warnings.push(format!(
            "Destination entry {} did not have a last modification timestamp",
            dest.id()
        ));
        Times::now()
    });

    if dest_last_modification == source_last_modification {
        if !have_entries_diverged(&dest, &source) {
            // This should never happen.
            //
            // An entry was updated without updating the last modification timestamp.
            return Err(MergeError::EntryModificationTimeNotUpdated(source.id()));
        }
        return Ok(());
    }

    let source_history = source.history.clone().unwrap_or_else(|| {
        log.warnings
            .push(format!("Source entry {} had no history.", source.id()));
        History::default()
    });

    let dest_history = dest.history.clone().unwrap_or_else(|| {
        log.warnings
            .push(format!("Destination entry {} had no history.", dest.id()));
        History::default()
    });

    let merged_history = Some(merge_history(&dest_history, &source_history, log)?);
    let merged_location_timestamp = dest.times.location_changed.or(source.times.location_changed);

    if source_last_modification > dest_last_modification {
        // The source entry is more recent than the destination entry. Replace dest with source.
        *dest = source.deref().clone();
    }

    dest.history = merged_history;
    dest.times.location_changed = merged_location_timestamp;

    Ok(())
}

/// Merge two histories together, returning the merged history.
fn merge_history(dest: &History, source: &History, log: &mut MergeLog) -> Result<History, MergeError> {
    let mut entries: Vec<Entry> = Vec::new();

    let mut entries_dest: Vec<Entry> = dest.entries.iter().cloned().collect();
    let mut entries_source: Vec<Entry> = source.entries.iter().cloned().collect();

    for e in entries_dest.iter_mut() {
        if e.times.last_modification.is_none() {
            log.warnings.push(format!(
                "Destination history entry {} did not have a last modification timestamp",
                e.id()
            ));
            e.times.last_modification = Some(Times::epoch());
        }
    }

    for e in entries_source.iter_mut() {
        if e.times.last_modification.is_none() {
            log.warnings.push(format!(
                "Source history entry {} did not have a last modification timestamp",
                e.id()
            ));
            e.times.last_modification = Some(Times::epoch());
        }
    }

    entries_dest.sort_by_key(|e| e.times.last_modification);
    entries_source.sort_by_key(|e| e.times.last_modification);

    // perform a merge of both histories, which are sorted by last modification time.
    loop {
        match (entries_dest.is_empty(), entries_dest.is_empty()) {
            (false, false) => {
                // Both histories have entries left to process.
                let dest_entry = entries_dest.last().unwrap();
                let source_entry = entries_source.last().unwrap();

                let dest_time = dest_entry.times.last_modification.unwrap();
                let source_time = source_entry.times.last_modification.unwrap();

                if dest_time > source_time {
                    entries.push(entries_dest.pop().unwrap());
                } else if source_time > dest_time {
                    entries.push(entries_source.pop().unwrap());
                } else {
                    if have_entries_diverged(dest_entry, source_entry) {
                        log.warnings.push(format!(
                            "History entries for {} have the same modification timestamp {} but have diverged.",
                            dest_entry.id(),
                            source_time,
                        ));

                        // Both entries have the same timestamp but are different.
                        entries.push(entries_dest.pop().unwrap());
                        entries.push(entries_source.pop().unwrap());
                    } else {
                        // The entries are the same, so we can just take one of them.
                        entries.push(entries_dest.pop().unwrap());
                        entries_source.pop();
                    }
                }
            }

            (true, false) => {
                // Only the source history has entries left to process - just take them all.
                entries.push(entries_source.pop().unwrap());
            }
            (false, true) => {
                // Only the destination history has entries left to process - just take them all.
                entries.push(entries_dest.pop().unwrap());
            }
            (true, true) => break,
        }
    }

    return Ok(History { entries });
}

fn have_groups_diverged(a: &Group, b: &Group) -> bool {
    let new_times = Times::default();

    let mut a_without_times = a.clone();
    a_without_times.times = new_times.clone();

    let mut b_without_times = b.clone();
    b_without_times.times = new_times.clone();

    !a_without_times.eq(&b_without_times)
}

/// Check if two entries are dissimilar, ignoring their timestamps.
fn have_entries_diverged(a: &Entry, b: &Entry) -> bool {
    let new_times = Times::default();

    let mut a_without_times = a.clone();
    a_without_times.times = new_times.clone();

    let mut b_without_times = b.clone();
    b_without_times.times = new_times.clone();

    !a_without_times.eq(&b_without_times)
}

#[cfg(test)]
mod merge_tests {
    use std::{thread, time};
    use uuid::Uuid;

    use crate::db::{Entry, Group, Times};
    use crate::Database;

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
