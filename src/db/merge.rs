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
    for (&id, source_timestamp) in source.deleted_objects.iter() {
        // compare deletion timestamps to determine which deletion is more recent and whether we
        // need to delete objects in dest
        let merged_timestamp = match (source_timestamp, dest.deleted_objects.get(&id)) {
            (None, None) => {
                // no timestamp in source, no deletion event in dest. add a blank deletion event
                // and delete the object
                None
            }
            (None, Some(None)) => {
                // no timestamp in source, dest has a blank deletion event - delete the object
                None
            }
            (None, Some(Some(_d))) => {
                // no timestamp in source, but dest has a timestamped deletion event, which we
                // assume is newer - don't perform additional deletions
                continue;
            }
            (Some(s), None) => {
                // timestamped deletion in source, no deletion event in dest - use source timestamp
                Some(s.clone())
            }
            (Some(s), Some(None)) => {
                // timestamped deletion in source, blank deletion event in dest - use source timestamp
                Some(s.clone())
            }
            (Some(s), Some(Some(d))) => {
                if s > d {
                    // timestamped deletion in source is newer than dest - use source timestamp
                    Some(s.clone())
                } else {
                    // timestamped deletion in dest is newer than source - don't delete again
                    continue;
                }
            }
        };

        let group_id = GroupId::with_uuid(id);
        if let Some(group) = dest.group_mut(group_id) {
            group.remove();
            log.events.push(MergeEvent {
                target: MergeEventTarget::Group(group_id),
                event_type: MergeEventType::Deleted,
            });
        }

        let entry_id = EntryId::with_uuid(id);
        if let Some(entry) = dest.entry_mut(entry_id) {
            entry.remove();
            log.events.push(MergeEvent {
                target: MergeEventTarget::Entry(entry_id),
                event_type: MergeEventType::Deleted,
            });
        }

        dest.deleted_objects.insert(id, merged_timestamp);
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
        if dest.as_ref().database().deleted_objects.contains_key(&id.uuid()) {
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
        if let Some(timestamp) = source.database().deleted_objects.get(&id.uuid()) {
            let db = dest.database_mut();
            db.deleted_objects.insert(id.uuid(), timestamp.clone());
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
        if dest.as_ref().database().deleted_objects.contains_key(&id.uuid()) {
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
        if let Some(timestamp) = source.database().deleted_objects.get(&id.uuid()) {
            let db = dest.database_mut();
            db.deleted_objects.insert(id.uuid(), timestamp.clone());
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
    use uuid::uuid;

    use crate::db::{EntryId, GroupId, Times};
    use crate::Database;

    const ROOT_GROUP_ID: GroupId = GroupId::with_uuid(uuid!("00000000-0000-0000-0000-000000000001"));
    const GROUP1_ID: GroupId = GroupId::with_uuid(uuid!("00000000-0000-0000-0000-000000000002"));
    const GROUP2_ID: GroupId = GroupId::with_uuid(uuid!("00000000-0000-0000-0000-000000000003"));
    const SUBGROUP1_ID: GroupId = GroupId::with_uuid(uuid!("00000000-0000-0000-0000-000000000004"));
    const SUBGROUP2_ID: GroupId = GroupId::with_uuid(uuid!("00000000-0000-0000-0000-000000000005"));
    const ENTRY1_ID: EntryId = EntryId::with_uuid(uuid!("00000000-0000-0000-0000-000000000006"));
    const ENTRY2_ID: EntryId = EntryId::with_uuid(uuid!("00000000-0000-0000-0000-000000000007"));

    /// Build up an example database for testing
    ///
    /// The database structure is as follows:
    ///
    /// root (ROOT_GROUP_ID)
    /// ├── entry1 (ENTRY1_ID)
    /// ├── group1 (GROUP1_ID)
    /// │   └── subgroup1 (SUBGROUP1_ID)
    /// │       └── entry2 (ENTRY2_ID)
    /// └── group2 (GROUP2_ID)
    ///    └── subgroup2 (SUBGROUP2_ID)
    ///
    fn create_test_database() -> Database {
        let mut db = Database::new_with_root_id(ROOT_GROUP_ID);

        // build up root -> group1 -> subgroup1 -> entry2
        db.root_mut()
            .add_group_with_id(GROUP1_ID)
            .edit(|g| g.name = "group1".to_string())
            .add_group_with_id(SUBGROUP1_ID)
            .edit(|sg| sg.name = "subgroup1".to_string())
            .add_entry_with_id(ENTRY2_ID)
            .edit(|e| e.track_changes().set_unprotected("Title", "entry2"));

        // build up root -> group2 -> subgroup2
        db.root_mut()
            .add_group_with_id(GROUP2_ID)
            .edit(|g| g.name = "group2".to_string())
            .add_group_with_id(SUBGROUP2_ID)
            .edit(|sg| sg.name = "subgroup2".to_string());

        // Placing the first entry in the root group
        db.root_mut()
            .add_entry_with_id(ENTRY1_ID)
            .track_changes()
            .set_unprotected("Title", "entry1");

        db
    }

    /// Test that merging a database with itself results in no changes.
    #[test]
    fn test_idempotence() {
        let mut destination_db = create_test_database();
        let source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_db.root().entries().count(), 1);
        assert_eq!(destination_db.root().groups().count(), 2);

        assert_eq!(destination_db.entries.len(), entry_count_before);
        assert_eq!(destination_db.groups.len(), group_count_before);

        // The 2 groups should be exactly the same after merging, since
        // nothing was performed during the merge.
        assert_eq!(destination_db, source_db);

        // Now modify an entry in the destination database, and merge again.
        destination_db
            .entry_mut(ENTRY1_ID)
            .unwrap()
            .edit_tracking(|e| e.set_unprotected("Title", "entry1_updated"));

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

    /// Test that a new entry in source is added to destination when merging.
    #[test]
    fn test_add_new_entry() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // create a new entry in source_db and retain its id
        let new_entry_id = source_db
            .root_mut()
            .add_entry()
            .edit_tracking(|e| e.set_unprotected("Title", "new_entry"))
            .id();

        // merge source_db into destination_db -- this should add the new entry
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);

        let root_entries_count = destination_db.root().entries().count();
        assert_eq!(root_entries_count, 2);

        let new_entry = destination_db
            .entry(new_entry_id)
            .expect("New entry should exist");
        assert_eq!(new_entry.get_str("Title"), Some("new_entry"));

        // Merging the same group again should not create a duplicate entry.
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);

        let root_entries_count = destination_db.root().entries().count();
        assert_eq!(root_entries_count, 2);
    }

    /// Test that an entry that is marked as deleted in the destination database is not re-added
    /// when merging from source
    #[test]
    fn test_deleted_entry_in_destination() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // add a new entry in source_db that will be marked as deleted in destination_db
        let deleted_entry_id = source_db
            .root_mut()
            .add_entry()
            .edit_tracking(|e| {
                e.set_unprotected("Title", "deleted_entry");
            })
            .id();

        // mark the entry as deleted in destination_db
        thread::sleep(time::Duration::from_secs(1));
        destination_db
            .deleted_objects
            .insert(deleted_entry_id.uuid(), Some(Times::now()));

        // merge source_db into destination_db -- the entry should not be added
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.entry(deleted_entry_id).is_none());
    }

    /// Test that an entry that is updated in source under a group that is deleted in destination
    /// will be deleted and not re-added.
    #[test]
    fn test_updated_entry_under_deleted_group() {
        let mut destination_db = create_test_database();

        let deleted_group_id = destination_db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "deleted_group".to_string())
            .id();

        let modified_entry_id = destination_db
            .root_mut()
            .add_entry()
            .edit_tracking(|e| e.set_unprotected("Title", "original_title"))
            .id();

        let mut source_db = destination_db.clone();

        // perform the update of the entry in source_db
        source_db
            .entry_mut(modified_entry_id)
            .unwrap()
            .edit_tracking(|e| {
                e.set_unprotected("Title", "modified_title");
            });

        // delete the group in destination_db
        destination_db.group_mut(deleted_group_id).unwrap().remove();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // perform the merge - the entry should not be re-added since its parent group was deleted
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(deleted_group_id).is_none());
        assert!(destination_db.entry(modified_entry_id).is_none());
    }

    /// Test that a group that is marked as deleted in the destination database is not re-added
    /// when merging from source
    #[test]
    fn test_deleted_group_in_destination() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // add a new group in source_db
        let deleted_group_id = source_db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "deleted_group".to_string())
            .id();

        thread::sleep(time::Duration::from_secs(1));

        // mark the group as deleted in destination_db
        destination_db
            .deleted_objects
            .insert(deleted_group_id.uuid(), Some(Times::now()));

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(deleted_group_id).is_none());
    }

    /// Test that an entry that is marked as deleted in the source database is deleted from destination
    #[test]
    fn test_deleted_entry_in_source() {
        let mut destination_db = create_test_database();

        let deleted_entry_id = destination_db
            .root_mut()
            .add_entry()
            .edit_tracking(|e| e.set_unprotected("Title", "deleted_entry"))
            .id();

        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // mark the entry as deleted in source_db
        thread::sleep(time::Duration::from_secs(1));
        source_db
            .entry_mut(deleted_entry_id)
            .unwrap()
            .track_changes()
            .remove();

        // perform the merge - the entry should be deleted
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        // verify that the entry was deleted
        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.entry(deleted_entry_id).is_none());
        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_entry_id.uuid()));
    }

    /// Test that a group that is marked as deleted in the source database is deleted from destination
    #[test]
    fn test_deleted_group_in_source() {
        let mut destination_db = create_test_database();

        let deleted_group_id = destination_db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "deleted_group".to_string())
            .id();

        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // mark the entry as deleted in source_db
        thread::sleep(time::Duration::from_secs(1));
        source_db
            .group_mut(deleted_group_id)
            .unwrap()
            .track_changes()
            .remove();

        // perform the merge - the entry should be deleted
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        // verify that the entry was deleted
        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before - 1);

        assert!(destination_db.group(deleted_group_id).is_none());
        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_group_id.uuid()));
    }

    /// Test that an entry that is marked as deleted in the source database but modified in
    /// destination is not deleted
    #[test]
    fn test_deleted_entry_in_source_modified_in_destination() {
        let mut destination_db = create_test_database();

        let deleted_entry_id = destination_db
            .root_mut()
            .add_entry()
            .edit_tracking(|e| e.set_unprotected("Title", "deleted_entry"))
            .id();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        let mut source_db = destination_db.clone();

        // mark the entry as deleted in source_db
        thread::sleep(time::Duration::from_secs(1));
        source_db
            .deleted_objects
            .insert(deleted_entry_id.uuid(), Some(Times::now()));

        // modify the entry in destination_db
        thread::sleep(time::Duration::from_secs(1));
        destination_db
            .entry_mut(deleted_entry_id)
            .unwrap()
            .edit_tracking(|e| e.set_unprotected("Title", "modified_in_destination"));

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.entry(deleted_entry_id).is_some());
        assert!(!destination_db
            .deleted_objects
            .contains_key(&deleted_entry_id.uuid()));
    }

    /// Test that a group subtree that is marked as deleted in the source database is deleted from
    /// destination
    #[test]
    fn test_group_subtree_deletion() {
        let mut destination_db = create_test_database();

        let deleted_group_id = destination_db
            .root_mut()
            .add_group()
            .edit(|g| {
                g.name = "deleted_group".to_string();
            })
            .id();

        let deleted_subgroup_id = destination_db
            .group_mut(deleted_group_id)
            .unwrap()
            .add_group()
            .edit(|g| {
                g.name = "deleted_subgroup".to_string();
            })
            .id();

        let deleted_entry_id = destination_db
            .group_mut(deleted_subgroup_id)
            .unwrap()
            .add_entry()
            .edit_tracking(|e| {
                e.set_unprotected("Title", "deleted_entry");
            })
            .id();

        let mut source_db = destination_db.clone();

        thread::sleep(time::Duration::from_secs(1));

        // mark the entire group subtree as deleted in source_db
        source_db
            .root_mut()
            .group_mut(deleted_group_id)
            .unwrap()
            .track_changes()
            .remove();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // perform the merge - the entire subtree should be deleted
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 3);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before - 2);

        assert!(destination_db.entry(deleted_entry_id).is_none());
        assert!(destination_db.group(deleted_subgroup_id).is_none());
        assert!(destination_db.group(deleted_group_id).is_none());

        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_entry_id.uuid()));
        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_subgroup_id.uuid()));
        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_group_id.uuid()));
    }

    /// Test that a tree that was deleted in source, but contains a group that is newer in
    /// destination is only partially deleted.
    #[test]
    fn test_group_subtree_partial_deletion() {
        let mut destination_db = create_test_database();

        let deleted_group_id = destination_db
            .root_mut()
            .add_group()
            .edit(|g| {
                g.name = "deleted_group".to_string();
            })
            .id();

        let deleted_subgroup_id = destination_db
            .group_mut(deleted_group_id)
            .unwrap()
            .add_group()
            .edit(|g| {
                g.name = "deleted_subgroup".to_string();
            })
            .id();

        let deleted_entry_id = destination_db
            .group_mut(deleted_subgroup_id)
            .unwrap()
            .add_entry()
            .edit_tracking(|e| {
                e.set_unprotected("Title", "deleted_entry");
            })
            .id();

        let mut source_db = destination_db.clone();

        // mark the entire group subtree as deleted in source_db
        thread::sleep(time::Duration::from_secs(1));
        source_db
            .group_mut(deleted_group_id)
            .unwrap()
            .track_changes()
            .remove();

        // modify the deleted subgroup in destination_db to be newer than the deletion time
        thread::sleep(time::Duration::from_secs(1));
        destination_db
            .group_mut(deleted_subgroup_id)
            .unwrap()
            .track_changes()
            .edit(|g| {
                g.notes = Some("modified in destination".to_string());
            });

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // perform the merge - the entry and subgroup should be deleted, but the group should
        // remain
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before - 1);
        assert_eq!(group_count_after, group_count_before - 1);

        assert!(destination_db.entry(deleted_entry_id).is_none());
        assert!(destination_db.group(deleted_subgroup_id).is_none());
        assert!(destination_db.group(deleted_group_id).is_some());

        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_entry_id.uuid()));
        assert!(destination_db
            .deleted_objects
            .contains_key(&deleted_subgroup_id.uuid()));
        assert!(!destination_db
            .deleted_objects
            .contains_key(&deleted_group_id.uuid()));
    }

    /// Test that a group that is marked as deleted in the source database but modified in
    /// destination is not deleted
    #[test]
    fn test_deleted_group_in_source_modified_in_destination() {
        let mut destination_db = create_test_database();

        let deleted_group_id = destination_db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "deleted_group".to_string())
            .id();

        let mut source_db = destination_db.clone();

        // mark the group as deleted in source_db
        thread::sleep(time::Duration::from_secs(1));
        source_db
            .group_mut(deleted_group_id)
            .unwrap()
            .track_changes()
            .remove();

        // modify the group in destination_db
        thread::sleep(time::Duration::from_secs(1));
        destination_db
            .group_mut(deleted_group_id)
            .unwrap()
            .track_changes()
            .edit(|g| g.notes = Some("modified_in_destination".to_string()));

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // perform the merge - the group should not be deleted
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(deleted_group_id).is_some());

        assert!(!destination_db
            .deleted_objects
            .contains_key(&deleted_group_id.uuid()));
    }

    /// Test that a group that is marked as deleted in the source database but has new entries
    /// added in destination is not deleted
    #[test]
    fn test_deleted_group_has_new_entries() {
        let mut destination_db = create_test_database();

        let deleted_group_id = destination_db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "deleted_group".to_string())
            .id();

        let mut source_db = destination_db.clone();

        // mark the group as deleted in source_db
        thread::sleep(time::Duration::from_secs(1));
        source_db
            .group_mut(deleted_group_id)
            .unwrap()
            .track_changes()
            .remove();

        // add a new entry to the deleted group in destination_db
        thread::sleep(time::Duration::from_secs(1));
        let new_entry_id = destination_db
            .group_mut(deleted_group_id)
            .unwrap()
            .add_entry()
            .edit_tracking(|e| {
                e.set_unprotected("Title", "new_entry_in_deleted_group");
            })
            .id();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // perform the merge - the group should not be deleted
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(deleted_group_id).is_some());
        assert!(destination_db.entry(new_entry_id).is_some());

        assert!(!destination_db
            .deleted_objects
            .contains_key(&deleted_group_id.uuid()));
        assert!(!destination_db.deleted_objects.contains_key(&new_entry_id.uuid()));
    }

    /// Test that a new entry in a non-root group in source is added to destination when merging.
    #[test]
    fn test_add_new_non_root_entry() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        let new_entry_id = source_db
            .group_mut(GROUP1_ID)
            .unwrap()
            .add_entry()
            .edit_tracking(|e| {
                e.set_unprotected("Title", "new_entry");
            })
            .id();

        // perform the merge - this should add the new entry
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.entry(new_entry_id).is_some());
    }

    // Test that a new entry in source under a new group/subgroup is added to destination when
    // merging.
    #[test]
    fn test_add_new_entry_new_group() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        let new_group_id = source_db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "new_group".to_string())
            .id();

        let new_subgroup_id = source_db
            .group_mut(new_group_id)
            .unwrap()
            .add_group()
            .edit(|g| g.name = "new_subgroup".to_string())
            .id();

        let new_entry_id = source_db
            .group_mut(new_subgroup_id)
            .unwrap()
            .add_entry()
            .edit_tracking(|e| {
                e.set_unprotected("Title", "new_entry");
            })
            .id();

        // perform the merge - this should add the new entry along with the new group and subgroup
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 3);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before + 2);

        assert!(destination_db.group(new_group_id).is_some());
        assert!(destination_db.group(new_subgroup_id).is_some());
        assert!(destination_db.entry(new_entry_id).is_some());
    }

    /// Test that an entry is relocated from one group to another in source and the relocation
    /// is reflected in destination when merging.
    #[test]
    fn test_entry_relocation_existing_group() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        thread::sleep(time::Duration::from_secs(1));

        // before
        // root (ROOT_GROUP_ID)
        // ├── entry1 (ENTRY1_ID)
        // ├── group1 (GROUP1_ID)
        // │   └── subgroup1 (SUBGROUP1_ID)
        // │       └── entry2 (ENTRY2_ID)   <-- this entry
        // └── group2 (GROUP2_ID)
        //    └── subgroup2 (SUBGROUP2_ID)
        //
        // after
        // root (ROOT_GROUP_ID)
        // ├── entry1 (ENTRY1_ID)
        // ├── group1 (GROUP1_ID)
        // │   └── subgroup1 (SUBGROUP1_ID)
        // └── group2 (GROUP2_ID)
        //     ├── entry2 (ENTRY2_ID)   <-- moved here
        //     └── subgroup2 (SUBGROUP2_ID)
        //
        source_db
            .entry_mut(ENTRY2_ID)
            .unwrap()
            .track_changes()
            .move_to(GROUP2_ID)
            .expect("move successful");

        let location_changed_timestamp = source_db
            .entry(ENTRY2_ID)
            .unwrap()
            .times
            .location_changed
            .unwrap();

        // perform the merge - this should relocate the entry in destination_db
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        assert!(destination_db.entry(ENTRY2_ID).is_some());

        let entry = destination_db.entry(ENTRY2_ID).unwrap();
        assert_eq!(entry.parent().id(), GROUP2_ID);
        assert_eq!(entry.times.location_changed, Some(location_changed_timestamp));
    }

    /// Test that an entry is relocated in source and modified in both source and destination
    /// and the correct content is kept after merging.
    #[test]
    fn test_entry_relocation_and_update() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // perform first edit of entry in source
        source_db.entry_mut(ENTRY2_ID).unwrap().edit_tracking(|e| {
            e.set_unprotected("Title", "entry2_modified_in_source");
        });

        // relocate entry in source
        thread::sleep(time::Duration::from_secs(1));
        source_db
            .entry_mut(ENTRY2_ID)
            .unwrap()
            .track_changes()
            .move_to(GROUP2_ID)
            .expect("move successful");

        let location_changed_timestamp = source_db
            .entry(ENTRY2_ID)
            .unwrap()
            .times
            .location_changed
            .unwrap();

        // perform second edit of entry in destination
        destination_db.entry_mut(ENTRY2_ID).unwrap().edit_tracking(|e| {
            e.set_unprotected("Title", "entry2_modified_in_destination");
        });

        let entry_modified_timestamp = destination_db
            .entry(ENTRY2_ID)
            .unwrap()
            .times
            .last_modification
            .unwrap();

        // perform the merge - this should relocate the entry in destination_db and keep the
        // content from destination_db since it was modified later
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        // check that move occurred
        assert!(destination_db.entry(ENTRY2_ID).is_some());
        let entry = destination_db.entry(ENTRY2_ID).unwrap();
        assert_eq!(entry.parent().id(), GROUP2_ID);
        assert_eq!(entry.times.location_changed, Some(location_changed_timestamp));

        // check that content from destination is kept
        assert_eq!(entry.get_str("Title"), Some("entry2_modified_in_destination"));
        assert_eq!(entry.times.last_modification, Some(entry_modified_timestamp));
    }

    /// Test that if an entry is moved in source and modified in destination, the entry ends up
    /// in the new location and with the modifications kept.
    #[test]
    fn test_entry_relocation_in_destination_and_update() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // edit entry in source
        source_db.entry_mut(ENTRY2_ID).unwrap().edit_tracking(|e| {
            e.set_unprotected("Title", "entry2_modified_in_source");
        });

        let entry_modified_timestamp = source_db
            .entry(ENTRY2_ID)
            .unwrap()
            .times
            .last_modification
            .unwrap();

        // relocate entry in destination
        thread::sleep(time::Duration::from_secs(1));
        destination_db
            .entry_mut(ENTRY2_ID)
            .unwrap()
            .track_changes()
            .move_to(GROUP2_ID)
            .expect("move successful");

        let location_changed_timestamp = destination_db
            .entry(ENTRY2_ID)
            .unwrap()
            .times
            .location_changed
            .unwrap();

        // perform the merge - this should keep the location from destination and the content from
        // source
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before);

        // check that move occurred
        assert!(destination_db.entry(ENTRY2_ID).is_some());

        let entry = destination_db.entry(ENTRY2_ID).unwrap();
        assert_eq!(entry.parent().id(), GROUP2_ID);
        assert_eq!(entry.times.location_changed, Some(location_changed_timestamp));

        // check that content from source is kept
        assert_eq!(entry.get_str("Title"), Some("entry2_modified_in_source"));
        assert_eq!(entry.times.last_modification, Some(entry_modified_timestamp));
    }

    /// Test that an entry can be relocated into a newly created group
    #[test]
    fn test_entry_relocation_new_group() {
        let mut destination_db = create_test_database();

        let new_entry_id = destination_db
            .root_mut()
            .add_entry()
            .edit_tracking(|e| {
                e.set_unprotected("Title", "new_entry");
            })
            .id();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        let mut source_db = destination_db.clone();

        let new_group_id = source_db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "new_group".to_string())
            .id();

        // modify the entry in source
        thread::sleep(time::Duration::from_secs(1));
        source_db.entry_mut(new_entry_id).unwrap().edit_tracking(|e| {
            e.set_unprotected("Title", "new_entry_modified_in_source");
        });

        // relocate the entry to the new group in source
        thread::sleep(time::Duration::from_secs(1));
        source_db
            .entry_mut(new_entry_id)
            .unwrap()
            .track_changes()
            .move_to(new_group_id)
            .expect("move successful");

        // perform the merge - this should create the new group and update and relocate the entry there
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before + 1);

        assert!(destination_db.entry(new_entry_id).is_some());
        let entry = destination_db.entry(new_entry_id).unwrap();
        assert_eq!(entry.parent().id(), new_group_id);
        assert_eq!(entry.get_str("Title"), Some("new_entry_modified_in_source"));
    }

    /// Test that a group relocation in source is reflected in destination when merging.
    #[test]
    fn test_group_relocation() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        thread::sleep(time::Duration::from_secs(1));

        // before
        // root (ROOT_GROUP_ID)
        // ├── entry1 (ENTRY1_ID)
        // ├── group1 (GROUP1_ID)
        // │   └── subgroup1 (SUBGROUP1_ID) <-- this group
        // │       └── entry2 (ENTRY2_ID)
        // └── group2 (GROUP2_ID)
        //    └── subgroup2 (SUBGROUP2_ID)
        //
        // after
        // root (ROOT_GROUP_ID)
        // ├── entry1 (ENTRY1_ID)
        // ├── group1 (GROUP1_ID)
        // └── group2 (GROUP2_ID)
        //    └── subgroup2 (SUBGROUP2_ID)
        //        └── subgroup1 (SUBGROUP1_ID) <-- moved here
        //            └── entry2 (ENTRY2_ID)

        source_db
            .group_mut(SUBGROUP1_ID)
            .unwrap()
            .track_changes()
            .move_to(GROUP2_ID)
            .expect("move successful");

        let location_changed_timestamp = source_db
            .group(SUBGROUP1_ID)
            .unwrap()
            .times
            .location_changed
            .unwrap();

        // perform the merge - this should relocate the group in destination_db
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(SUBGROUP1_ID).is_some());
        assert!(destination_db.entry(ENTRY2_ID).is_some());

        let group = destination_db.group(SUBGROUP1_ID).unwrap();
        assert_eq!(group.parent().unwrap().id(), GROUP2_ID);
        assert_eq!(group.times.location_changed, Some(location_changed_timestamp));
    }

    /// Test that an entry updated in destination is not touched when merging.
    #[test]
    fn test_update_in_destination_no_conflict() {
        let mut destination_db = create_test_database();
        let source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // update entry in destination
        destination_db.entry_mut(ENTRY1_ID).unwrap().edit_tracking(|e| {
            e.set_unprotected("Title", "entry1_updated");
        });

        // perform the merge - this should not change anything since source is older
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        // check that history is preserved
        let merged_history = destination_db.entry(ENTRY1_ID).unwrap().history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 2);

        // check that we can find the old version of the entry
        let merged_entry = &merged_history.entries[1];
        assert_eq!(merged_entry.get_str("Title"), Some("entry1"));

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert_eq!(
            destination_db.entry(ENTRY1_ID).unwrap().get_str("Title"),
            Some("entry1_updated")
        );
    }

    /// Test that an entry updated in source is merged into destination when merging.
    #[test]
    fn test_update_in_source_no_conflict() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // update entry in source
        source_db.entry_mut(ENTRY1_ID).unwrap().edit_tracking(|e| {
            e.set_unprotected("Title", "entry1_updated");
        });

        // perform the merge - this should update the entry in destination_db
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        // check that history is preserved
        let merged_history = destination_db.entry(ENTRY1_ID).unwrap().history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 2);

        // check that we can find the old version of the entry
        let merged_entry = &merged_history.entries[1];
        assert_eq!(merged_entry.get_str("Title"), Some("entry1"));

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        // check that the entry was updated
        assert_eq!(
            destination_db.entry(ENTRY1_ID).unwrap().get_str("Title"),
            Some("entry1_updated")
        );
    }

    /// Test that an entry updated in both source and destination is merged correctly.
    #[test]
    fn test_update_with_conflicts() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // update entry in destination
        destination_db.entry_mut(ENTRY1_ID).unwrap().edit_tracking(|e| {
            e.set_unprotected("Title", "entry1_updated_from_destination");
        });

        thread::sleep(time::Duration::from_secs(1));

        // update entry in source
        source_db.entry_mut(ENTRY1_ID).unwrap().edit_tracking(|e| {
            e.set_unprotected("Title", "entry1_updated_from_source");
        });

        // perform the merge - this should merge the changes from both databases, keeping the newer
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        // check that the entry was updated with the source change (newer)
        let entry = destination_db.entry(ENTRY1_ID).unwrap();
        assert_eq!(entry.get_str("Title"), Some("entry1_updated_from_source"));

        // check that history is preserved and contains both older versions
        let merged_history = entry.history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 3);
        assert_eq!(
            merged_history.entries[1].get_str("Title"),
            Some("entry1_updated_from_destination")
        );
        assert_eq!(merged_history.entries[1].get_str("Title"), Some("entry1"));

        // Merging again should not result in any additional change.
        let merge_result = destination_db.merge(&destination_db.clone()).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
    }

    /// Test that a group updated in source is merged into destination when merging.
    #[test]
    fn test_group_update_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        thread::sleep(time::Duration::from_secs(1));
        source_db.group_mut(SUBGROUP1_ID).unwrap().edit_tracking(|g| {
            g.name = "subgroup1_updated_name".to_string();
        });

        let modification_timestamp = source_db
            .group(SUBGROUP1_ID)
            .unwrap()
            .times
            .last_modification
            .unwrap();

        // perform the merge - this should update the group in destination
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(SUBGROUP1_ID).is_some());

        assert_eq!(
            destination_db.group(SUBGROUP1_ID).unwrap().name,
            "subgroup1_updated_name"
        );
        assert_eq!(
            destination_db
                .group(SUBGROUP1_ID)
                .unwrap()
                .times
                .last_modification,
            Some(modification_timestamp)
        );
    }

    /// Test that a group updated in destination is not changed when merging.
    #[test]
    fn test_group_update_in_destination() {
        let mut destination_db = create_test_database();
        let source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        thread::sleep(time::Duration::from_secs(1));
        destination_db
            .group_mut(SUBGROUP1_ID)
            .unwrap()
            .edit_tracking(|g| {
                g.name = "subgroup1_updated_name".to_string();
            });

        let last_modification = destination_db
            .group(SUBGROUP1_ID)
            .unwrap()
            .times
            .last_modification
            .unwrap();

        // perform the merge - this should not change anything since source is older
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(SUBGROUP1_ID).is_some());
        assert_eq!(
            destination_db.group(SUBGROUP1_ID).unwrap().name,
            "subgroup1_updated_name"
        );

        assert_eq!(
            destination_db
                .group(SUBGROUP1_ID)
                .unwrap()
                .times
                .last_modification,
            Some(last_modification)
        );
    }

    /// Test that a group updated in source and relocated is merged correctly.
    #[test]
    fn test_group_update_and_relocation() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        thread::sleep(time::Duration::from_secs(1));

        source_db
            .group_mut(SUBGROUP1_ID)
            .unwrap()
            .edit_tracking(|g| {
                g.name = "subgroup1_updated_name".to_string();
            })
            .move_to(GROUP2_ID)
            .expect("move successful");

        let modification_timestamp = source_db
            .group(SUBGROUP1_ID)
            .unwrap()
            .times
            .last_modification
            .unwrap();

        let location_changed_timestamp = source_db
            .group(SUBGROUP1_ID)
            .unwrap()
            .times
            .location_changed
            .unwrap();

        // perform the merge - this should update and relocate the group in destination
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(SUBGROUP1_ID).is_some());
        let group = destination_db.group(SUBGROUP1_ID).unwrap();
        assert_eq!(group.name, "subgroup1_updated_name");
        assert_eq!(group.parent().unwrap().id(), GROUP2_ID);
        assert_eq!(group.times.last_modification, Some(modification_timestamp));
        assert_eq!(group.times.location_changed, Some(location_changed_timestamp));
    }

    /// Test that a group updated in source and relocated in destionation is merged correctly.
    #[test]
    fn test_group_update_in_destination_and_relocation_in_source() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = destination_db.entries.len();
        let group_count_before = destination_db.groups.len();

        // rename group in source
        thread::sleep(time::Duration::from_secs(1));
        source_db.group_mut(SUBGROUP1_ID).unwrap().edit_tracking(|g| {
            g.name = "subgroup1_updated_name".to_string();
        });

        let modification_timestamp = source_db
            .group(SUBGROUP1_ID)
            .unwrap()
            .times
            .last_modification
            .unwrap();

        // relocate group in destination
        thread::sleep(time::Duration::from_secs(1));
        destination_db
            .group_mut(SUBGROUP1_ID)
            .unwrap()
            .track_changes()
            .move_to(GROUP2_ID)
            .expect("move successful");

        let location_changed_timestamp = destination_db
            .group(SUBGROUP1_ID)
            .unwrap()
            .times
            .location_changed
            .unwrap();

        // perform the merge - this should update the group name from source and keep the new
        // location from destination
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = destination_db.entries.len();
        let group_count_after = destination_db.groups.len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        assert!(destination_db.group(SUBGROUP1_ID).is_some());
        let group = destination_db.group(SUBGROUP1_ID).unwrap();
        assert_eq!(group.name, "subgroup1_updated_name");
        assert_eq!(group.parent().unwrap().id(), GROUP2_ID);
        assert_eq!(group.times.last_modification, Some(modification_timestamp));
        assert_eq!(group.times.location_changed, Some(location_changed_timestamp));
    }
}
