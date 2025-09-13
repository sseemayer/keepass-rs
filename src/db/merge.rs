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

impl Group {}

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

    #[cfg(test)]
    // Convenience function used in unit tests, to make sure that:
    // 1. The history gets updated after changing a field
    // 2. We wait a second before commiting the changes so that the timestamp is not the same
    //    as it previously was. This is necessary since the timestamps in the KDBX format
    //    do not preserve the msecs.
    pub(crate) fn set_field_and_commit(&mut self, field_name: &str, field_value: &str) {
        self.fields.insert(
            field_name.to_string(),
            Value::Unprotected(field_value.to_string()),
        );
        thread::sleep(time::Duration::from_secs(1));
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
