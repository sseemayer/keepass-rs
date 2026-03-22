use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use thiserror::Error;
use uuid::Uuid;

use crate::{
    db::{EntryId, EntryMut, EntryRef, GroupId, GroupMut, GroupRef},
    Database,
};

/// Icon specification for an [Entry][crate::db::Entry] or [Group][crate::db::Group].
#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum Icon {
    /// The icon is a built-in icon specified by an index
    BuiltIn(usize),

    /// The icon is a custom icon specified by a [CustomIconId]
    Custom(CustomIconId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomIconId(Uuid);

impl std::fmt::Display for CustomIconId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl CustomIconId {
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomIcon {
    pub(crate) id: CustomIconId,

    pub(crate) entries: HashSet<(EntryId, Option<usize>)>,
    pub(crate) groups: HashSet<GroupId>,

    pub data: Vec<u8>,
}

impl CustomIcon {
    pub fn id(&self) -> CustomIconId {
        self.id
    }
}

impl Deref for CustomIcon {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for CustomIcon {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// An immutable reference to a [CustomIcon]. Implements [Deref] to [&CustomIcon][CustomIcon]
pub struct CustomIconRef<'a> {
    database: &'a Database,
    id: CustomIconId,
}

impl CustomIconRef<'_> {
    pub(crate) fn new(database: &Database, id: CustomIconId) -> CustomIconRef<'_> {
        CustomIconRef { database, id }
    }

    pub fn database(&self) -> &Database {
        self.database
    }

    /// Get an iterator over the entries that reference this custom icon.
    ///
    /// If `include_historical` is false, only returns entries that currently reference this
    /// icon. If `include_historical` is true, also returns old versions of entries that
    /// reference this icon, even if they have been modified to no longer reference it.
    pub fn entries(&self, include_historical: bool) -> impl Iterator<Item = EntryRef<'_>> {
        self.entries.iter().filter_map(move |&(id, history_index)| {
            if !include_historical && history_index.is_some() {
                return None;
            }

            Some(EntryRef::new_historical(self.database, id, history_index))
        })
    }

    /// Get an iterator over the groups that reference this custom icon.
    pub fn groups(&self) -> impl Iterator<Item = GroupRef<'_>> {
        self.groups
            .iter()
            .map(move |&id| GroupRef::new(self.database, id))
    }
}

impl Deref for CustomIconRef<'_> {
    type Target = CustomIcon;

    fn deref(&self) -> &Self::Target {
        self.database
            .custom_icons
            .get(&self.id)
            .expect("Custom icon ID always valid")
    }
}

/// A mutable reference to a [CustomIcon]. Implements [DerefMut] to [&mut CustomIcon][CustomIcon]
pub struct CustomIconMut<'a> {
    database: &'a mut Database,
    id: CustomIconId,
}

impl CustomIconMut<'_> {
    pub(crate) fn new(database: &mut Database, id: CustomIconId) -> CustomIconMut<'_> {
        CustomIconMut { database, id }
    }

    /// Get an immutable reference to this custom icon.
    pub fn as_ref(&self) -> CustomIconRef<'_> {
        CustomIconRef {
            database: self.database,
            id: self.id,
        }
    }

    /// Edit this custom icon using a closure. The closure is passed a mutable reference to this
    /// custom icon.
    pub fn edit(&mut self, f: impl FnOnce(&mut CustomIconMut<'_>)) -> &mut Self {
        f(self);
        self
    }

    /// Get a mutable reference to the database that owns this custom icon.
    pub fn database_mut(&mut self) -> &mut Database {
        self.database
    }

    /// Apply a closure to each entry that references this custom icon.
    ///
    /// The closure is passed a mutable reference to each entry. If `include_historical` is false,
    /// only applies the closure to entries that currently reference this icon.
    /// If `include_historical` is true, also applies the closure to old versions of entries that
    /// reference this icon, even if they have been modified to no longer reference it.
    pub fn foreach_entry_mut<F>(&mut self, mut f: F, include_historical: bool)
    where
        F: FnMut(EntryMut<'_>),
    {
        let entries: Vec<(EntryId, Option<usize>)> = self.entries.iter().copied().collect();
        for (id, history_index) in entries {
            if !include_historical && history_index.is_some() {
                continue;
            }

            f(EntryMut::new_historical(self.database, id, history_index));
        }
    }

    /// Apply a closure to each group that references this custom icon.
    pub fn foreach_group_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(GroupMut<'_>),
    {
        let groups: Vec<GroupId> = self.groups.iter().copied().collect();
        for id in groups {
            f(GroupMut::new(self.database, id));
        }
    }

    /// Remove this custom icon from the database, and all references to it
    pub fn remove(mut self) {
        let id = self.id;

        self.foreach_entry_mut(
            |mut entry| {
                if entry.icon == Some(Icon::Custom(id)) {
                    entry.icon = None;
                }
            },
            true,
        );

        self.foreach_group_mut(|mut group| {
            if group.icon == Some(Icon::Custom(id)) {
                group.icon = None;
            }
        });

        self.database.custom_icons.remove(&id);
    }
}

impl Deref for CustomIconMut<'_> {
    type Target = CustomIcon;

    fn deref(&self) -> &Self::Target {
        self.database
            .custom_icons
            .get(&self.id)
            .expect("Custom icon ID always valid")
    }
}

impl DerefMut for CustomIconMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.database
            .custom_icons
            .get_mut(&self.id)
            .expect("Custom icon ID always valid")
    }
}

/// Error type for when a [CustomIconId] is provided that does not exist in the database
#[derive(Error, Debug)]
#[error("Custom icon {0} not found")]
pub struct CustomIconNotFoundError(pub(crate) CustomIconId);
