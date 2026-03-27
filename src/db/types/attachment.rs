use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
};

use crate::{
    db::{EntryId, EntryMut, EntryRef, Value},
    Database,
};

/// Identifier for an [Attachment]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AttachmentId(usize);

impl AttachmentId {
    pub(crate) fn new(id: usize) -> Self {
        AttachmentId(id)
    }

    /// Get the underlying usize ID of this attachment.
    pub fn id(&self) -> usize {
        self.0
    }

    pub(crate) fn next_free(database: &Database) -> Self {
        let mut id = 0;
        while database.attachments.contains_key(&AttachmentId(id)) {
            id += 1;
        }
        AttachmentId(id)
    }
}

impl std::fmt::Display for AttachmentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Attachment for an entry.
///
/// Both header attachments (KDBX4-style) and XML attachments (KDBX3-style) will be converted to
/// this format when parsing.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Attachment {
    pub(crate) id: AttachmentId,

    /// The entries that reference this attachment, along with the history index of the entry
    /// version that references it (if applicable).
    pub(crate) entries: HashSet<(EntryId, Option<usize>)>,

    /// The binary data of the attachment.
    pub data: Value<Vec<u8>>,
}

impl Attachment {
    /// Get the ID of this attachment.
    pub fn id(&self) -> AttachmentId {
        self.id
    }
}

impl Deref for Attachment {
    type Target = Value<Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for Attachment {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// An immutable reference to an [Attachment]. Implements [Deref] to [&Attachment][Attachment]
pub struct AttachmentRef<'a> {
    database: &'a Database,
    id: AttachmentId,
}

impl AttachmentRef<'_> {
    pub(crate) fn new(database: &Database, id: AttachmentId) -> AttachmentRef<'_> {
        AttachmentRef { database, id }
    }

    /// Get an immutable reference to the database that owns this attachment.
    pub fn database(&self) -> &Database {
        self.database
    }

    /// Get an iterator over the entries that reference this attachment.
    ///
    /// If `include_historical` is false, only returns entries that currently reference this
    /// attachment. If `include_historical` is true, also returns old versions of entries that
    /// reference this attachment, even if they have been modified to no longer reference it.
    pub fn entries(&self, include_historical: bool) -> impl Iterator<Item = EntryRef<'_>> {
        self.entries.iter().filter_map(move |&(id, history_index)| {
            if !include_historical && history_index.is_some() {
                return None;
            }

            Some(EntryRef::new_historical(self.database, id, history_index))
        })
    }
}

impl Deref for AttachmentRef<'_> {
    type Target = Attachment;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: AttachmentRef should only be created with valid AttachmentIds
        #[allow(clippy::expect_used)]
        self.database
            .attachments
            .get(&self.id)
            .expect("AttachmentRef points to non-existent attachment")
    }
}

/// A mutable reference to an [Attachment]. Implements [DerefMut] to [&mut Attachment][Attachment]
pub struct AttachmentMut<'a> {
    database: &'a mut Database,
    id: AttachmentId,
}

impl AttachmentMut<'_> {
    pub(crate) fn new(database: &mut Database, id: AttachmentId) -> AttachmentMut<'_> {
        AttachmentMut { database, id }
    }

    /// Get an immutable reference to this attachment.
    pub fn as_ref(&self) -> AttachmentRef<'_> {
        AttachmentRef {
            database: self.database,
            id: self.id,
        }
    }

    /// Edit this attachment with a closure, which is passed a mutable reference to this attachment.
    pub fn edit(&mut self, f: impl FnOnce(&mut AttachmentMut<'_>)) -> &mut Self {
        f(self);
        self
    }

    /// Get a mutable reference to the database that owns this attachment.
    pub fn database_mut(&mut self) -> &mut Database {
        self.database
    }

    /// Get an iterator over the entries that reference this attachment, with mutable access.
    ///
    /// If `include_historical` is false, only returns entries that currently reference this
    /// attachment. If `include_historical` is true, also returns old versions of entries that
    /// reference this attachment, even if they have been modified to no longer reference it.
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

    /// Remove this attachment from the database, and all references to it
    pub fn remove(mut self) {
        let id = self.id;

        self.foreach_entry_mut(
            |mut entry| {
                let mut attachments_to_remove = Vec::new();
                for (name, attachment_id) in &entry.attachments {
                    if *attachment_id == id {
                        attachments_to_remove.push(name.clone());
                    }
                }

                for name in attachments_to_remove {
                    entry.attachments.remove(&name);
                }
            },
            true,
        );

        self.database.attachments.remove(&self.id);
    }
}

impl Deref for AttachmentMut<'_> {
    type Target = Attachment;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: AttachmentMut should only be created with valid AttachmentIds
        #[allow(clippy::expect_used)]
        self.database
            .attachments
            .get(&self.id)
            .expect("AttachmentMut points to non-existent attachment")
    }
}

impl DerefMut for AttachmentMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // UNWRAP safety: AttachmentMut should only be created with valid AttachmentIds
        #[allow(clippy::expect_used)]
        self.database
            .attachments
            .get_mut(&self.id)
            .expect("AttachmentMut points to non-existent attachment")
    }
}
