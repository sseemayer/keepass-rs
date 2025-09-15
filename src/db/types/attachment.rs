use std::ops::{Deref, DerefMut};

use secrecy::{ExposeSecret, SecretBox};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AttachmentId(Uuid);

/// Attachment associated with an entry
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Attachment {
    id: AttachmentId,
    pub name: String,
    pub protected: bool,
    data: SecretBox<[u8]>,
}

impl Attachment {
    pub(crate) fn new() -> Self {
        Attachment {
            id: AttachmentId(Uuid::new_v4()),
            name: String::new(),
            protected: true,
            data: SecretBox::new(Box::new([])),
        }
    }

    pub fn id(&self) -> AttachmentId {
        self.id
    }

    pub fn data(&self) -> &[u8] {
        &self.data.expose_secret()
    }

    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = SecretBox::new(data.into_boxed_slice());
    }
}

pub struct AttachmentRef<'a> {
    database: &'a crate::db::Database,
    id: AttachmentId,
}

impl AttachmentRef<'_> {
    pub(crate) fn new(database: &crate::db::Database, id: AttachmentId) -> AttachmentRef<'_> {
        AttachmentRef { database, id }
    }
}

impl Deref for AttachmentRef<'_> {
    type Target = Attachment;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: AttachmentRef can only be constructed with a valid AttachmentId
        self.database.header_attachments.get(&self.id).unwrap()
    }
}

pub struct AttachmentMut<'a> {
    database: &'a mut crate::db::Database,
    id: AttachmentId,
}

impl AttachmentMut<'_> {
    pub(crate) fn new(database: &mut crate::db::Database, id: AttachmentId) -> AttachmentMut<'_> {
        AttachmentMut { database, id }
    }
}

impl Deref for AttachmentMut<'_> {
    type Target = Attachment;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: AttachmentMut can only be constructed with a valid AttachmentId
        self.database.header_attachments.get(&self.id).unwrap()
    }
}

impl DerefMut for AttachmentMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // UNWRAP safety: AttachmentMut can only be constructed with a valid AttachmentId
        self.database.header_attachments.get_mut(&self.id).unwrap()
    }
}
