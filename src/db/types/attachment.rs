use std::ops::{Deref, DerefMut};

use secrecy::{ExposeSecret, SecretBox};

/// Unique identifier for an [Attachment]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AttachmentId(usize);

impl AttachmentId {
    /// Create an AttachmentId from a usize
    ///
    /// this is only accessible within the crate because the user could create conflicts
    pub(crate) fn from_usize(id: usize) -> Self {
        AttachmentId(id)
    }

    /// Generate the next free AttachmentId in the database
    pub(crate) fn next_free(database: &crate::db::Database) -> Self {
        let mut id = AttachmentId(0);
        while database.attachments.contains_key(&id) {
            id.0 += 1;
        }
        id
    }
}

/// Attachment associated with an [Entry][crate::db::Entry]
#[derive(Debug, Clone)]
pub struct Attachment {
    id: AttachmentId,
    pub name: String,
    pub protected: bool,
    data: SecretBox<[u8]>,
}

impl Attachment {
    pub(crate) fn with_id(id: AttachmentId) -> Self {
        Attachment {
            id,
            name: String::new(),
            protected: true,
            data: SecretBox::new(Box::new([])),
        }
    }

    pub fn id(&self) -> AttachmentId {
        self.id
    }

    pub fn data(&self) -> &[u8] {
        self.data.expose_secret()
    }

    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data = SecretBox::new(data.into_boxed_slice());
    }
}

impl PartialEq for Attachment {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.name == other.name
            && self.protected == other.protected
            && self.data.expose_secret() == other.data.expose_secret()
    }
}

impl Eq for Attachment {}

#[cfg(feature = "serialization")]
impl serde::Serialize for Attachment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use base64::{engine::general_purpose as base64_engine, Engine as _};
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Attachment", 4)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("protected", &self.protected)?;
        state.serialize_field("data", &base64_engine::STANDARD.encode(self.data()))?;
        state.end()
    }
}

/// An immutable reference to an [Attachment]. Implements [Deref] to [&Attachment][Attachment].
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
        self.database.attachments.get(&self.id).unwrap()
    }
}

/// A mutable reference to an [Attachment]. Implements [DerefMut] to [&mut Attachment][Attachment].
pub struct AttachmentMut<'a> {
    database: &'a mut crate::db::Database,
    id: AttachmentId,
}

impl AttachmentMut<'_> {
    pub(crate) fn new(database: &mut crate::db::Database, id: AttachmentId) -> AttachmentMut<'_> {
        AttachmentMut { database, id }
    }

    /// Edit the attachment in place using a closure
    pub fn edit<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut AttachmentMut),
    {
        f(self);
        self
    }
}

impl Deref for AttachmentMut<'_> {
    type Target = Attachment;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: AttachmentMut can only be constructed with a valid AttachmentId
        self.database.attachments.get(&self.id).unwrap()
    }
}

impl DerefMut for AttachmentMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // UNWRAP safety: AttachmentMut can only be constructed with a valid AttachmentId
        self.database.attachments.get_mut(&self.id).unwrap()
    }
}
