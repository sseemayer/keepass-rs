use std::ops::{Deref, DerefMut};

use crate::db::Value;

/// Attachment for an entry.
///
/// Both header attachments (KDBX4-style) and XML attachments (KDBX3-style) will be converted to
/// this format when parsing.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Attachment {
    /// The binary data of the attachment.
    pub data: Value<Vec<u8>>,
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
