use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct BinaryAttachmentId(Uuid);

/// Binary attachment in the metadata of a XML database
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct BinaryAttachment {
    id: BinaryAttachmentId,

    identifier: Option<String>,
    compressed: bool,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct HeaderAttachmentId(Uuid);

/// Header attachment in the header of a database
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct HeaderAttachment {
    id: HeaderAttachmentId,

    flags: u8,
    data: Vec<u8>,
}

pub struct BinaryAttachmentRef<'a> {
    database: &'a crate::db::Database,
    id: BinaryAttachmentId,
}

pub struct BinaryAttachmentMut<'a> {
    database: &'a mut crate::db::Database,
    id: BinaryAttachmentId,
}

pub struct HeaderAttachmentRef<'a> {
    database: &'a crate::db::Database,
    id: HeaderAttachmentId,
}

pub struct HeaderAttachmentMut<'a> {
    database: &'a mut crate::db::Database,
    id: HeaderAttachmentId,
}
