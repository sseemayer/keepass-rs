/// Binary attachments stored in a database inner header
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct HeaderAttachment {
    pub flags: u8,
    pub content: Vec<u8>,
}

/// Collection of binary attachments in the metadata of an XML database
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct BinaryAttachments {
    pub binaries: Vec<BinaryAttachment>,
}

/// Binary attachment in the metadata of a XML database
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct BinaryAttachment {
    pub identifier: Option<String>,
    pub compressed: bool,
    pub content: Vec<u8>,
}
