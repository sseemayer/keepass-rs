#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Attachment {
    pub protected: bool,
    pub data: Vec<u8>,
}
