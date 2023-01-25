/// Database metadata
#[derive(Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Meta {
    pub recyclebin_uuid: String,
}
