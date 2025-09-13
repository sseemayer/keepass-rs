/// An AutoType setting associated with an Entry
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AutoType {
    pub enabled: bool,
    pub sequence: Option<String>,
    pub associations: Vec<AutoTypeAssociation>,
}

/// A window association associated with an AutoType setting
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AutoTypeAssociation {
    pub window: Option<String>,
    pub sequence: Option<String>,
}
