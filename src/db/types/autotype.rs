/// An AutoType setting associated with an [Entry][crate::db::Entry]
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AutoType {
    /// Whether AutoType is enabled for this entry
    pub enabled: bool,

    /// Default AutoType sequence. This is used if no window associations match.
    pub default_sequence: Option<String>,

    /// Whether an implementation MAY try to obfuscate Auto-Type key strokes to make it harder
    /// for key loggers to record the full sequence.
    pub data_transfer_obfuscation: Option<bool>,

    /// Window associations for this entry. The first association whose window matches the active
    /// window will be used.
    pub associations: Vec<AutoTypeAssociation>,
}

/// A window association associated with an [AutoType] setting
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AutoTypeAssociation {
    /// The title of the window to match with this entry. The string MUST support * as a wildcard character.
    pub window: String,

    /// A custom Auto-Type sequence. If the value is left empty, the sequence from default_sequence is
    /// used or, if that is empty as well, the group or global default.
    pub sequence: String,
}
