use uuid::Uuid;

use crate::db::Database;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct IconId(Uuid);

impl IconId {
    pub(crate) fn from_uuid(id: Uuid) -> IconId {
        IconId(id)
    }

    pub fn to_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for IconId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A custom icon
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Icon {
    /// UUID, to reference the icon
    pub(crate) id: IconId,

    /// Image data
    pub data: Vec<u8>,
}

impl Icon {
    pub fn id(&self) -> IconId {
        self.id
    }
}

/// An immutable reference to an icon in the database
pub struct IconRef<'a> {
    database: &'a Database,
    id: IconId,
}

impl IconRef<'_> {
    pub(crate) fn new(database: &Database, id: IconId) -> IconRef<'_> {
        IconRef { database, id }
    }
}

impl std::ops::Deref for IconRef<'_> {
    type Target = Icon;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: IconRef can only be constructed with a valid id
        self.database.custom_icons.get(&self.id).unwrap()
    }
}

/// A mutable reference to an icon in the database  
pub struct IconMut<'a> {
    database: &'a mut Database,
    id: IconId,
}

impl IconMut<'_> {
    pub(crate) fn new(database: &mut Database, id: IconId) -> IconMut<'_> {
        IconMut { database, id }
    }
}

impl std::ops::Deref for IconMut<'_> {
    type Target = Icon;

    fn deref(&self) -> &Self::Target {
        // UNWRAP safety: IconMut can only be constructed with a valid id
        self.database.custom_icons.get(&self.id).unwrap()
    }
}

impl std::ops::DerefMut for IconMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // UNWRAP safety: IconMut can only be constructed with a valid id
        self.database.custom_icons.get_mut(&self.id).unwrap()
    }
}
