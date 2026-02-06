use uuid::Uuid;

use crate::db::Database;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct IconId(Uuid);

impl IconId {
    pub(crate) fn new() -> IconId {
        IconId(Uuid::new_v4())
    }

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

    pub fn as_ref(&self) -> IconRef<'_> {
        IconRef::new(self.database, self.id)
    }

    /// Remove the icon from the database, and remove references to it from all entries
    pub fn remove(self) {
        self.database.custom_icons.remove(&self.id);

        for entry in self.database.entries.values_mut() {
            if entry.custom_icon_id == Some(self.id) {
                entry.custom_icon_id = None;
            }
        }
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

#[cfg(test)]
mod tests {
    use crate::db::Database;

    #[test]
    fn test_custom_icons() {
        let mut db = Database::new();

        let icon1_id = db.add_custom_icon(vec![1, 2, 3]).id();
        let icon2_id = db.add_custom_icon(vec![4, 5, 6]).id();

        assert_eq!(db.custom_icons.len(), 2);
        assert_eq!(db.custom_icons.get(&icon1_id).unwrap().data, vec![1, 2, 3]);
        assert_eq!(db.custom_icons.get(&icon2_id).unwrap().data, vec![4, 5, 6]);

        {
            let icon1_mut = db.custom_icons.get_mut(&icon1_id).unwrap();
            icon1_mut.data = vec![7, 8, 9];
        }

        assert_eq!(db.custom_icons.get(&icon1_id).unwrap().data, vec![7, 8, 9]);

        {
            let icon1_ref = db.custom_icons.get(&icon1_id).unwrap();
            assert_eq!(icon1_ref.data, vec![7, 8, 9]);
        }

        let entry_id = db
            .root_mut()
            .add_entry()
            .edit(|e| {
                let _ = e.set_custom_icon(Some(icon1_id)).unwrap();
            })
            .id();

        assert_eq!(
            db.entry(entry_id).unwrap().custom_icon().unwrap().data,
            &[7, 8, 9]
        );

        db.foreach_icon_mut(|mut icon| {
            icon.data = icon.data.iter().map(|b| b + 1).collect();
        });

        for icon in db.iter_all_icons() {
            assert_eq!(icon.data.len(), 3);
        }

        assert_eq!(
            db.entry(entry_id).unwrap().custom_icon().unwrap().data,
            &[8, 9, 10]
        );

        db.custom_icon_mut(icon1_id).unwrap().remove();

        assert!(db.custom_icons.get(&icon1_id).is_none());
        assert!(db.entry(entry_id).unwrap().custom_icon().is_none());
        assert_eq!(db.custom_icons.len(), 1);
    }
}
