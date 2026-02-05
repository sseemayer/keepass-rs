//! Serialization of the database to JSON, using nested structs to represent the recursive
//! structure of groups and entries
use serde::{ser::SerializeStruct, Serialize};

use crate::db::{Database, EntryRef, GroupRef};

impl Serialize for Database {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Database", 3)?;
        state.serialize_field("config", &self.config)?;
        state.serialize_field("meta", &self.meta)?;

        state.serialize_field("root", &RecursiveGroup(self.root()))?;

        state.serialize_field("deleted_objects", &self.deleted_objects)?;

        state.end()
    }
}

struct RecursiveGroup<'a>(GroupRef<'a>);

impl<'a> std::ops::Deref for RecursiveGroup<'a> {
    type Target = GroupRef<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for RecursiveGroup<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Group", 5)?;
        state.serialize_field("id", &self.id())?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("notes", &self.notes)?;
        state.serialize_field("entries", &self.entries().map(RecursiveEntry).collect::<Vec<_>>())?;
        state.serialize_field("groups", &self.groups().map(RecursiveGroup).collect::<Vec<_>>())?;

        state.end()
    }
}

struct RecursiveEntry<'a>(EntryRef<'a>);

impl<'a> std::ops::Deref for RecursiveEntry<'a> {
    type Target = EntryRef<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for RecursiveEntry<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Entry", 3)?;
        state.serialize_field("id", &self.id())?;
        state.serialize_field("fields", &self.fields)?;
        state.serialize_field(
            "attachments",
            &self.attachments().map(|a| (*a).clone()).collect::<Vec<_>>(),
        )?;

        state.end()
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Database;

    #[test]
    fn test_serialize_database() {
        let mut db = Database::new();

        db.root_mut()
            .add_group()
            .edit(|g| {
                g.name = "My Group".into();
                g.notes = Some("This is an example group".into());
            })
            .add_group()
            .edit(|g| {
                g.name = "My Subgroup".into();
            })
            .add_entry()
            .edit(|e| {
                e.set_unprotected("Title", "My Entry");
                e.set_unprotected("Username", "jdoe");
                e.set_protected("Password", "hunter2");
                e.add_attachment().edit(|a| {
                    a.name = "myfile.txt".into();
                    a.set_data(b"Hello, world!".to_vec());
                });
            });

        let json = serde_json::to_string(&db).unwrap();
        println!("{}", json);

        assert!(json.contains(r#""name":"My Group""#));
        assert!(json.contains(r#""name":"My Subgroup""#));
        assert!(json.contains(r#""Title":"My Entry""#));
        assert!(json.contains(r#""Username":"jdoe""#));
        assert!(json.contains(r#""Password":"hunter2""#));
        assert!(json.contains(r#""name":"myfile.txt""#));
        assert!(json.contains(r#""data":"SGVsbG8sIHdvcmxkIQ==""#)); // Base64-encoded "Hello, world!"
    }
}

