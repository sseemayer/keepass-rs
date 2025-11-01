use keepass::{
    db::{Database, Entry, Group, Value},
    DatabaseKey,
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db = Database::new(Default::default());

    db.meta.database_name = Some("Demo database".to_string());

    let mut group = Group::new("Demo group");

    let mut entry = Entry::new();
    entry
        .fields
        .insert("Title".to_string(), Value::Unprotected("Demo entry".to_string()));
    entry
        .fields
        .insert("UserName".to_string(), Value::Unprotected("jdoe".to_string()));
    entry.fields.insert(
        "Password".to_string(),
        Value::Protected("hunter2".as_bytes().into()),
    );

    group.add_child(entry);

    db.root.add_child(group);

    #[cfg(feature = "save_kdbx4")]
    db.save(
        &mut File::create("demo.kdbx")?,
        DatabaseKey::new().with_password("demopass"),
    )?;

    Ok(())
}
