use keepass::{
    db::{fields, Database, Value},
    DatabaseKey,
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db = Database::new();

    db.meta.database_name = Some("Demo database".to_string());

    // create a group and entry using a simple API
    let mut root = db.root_mut();
    let root_id = root.id();

    let mut group = root.add_group();
    group.name = "Demo group".to_string();

    let mut entry = group.add_entry();
    entry.set(fields::TITLE, Value::string("Demo entry"));
    entry.set(fields::USERNAME, Value::string("jdoe"));
    entry.set(fields::PASSWORD, Value::protected_string("hunter2"));

    // retrieve the entry ID because we cannot keep a mutable reference to `entry` around
    let entry_id = entry.id();

    // create a group, sub-group, and entry using the fluent API
    db.root_mut()
        .add_group()
        .edit(|g| {
            // g is the newly-created group
            g.name = "Second Group".to_string();
        })
        .add_group()
        .edit(|sg| {
            // sg is the newly-created sub-group
            sg.name = "Sub Group".to_string();
            sg.notes = Some("Some notes".to_string());
        })
        .add_entry()
        .edit(|e| {
            e.set_unprotected(fields::TITLE, "New Entry");
            e.set_unprotected(fields::USERNAME, "user");
            e.set_protected(fields::PASSWORD, "pass");
        });

    assert_eq!(db.num_groups(), 4);
    assert_eq!(db.num_entries(), 2);

    // get back the first entry and verify its password
    assert_eq!(
        db.entry(entry_id).unwrap().get_str(fields::PASSWORD),
        Some("hunter2")
    );

    // Use history tracking to modify and move an existing entry while tracking its history
    db.entry_mut(entry_id)
        .unwrap()
        .track_changes()
        .edit(|e| {
            e.set_unprotected(fields::PASSWORD, "newpassword");
        })
        .move_to(root_id)?;

    #[cfg(feature = "save_kdbx4")]
    db.save(
        &mut File::create("demo.kdbx")?,
        DatabaseKey::new().with_password("demopass"),
    )?;

    Ok(())
}
