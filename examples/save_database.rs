use keepass::{
    db::{fields, Database, Entry, Group},
    DatabaseKey,
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db = Database::new(Default::default());

    db.meta.database_name = Some("Demo database".to_string());

    let mut group = Group::new("Demo group");

    let mut entry = Entry::new();
    entry.set_unprotected(fields::TITLE, "Demo entry");
    entry.set_unprotected(fields::USERNAME, "jdoe");
    entry.set_protected(fields::PASSWORD, "hunter2");

    group.entries.push(entry);

    db.root.groups.push(group);

    #[cfg(feature = "save_kdbx4")]
    db.save(
        &mut File::create("demo.kdbx")?,
        DatabaseKey::new().with_password("demopass"),
    )?;

    Ok(())
}
