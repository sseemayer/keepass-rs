use keepass::{
    db::{fields, Database, Value},
    DatabaseKey,
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db = Database::new();

    db.meta.database_name = Some("Demo database".to_string());

    let mut root = db.root_mut();

    let mut group = root.add_group();
    group.name = "Demo group".to_string();

    let mut entry = group.add_entry();
    entry.set(fields::TITLE, Value::string("Demo entry"));
    entry.set(fields::USERNAME, Value::string("jdoe"));
    entry.set(fields::PASSWORD, Value::protected_string("hunter2"));

    #[cfg(feature = "save_kdbx4")]
    db.save(
        &mut File::create("demo.kdbx")?,
        DatabaseKey::new().with_password("demopass"),
    )?;

    Ok(())
}
