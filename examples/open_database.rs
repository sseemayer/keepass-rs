use keepass::{db::Group, error::DatabaseOpenError, Database, DatabaseKey};
use std::fs::File;

fn main() -> Result<(), DatabaseOpenError> {
    // Open KeePass database using a password (keyfile is also supported)
    let mut file = File::open("tests/resources/test_db_with_password.kdbx")?;
    let key = DatabaseKey::new().with_password("demopass");
    let db = Database::open(&mut file, key)?;

    explore(&db.root);

    Ok(())
}

fn explore(group: &Group) {
    for group in &group.groups {
        println!("Saw group '{0}'", group.name);
        explore(group);
    }

    for entry in &group.entries {
        let title = entry.get_title().unwrap_or("(no title)");
        let user = entry.get_username().unwrap_or("(no username)");
        let pass = entry.get_password().unwrap_or("(no password)");
        println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
    }
}
