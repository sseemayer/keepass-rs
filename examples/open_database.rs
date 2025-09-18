use keepass::{db::fields, Database, DatabaseKey, DatabaseOpenError};
use std::fs::File;

fn main() -> Result<(), DatabaseOpenError> {
    // Open KeePass database using a password (keyfile is also supported)
    let mut file = File::open("tests/resources/test_db_with_password.kdbx")?;
    let key = DatabaseKey::new().with_password("demopass");
    let db = Database::open(&mut file, key)?;

    for entry in db.iter_all_entries() {
        println!("Title: {}", entry.get_str(fields::TITLE).unwrap_or("<no title>"));
    }

    Ok(())
}
