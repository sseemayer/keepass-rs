//! Example for opening and traversing a KeePass database
use keepass::{db::fields, Database, DatabaseKey, DatabaseOpenError};
use std::fs::File;

fn main() -> Result<(), DatabaseOpenError> {
    // Open KeePass database using a password (keyfile is also supported)
    let mut file = File::open("tests/resources/test_db_with_password.kdbx")?;
    let key = DatabaseKey::new().with_password("demopass");
    let db = Database::open(&mut file, key)?;

    // Iterate over all entries and print their titles
    for entry in db.iter_all_entries() {
        println!("Title: {}", entry.get_str(fields::TITLE).unwrap_or("<no title>"));
    }

    // find an entry by title
    if let Some(entry) = db
        .iter_all_entries()
        .find(|e| e.get_str(fields::TITLE) == Some("asdf"))
    {
        println!("\nFound entry with title 'asdf'");

        println!(
            "Username: {}",
            entry.get_str(fields::USERNAME).unwrap_or("<no username>")
        );
        println!(
            "Password: {}",
            entry.get_str(fields::PASSWORD).unwrap_or("<no password>")
        );
    }

    // print the database structure using a recursive function
    println!();
    print_recursively(db.root(), 0);

    Ok(())
}

fn print_recursively(group: keepass::db::GroupRef<'_>, indent: usize) {
    let indent_str = " ".repeat(indent);
    println!("{}\u{f07b} {}", indent_str, group.name);

    for subgroup in group.groups() {
        print_recursively(subgroup, indent + 2);
    }

    for entry in group.entries() {
        println!(
            "{}  \u{f0b77} {}",
            indent_str,
            entry.get_str(fields::TITLE).unwrap_or("<no title>")
        );
    }
}
