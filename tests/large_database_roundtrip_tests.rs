#[cfg(feature = "save_kdbx4")]
mod large_file_roundtrip_tests {
    use std::fs::File;

    use keepass::{
        db::{fields, Database, GroupRef},
        DatabaseKey,
    };

    /// This can be tuned based on how "large" we expect databases to realistically be.
    const LARGE_DATABASE_ENTRY_COUNT: usize = 100000;

    /// Constants for the test database.
    const TEST_DATABASE_FILE_NAME: &str = "demo.kdbx";
    const TEST_DATABASE_PASSWORD: &str = "demopass";

    /// Writing and reading back a large databack should function as expected.
    /// This tests guards against issues that might affect large databases.
    #[test]
    fn write_and_read_large_database() -> Result<(), Box<dyn std::error::Error>> {
        let mut db = Database::new();

        db.meta.database_name = Some("Demo database".to_string());

        for i in 0..LARGE_DATABASE_ENTRY_COUNT {
            db.root_mut().add_entry().edit(|entry| {
                entry.set_unprotected(fields::TITLE, format!("Entry_{i}"));
                entry.set_unprotected(fields::USERNAME, format!("UserName_{i}"));
                entry.set_protected(fields::PASSWORD, format!("Password_{i}"));
            });
        }

        // Define database key.
        let key = DatabaseKey::new().with_password(TEST_DATABASE_PASSWORD);
        db.save(&mut File::create(TEST_DATABASE_FILE_NAME)?, key.clone())?;

        // Read the database that was written in the previous block.
        let db = Database::open(&mut File::open(TEST_DATABASE_FILE_NAME)?, key)?;
        // Validate that the data is what we expect.
        let mut entry_counter = 0;

        fn explore(group: GroupRef<'_>, entry_counter: &mut usize) {
            for group in group.groups() {
                println!("Saw group '{0}'", group.name);
                explore(group, entry_counter);
            }

            for entry in group.entries() {
                let n = entry
                    .get(fields::TITLE)
                    .unwrap()
                    .strip_prefix("Entry_")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                println!("Saw entry '{0}'", entry.get(fields::TITLE).unwrap());

                assert_eq!(format!("Entry_{n}"), entry.get(fields::TITLE).unwrap());
                assert_eq!(format!("UserName_{n}"), entry.get(fields::USERNAME).unwrap());
                assert_eq!(format!("Password_{n}"), entry.get(fields::PASSWORD).unwrap());
                *entry_counter += 1;
            }
        }

        explore(db.root(), &mut entry_counter);

        assert_eq!(entry_counter, LARGE_DATABASE_ENTRY_COUNT);
        Ok(())
    }
}
