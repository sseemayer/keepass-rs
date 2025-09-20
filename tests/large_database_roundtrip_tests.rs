#[cfg(feature = "save_kdbx4")]
mod large_file_roundtrip_tests {
    use std::fs::File;

    use keepass::{
        db::{fields, Database},
        DatabaseKey,
    };

    /// This can be tuned based on how "large" we expect databases to realistically be.
    const LARGE_DATABASE_ENTRY_COUNT: usize = 10_000;

    /// Constants for the test database.
    const TEST_DATABASE_FILE_NAME: &str = "demo.kdbx";
    const TEST_DATABASE_PASSWORD: &str = "demopass";

    /// Writing and reading back a large databack should function as expected.
    /// This tests guards against issues that might affect large databases.
    #[test]
    fn write_and_read_large_database() -> Result<(), Box<dyn std::error::Error>> {
        let mut db = Database::new();

        db.meta.database_name = Some("Demo database".to_string());

        let mut root = db.root_mut();

        for i in 0..LARGE_DATABASE_ENTRY_COUNT {
            let mut entry = root.add_entry();

            entry.set_unprotected(fields::TITLE, format!("Entry_{i}"));
            entry.set_unprotected(fields::USERNAME, format!("UserName_{i}"));
            entry.set_protected(fields::PASSWORD, format!("Password_{i}"));
        }

        // Define database key.
        let key = DatabaseKey::new().with_password(TEST_DATABASE_PASSWORD);
        db.save(&mut File::create(TEST_DATABASE_FILE_NAME)?, key.clone())?;

        // Read the database that was written in the previous block.
        let db = Database::open(&mut File::open(TEST_DATABASE_FILE_NAME)?, key)?;

        // Validate that the data is what we expect.
        let root = db.root();
        for i in 0..LARGE_DATABASE_ENTRY_COUNT {
            let entry = root
                .entry_by_name(&format!("Entry_{i}"))
                .expect("Entry should be found");

            assert_eq!(
                format!("Entry_{i}"),
                entry.get_str(fields::TITLE).expect("Title should be defined")
            );
            assert_eq!(
                format!("UserName_{i}"),
                entry
                    .get_str(fields::USERNAME)
                    .expect("Username should be defined")
            );
            assert_eq!(
                format!("Password_{i}"),
                entry
                    .get_str(fields::PASSWORD)
                    .expect("Password should be defined")
            );
        }

        Ok(())
    }
}
