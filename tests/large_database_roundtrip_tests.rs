mod large_file_roundtrip_tests {
    use std::fs::File;

    use keepass::{
        db::{Database, Entry, NodeRef, Value},
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
        let mut db = Database::new(Default::default());

        db.meta.database_name = Some("Demo database".to_string());

        for i in 0..LARGE_DATABASE_ENTRY_COUNT {
            let mut entry = Entry::new();
            entry
                .fields
                .insert("Title".to_string(), Value::Unprotected(format!("Entry_{i}")));
            entry.fields.insert(
                "UserName".to_string(),
                Value::Unprotected(format!("UserName_{i}")),
            );
            entry.fields.insert(
                "Password".to_string(),
                Value::Protected(format!("Password_{i}").as_bytes().into()),
            );
            db.root.add_child(entry);
        }

        // Define database key.
        let key = DatabaseKey::new().with_password(TEST_DATABASE_PASSWORD);
        #[cfg(feature = "save_kdbx4")]
        {
            db.save(&mut File::create(TEST_DATABASE_FILE_NAME)?, key.clone())?;
        }
        // Read the database that was written in the previous block.
        let db = Database::open(&mut File::open(TEST_DATABASE_FILE_NAME)?, key)?;
        // Validate that the data is what we expect.
        let mut entry_counter = 0;
        for node in &db.root {
            match node {
                NodeRef::Group(g) => {
                    println!("Saw group '{0}'", g.name);
                }
                NodeRef::Entry(e) => {
                    assert_eq!(
                        format!("Entry_{entry_counter}"),
                        e.get_title().expect("Title should be defined")
                    );
                    assert_eq!(
                        format!("UserName_{entry_counter}"),
                        e.get_username().expect("Username should be defined")
                    );
                    assert_eq!(
                        format!("Password_{entry_counter}"),
                        e.get_password().expect("Password should be defined")
                    );
                    entry_counter += 1;
                }
            }
        }
        assert_eq!(entry_counter, LARGE_DATABASE_ENTRY_COUNT);
        Ok(())
    }
}
