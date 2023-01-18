mod tests {
    use keepass::*;
    use std::{fs::File, path::Path};

    #[test]
    fn kdbx3_entry() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        // get an entry on the root node
        if let Some(NodeRef::Entry(e)) = db.root.get(&["Sample Entry"]) {
            assert_eq!(e.get_uuid(), "Dr7dsu1OUUS8NBowkmalEw==");
            assert_eq!(e.get_title(), Some("Sample Entry"));
            assert_eq!(e.get_username(), Some("User Name"));
            assert_eq!(e.get_password(), Some("Password"));
            assert_eq!(e.get_url(), Some("http://keepass.info/"));
            assert_eq!(e.get("custom attribute"), Some("data for custom attribute"));
            assert_eq!(e.get("URL"), Some("http://keepass.info/"));
            assert_eq!(e.expires, false);

            let et =
                chrono::NaiveDateTime::parse_from_str("2016-01-06 09:43:01", "%Y-%m-%d %H:%M:%S")
                    .unwrap();
            assert_eq!(e.get_expiry_time(), Some(&et));
            assert_eq!(e.get_time("ExpiryTime"), Some(&et));

            if let Some(ref at) = e.autotype {
                if let Some(ref s) = at.sequence {
                    assert_eq!(s, "{USERNAME}{TAB}{TAB}{PASSWORD}{ENTER}");
                } else {
                    panic!("Expected a sequence")
                }
            } else {
                panic!("Expected an AutoType entry");
            }
        } else {
            panic!("Expected an entry");
        }

        if let Some(NodeRef::Entry(e)) = db.root.get(&["General", "Subgroup", "test entry"]) {
            assert_eq!(e.get_uuid(), "XkyK0ZzVOUyQORF43BQLSg==");
            assert_eq!(e.get_title(), Some("test entry"));
            assert_eq!(e.get_username(), Some("jdoe"));
            assert_eq!(e.get_password(), Some("nWuu5AtqsxqNhnYgLwoB"));
            assert_eq!(e.get_url(), None);
            assert_eq!(e.expires, false);
            if let Some(t) = e.get_time("ExpiryTime") {
                assert_eq!(format!("{}", t), "2016-01-28 12:25:36");
            } else {
                panic!("Expected an ExpiryTime");
            }
        } else {
            panic!("Expected an entry");
        }

        Ok(())
    }

    #[test]
    fn kdbx4_entry() -> Result<(), DatabaseOpenError> {
        // KDBX4 database format Base64 encodes ExpiryTime (and all other XML timestamps)
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        // get an entry on the root node
        if let Some(NodeRef::Entry(e)) = db.root.get(&["ASDF"]) {
            assert_eq!(e.get_uuid(), "TzgWvYMwSGWHn6EIoS8oXA==");
            assert_eq!(e.get_title(), Some("ASDF"));
            assert_eq!(e.get_username(), Some("ghj"));
            assert_eq!(e.get_password(), Some("klmno"));
            assert_eq!(e.get_url(), Some("https://example.com"));
            assert_eq!(e.tags, vec!["keepass-rs".to_string(), "test".to_string()]);
            assert_eq!(e.expires, true);
            if let Some(t) = e.get_time("ExpiryTime") {
                assert_eq!(format!("{}", t), "2021-04-10 16:53:18");
            } else {
                panic!("Expected an ExpiryTime");
            }
        } else {
            panic!("Expected an entry");
        }

        Ok(())
    }
    #[test]
    fn kdbx4_entry_bad_password() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            Some("this password is not correct"),
            None,
        );

        assert!(db.is_err());

        Ok(())
    }

    #[test]
    fn databasekeyerror_into_databaseopenerror() -> Result<(), DatabaseOpenError> {
        let _: DatabaseOpenError = DatabaseKeyError::IncorrectKey.into();
        Ok(())
    }
}
