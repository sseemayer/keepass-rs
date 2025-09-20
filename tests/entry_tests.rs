mod entry_tests {
    use anyhow::Result;
    use keepass::{
        db::{fields, Database},
        DatabaseKey,
    };
    use std::{collections::HashSet, fs::File, path::Path};
    use uuid::uuid;

    #[test]
    fn kdbx3_entry() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        let root = db.root();

        let root_entry = root
            .entry_by_name("Sample Entry")
            .expect("Expect to find Sample Entry");

        assert_eq!(
            root_entry.id().uuid(),
            uuid!("0ebeddb2-ed4e-5144-bc34-1a309266a513")
        );

        assert_eq!(root_entry.get_str(fields::TITLE), Some("Sample Entry"));
        assert_eq!(root_entry.get_str(fields::USERNAME), Some("User Name"));
        assert_eq!(root_entry.get_str(fields::PASSWORD), Some("Password"));
        assert_eq!(root_entry.get_str(fields::URL), Some("http://keepass.info/"));
        assert_eq!(
            root_entry.get_str("custom attribute"),
            Some("data for custom attribute")
        );

        assert_eq!(root_entry.times.expires, Some(false));

        let et = chrono::NaiveDateTime::parse_from_str("2016-01-06 09:43:01", "%Y-%m-%d %H:%M:%S").unwrap();

        assert_eq!(root_entry.times.expiry, Some(et));

        assert_eq!(
            root_entry.autotype.as_ref().unwrap().default_sequence,
            Some("{USERNAME}{TAB}{TAB}{PASSWORD}{ENTER}".to_string())
        );

        let subgroup = root
            .group_by_path(&["General", "Subgroup"])
            .expect("Expect to find General/Subgroup");
        let subgroup_entry = subgroup
            .entry_by_name("test entry")
            .expect("Expect to find test entry");

        assert_eq!(
            subgroup_entry.id().uuid(),
            uuid!("5e4c8ad1-9cd5-394c-9039-1178dc140b4a")
        );
        assert_eq!(subgroup_entry.get_str(fields::TITLE), Some("test entry"));
        assert_eq!(subgroup_entry.get_str(fields::USERNAME), Some("jdoe"));
        assert_eq!(
            subgroup_entry.get_str(fields::PASSWORD),
            Some("nWuu5AtqsxqNhnYgLwoB")
        );
        assert_eq!(subgroup_entry.get_str(fields::URL), None);
        assert_eq!(subgroup_entry.times.expires, Some(false));

        let et2 = chrono::NaiveDateTime::parse_from_str("2016-01-28 12:25:36", "%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(subgroup_entry.times.expiry, Some(et2));
        Ok(())
    }

    #[test]
    fn kdbx4_entry() -> Result<()> {
        // KDBX4 database format Base64 encodes ExpiryTime (and all other XML timestamps)
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        let root = db.root();

        let root_entry = root.entry_by_name("ASDF").expect("Expect to find ASDF entry");

        assert_eq!(
            root_entry.id().uuid(),
            uuid!("4f3816bd-8330-4865-879f-a108a12f285c")
        );

        assert_eq!(root_entry.get_str(fields::TITLE), Some("ASDF"));
        assert_eq!(root_entry.get_str(fields::USERNAME), Some("ghj"));
        assert_eq!(root_entry.get_str(fields::PASSWORD), Some("klmno"));
        assert_eq!(root_entry.get_str(fields::URL), Some("https://example.com"));

        let mut expected_tags = HashSet::new();
        expected_tags.insert("keepass-rs".to_string());
        expected_tags.insert("test".to_string());

        assert_eq!(root_entry.tags, expected_tags);
        assert_eq!(root_entry.times.expires, Some(true));
        if let Some(t) = root_entry.times.expiry {
            assert_eq!(format!("{}", t), "2021-04-10 16:53:18");
        } else {
            panic!("Expected an ExpiryTime");
        }

        Ok(())
    }

    #[test]
    fn kdbx4_entry_bad_password() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("this password is not correct"),
        );

        assert!(db.is_err());

        Ok(())
    }
}
