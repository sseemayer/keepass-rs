mod tests {
    use keepass::result::*;
    use keepass::*;
    use std::{fs::File, path::Path};

    #[test]
    fn open_kdbx3_with_password() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        println!("{:?} DB Opened", db);
        assert_eq!(db.root.name, "sample");
        assert_eq!(db.root.children.len(), 5);

        let mut total_groups = 0;
        let mut total_entries = 0;
        for node in &db.root {
            match node {
                NodeRef::Group(g) => {
                    println!("Saw group '{0}'", g.name);
                    total_groups += 1;
                }
                NodeRef::Entry(e) => {
                    let title = e.get_title().unwrap();
                    let user = e.get_username().unwrap();
                    let pass = e.get_password().unwrap();
                    println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
                    total_entries += 1;
                }
            }
        }

        assert_eq!(total_groups, 5);
        assert_eq!(total_entries, 6);

        println!("{:?}", db);

        Ok(())
    }

    #[test]
    fn open_kdbx3_with_keyfile() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_keyfile.kdbx");
        let kf_path = Path::new("tests/resources/test_key.key");
        let db = Database::open(
            &mut File::open(path)?,
            None,
            Some(&mut File::open(kf_path)?),
        )?;

        println!("{:?} DB Opened", db);
        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        let mut total_groups = 0;
        let mut total_entries = 0;
        for node in &db.root {
            match node {
                NodeRef::Group(g) => {
                    println!("Saw group '{0}'", g.name);
                    total_groups += 1;
                }
                NodeRef::Entry(e) => {
                    let title = e.get_title().unwrap();
                    let user = e.get_username().unwrap();
                    let pass = e.get_password().unwrap();
                    println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
                    total_entries += 1;
                }
            }
        }

        assert_eq!(total_groups, 1);
        assert_eq!(total_entries, 1);

        println!("{:?}", db);

        Ok(())
    }

    #[test]
    fn open_kdbx3_with_keyfile_xml() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_keyfile_xml.kdbx");
        let kf_path = Path::new("tests/resources/test_key_xml.key");
        let db = Database::open(
            &mut File::open(path)?,
            None,
            Some(&mut File::open(kf_path)?),
        )?;

        println!("{:?} DB Opened", db);
        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 4);

        let mut total_groups = 0;
        let mut total_entries = 0;
        for node in &db.root {
            match node {
                NodeRef::Group(g) => {
                    println!("Saw group '{0}'", g.name);
                    total_groups += 1;
                }
                NodeRef::Entry(e) => {
                    let title = e.get_title().unwrap();
                    let user = e.get_username().unwrap();
                    let pass = e.get_password().unwrap();
                    println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
                    total_entries += 1;
                }
            }
        }

        assert_eq!(total_groups, 5);
        assert_eq!(total_entries, 6);

        println!("{:?}", db);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2_cipher_aes() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2.kdbx");

        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 2);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_aes_cipher_aes() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2_cipher_twofish() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2_twofish.kdbx");

        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2_cipher_chacha20() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2_chacha20.kdbx");

        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_keyfile() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_keyfile.kdbx");
        let kf_path = Path::new("tests/resources/test_key.key");

        let db = Database::open(
            &mut File::open(path)?,
            None,
            Some(&mut File::open(kf_path)?),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    #[should_panic(expected = r#"InvalidKDBXIdentifier"#)]
    fn open_broken_random_data() {
        let path = Path::new("tests/resources/broken_random_data.kdbx");
        Database::open(&mut File::open(path).unwrap(), None, None).unwrap();
    }

    #[test]
    #[should_panic(expected = r#"InvalidKDBXVersion"#)]
    fn open_broken_kdbx_version() {
        let path = Path::new("tests/resources/broken_kdbx_version.kdbx");
        Database::open(&mut File::open(path).unwrap(), None, None).unwrap();
    }

    #[test]
    fn open_kdb_with_password() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdb_with_password.kdb");
        let db = Database::open(&mut File::open(path)?, Some("foobar"), None)?;

        println!("{:?} DB Opened", db);
        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 3);

        let mut total_groups = 0;
        let mut total_entries = 0;
        for node in &db.root {
            match node {
                NodeRef::Group(g) => {
                    println!("Saw group '{0}'", g.name);
                    total_groups += 1;
                }
                NodeRef::Entry(e) => {
                    let title = e.get_title().unwrap();
                    let user = e.get_username().unwrap();
                    let pass = e.get_password().unwrap();
                    println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
                    total_entries += 1;
                }
            }
        }

        assert_eq!(total_groups, 12);
        assert_eq!(total_entries, 5);

        println!("{:?}", db);

        Ok(())
    }
    #[test]
    fn open_kdbx4_with_password_deleted_entry() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_deleted_entry.kdbx");

        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.meta.recyclebin_uuid, "VjFx/mWYQtyAA/mN3jLocg==");

        let recycle_group: Vec<NodeRef> = db
            .root
            .iter()
            .filter(|child| match child {
                NodeRef::Group(g) => g.uuid == db.meta.recyclebin_uuid,
                NodeRef::Entry(_) => false,
            })
            .collect();

        assert_eq!(recycle_group.len(), 1);
        let group = &recycle_group[0];
        if let NodeRef::Group(g) = group {
            assert_eq!(g.name, "Recycle Bin");
        } else {
            panic!("It should've matched a Group!");
        }
        Ok(())
    }
}
