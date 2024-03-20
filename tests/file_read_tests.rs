mod file_read_tests {
    use keepass::{
        db::{Database, NodeRef},
        error::{DatabaseIntegrityError, DatabaseOpenError},
        DatabaseKey,
    };
    use uuid::uuid;

    use std::{fs::File, path::Path};

    #[test]
    fn open_kdbx3_with_password() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

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
                    let title = e.get_title().unwrap_or("(no title)");
                    let user = e.get_username().unwrap_or("(no user)");
                    let pass = e.get_password().unwrap_or("(no password)");
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
    fn open_kdbx3_with_keyfile() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_with_keyfile.kdbx");
        let kf_path = Path::new("tests/resources/test_key.key");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_keyfile(&mut File::open(kf_path)?)?,
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
                    let title = e.get_title().unwrap_or("(no title)");
                    let user = e.get_username().unwrap_or("(no user)");
                    let pass = e.get_password().unwrap_or("(no password)");
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
    fn open_kdbx3_with_keyfile_xml() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_with_keyfile_xml.kdbx");
        let kf_path = Path::new("tests/resources/test_key_xml.key");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_keyfile(&mut File::open(kf_path)?)?,
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
                    let title = e.get_title().unwrap_or("(no title)");
                    let user = e.get_username().unwrap_or("(no user)");
                    let pass = e.get_password().unwrap_or("(no password)");
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
    fn open_kdbx4_with_password_kdf_argon2_cipher_aes() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 2);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2id_cipher_aes() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2id.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 2);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_aes_cipher_aes() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2_cipher_twofish() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2_twofish.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2_cipher_chacha20() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2_chacha20.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2id_cipher_twofish() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2id_twofish.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2id_cipher_chacha20() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2id_chacha20.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_keyfile() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_keyfile.kdbx");
        let kf_path = Path::new("tests/resources/test_key.key");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_keyfile(&mut File::open(kf_path)?)?,
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_keyfile_v2() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_keyfile_v2.kdbx");
        let kf_path = Path::new("tests/resources/test_db_kdbx4_with_keyfile_v2.keyx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new()
                .with_password("demopass")
                .with_keyfile(&mut File::open(kf_path)?)?,
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
        Database::open(
            &mut File::open(path).unwrap(),
            DatabaseKey::new().with_password(""),
        )
        .unwrap();
    }

    #[test]
    #[should_panic(expected = r#"InvalidKDBXVersion"#)]
    fn open_broken_kdbx_version() {
        let path = Path::new("tests/resources/broken_kdbx_version.kdbx");
        Database::open(
            &mut File::open(path).unwrap(),
            DatabaseKey::new().with_password(""),
        )
        .unwrap();
    }

    #[test]
    fn open_kdb_with_password() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdb_with_password.kdb");
        let db = Database::open(&mut File::open(path)?, DatabaseKey::new().with_password("foobar"))?;

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
                    let title = e.get_title().unwrap_or("(no title)");
                    let user = e.get_username().unwrap_or("(no user)");
                    let pass = e.get_password().unwrap_or("(no password)");
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
    fn open_kdb_with_larger_than_1mb_file_does_not_crash() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdb3_with_file_larger_1mb.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("samplepassword"),
        )?;

        println!("{:?} DB Opened", db);
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
                    let title = e.get_title().unwrap_or("(no title)");
                    let user = e.get_username().unwrap_or("(no user)");
                    let pass = e.get_password().unwrap_or("(no password)");
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
    fn open_kdbx4_with_password_deleted_entry() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_deleted_entry.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        println!("{:?} DB Opened", db);

        assert_eq!(db.root.name, "Root");
        assert_eq!(
            db.meta.recyclebin_uuid,
            Some(uuid!("563171fe-6598-42dc-8003-f98dde32e872"))
        );

        let recycle_group: Vec<NodeRef> = db
            .root
            .iter()
            .filter(|child| match child {
                NodeRef::Group(g) => Some(&g.uuid) == db.meta.recyclebin_uuid.as_ref(),
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

    #[test]
    #[cfg(feature = "challenge_response")]
    fn open_kdbx4_with_challenge_response_key() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_with_challenge_response_key.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new()
                .with_password("demopass")
                .with_challenge_response_key(keepass::ChallengeResponseKey::LocalChallenge(
                    "0102030405060708090a0b0c0d0e0f1011121314".to_string(),
                )),
        )?;

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 2);
        Ok(())
    }

    #[test]
    #[ignore]
    #[cfg(feature = "challenge_response")]
    fn open_kdbx4_with_yubikey_challenge_response_key() -> Result<(), DatabaseOpenError> {
        let path = Path::new("tests/resources/test_db_with_challenge_response_key.kdbx");
        let yubikey = keepass::ChallengeResponseKey::get_yubikey(None)?;
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new()
                .with_password("demopass")
                .with_challenge_response_key(keepass::ChallengeResponseKey::YubikeyChallenge(
                    yubikey,
                    "2".to_string(),
                )),
        )?;

        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.children.len(), 2);
        Ok(())
    }

    #[test]
    fn test_get_version() -> Result<(), DatabaseIntegrityError> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let version = Database::get_version(&mut File::open(path)?)?;
        assert_eq!(version.to_string(), "KDBX3.1");

        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2.kdbx");
        let version = Database::get_version(&mut File::open(path)?)?;
        assert_eq!(version.to_string(), "KDBX4.0");

        Ok(())
    }
}
