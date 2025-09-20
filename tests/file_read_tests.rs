mod file_read_tests {

    use anyhow::Result;
    use keepass::{
        db::{Database, GroupId},
        DatabaseKey,
    };
    use uuid::uuid;

    use std::{fs::File, path::Path};

    #[test]
    fn open_kdbx3_with_password() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "sample");

        assert_eq!(db.num_groups(), 5);
        assert_eq!(db.num_entries(), 6);

        Ok(())
    }

    #[test]
    fn open_kdbx3_with_keyfile() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_keyfile.kdbx");
        let kf_path = Path::new("tests/resources/test_key.key");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_keyfile(&mut File::open(kf_path)?)?,
        )?;

        assert_eq!(db.root().name, "Root");

        assert_eq!(db.num_groups(), 1);
        assert_eq!(db.num_entries(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx3_with_keyfile_xml() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_keyfile_xml.kdbx");
        let kf_path = Path::new("tests/resources/test_key_xml.key");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_keyfile(&mut File::open(kf_path)?)?,
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 2);
        assert_eq!(db.root().entries().count(), 2);

        assert_eq!(db.num_groups(), 5);
        assert_eq!(db.num_entries(), 6);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2_cipher_aes() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 2);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2id_cipher_aes() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2id.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 2);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_aes_cipher_aes() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_aes.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2_cipher_twofish() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2_twofish.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2_cipher_chacha20() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2_chacha20.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2id_cipher_twofish() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2id_twofish.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_kdf_argon2id_cipher_chacha20() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2id_chacha20.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_keyfile() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_keyfile.kdbx");
        let kf_path = Path::new("tests/resources/test_key.key");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_keyfile(&mut File::open(kf_path)?)?,
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_keyfile_v2() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_keyfile_v2.kdbx");
        let kf_path = Path::new("tests/resources/test_db_kdbx4_with_keyfile_v2.keyx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new()
                .with_password("demopass")
                .with_keyfile(&mut File::open(kf_path)?)?,
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 1);

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
    fn open_kdb_with_password() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdb_with_password.kdb");
        let db = Database::open(&mut File::open(path)?, DatabaseKey::new().with_password("foobar"))?;

        assert_eq!(db.root().groups().count(), 3);
        assert_eq!(db.root().entries().count(), 0);

        assert_eq!(db.num_groups(), 12);
        assert_eq!(db.num_entries(), 5);

        Ok(())
    }

    #[test]
    fn open_kdb_with_larger_than_1mb_file_does_not_crash() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdb3_with_file_larger_1mb.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("samplepassword"),
        )?;

        assert_eq!(db.root().groups().count(), 0);
        assert_eq!(db.root().entries().count(), 1);

        assert_eq!(db.num_groups(), 1);
        assert_eq!(db.num_entries(), 1);

        Ok(())
    }

    #[test]
    fn open_kdbx4_with_password_deleted_entry() -> Result<()> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_password_deleted_entry.kdbx");

        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("demopass"),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(
            db.meta.recyclebin_uuid,
            Some(uuid!("563171fe-6598-42dc-8003-f98dde32e872"))
        );

        let recycle_group = db.recycle_bin();
        assert!(recycle_group.is_some());

        let recycle_group = recycle_group.unwrap();

        assert_eq!(recycle_group.name, "Recycle Bin");
        assert_eq!(recycle_group.groups().count(), 0);
        assert_eq!(recycle_group.entries().count(), 1);

        Ok(())
    }

    #[test]
    #[cfg(feature = "challenge_response")]
    fn open_kdbx4_with_challenge_response_key() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_challenge_response_key.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new()
                .with_password("demopass")
                .with_challenge_response_key(keepass::ChallengeResponseKey::LocalChallenge(
                    "0102030405060708090a0b0c0d0e0f1011121314".to_string(),
                )),
        )?;

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().entries().count(), 2);
        Ok(())
    }

    #[test]
    #[ignore]
    #[cfg(feature = "challenge_response")]
    fn open_kdbx4_with_yubikey_challenge_response_key() -> Result<()> {
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

        assert_eq!(db.root().name, "Root");
        assert_eq!(db.root().entries().count(), 2);
        Ok(())
    }

    #[test]
    fn test_get_version() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let version = Database::get_version(&mut File::open(path)?)?;
        assert_eq!(version.to_string(), "KDBX3.1");

        let path = Path::new("tests/resources/test_db_kdbx4_with_password_argon2.kdbx");
        let version = Database::get_version(&mut File::open(path)?)?;
        assert_eq!(version.to_string(), "KDBX4.0");

        Ok(())
    }
}
