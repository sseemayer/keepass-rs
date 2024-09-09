#[cfg(feature = "save_kdbx4")]
pub mod dump;
pub mod parse;

/// In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00.
/// This function returns the epoch baseline used by KDBX for date serialization.
pub fn get_epoch_baseline() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap()
}

#[cfg(feature = "save_kdbx4")]
#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use secstr::SecStr;
    use std::collections::HashMap;
    use uuid::uuid;

    use crate::{
        config::{DatabaseConfig, InnerCipherConfig},
        db::{
            entry::History,
            meta::{BinaryAttachments, CustomIcons, Icon, MemoryProtection},
            AutoType, AutoTypeAssociation, BinaryAttachment, CustomData, CustomDataItem, Database,
            DeletedObject, Entry, Group, Meta, Node, Times, Value,
        },
        format::kdbx4,
        key::DatabaseKey,
        xml_db::dump::DumpXml,
    };

    fn make_key() -> DatabaseKey {
        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        DatabaseKey::new().with_password(&password)
    }

    #[test]
    pub fn test_entry() {
        let mut root_group = Group::new("Root");
        let mut entry = Entry::new();

        entry
            .fields
            .insert("Title".to_string(), Value::Unprotected("ASDF".to_string()));
        entry
            .fields
            .insert("UserName".to_string(), Value::Unprotected("ghj".to_string()));
        entry.fields.insert(
            "Password".to_string(),
            Value::Protected(std::str::from_utf8(b"klmno").unwrap().into()),
        );
        entry.tags.push("test".to_string());
        entry.tags.push("keepass-rs".to_string());
        entry.times.expires = true;
        entry.times.usage_count = 42;
        entry.times.set_creation(NaiveDateTime::default());
        entry.times.set_expiry(NaiveDateTime::default());
        entry.times.set_last_access(NaiveDateTime::default());
        entry.times.set_location_changed(Times::now());
        entry.times.set_last_modification(Times::now());

        entry.autotype = Some(AutoType {
            enabled: true,
            sequence: Some("Autotype-sequence".to_string()),
            associations: vec![
                AutoTypeAssociation {
                    window: Some("window-1".to_string()),
                    sequence: Some("sequence-1".to_string()),
                },
                AutoTypeAssociation {
                    window: None,
                    sequence: None,
                },
            ],
        });

        entry.custom_data.items.insert(
            "CDI-key".to_string(),
            CustomDataItem {
                value: Some(Value::Unprotected("CDI-Value".to_string())),
                last_modification_time: Some(NaiveDateTime::default()),
            },
        );

        entry.icon_id = Some(123);
        entry.custom_icon_uuid = Some(uuid!("22222222222222222222222222222222"));

        entry.foreground_color = Some("#C0FFEE".parse().unwrap());
        entry.background_color = Some("#1C1357".parse().unwrap());

        entry.override_url = Some("https://docs.rs/keepass-rs/".to_string());
        entry.quality_check = Some(true);

        let mut history = History::default();
        history.entries.push(entry.clone());

        entry.history = Some(history);

        root_group.add_child(entry.clone());

        let mut db = Database::new(DatabaseConfig::default());
        db.root = root_group;

        let db_key = make_key();

        let mut encrypted_db = Vec::new();
        kdbx4::dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();
        let decrypted_db = kdbx4::parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(_) => panic!("Was expecting an entry as the only child."),
        };

        assert_eq!(decrypted_entry, &entry);
    }

    #[test]
    pub fn test_group() {
        let group = Group::new("");
        let mut inner_cipher = InnerCipherConfig::Plain.get_cipher(&[]).unwrap();
        let mut writer = xml::EventWriter::new(Vec::new());
        let _v = group.dump_xml(&mut writer, &mut *inner_cipher).unwrap();
        let xml = writer.into_inner();
        assert!(String::from_utf8(xml).unwrap().contains("<Name />"));

        let mut root_group = Group::new("Root");
        let mut entry = Entry::new();
        let new_entry_uuid = entry.uuid.clone();
        entry
            .fields
            .insert("Title".to_string(), Value::Unprotected("ASDF".to_string()));

        root_group.add_child(entry);

        let mut subgroup = Group::new("Child group");
        subgroup.notes = Some("I am a subgroup".to_string());
        subgroup.icon_id = Some(42);
        subgroup.custom_icon_uuid = Some(uuid!("11111111111111111111111111111111"));
        subgroup.times.expires = true;
        subgroup.times.usage_count = 100;
        subgroup.times.set_creation(NaiveDateTime::default());
        subgroup.times.set_expiry(NaiveDateTime::default());
        subgroup.times.set_last_access(NaiveDateTime::default());
        subgroup.times.set_location_changed(Times::now());
        subgroup.times.set_last_modification(Times::now());
        subgroup.is_expanded = true;
        subgroup.default_autotype_sequence =
            Some("{UP}{UP}{DOWN}{DOWN}{LEFT}{RIGHT}{LEFT}{RIGHT}BA".to_string());
        subgroup.enable_autotype = Some("yes".to_string());
        subgroup.enable_searching = Some("sure".to_string());

        subgroup.last_top_visible_entry = Some(uuid!("43210000000000000000000000000000"));

        subgroup.custom_data.items.insert(
            "CustomOption".to_string(),
            CustomDataItem {
                value: Some(Value::Unprotected("CustomOption-Value".to_string())),
                last_modification_time: Some(NaiveDateTime::default()),
            },
        );

        root_group.add_child(subgroup);

        let mut db = Database::new(DatabaseConfig::default());
        db.root = root_group.clone();

        let db_key = make_key();

        let mut encrypted_db = Vec::new();
        kdbx4::dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();
        let decrypted_db = kdbx4::parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 2);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(_) => panic!("Was expecting an entry as the first child."),
        };

        assert_eq!(decrypted_entry.get_title(), Some("ASDF"));
        assert_eq!(decrypted_entry.get_uuid(), &new_entry_uuid);

        assert_eq!(&decrypted_db.root, &root_group);
    }

    #[test]
    pub fn test_meta() {
        let mut db = Database::new(DatabaseConfig::default());

        let meta = Meta {
            generator: Some("test-generator".to_string()),
            database_name: Some("test-database-name".to_string()),
            database_name_changed: Some("2000-12-31T12:34:56".parse().unwrap()),
            database_description: Some("test-database-description".to_string()),
            database_description_changed: Some("2000-12-31T12:34:57".parse().unwrap()),
            default_username: Some("test-default-username".to_string()),
            default_username_changed: Some("2000-12-31T12:34:58".parse().unwrap()),
            maintenance_history_days: Some(123),
            color: Some("#C0FFEE".parse().unwrap()),
            master_key_changed: Some("2000-12-31T12:34:59".parse().unwrap()),
            master_key_change_rec: Some(-1),
            master_key_change_force: Some(42),
            memory_protection: Some(MemoryProtection {
                protect_title: true,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: true,
            }),
            custom_icons: CustomIcons {
                icons: vec![Icon {
                    uuid: uuid!("a1a2a3a4b1bffffffffffff4d5d6d7d8"),
                    data: b"fake-data".to_vec(),
                }],
            },
            recyclebin_enabled: Some(true),
            recyclebin_uuid: Some(uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8")),
            recyclebin_changed: Some("2000-12-31T12:35:00".parse().unwrap()),
            entry_templates_group: Some(uuid!("123456789abcdef0d1d2d3d4d5d6d7d8")),
            entry_templates_group_changed: Some("2000-12-31T12:35:01".parse().unwrap()),
            last_selected_group: Some(uuid!("fffffffffffff1c2d1d2d3d4d5d6d7d8")),
            last_top_visible_group: Some(uuid!("a1a2a3a4b1b2c1c2d1d2d3ffffffffff")),
            history_max_items: Some(456),
            history_max_size: Some(789),
            settings_changed: Some("2000-12-31T12:35:02".parse().unwrap()),
            binaries: BinaryAttachments {
                binaries: vec![
                    BinaryAttachment {
                        identifier: Some("1".to_string()),
                        compressed: false,
                        content: b"i am binary data".to_vec(),
                    },
                    BinaryAttachment {
                        identifier: Some("2".to_string()),
                        compressed: true,
                        content: b"i am compressed binary data".to_vec(),
                    },
                    BinaryAttachment {
                        identifier: None,
                        compressed: true,
                        content: b"i am compressed binary data without an identifier".to_vec(),
                    },
                ],
            },
            custom_data: CustomData {
                items: HashMap::from([
                    (
                        "custom-data-key".to_string(),
                        CustomDataItem {
                            value: Some(Value::Unprotected("custom-data-value".to_string())),
                            last_modification_time: Some("2000-12-31T12:35:03".parse().unwrap()),
                        },
                    ),
                    (
                        "custom-data-key-without-value".to_string(),
                        CustomDataItem {
                            value: None,
                            last_modification_time: None,
                        },
                    ),
                    (
                        "custom-data-protected-key".to_string(),
                        CustomDataItem {
                            value: Some(Value::Protected(SecStr::new(b"custom-data-value".to_vec()))),
                            last_modification_time: Some("2000-12-31T12:35:03".parse().unwrap()),
                        },
                    ),
                ]),
            },
        };

        db.meta = meta.clone();

        let db_key = make_key();

        let mut encrypted_db = Vec::new();
        kdbx4::dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();
        let decrypted_db = kdbx4::parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db.meta, meta);
    }

    #[test]
    fn test_deleted_objects() {
        let mut db = Database::new(DatabaseConfig::default());
        db.deleted_objects.objects = vec![
            DeletedObject {
                uuid: uuid!("123e4567-e89b-12d3-a456-426655440000"),
                deletion_time: "2000-12-31T12:34:56".parse().unwrap(),
            },
            DeletedObject {
                uuid: uuid!("00112233-4455-6677-8899-aabbccddeeff"),
                deletion_time: "2000-12-31T12:35:00".parse().unwrap(),
            },
        ];

        let db_key = make_key();

        let mut encrypted_db = Vec::new();
        kdbx4::dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();
        let decrypted_db = kdbx4::parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db, db);
    }
}
