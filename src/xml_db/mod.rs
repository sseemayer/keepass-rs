pub mod dump;
pub mod parse;

/// In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00.
/// This function returns the epoch baseline used by KDBX for date serialization.
pub fn get_epoch_baseline() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap()
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDateTime;
    use secstr::SecStr;

    use crate::{
        entry::History,
        format::kdbx4,
        meta::{BinaryAttachments, CustomIcons, Icon, MemoryProtection},
        AutoTypeAssociation, BinaryAttachment, CustomData, CustomDataItem, Database, Entry, Group,
        Meta, Node, Value,
    };

    fn make_key() -> Vec<Vec<u8>> {
        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = Database::get_key_elements(Some(&password), None).unwrap();
        key_elements
    }

    #[test]
    pub fn test_entry() {
        let mut root_group = Group::new("Root");
        let mut entry = Entry::new();

        entry.fields.insert(
            "Title".to_string(),
            crate::Value::Unprotected("ASDF".to_string()),
        );
        entry.fields.insert(
            "UserName".to_string(),
            crate::Value::Unprotected("ghj".to_string()),
        );
        entry.fields.insert(
            "Password".to_string(),
            crate::Value::Protected(std::str::from_utf8(b"klmno").unwrap().into()),
        );
        entry.tags.push("test".to_string());
        entry.tags.push("keepass-rs".to_string());
        entry.times.expires = true;
        entry.times.usage_count = 42;
        entry
            .times
            .times
            .insert("Created".to_string(), NaiveDateTime::default());
        entry.autotype = Some(crate::AutoType {
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

        entry.custom_data.items.push(CustomDataItem {
            key: "CDI-key".to_string(),
            value: Some(Value::Unprotected("CDI-Value".to_string())),
            last_modification_time: Some(NaiveDateTime::default()),
        });

        entry.icon_id = Some(123);
        entry.custom_icon_uuid = Some("custom-icon-uuid".to_string());

        entry.foreground_color = Some("#C0FFEE".to_string());
        entry.background_color = Some("#1C1357".to_string());

        entry.override_url = Some("https://docs.rs/keepass-rs/".to_string());
        entry.quality_check = Some(true);

        let mut history = History::default();
        history.entries.push(entry.clone());

        entry.history = Some(history);

        root_group.children.push(Node::Entry(entry.clone()));

        let mut db = Database::new(crate::NewDatabaseSettings::default()).unwrap();
        db.root = root_group;

        let key_elements = make_key();

        let encrypted_db = kdbx4::dump(&db, &key_elements).unwrap();
        let decrypted_db = kdbx4::parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(_) => panic!("Was expecting an entry as the only child."),
        };

        assert_eq!(decrypted_entry, &entry);
    }

    #[test]
    pub fn test_group() {
        let mut root_group = Group::new("Root");
        let mut entry = Entry::new();
        let new_entry_uuid = entry.uuid.clone();
        entry.fields.insert(
            "Title".to_string(),
            crate::Value::Unprotected("ASDF".to_string()),
        );

        root_group.children.push(Node::Entry(entry));

        let mut subgroup = Group::new("Child group");
        subgroup.notes = Some("I am a subgroup".to_string());
        subgroup.icon_id = Some(42);
        subgroup.custom_icon_uuid = Some("CUSTOM-ICON".to_string());
        subgroup.times.expires = true;
        subgroup.times.usage_count = 100;
        subgroup
            .times
            .times
            .insert("Created".to_string(), NaiveDateTime::default());
        subgroup.is_expanded = true;
        subgroup.default_autotype_sequence =
            Some("{UP}{UP}{DOWN}{DOWN}{LEFT}{RIGHT}{LEFT}{RIGHT}BA".to_string());
        subgroup.enable_autotype = Some("yes".to_string());
        subgroup.enable_searching = Some("sure".to_string());

        subgroup.last_top_visible_entry = Some("an-entry".to_string());

        root_group.children.push(Node::Group(subgroup));

        let mut db = Database::new(crate::NewDatabaseSettings::default()).unwrap();
        db.root = root_group.clone();

        let key_elements = make_key();

        let encrypted_db = kdbx4::dump(&db, &key_elements).unwrap();
        let decrypted_db = kdbx4::parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 2);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(_) => panic!("Was expecting an entry as the first child."),
        };

        assert_eq!(decrypted_entry.get_title(), Some("ASDF"));
        assert_eq!(decrypted_entry.get_uuid(), new_entry_uuid);

        assert_eq!(&decrypted_db.root, &root_group);
    }

    #[test]
    pub fn test_meta() {
        let mut db = Database::new(crate::NewDatabaseSettings::default()).unwrap();

        let meta = Meta {
            generator: Some("test-generator".to_string()),
            database_name: Some("test-database-name".to_string()),
            database_name_changed: Some("2000-12-31T12:34:56".parse().unwrap()),
            database_description: Some("test-database-description".to_string()),
            database_description_changed: Some("2000-12-31T12:34:57".parse().unwrap()),
            default_username: Some("test-default-username".to_string()),
            default_username_changed: Some("2000-12-31T12:34:58".parse().unwrap()),
            maintenance_history_days: Some(123),
            color: Some("#C0FFEE".to_string()),
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
                    uuid: "a-fake-uuid".to_string(),
                    data: b"fake-data".to_vec(),
                }],
            },
            recyclebin_enabled: Some(true),
            recyclebin_uuid: Some("another-fake-uuid".to_string()),
            recyclebin_changed: Some("2000-12-31T12:35:00".parse().unwrap()),
            entry_templates_group: Some("even-more-fake-uuid".to_string()),
            entry_templates_group_changed: Some("2000-12-31T12:35:01".parse().unwrap()),
            last_selected_group: Some("so-many-fake-uuids".to_string()),
            last_top_visible_group: Some("hey-another-fake-uuid".to_string()),
            history_max_items: Some(456),
            history_max_size: Some(789),
            settings_changed: Some("2000-12-31T12:35:02".parse().unwrap()),
            binaries: BinaryAttachments {
                binaries: vec![
                    BinaryAttachment {
                        identifier: Some("1".to_string()),
                        flags: 0,
                        compressed: false,
                        content: b"i am binary data".to_vec(),
                    },
                    BinaryAttachment {
                        identifier: Some("2".to_string()),
                        flags: 0,
                        compressed: true,
                        content: b"i am compressed binary data".to_vec(),
                    },
                    BinaryAttachment {
                        identifier: None,
                        flags: 0,
                        compressed: true,
                        content: b"i am compressed binary data without an identifier".to_vec(),
                    },
                ],
            },
            custom_data: CustomData {
                items: vec![
                    CustomDataItem {
                        key: "custom-data-key".to_string(),
                        value: Some(Value::Unprotected("custom-data-value".to_string())),
                        last_modification_time: Some("2000-12-31T12:35:03".parse().unwrap()),
                    },
                    CustomDataItem {
                        key: "custom-data-key-without-value".to_string(),
                        value: None,
                        last_modification_time: None,
                    },
                    CustomDataItem {
                        key: "custom-data-protected-key".to_string(),
                        value: Some(Value::Protected(SecStr::new(b"custom-data-value".to_vec()))),
                        last_modification_time: Some("2000-12-31T12:35:03".parse().unwrap()),
                    },
                ],
            },
        };

        db.meta = meta.clone();

        let key_elements = make_key();

        let encrypted_db = kdbx4::dump(&db, &key_elements).unwrap();
        let decrypted_db = kdbx4::parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.meta, meta);
    }
}
