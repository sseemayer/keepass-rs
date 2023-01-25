pub mod dump;
pub mod parse;

/// In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00.
/// This function returns the epoch baseline used by KDBX for date serialization.
pub fn get_epoch_baseline() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap()
}

#[cfg(test)]
mod tests {
    use crate::{
        config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
        parse::kdbx4,
        Database, Entry, Group, Node,
    };

    #[test]
    pub fn test_entry() {
        let mut root_group = Group::new("Root");
        let mut entry = Entry::new();
        let new_entry_uuid = entry.uuid.clone();

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

        root_group.children.push(Node::Entry(entry));

        let db = Database::new(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 65536,
                parallelism: 1,
                version: argon2::Version::Version13,
            },
            root_group,
            vec![],
        )
        .unwrap();

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = Database::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = kdbx4::dump(&db, &key_elements).unwrap();

        let decrypted_db = kdbx4::parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(_) => panic!("Was expecting an entry as the only child."),
        };

        assert_eq!(decrypted_entry.get_uuid(), new_entry_uuid);
        assert_eq!(decrypted_entry.get_title(), Some("ASDF"));
        assert_eq!(decrypted_entry.get_username(), Some("ghj"));
        assert_eq!(decrypted_entry.get("Password"), Some("klmno"));
        assert_eq!(
            decrypted_entry.tags,
            vec!["keepass-rs".to_string(), "test".to_string()]
        );
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

        let db = Database::new(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 65536,
                parallelism: 1,
                version: argon2::Version::Version13,
            },
            root_group,
            vec![],
        )
        .unwrap();

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = Database::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = kdbx4::dump(&db, &key_elements).unwrap();

        let decrypted_db = kdbx4::parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(_) => panic!("Was expecting an entry as the only child."),
        };

        assert_eq!(decrypted_entry.get_title(), Some("ASDF"));
        assert_eq!(decrypted_entry.get_uuid(), new_entry_uuid);

        let decrypted_root_group = &decrypted_db.root;
        assert_eq!(decrypted_root_group.name, "Root");
    }
}
