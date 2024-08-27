#[cfg(feature = "save_kdbx4")]
mod dump;
mod parse;

use crate::{
    config::{CompressionConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    format::DatabaseVersion,
};

#[cfg(feature = "save_kdbx4")]
pub(crate) use crate::format::kdbx4::dump::dump_kdbx4;
pub(crate) use crate::format::kdbx4::parse::{decrypt_kdbx4, parse_kdbx4};

#[cfg(feature = "save_kdbx4")]
/// Size for a master seed in bytes
pub const HEADER_MASTER_SEED_SIZE: usize = 32;

/// Header entry denoting the end of the header
pub const HEADER_END: u8 = 0;
/// Header entry denoting a comment
pub const HEADER_COMMENT: u8 = 1;
/// A UUID specifying which cipher suite should be used to encrypt the payload
pub const HEADER_OUTER_ENCRYPTION_ID: u8 = 2;
/// First byte determines compression of payload
pub const HEADER_COMPRESSION_ID: u8 = 3;
/// Master seed for deriving the master key
pub const HEADER_MASTER_SEED: u8 = 4;
/// Initialization Vector for decrypting the payload
pub const HEADER_ENCRYPTION_IV: u8 = 7;
/// Parameters for the key derivation function
pub const HEADER_KDF_PARAMS: u8 = 11;

/// Inner header entry denoting the end of the inner header
pub const INNER_HEADER_END: u8 = 0x00;
/// Inner header entry denoting the UUID of the inner cipher
pub const INNER_HEADER_RANDOM_STREAM_ID: u8 = 0x01;
/// Inner header entry denoting the key of the inner cipher
pub const INNER_HEADER_RANDOM_STREAM_KEY: u8 = 0x02;
/// Inner header entry denoting a binary attachment
pub const INNER_HEADER_BINARY_ATTACHMENTS: u8 = 0x03;

struct KDBX4OuterHeader {
    version: DatabaseVersion,
    outer_cipher_config: OuterCipherConfig,
    compression_config: CompressionConfig,
    master_seed: Vec<u8>,
    outer_iv: Vec<u8>,
    kdf_config: KdfConfig,
    kdf_seed: Vec<u8>,
}

struct KDBX4InnerHeader {
    inner_random_stream: InnerCipherConfig,
    inner_random_stream_key: Vec<u8>,
}

#[cfg(feature = "save_kdbx4")]
#[cfg(test)]
mod kdbx4_tests {
    use super::*;

    use crate::format::kdbx4::dump::dump_kdbx4;
    use crate::{
        config::{CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
        db::{Database, Entry, Group, HeaderAttachment, NodeRef, Value},
        format::KDBX4_CURRENT_MINOR_VERSION,
        key::DatabaseKey,
    };

    #[cfg(feature = "challenge_response")]
    #[test]
    fn test_with_challenge_response() {
        let mut db = Database::new(DatabaseConfig::default());

        let mut root_group = Group::new("Root");
        root_group.add_child(Entry::new());
        root_group.add_child(Entry::new());
        root_group.add_child(Entry::new());
        db.root = root_group;

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let db_key = DatabaseKey::new()
            .with_password(&password)
            .with_challenge_response_key(crate::key::ChallengeResponseKey::LocalChallenge(
                "0102030405060708090a0b0c0d0e0f1011121314".to_string(),
            ));

        let mut encrypted_db = Vec::new();
        dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();

        let decrypted_db = parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 3);
    }

    fn test_with_config(config: DatabaseConfig) {
        let mut db = Database::new(config);

        let mut root_group = Group::new("Root");

        let mut entry_with_password = Entry::new();
        entry_with_password
            .fields
            .insert("Title".to_string(), Value::Unprotected("Demo Entry".into()));

        entry_with_password
            .fields
            .insert("Password".to_string(), Value::Protected("secret".into()));

        root_group.add_child(entry_with_password);
        root_group.add_child(Entry::new());
        root_group.add_child(Entry::new());
        db.root = root_group;

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let db_key = DatabaseKey::new().with_password(&password);

        let mut encrypted_db = Vec::new();
        dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();

        let decrypted_db = parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 3);

        if let Some(NodeRef::Entry(e)) = decrypted_db.root.get(&["Demo Entry"]) {
            assert_eq!(e.get_password(), Some("secret"));
        } else {
            panic!("Could not get NodeRef")
        }
    }

    #[test]
    pub fn test_config_matrix() {
        let outer_cipher_configs = [
            OuterCipherConfig::AES256,
            OuterCipherConfig::Twofish,
            OuterCipherConfig::ChaCha20,
        ];

        let compression_configs = [CompressionConfig::None, CompressionConfig::GZip];

        let inner_cipher_configs = [
            InnerCipherConfig::Plain,
            InnerCipherConfig::Salsa20,
            InnerCipherConfig::ChaCha20,
        ];

        let kdf_configs = [
            KdfConfig::Aes { rounds: 10 },
            KdfConfig::Argon2 {
                iterations: 10,
                memory: 65536,
                parallelism: 2,
                version: argon2::Version::Version13,
            },
            KdfConfig::Argon2id {
                iterations: 10,
                memory: 65536,
                parallelism: 2,
                version: argon2::Version::Version13,
            },
        ];

        for outer_cipher_config in &outer_cipher_configs {
            for compression_config in &compression_configs {
                for inner_cipher_config in &inner_cipher_configs {
                    for kdf_config in &kdf_configs {
                        let config = DatabaseConfig {
                            version: DatabaseVersion::KDB4(KDBX4_CURRENT_MINOR_VERSION),
                            outer_cipher_config: outer_cipher_config.clone(),
                            compression_config: compression_config.clone(),
                            inner_cipher_config: inner_cipher_config.clone(),
                            kdf_config: kdf_config.clone(),
                        };

                        println!("Testing with config: {config:?}");

                        test_with_config(config);
                    }
                }
            }
        }
    }

    #[test]
    pub fn header_attachments() {
        let mut root_group = Group::new("Root");
        root_group.add_child(Entry::new());

        let mut db = Database::new(DatabaseConfig::default());

        db.header_attachments = vec![
            HeaderAttachment {
                flags: 1,
                content: vec![0x01, 0x02, 0x03, 0x04],
            },
            HeaderAttachment {
                flags: 2,
                content: vec![0x04, 0x03, 0x02, 0x01],
            },
        ];

        let mut entry = Entry::new();
        entry
            .fields
            .insert("Title".to_string(), Value::Unprotected("Demo entry".to_string()));

        db.root.add_child(entry);

        let db_key = DatabaseKey::new().with_password("test");

        let mut encrypted_db = Vec::new();
        dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();

        let decrypted_db = parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let header_attachments = &decrypted_db.header_attachments;
        assert_eq!(header_attachments.len(), 2);
        assert_eq!(header_attachments[0].flags, 1);
        assert_eq!(header_attachments[0].content, [0x01, 0x02, 0x03, 0x04]);
    }
}
