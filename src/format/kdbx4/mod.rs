#[cfg(feature = "save_kdbx4")]
mod dump;
mod parse;

use crate::{
    config::{CompressionConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    format::variant_dictionary::VariantDictionary,
};

#[cfg(feature = "save_kdbx4")]
pub(crate) use crate::format::kdbx4::dump::dump_kdbx4;
pub(crate) use crate::format::kdbx4::parse::{decrypt_kdbx4, parse_kdbx4};

pub use crate::format::kdbx4::parse::{Kdbx4InnerHeaderError, Kdbx4OpenError, Kdbx4OuterHeaderError};

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
/// Custom data of plugins/ports.
pub const HEADER_PUBLIC_CUSTOM_DATA: u8 = 12;

/// Inner header entry denoting the end of the inner header
pub const INNER_HEADER_END: u8 = 0x00;
/// Inner header entry denoting the UUID of the inner cipher
pub const INNER_HEADER_RANDOM_STREAM_ID: u8 = 0x01;
/// Inner header entry denoting the key of the inner cipher
pub const INNER_HEADER_RANDOM_STREAM_KEY: u8 = 0x02;
/// Inner header entry denoting a binary attachment
pub const INNER_HEADER_BINARY_ATTACHMENTS: u8 = 0x03;

struct KDBX4OuterHeader {
    outer_cipher_config: OuterCipherConfig,
    compression_config: CompressionConfig,
    master_seed: Vec<u8>,
    outer_iv: Vec<u8>,
    kdf_config: KdfConfig,
    kdf_seed: Vec<u8>,
    public_custom_data: Option<VariantDictionary>,
}

struct KDBX4InnerHeader {
    inner_random_stream: InnerCipherConfig,
    inner_random_stream_key: Vec<u8>,
}

#[cfg(feature = "save_kdbx4")]
#[cfg(test)]
mod kdbx4_tests {
    use super::*;

    use crate::db::{fields, Value};
    use crate::format::kdbx4::dump::dump_kdbx4;
    use crate::format::DatabaseVersion;
    use crate::{
        config::{CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
        db::Database,
        format::KDBX4_CURRENT_MINOR_VERSION,
        key::DatabaseKey,
    };

    #[cfg(feature = "challenge_response")]
    #[test]
    fn test_with_challenge_response() {
        let mut db = Database::new();

        db.root_mut().add_entry();
        db.root_mut().add_entry();
        db.root_mut().add_entry();

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::fill(&mut password_bytes).unwrap();
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

        assert_eq!(decrypted_db.num_entries(), 3);
    }

    fn test_with_config(config: DatabaseConfig) {
        let mut db = Database::with_config(config);

        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Demo Entry");
            e.set_protected(fields::PASSWORD, "secret")
        });

        db.root_mut().add_entry();
        db.root_mut().add_entry();

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::fill(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let db_key = DatabaseKey::new().with_password(&password);

        let mut encrypted_db = Vec::new();
        dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();

        let decrypted_db = parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db.num_entries(), 3);

        let root = decrypted_db.root();
        let entry = root.entry_by_name("Demo Entry").unwrap();
        assert_eq!(entry.get_password(), Some("secret"));
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
                            public_custom_data: Default::default(),
                        };

                        println!("Testing with config: {config:?}");

                        test_with_config(config);
                    }
                }
            }
        }
    }

    #[test]
    pub fn attachments() {
        let mut db = Database::new();

        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Demo entry");

            e.add_attachment("file1.txt", Value::protected(vec![0x01, 0x02, 0x03, 0x04]));
            e.add_attachment("file2.txt", Value::unprotected(vec![0x04, 0x03, 0x02, 0x01]));
        });

        let db_key = DatabaseKey::new().with_password("test");

        let mut encrypted_db = Vec::new();
        dump_kdbx4(&db, &db_key, &mut encrypted_db).unwrap();

        let decrypted_db = parse_kdbx4(&encrypted_db, &db_key).unwrap();

        assert_eq!(decrypted_db.num_entries(), 1);

        let root = decrypted_db.root();

        let entry = root.entry_by_name("Demo entry").unwrap();

        assert_eq!(entry.attachments().count(), 2);

        assert!(entry.attachment_by_name("file1.txt").is_some());
        assert!(entry.attachment_by_name("file1.txt").unwrap().is_protected());
        assert_eq!(
            entry.attachment_by_name("file1.txt").unwrap().get(),
            &[0x01, 0x02, 0x03, 0x04]
        );

        assert!(entry.attachment_by_name("file2.txt").is_some());
        assert!(!entry.attachment_by_name("file2.txt").unwrap().is_protected());
        assert_eq!(
            entry.attachment_by_name("file2.txt").unwrap().get(),
            &[0x04, 0x03, 0x02, 0x01]
        );
    }
}
