mod dump;
mod parse;

use crate::{
    config::{CompressionConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    format::DatabaseVersion,
};

pub(crate) use crate::format::kdbx4::dump::dump_kdbx4;
pub(crate) use crate::format::kdbx4::parse::{decrypt_kdbx4, parse_kdbx4};

pub const HEADER_MASTER_SEED_SIZE: usize = 32;

pub const HEADER_END: u8 = 0;
pub const HEADER_COMMENT: u8 = 1;
// A UUID specifying which cipher suite
// should be used to encrypt the payload
pub const HEADER_OUTER_ENCRYPTION_ID: u8 = 2;
// First byte determines compression of payload
pub const HEADER_COMPRESSION_ID: u8 = 3;
// Master seed for deriving the master key
pub const HEADER_MASTER_SEED: u8 = 4;
// Initialization Vector for decrypting the payload
pub const HEADER_ENCRYPTION_IV: u8 = 7;
pub const HEADER_KDF_PARAMS: u8 = 11;

pub const INNER_HEADER_END: u8 = 0x00;
/// The ID of the inner header random stream
pub const INNER_HEADER_RANDOM_STREAM_ID: u8 = 0x01;
pub const INNER_HEADER_RANDOM_STREAM_KEY: u8 = 0x02;
pub const INNER_HEADER_BINARY_ATTACHMENTS: u8 = 0x03;

struct KDBX4OuterHeader {
    version: DatabaseVersion,
    outer_cipher_suite: OuterCipherConfig,
    compression: CompressionConfig,
    master_seed: Vec<u8>,
    outer_iv: Vec<u8>,
    kdf_settings: KdfConfig,
    kdf_seed: Vec<u8>,
}

struct KDBX4InnerHeader {
    inner_random_stream: InnerCipherConfig,
    inner_random_stream_key: Vec<u8>,
}

#[cfg(test)]
mod kdbx4_tests {
    use super::*;

    use crate::{
        config::{CompressionConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
        db::{Database, DatabaseSettings, Entry, Group, HeaderAttachment, Node, Value},
        format::{kdbx4::dump::dump_kdbx4, KDBX4_CURRENT_MINOR_VERSION},
        key::Key,
    };

    fn test_with_settings(
        outer_cipher_suite: OuterCipherConfig,
        compression: CompressionConfig,
        inner_cipher_suite: InnerCipherConfig,
        kdf_setting: KdfConfig,
    ) {
        let mut db = Database::new(DatabaseSettings {
            version: DatabaseVersion::KDB4(KDBX4_CURRENT_MINOR_VERSION),
            outer_cipher_suite,
            compression,
            inner_cipher_suite,
            kdf_settings: kdf_setting,
        });

        let mut root_group = Group::new("Root");
        root_group.children.push(Node::Entry(Entry::new()));
        root_group.children.push(Node::Entry(Entry::new()));
        root_group.children.push(Node::Entry(Entry::new()));
        db.root = root_group;

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = Key::with_password(&password).get_key_elements().unwrap();

        let mut encrypted_db = Vec::new();
        dump_kdbx4(&db, &key_elements, &mut encrypted_db).unwrap();

        let decrypted_db = parse_kdbx4(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 3);
    }

    #[test]
    pub fn aes256_chacha20_aes() {
        test_with_settings(
            OuterCipherConfig::AES256,
            CompressionConfig::GZip,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Aes { rounds: 100 },
        );
    }

    #[test]
    pub fn aes256_chacha20_argon2() {
        test_with_settings(
            OuterCipherConfig::AES256,
            CompressionConfig::GZip,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Argon2 {
                iterations: 1000,
                memory: 65536,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn aes256_chacha20_argon2_no_compression() {
        test_with_settings(
            OuterCipherConfig::AES256,
            CompressionConfig::GZip,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Argon2 {
                iterations: 1000,
                memory: 65536,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn aes256_salsa20_aes() {
        test_with_settings(
            OuterCipherConfig::AES256,
            CompressionConfig::GZip,
            InnerCipherConfig::Salsa20,
            KdfConfig::Aes { rounds: 100 },
        );
    }

    #[test]
    pub fn aes256_salsa20_argon2() {
        test_with_settings(
            OuterCipherConfig::AES256,
            CompressionConfig::GZip,
            InnerCipherConfig::Salsa20,
            KdfConfig::Argon2 {
                iterations: 100,
                memory: 65536,
                parallelism: 1,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn chacha20_chacha20_aes() {
        test_with_settings(
            OuterCipherConfig::ChaCha20,
            CompressionConfig::GZip,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Aes { rounds: 100 },
        );
    }

    #[test]
    pub fn chacha20_chacha20_aes_no_compression() {
        test_with_settings(
            OuterCipherConfig::ChaCha20,
            CompressionConfig::None,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Aes { rounds: 100 },
        );
    }

    #[test]
    pub fn chacha20_chacha20_argon2() {
        test_with_settings(
            OuterCipherConfig::ChaCha20,
            CompressionConfig::GZip,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Argon2 {
                iterations: 1000,
                memory: 65536,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn chacha20_chacha20_argon2_no_compression() {
        test_with_settings(
            OuterCipherConfig::ChaCha20,
            CompressionConfig::None,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Argon2 {
                iterations: 1000,
                memory: 65536,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn twofish_chacha20_aes() {
        test_with_settings(
            OuterCipherConfig::Twofish,
            CompressionConfig::GZip,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Aes { rounds: 100 },
        );
    }

    #[test]
    pub fn twofish_chacha20_aes_no_compression() {
        test_with_settings(
            OuterCipherConfig::Twofish,
            CompressionConfig::None,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Aes { rounds: 100 },
        );
    }

    #[test]
    pub fn twofish_chacha20_argon2() {
        test_with_settings(
            OuterCipherConfig::Twofish,
            CompressionConfig::GZip,
            InnerCipherConfig::ChaCha20,
            KdfConfig::Argon2 {
                iterations: 1000,
                memory: 65536,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn header_attachments() {
        let mut root_group = Group::new("Root");
        root_group.children.push(Node::Entry(Entry::new()));

        let mut db = Database::new(DatabaseSettings::default());

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
        entry.fields.insert(
            "Title".to_string(),
            Value::Unprotected("Demo entry".to_string()),
        );

        db.root.children.push(Node::Entry(entry));

        let key_elements = Key::with_password("test").get_key_elements().unwrap();

        let mut encrypted_db = Vec::new();
        dump_kdbx4(&db, &key_elements, &mut encrypted_db).unwrap();

        let decrypted_db = parse_kdbx4(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let header_attachments = &decrypted_db.header_attachments;
        assert_eq!(header_attachments.len(), 2);
        assert_eq!(header_attachments[0].flags, 1);
        assert_eq!(header_attachments[0].content, [0x01, 0x02, 0x03, 0x04]);
    }
}
