use std::convert::TryFrom;
use std::convert::TryInto;

use crate::meta::BinaryAttachment;
use crate::{
    config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
    crypt,
    db::{Database, Header, InnerHeader},
    hmac_block_stream,
    parse::DatabaseVersion,
    variant_dictionary::VariantDictionary,
    DatabaseIntegrityError, DatabaseKeyError, DatabaseOpenError, DatabaseSaveError,
};

use byteorder::{ByteOrder, LittleEndian};

pub const HEADER_MASTER_SEED_SIZE: u8 = 32;

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

#[derive(Debug)]
pub struct KDBX4Header {
    // https://gist.github.com/msmuenchen/9318327
    pub version: DatabaseVersion,
    pub outer_cipher: OuterCipherSuite,
    pub compression: Compression,
    pub master_seed: Vec<u8>,
    pub outer_iv: Vec<u8>,
    pub kdf: KdfSettings,
}

impl From<&[u8]> for BinaryAttachment {
    fn from(data: &[u8]) -> Self {
        let flags = data[0];
        let content = data[1..].to_vec();

        BinaryAttachment {
            identifier: None,
            compressed: false,
            flags,
            content,
        }
    }
}

impl BinaryAttachment {
    fn dump(&self) -> Vec<u8> {
        let mut attachment: Vec<u8> = vec![self.flags];
        attachment.extend_from_slice(&self.content.clone());
        attachment
    }
}

#[derive(Debug)]
pub struct KDBX4InnerHeader {
    pub inner_random_stream: InnerCipherSuite,
    pub inner_random_stream_key: Vec<u8>,
    pub binaries: Vec<BinaryAttachment>,
}

fn dump_outer_header(header: &KDBX4Header) -> Result<Vec<u8>, DatabaseSaveError> {
    let mut header_data: Vec<u8> = vec![];
    header_data.extend_from_slice(&header.version.dump());

    write_header_field(
        &mut header_data,
        HEADER_OUTER_ENCRYPTION_ID,
        &header.outer_cipher.dump(),
    );

    write_header_field(
        &mut header_data,
        HEADER_COMPRESSION_ID,
        &header.compression.dump(),
    );

    write_header_field(&mut header_data, HEADER_ENCRYPTION_IV, &header.outer_iv);

    write_header_field(&mut header_data, HEADER_MASTER_SEED, &header.master_seed);

    let vd: VariantDictionary = header.kdf.dump();
    write_header_field(&mut header_data, HEADER_KDF_PARAMS, &vd.dump());

    write_header_field(&mut header_data, HEADER_END, &[]);

    Ok(header_data)
}

fn write_header_field(header_data: &mut Vec<u8>, field_id: u8, field_value: &[u8]) {
    header_data.push(field_id);
    let pos = header_data.len();
    header_data.resize(pos + 4, 0);
    LittleEndian::write_u32(
        &mut header_data[pos..pos + 4],
        field_value.len().try_into().unwrap(),
    );
    header_data.extend_from_slice(field_value);
}

fn parse_outer_header(data: &[u8]) -> Result<(KDBX4Header, usize), DatabaseOpenError> {
    let database_version = DatabaseVersion::parse(data)?;
    // skip over the version header
    let mut pos = DatabaseVersion::get_version_header_size();

    let mut outer_cipher: Option<OuterCipherSuite> = None;
    let mut compression: Option<Compression> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut kdf: Option<KdfSettings> = None;

    // parse header
    loop {
        // parse header blocks.
        //
        // every block is a triplet of (3 + entry_length) bytes with this structure:
        //
        // (
        //   entry_type: u8,                        // a numeric entry type identifier
        //   entry_length: u32,                     // length of the entry buffer
        //   entry_buffer: [u8; entry_length]       // the entry buffer
        // )

        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u32(&data[pos + 1..(pos + 5)]) as usize;
        let entry_buffer = &data[(pos + 5)..(pos + 5 + entry_length)];

        pos += 5 + entry_length;

        match entry_type {
            HEADER_END => {
                break;
            }

            HEADER_COMMENT => {}

            HEADER_OUTER_ENCRYPTION_ID => {
                outer_cipher = Some(OuterCipherSuite::try_from(entry_buffer)?);
            }

            HEADER_COMPRESSION_ID => {
                compression = Some(Compression::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
            }

            HEADER_MASTER_SEED => master_seed = Some(entry_buffer.to_vec()),

            HEADER_ENCRYPTION_IV => outer_iv = Some(entry_buffer.to_vec()),

            HEADER_KDF_PARAMS => {
                let vd = VariantDictionary::parse(entry_buffer)?;
                kdf = Some(KdfSettings::try_from(vd)?);
            }

            _ => {
                return Err(DatabaseIntegrityError::InvalidOuterHeaderEntry { entry_type }.into());
            }
        };
    }

    // at this point, the header needs to be fully defined - unwrap options and return errors if
    // something is missing

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T, DatabaseIntegrityError> {
        v.ok_or_else(|| {
            DatabaseIntegrityError::IncompleteOuterHeader {
                missing_field: err.into(),
            }
            .into()
        })
    }

    let outer_cipher = get_or_err(outer_cipher, "Outer Cipher ID")?;
    let compression = get_or_err(compression, "Compression ID")?;
    let master_seed = get_or_err(master_seed, "Master seed")?;
    let outer_iv = get_or_err(outer_iv, "Outer IV")?;
    let kdf = get_or_err(kdf, "Key Derivation Function Parameters")?;

    Ok((
        KDBX4Header {
            version: database_version,
            outer_cipher,
            compression,
            master_seed,
            outer_iv,
            kdf,
        },
        pos,
    ))
}

fn parse_inner_header(data: &[u8]) -> Result<(KDBX4InnerHeader, usize), DatabaseOpenError> {
    let mut pos = 0;

    let mut inner_random_stream = None;
    let mut inner_random_stream_key = None;
    let mut binaries = Vec::new();

    loop {
        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u32(&data[pos + 1..(pos + 5)]) as usize;
        let entry_buffer = &data[(pos + 5)..(pos + 5 + entry_length)];

        pos += 5 + entry_length;

        match entry_type {
            INNER_HEADER_END => break,

            INNER_HEADER_RANDOM_STREAM_ID => {
                inner_random_stream = Some(InnerCipherSuite::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
            }

            INNER_HEADER_RANDOM_STREAM_KEY => inner_random_stream_key = Some(entry_buffer.to_vec()),

            INNER_HEADER_BINARY_ATTACHMENTS => {
                let binary = BinaryAttachment::from(entry_buffer);
                binaries.push(binary);
            }

            _ => {
                return Err(DatabaseIntegrityError::InvalidInnerHeaderEntry { entry_type }.into());
            }
        }
    }

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T, DatabaseIntegrityError> {
        v.ok_or_else(|| {
            DatabaseIntegrityError::IncompleteInnerHeader {
                missing_field: err.into(),
            }
            .into()
        })
    }

    let inner_random_stream = get_or_err(inner_random_stream, "Inner random stream UUID")?;
    let inner_random_stream_key = get_or_err(inner_random_stream_key, "Inner random stream key")?;

    Ok((
        KDBX4InnerHeader {
            inner_random_stream,
            inner_random_stream_key,
            binaries,
        },
        pos,
    ))
}

fn dump_inner_header(inner_header: &KDBX4InnerHeader) -> Vec<u8> {
    let mut header_data: Vec<u8> = vec![];

    let mut random_stream_data: Vec<u8> = vec![];
    random_stream_data.resize(4, 0);
    LittleEndian::write_u32(
        &mut random_stream_data[0..4],
        inner_header.inner_random_stream.dump(),
    );
    write_header_field(
        &mut header_data,
        INNER_HEADER_RANDOM_STREAM_ID,
        &random_stream_data,
    );

    write_header_field(
        &mut header_data,
        INNER_HEADER_RANDOM_STREAM_KEY,
        &inner_header.inner_random_stream_key,
    );

    for binary in &inner_header.binaries {
        write_header_field(
            &mut header_data,
            INNER_HEADER_BINARY_ATTACHMENTS,
            &binary.dump(),
        );
    }

    write_header_field(&mut header_data, INNER_HEADER_END, &[]);

    header_data
}

/// Dump a KeePass database using the key elements
pub fn dump(db: &Database, key_elements: &[Vec<u8>]) -> Result<Vec<u8>, DatabaseSaveError> {
    let mut data: Vec<u8> = vec![];

    let header = match &db.header {
        Header::KDBX4(h) => h,
        _ => return Err(DatabaseSaveError::UnsupportedVersion.into()),
    };

    let header_data = dump_outer_header(&header)?;
    data.extend_from_slice(&header_data);

    let header_sha256 = crypt::calculate_sha256(&[&header_data])?;
    data.extend_from_slice(&header_sha256);

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = header.kdf.get_kdf().transform_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::max_value(), &hmac_key)?;
    let header_hmac = crypt::calculate_hmac(&[&header_data], &header_hmac_key)?;
    data.extend_from_slice(&header_hmac);

    let mut payload: Vec<u8> = vec![];
    let inner_header = match &db.inner_header {
        InnerHeader::KDBX4(h) => h,
        _ => return Err(DatabaseSaveError::UnsupportedVersion.into()),
    };
    let inner_header_data = dump_inner_header(&inner_header);
    payload.extend_from_slice(&inner_header_data);

    // Initialize inner decryptor from inner header params
    let mut inner_cipher = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    // after inner header is one XML document
    let xml = crate::xml_db::dump::dump(&db, &mut *inner_cipher)?;
    payload.extend_from_slice(&xml);

    let payload_compressed = header.compression.get_compression().compress(&payload)?;

    let payload_encrypted = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .encrypt(&payload_compressed)?;

    let payload_hmac = hmac_block_stream::write_hmac_block_stream(&payload_encrypted, &hmac_key)?;
    data.extend_from_slice(&payload_hmac);

    Ok(data)
}

/// Open, decrypt and parse a KeePass database from a source and key elements
pub(crate) fn parse(data: &[u8], key_elements: &[Vec<u8>]) -> Result<Database, DatabaseOpenError> {
    let (header, inner_header, xml) = decrypt_xml(data, key_elements)?;

    // Initialize inner decryptor from inner header params
    let mut inner_decryptor = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    let database_content = crate::xml_db::parse::parse(&xml, &mut *inner_decryptor)?;

    let db = Database {
        header: Header::KDBX4(header),
        inner_header: InnerHeader::KDBX4(inner_header),
        root: database_content.root.group,
        meta: database_content.meta,
    };

    Ok(db)
}

/// Open and decrypt a KeePass KDBX4 database from a source and key elements
pub(crate) fn decrypt_xml(
    data: &[u8],
    key_elements: &[Vec<u8>],
) -> Result<(KDBX4Header, KDBX4InnerHeader, Vec<u8>), DatabaseOpenError> {
    // parse header
    let (header, inner_header_start) = parse_outer_header(data)?;

    // split file into segments:
    //      header_data         - The outer header data
    //      header_sha256       - A Sha256 hash of header_data (for verification of header integrity)
    //      header_hmac         - A HMAC of the header_data (for verification of the key_elements)
    //      hmac_block_stream   - A HMAC-verified block stream of encrypted and compressed blocks
    let header_data = &data[0..inner_header_start];
    let header_sha256 = &data[inner_header_start..(inner_header_start + 32)];
    let header_hmac = &data[(inner_header_start + 32)..(inner_header_start + 64)];
    let hmac_block_stream = &data[(inner_header_start + 64)..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = header.kdf.get_kdf().transform_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify header
    if header_sha256 != crypt::calculate_sha256(&[&data[0..inner_header_start]])?.as_slice() {
        return Err(DatabaseIntegrityError::HeaderHashMismatch.into());
    }

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::max_value(), &hmac_key)?;
    if header_hmac != crypt::calculate_hmac(&[header_data], &header_hmac_key)?.as_slice() {
        return Err(DatabaseKeyError::IncorrectKey.into());
    }

    // read encrypted payload from hmac-verified block stream
    let payload_encrypted =
        hmac_block_stream::read_hmac_block_stream(&hmac_block_stream, &hmac_key)?;

    // Decrypt and decompress encrypted payload
    let payload_compressed = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .decrypt(&payload_encrypted)?;
    let payload = header
        .compression
        .get_compression()
        .decompress(&payload_compressed)?;

    // KDBX4 has inner header, too - parse it
    let (inner_header, body_start) = parse_inner_header(&payload)?;

    // after inner header is one XML document
    let xml = &payload[body_start..];

    Ok((header, inner_header, xml.to_vec()))
}

#[cfg(test)]
mod kdbx4_tests {
    use super::*;

    use crate::{
        config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
        Database, Entry, Group, NewDatabaseSettings, Node, Value,
    };

    fn test_with_settings(
        outer_cipher_suite: OuterCipherSuite,
        compression: Compression,
        inner_cipher_suite: InnerCipherSuite,
        kdf_setting: KdfSettings,
    ) {
        let mut db = Database::new(NewDatabaseSettings {
            outer_cipher_suite,
            compression,
            inner_cipher_suite,
            kdf_setting,
        })
        .unwrap();

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

        let key_elements = Database::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 3);
    }

    #[test]
    pub fn aes256_chacha20_aes() {
        test_with_settings(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn aes256_chacha20_argon2() {
        test_with_settings(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Argon2 {
                salt: vec![],
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
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Argon2 {
                salt: vec![],
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
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn aes256_salsa20_argon2() {
        test_with_settings(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Argon2 {
                salt: vec![],
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
            OuterCipherSuite::ChaCha20,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn chacha20_chacha20_aes_no_compression() {
        test_with_settings(
            OuterCipherSuite::ChaCha20,
            Compression::None,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn chacha20_chacha20_argon2() {
        test_with_settings(
            OuterCipherSuite::ChaCha20,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Argon2 {
                salt: vec![],
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
            OuterCipherSuite::ChaCha20,
            Compression::None,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Argon2 {
                salt: vec![],
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
            OuterCipherSuite::Twofish,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn twofish_chacha20_aes_no_compression() {
        test_with_settings(
            OuterCipherSuite::Twofish,
            Compression::None,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Aes {
                seed: vec![],
                rounds: 100,
            },
        );
    }

    #[test]
    pub fn twofish_chacha20_argon2() {
        test_with_settings(
            OuterCipherSuite::Twofish,
            Compression::GZip,
            InnerCipherSuite::ChaCha20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 65536,
                parallelism: 8,
                version: argon2::Version::Version13,
            },
        );
    }

    #[test]
    pub fn binary_attachments() {
        let mut root_group = Group::new("Root");
        root_group.children.push(Node::Entry(Entry::new()));

        let mut db = Database::new(NewDatabaseSettings::default()).unwrap();

        if let InnerHeader::KDBX4(KDBX4InnerHeader { binaries, .. }) = &mut db.inner_header {
            *binaries = vec![
                BinaryAttachment {
                    identifier: None,
                    flags: 1,
                    compressed: false,
                    content: vec![0x01, 0x02, 0x03, 0x04],
                },
                BinaryAttachment {
                    identifier: None,
                    flags: 2,
                    compressed: false,
                    content: vec![0x04, 0x03, 0x02, 0x01],
                },
            ];
        } else {
            panic!("Expected inner kdbx4 header");
        }

        let mut entry = Entry::new();
        entry.fields.insert(
            "Title".to_string(),
            Value::Unprotected("Demo entry".to_string()),
        );

        db.root.children.push(Node::Entry(entry));

        let password = "test".to_string();
        let key_elements = Database::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = dump(&db, &key_elements).unwrap();

        let decrypted_db = parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let binaries = match decrypted_db.inner_header {
            InnerHeader::KDBX4(KDBX4InnerHeader { binaries, .. }) => binaries,
            _ => panic!(""),
        };
        assert_eq!(binaries.len(), 2);
        assert_eq!(binaries[0].flags, 1);
        assert_eq!(binaries[0].content, [0x01, 0x02, 0x03, 0x04]);
    }
}
