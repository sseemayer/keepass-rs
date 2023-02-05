use std::convert::{TryFrom, TryInto};

use byteorder::{ByteOrder, LittleEndian};

use crate::{
    config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
    crypt::{self, ciphers::Cipher},
    format::{
        kdbx4::{
            KDBX4OuterHeader, HEADER_COMMENT, HEADER_COMPRESSION_ID, HEADER_ENCRYPTION_IV,
            HEADER_END, HEADER_KDF_PARAMS, HEADER_MASTER_SEED, HEADER_OUTER_ENCRYPTION_ID,
            INNER_HEADER_BINARY_ATTACHMENTS, INNER_HEADER_END, INNER_HEADER_RANDOM_STREAM_ID,
            INNER_HEADER_RANDOM_STREAM_KEY,
        },
        DatabaseVersion,
    },
    hmac_block_stream,
    meta::{BinaryAttachment, BinaryAttachments},
    variant_dictionary::VariantDictionary,
    Database, DatabaseIntegrityError, DatabaseKeyError, DatabaseOpenError, DatabaseSettings,
};

use super::KDBX4InnerHeader;

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

/// Open, decrypt and parse a KeePass database from a source and key elements
pub(crate) fn parse_kdbx4(
    data: &[u8],
    key_elements: &[Vec<u8>],
) -> Result<Database, DatabaseOpenError> {
    let (settings, header_attachments, mut inner_decryptor, xml) =
        decrypt_kdbx4(data, key_elements)?;

    let database_content = crate::xml_db::parse::parse(&xml, &mut *inner_decryptor)?;

    let db = Database {
        settings,
        header_attachments,
        root: database_content.root.group,
        meta: database_content.meta,
    };

    Ok(db)
}

/// Open and decrypt a KeePass KDBX4 database from a source and key elements
pub(crate) fn decrypt_kdbx4(
    data: &[u8],
    key_elements: &[Vec<u8>],
) -> Result<
    (
        DatabaseSettings,
        BinaryAttachments,
        Box<dyn Cipher>,
        Vec<u8>,
    ),
    DatabaseOpenError,
> {
    // parse header
    let (outer_header, inner_header_start) = parse_outer_header(data)?;

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
    let transformed_key = outer_header
        .kdf_settings
        .get_kdf(&outer_header.kdf_seed)
        .transform_key(&composite_key)?;
    let master_key =
        crypt::calculate_sha256(&[outer_header.master_seed.as_ref(), &transformed_key])?;

    // verify header
    if header_sha256 != crypt::calculate_sha256(&[&data[0..inner_header_start]])?.as_slice() {
        return Err(DatabaseIntegrityError::HeaderHashMismatch.into());
    }

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[
        &outer_header.master_seed,
        &transformed_key,
        &hmac_block_stream::HMAC_KEY_END,
    ])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::max_value(), &hmac_key)?;
    if header_hmac != crypt::calculate_hmac(&[header_data], &header_hmac_key)?.as_slice() {
        return Err(DatabaseKeyError::IncorrectKey.into());
    }

    // read encrypted payload from hmac-verified block stream
    let payload_encrypted =
        hmac_block_stream::read_hmac_block_stream(&hmac_block_stream, &hmac_key)?;

    // Decrypt and decompress encrypted payload
    let payload_compressed = outer_header
        .outer_cipher_suite
        .get_cipher(&master_key, &outer_header.outer_iv)?
        .decrypt(&payload_encrypted)?;

    let payload = outer_header
        .compression
        .get_compression()
        .decompress(&payload_compressed)?;

    // KDBX4 has inner header, too - parse it
    let (binary_attachments, inner_header, body_start) = parse_inner_header(&payload)?;

    // after inner header is one XML document
    let xml = &payload[body_start..];

    // initialize the inner decryptor
    let inner_decryptor = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    let settings = DatabaseSettings {
        version: outer_header.version,
        outer_cipher_suite: outer_header.outer_cipher_suite,
        compression: outer_header.compression,
        inner_cipher_suite: inner_header.inner_random_stream,
        kdf_settings: outer_header.kdf_settings,
    };

    Ok((settings, binary_attachments, inner_decryptor, xml.to_vec()))
}

fn parse_outer_header(data: &[u8]) -> Result<(KDBX4OuterHeader, usize), DatabaseOpenError> {
    let version = DatabaseVersion::parse(data)?;

    // skip over the version header
    let mut pos = DatabaseVersion::get_version_header_size();

    let mut outer_cipher: Option<OuterCipherSuite> = None;
    let mut compression: Option<Compression> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut kdf_settings: Option<KdfSettings> = None;
    let mut kdf_seed: Option<Vec<u8>> = None;

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
                let (ksettings, kseed) = vd.try_into()?;
                kdf_settings = Some(ksettings);
                kdf_seed = Some(kseed)
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

    let outer_cipher_suite = get_or_err(outer_cipher, "Outer Cipher ID")?;
    let compression = get_or_err(compression, "Compression ID")?;
    let master_seed = get_or_err(master_seed, "Master seed")?;
    let outer_iv = get_or_err(outer_iv, "Outer IV")?;
    let kdf_settings = get_or_err(kdf_settings, "Key Derivation Function Parameters")?;
    let kdf_seed = get_or_err(kdf_seed, "Key Derivation Function Seed")?;

    Ok((
        KDBX4OuterHeader {
            version,
            outer_cipher_suite,
            compression,
            master_seed,
            outer_iv,
            kdf_settings,
            kdf_seed,
        },
        pos,
    ))
}

fn parse_inner_header(
    data: &[u8],
) -> Result<(BinaryAttachments, KDBX4InnerHeader, usize), DatabaseOpenError> {
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

    let binaries = BinaryAttachments { binaries };

    let inner_random_stream = get_or_err(inner_random_stream, "Inner random stream")?;
    let inner_random_stream_key = get_or_err(inner_random_stream_key, "Inner random stream key")?;

    let inner_header = KDBX4InnerHeader {
        inner_random_stream,
        inner_random_stream_key,
    };

    Ok((binaries, inner_header, pos))
}
