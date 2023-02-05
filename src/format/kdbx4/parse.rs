use std::convert::TryFrom;

use byteorder::{ByteOrder, LittleEndian};

use crate::{
    config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
    crypt,
    format::{
        kdbx4::{
            KDBX4Header, KDBX4InnerHeader, HEADER_COMMENT, HEADER_COMPRESSION_ID,
            HEADER_ENCRYPTION_IV, HEADER_END, HEADER_KDF_PARAMS, HEADER_MASTER_SEED,
            HEADER_OUTER_ENCRYPTION_ID, INNER_HEADER_BINARY_ATTACHMENTS, INNER_HEADER_END,
            INNER_HEADER_RANDOM_STREAM_ID, INNER_HEADER_RANDOM_STREAM_KEY,
        },
        DatabaseVersion,
    },
    hmac_block_stream,
    meta::BinaryAttachment,
    variant_dictionary::VariantDictionary,
    Database, DatabaseIntegrityError, DatabaseKeyError, DatabaseOpenError, Header, InnerHeader,
};

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
    let (header, inner_header, xml) = decrypt_kdbx4(data, key_elements)?;

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
pub(crate) fn decrypt_kdbx4(
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
