use std::convert::{TryFrom, TryInto};

use byteorder::{ByteOrder, LittleEndian};
use cipher::{block_padding::UnpadError, InvalidLength};
use thiserror::Error;

use crate::{
    config::{CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    crypt::{self, ciphers::Cipher},
    db::{Attachment, Database},
    format::{
        kdbx4::{
            KDBX4OuterHeader, HEADER_COMMENT, HEADER_COMPRESSION_ID, HEADER_ENCRYPTION_IV, HEADER_END,
            HEADER_KDF_PARAMS, HEADER_MASTER_SEED, HEADER_OUTER_ENCRYPTION_ID, HEADER_PUBLIC_CUSTOM_DATA,
            INNER_HEADER_BINARY_ATTACHMENTS, INNER_HEADER_END, INNER_HEADER_RANDOM_STREAM_ID,
            INNER_HEADER_RANDOM_STREAM_KEY,
        },
        DatabaseVersion, DatabaseVersionParseError,
    },
    hmac_block_stream,
    key::DatabaseKey,
    variant_dictionary::VariantDictionary,
};

use super::KDBX4InnerHeader;

/// Open, decrypt and parse a KeePass database from a source and key elements
pub(crate) fn parse_kdbx4(data: &[u8], db_key: &DatabaseKey) -> Result<Database, ParseKdbx4Error> {
    let (config, header_attachments, mut inner_decryptor, xml) = decrypt_kdbx4(data, db_key)?;

    let mut db = crate::format::xml_db::parse_xml(&xml, &header_attachments, &mut *inner_decryptor)?;
    db.config = config;

    Ok(db)
}

pub(crate) fn get_xml(data: &[u8], db_key: &DatabaseKey) -> Result<String, ParseKdbx4Error> {
    let (_, _, _, xml) = decrypt_kdbx4(data, db_key)?;
    let xml_str = String::from_utf8_lossy(&xml).to_string();
    Ok(xml_str)
}

#[derive(Error, Debug)]
pub enum ParseKdbx4Error {
    #[error("Error opening or decrypting KDBX4 database: {0}")]
    Decrypt(#[from] DecryptKdbx4Error),

    #[error("Error parsing XML data: {0}")]
    Xml(#[from] quick_xml::DeError),
}

/// Open and decrypt a KeePass KDBX4 database from a source and key elements
#[allow(clippy::type_complexity)]
pub(crate) fn decrypt_kdbx4(
    data: &[u8],
    db_key: &DatabaseKey,
) -> Result<(DatabaseConfig, Vec<Attachment>, Box<dyn Cipher>, Vec<u8>), DecryptKdbx4Error> {
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

    // verify header
    if header_sha256 != crypt::calculate_sha256(&[header_data]).as_slice() {
        return Err(DecryptKdbx4Error::HeaderHashMismatch);
    }

    #[cfg(feature = "challenge_response")]
    let db_key = db_key.clone().perform_challenge(&outer_header.kdf_seed)?;

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements = db_key.get_key_elements()?;
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements);
    let transformed_key = outer_header
        .kdf_config
        .get_kdf_seeded(&outer_header.kdf_seed)
        .transform_key(&composite_key)
        .map_err(|e| DecryptKdbx4Error::TransformKey(e.to_string()))?;

    let master_key = crypt::calculate_sha256(&[outer_header.master_seed.as_ref(), &transformed_key]);

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[
        &outer_header.master_seed,
        &transformed_key,
        &hmac_block_stream::HMAC_KEY_END,
    ]);
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::MAX, &hmac_key);
    if header_hmac
        != crypt::calculate_hmac(&[header_data], &header_hmac_key)
            .expect("Always derive a valid HMAC key")
            .as_slice()
    {
        return Err(DecryptKdbx4Error::IncorrectKey);
    }

    // read encrypted payload from hmac-verified block stream
    let payload_encrypted = hmac_block_stream::read_hmac_block_stream(hmac_block_stream, &hmac_key)?;

    // Decrypt and decompress encrypted payload
    let payload_compressed = outer_header
        .outer_cipher_config
        .get_cipher(&master_key, &outer_header.outer_iv)?
        .decrypt(&payload_encrypted)?;

    let payload = outer_header
        .compression_config
        .get_compression()
        .decompress(&payload_compressed)?;

    // KDBX4 has inner header, too - parse it
    let (header_attachments, inner_header, body_start) = parse_inner_header(&payload)?;

    // after inner header is one XML document
    let xml = &payload[body_start..];

    // initialize the inner decryptor
    let inner_decryptor = inner_header
        .inner_random_stream
        .get_decryptor(&inner_header.inner_random_stream_key)?;

    let config = DatabaseConfig {
        version: outer_header.version,
        outer_cipher_config: outer_header.outer_cipher_config,
        compression_config: outer_header.compression_config,
        inner_cipher_config: inner_header.inner_random_stream,
        kdf_config: outer_header.kdf_config,
        public_custom_data: outer_header.public_custom_data,
    };

    Ok((config, header_attachments, inner_decryptor, xml.to_vec()))
}

#[derive(Error, Debug)]
pub enum DecryptKdbx4Error {
    #[error("Corrupt KDBX4 header (hash mismatch)")]
    HeaderHashMismatch,

    #[cfg(feature = "challenge_response")]
    #[error(transparent)]
    ChallengeResponse(#[from] crate::key::ChallengeResponseError),

    #[error("Incorrect key")]
    IncorrectKey,

    #[error(transparent)]
    OuterHeader(#[from] ParseOuterHeaderError),

    #[error(transparent)]
    KeyElements(#[from] crate::key::GetKeyElementsError),

    #[error("Error transforming key: {0}")]
    TransformKey(String),

    #[error(transparent)]
    HmacBlockStream(#[from] hmac_block_stream::BlockHashMismatchError),

    #[error("Outer cipher IV has invalid length: {0}")]
    InvalidOuterCipherIv(#[from] InvalidLength),

    #[error("Unpadding error in outer cipher: {0}")]
    OuterCipherUnpad(#[from] UnpadError),

    #[error("I/O error during decompression: {0}")]
    Decompress(#[from] std::io::Error),

    #[error("Error parsing inner header: {0}")]
    InnerHeader(#[from] ParseInnerHeaderError),
}

fn parse_outer_header(data: &[u8]) -> Result<(KDBX4OuterHeader, usize), ParseOuterHeaderError> {
    let version = DatabaseVersion::parse(data)?;

    // skip over the version header
    let mut pos = DatabaseVersion::get_version_header_size();

    let mut outer_cipher: Option<OuterCipherConfig> = None;
    let mut compression_config: Option<CompressionConfig> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut kdf_config: Option<KdfConfig> = None;
    let mut kdf_seed: Option<Vec<u8>> = None;
    let mut public_custom_data: Option<VariantDictionary> = None;

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
                outer_cipher = Some(OuterCipherConfig::try_from(entry_buffer)?);
            }

            HEADER_COMPRESSION_ID => {
                compression_config = Some(CompressionConfig::try_from(LittleEndian::read_u32(entry_buffer))?);
            }

            HEADER_MASTER_SEED => master_seed = Some(entry_buffer.to_vec()),

            HEADER_ENCRYPTION_IV => outer_iv = Some(entry_buffer.to_vec()),

            HEADER_KDF_PARAMS => {
                let vd = VariantDictionary::parse(entry_buffer)?;
                let (kconf, kseed) = vd.try_into()?;
                kdf_config = Some(kconf);
                kdf_seed = Some(kseed)
            }

            HEADER_PUBLIC_CUSTOM_DATA => {
                let vd = VariantDictionary::parse(entry_buffer)?;
                public_custom_data = Some(vd)
            }

            _ => {
                return Err(ParseOuterHeaderError::InvalidOuterHeaderEntry { entry_type }.into());
            }
        };
    }

    // at this point, the header needs to be fully defined - unwrap options and return errors if
    // something is missing

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T, ParseOuterHeaderError> {
        v.ok_or_else(|| ParseOuterHeaderError::IncompleteOuterHeader {
            missing_field: err.into(),
        })
    }

    let outer_cipher_config = get_or_err(outer_cipher, "Outer Cipher ID")?;
    let compression_config = get_or_err(compression_config, "Compression ID")?;
    let master_seed = get_or_err(master_seed, "Master seed")?;
    let outer_iv = get_or_err(outer_iv, "Outer IV")?;
    let kdf_config = get_or_err(kdf_config, "Key Derivation Function Parameters")?;
    let kdf_seed = get_or_err(kdf_seed, "Key Derivation Function Seed")?;

    Ok((
        KDBX4OuterHeader {
            version,
            outer_cipher_config,
            compression_config,
            master_seed,
            outer_iv,
            kdf_config,
            kdf_seed,
            public_custom_data,
        },
        pos,
    ))
}

#[derive(Error, Debug)]
pub enum ParseOuterHeaderError {
    #[error("Error parsing database version: {0}")]
    Version(#[from] DatabaseVersionParseError),

    #[error("Error parsing compression configuration: {0}")]
    Compression(#[from] crate::config::InvalidCompressionSuiteId),

    #[error("Error parsing outer cipher configuration from variant dictionary: {0}")]
    VariantDictionary(#[from] crate::variant_dictionary::VariantDictionaryParseError),

    #[error("Invalid outer header entry: {entry_type}")]
    InvalidOuterHeaderEntry { entry_type: u8 },

    #[error("Missing outer header field: {missing_field}")]
    IncompleteOuterHeader { missing_field: String },

    #[error("Error parsing outer cipher configuration: {0}")]
    InvlaidOuterCipherId(#[from] crate::config::InvalidOuterCipherId),

    #[error("Invalid KDF configuration: {0}")]
    Kdf(#[from] crate::config::KdfConfigError),
}

fn parse_inner_header(
    data: &[u8],
) -> Result<(Vec<Attachment>, KDBX4InnerHeader, usize), ParseInnerHeaderError> {
    let mut pos = 0;

    let mut inner_random_stream = None;
    let mut inner_random_stream_key = None;
    let mut header_attachments = Vec::new();

    loop {
        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u32(&data[pos + 1..(pos + 5)]) as usize;
        let entry_buffer = &data[(pos + 5)..(pos + 5 + entry_length)];

        pos += 5 + entry_length;

        match entry_type {
            INNER_HEADER_END => break,

            INNER_HEADER_RANDOM_STREAM_ID => {
                inner_random_stream = Some(InnerCipherConfig::try_from(LittleEndian::read_u32(entry_buffer))?);
            }

            INNER_HEADER_RANDOM_STREAM_KEY => inner_random_stream_key = Some(entry_buffer.to_vec()),

            INNER_HEADER_BINARY_ATTACHMENTS => {
                let flags = entry_buffer[0];
                let data = &entry_buffer[1..];

                // according to the KeePass documentation, protected means "should be protected in
                // process memory", not encrypted in the inner header
                let protected = (flags & 0x01) != 0;

                let mut attachment = Attachment::new();
                attachment.protected = protected;
                attachment.set_data(data.to_vec());

                header_attachments.push(attachment);
            }

            _ => {
                return Err(ParseInnerHeaderError::InvalidInnerHeaderEntry { entry_type }.into());
            }
        }
    }

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T, ParseInnerHeaderError> {
        v.ok_or_else(|| ParseInnerHeaderError::IncompleteInnerHeader {
            missing_field: err.into(),
        })
    }

    let inner_random_stream = get_or_err(inner_random_stream, "Inner random stream")?;
    let inner_random_stream_key = get_or_err(inner_random_stream_key, "Inner random stream key")?;

    let inner_header = KDBX4InnerHeader {
        inner_random_stream,
        inner_random_stream_key,
    };

    Ok((header_attachments, inner_header, pos))
}

#[derive(Error, Debug)]
pub enum ParseInnerHeaderError {
    #[error("Invalid inner header entry of type {entry_type}")]
    InvalidInnerHeaderEntry { entry_type: u8 },

    #[error("Missing inner header field: {missing_field}")]
    IncompleteInnerHeader { missing_field: String },

    #[error("Error parsing inner cipher configuration: {0}")]
    InvalidInnerCipherId(#[from] crate::config::InvalidInnerCipherId),
}
