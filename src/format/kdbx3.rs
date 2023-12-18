use crate::{
    config::{CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    crypt::{calculate_sha256, ciphers::Cipher},
    db::Database,
    error::{BlockStreamError, DatabaseIntegrityError, DatabaseKeyError, DatabaseOpenError},
    format::DatabaseVersion,
    key::DatabaseKey,
};

use byteorder::{ByteOrder, LittleEndian};

use std::convert::TryFrom;

#[derive(Debug)]
struct KDBX3Header {
    // https://gist.github.com/msmuenchen/9318327
    outer_cipher: OuterCipherConfig,
    compression: CompressionConfig,
    master_seed: Vec<u8>,

    transform_seed: Vec<u8>,
    kdf_config: KdfConfig,

    outer_iv: Vec<u8>,
    protected_stream_key: Vec<u8>,
    stream_start: Vec<u8>,
    inner_cipher: InnerCipherConfig,
    body_start: usize,
}

fn parse_outer_header(data: &[u8]) -> Result<KDBX3Header, DatabaseOpenError> {
    let mut outer_cipher: Option<OuterCipherConfig> = None;
    let mut compression: Option<CompressionConfig> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut transform_seed: Option<Vec<u8>> = None;
    let mut transform_rounds: Option<u64> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut protected_stream_key: Option<Vec<u8>> = None;
    let mut stream_start: Option<Vec<u8>> = None;
    let mut inner_cipher: Option<InnerCipherConfig> = None;

    // skip over the version header
    let mut pos = DatabaseVersion::get_version_header_size();

    // parse header
    loop {
        // parse header blocks.
        //
        // every block is a triplet of (3 + entry_length) bytes with this structure:
        //
        // (
        //   entry_type: u8,                        // a numeric entry type identifier
        //   entry_length: u16,                     // length of the entry buffer
        //   entry_buffer: [u8; entry_length]       // the entry buffer
        // )

        let entry_type = data[pos];
        let entry_length: usize = LittleEndian::read_u16(&data[pos + 1..(pos + 3)]) as usize;
        let entry_buffer = &data[(pos + 3)..(pos + 3 + entry_length)];

        pos += 3 + entry_length;

        match entry_type {
            // END - finished parsing header
            0 => {
                break;
            }

            // COMMENT
            1 => {}

            // CIPHERID - a UUID specifying which cipher suite
            //            should be used to encrypt the payload
            2 => {
                outer_cipher = Some(
                    OuterCipherConfig::try_from(entry_buffer).map_err(|e| DatabaseIntegrityError::from(e))?,
                );
            }

            // COMPRESSIONFLAGS - first byte determines compression of payload
            3 => {
                compression = Some(
                    CompressionConfig::try_from(LittleEndian::read_u32(&entry_buffer))
                        .map_err(|e| DatabaseIntegrityError::from(e))?,
                );
            }

            // MASTERSEED - Master seed for deriving the master key
            4 => master_seed = Some(entry_buffer.to_vec()),

            // TRANSFORMSEED - Seed used in deriving the transformed key
            5 => transform_seed = Some(entry_buffer.to_vec()),

            // TRANSFORMROUNDS - Number of rounds used in derivation of transformed key
            6 => transform_rounds = Some(LittleEndian::read_u64(entry_buffer)),

            // ENCRYPTIONIV - Initialization Vector for decrypting the payload
            7 => outer_iv = Some(entry_buffer.to_vec()),

            // PROTECTEDSTREAMKEY - Key for decrypting the inner protected values
            8 => protected_stream_key = Some(entry_buffer.to_vec()),

            // STREAMSTARTBYTES - First bytes of decrypted payload (to check correct decryption)
            9 => stream_start = Some(entry_buffer.to_vec()),

            // INNERRANDOMSTREAMID - specifies which cipher suite
            //                       to use for decrypting the inner protected values
            10 => {
                inner_cipher = Some(
                    InnerCipherConfig::try_from(LittleEndian::read_u32(entry_buffer))
                        .map_err(|e| DatabaseIntegrityError::from(e))?,
                );
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
    let transform_seed = get_or_err(transform_seed, "Transform seed")?;
    let transform_rounds = get_or_err(transform_rounds, "Number of transformation rounds")?;
    let outer_iv = get_or_err(outer_iv, "Outer cipher IV")?;
    let protected_stream_key = get_or_err(protected_stream_key, "Protected stream key")?;
    let stream_start = get_or_err(stream_start, "Stream start bytes")?;
    let inner_cipher = get_or_err(inner_cipher, "Inner cipher ID")?;

    // KDF type is always AES for KDBX3
    let kdf_config = KdfConfig::Aes {
        rounds: transform_rounds,
    };

    Ok(KDBX3Header {
        outer_cipher,
        compression,
        master_seed,
        transform_seed,
        kdf_config,
        outer_iv,
        protected_stream_key,
        stream_start,
        inner_cipher,
        body_start: pos,
    })
}

/// Open, decrypt and parse a KeePass database from a source and a password
pub(crate) fn parse_kdbx3(data: &[u8], db_key: &DatabaseKey) -> Result<Database, DatabaseOpenError> {
    let (config, mut inner_decryptor, xml) = decrypt_kdbx3(data, db_key)?;

    // Parse XML data blocks
    let database_content = crate::xml_db::parse::parse(&xml, &mut *inner_decryptor)
        .map_err(|e| DatabaseIntegrityError::from(e))?;

    let db = Database {
        config,
        header_attachments: Vec::new(),
        root: database_content.root.group,
        deleted_objects: database_content.root.deleted_objects,
        meta: database_content.meta,
    };

    Ok(db)
}

/// Open and decrypt a KeePass KDBX3 database from a source and a password
pub(crate) fn decrypt_kdbx3(
    data: &[u8],
    db_key: &DatabaseKey,
) -> Result<(DatabaseConfig, Box<dyn Cipher>, Vec<u8>), DatabaseOpenError> {
    let version = DatabaseVersion::parse(data)?;
    let header = parse_outer_header(data)?;

    // Derive stream key for decrypting inner protected values and set up decryption context
    let stream_key = calculate_sha256(&[header.protected_stream_key.as_ref()])
        .map_err(|e| DatabaseIntegrityError::from(e))?;

    let inner_decryptor = header
        .inner_cipher
        .get_cipher(&stream_key)
        .map_err(|e| DatabaseIntegrityError::from(e))?;

    let config = DatabaseConfig {
        version,
        outer_cipher_config: header.outer_cipher,
        compression_config: header.compression,
        inner_cipher_config: header.inner_cipher,
        kdf_config: header.kdf_config,
    };

    let mut pos = header.body_start;

    // Turn enums into appropriate trait objects
    let compression = config.compression_config.get_compression();

    // Rest of file after header is payload
    let payload_encrypted = &data[pos..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements = db_key.get_key_elements()?;
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = calculate_sha256(&key_elements)?;

    // transform the key
    let transformed_key = config
        .kdf_config
        .get_kdf_seeded(&header.transform_seed)
        .transform_key(&composite_key)?;

    let master_key = calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // Decrypt payload
    let payload = config
        .outer_cipher_config
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .decrypt(payload_encrypted)?;

    // Check if we decrypted correctly
    if &payload[0..header.stream_start.len()] != header.stream_start.as_slice() {
        return Err(DatabaseKeyError::IncorrectKey.into());
    }

    let mut buf = Vec::new();

    pos = 32;
    let mut block_index = 0;
    loop {
        // Parse blocks in payload.
        //
        // Each block is a tuple of size (40 + block_size) with structure:
        //
        // (
        //   block_id: u32,                                 // a numeric block ID (starts at 0)
        //   block_hash: [u8, 32],                          // SHA256 of block_buffer_compressed
        //   block_size: u32,                               // block_size size in bytes
        //   block_buffer_compressed: [u8, block_size]      // Block data, possibly compressed
        // )

        // let block_id = LittleEndian::read_u32(&payload[pos..(pos + 4)]);
        let block_hash = &payload[(pos + 4)..(pos + 36)];
        let block_size = LittleEndian::read_u32(&payload[(pos + 36)..(pos + 40)]) as usize;

        // A block with size 0 means we have hit EOF
        if block_size == 0 {
            break;
        }

        let block_buffer_compressed = &payload[(pos + 40)..(pos + 40 + block_size)];

        // Test block hash
        let block_hash_check = calculate_sha256(&[&block_buffer_compressed])?;
        if block_hash != block_hash_check.as_slice() {
            return Err(BlockStreamError::BlockHashMismatch { block_index }.into());
        }

        // Decompress block_buffer_compressed
        buf.append(&mut block_buffer_compressed.to_vec());

        pos += 40 + block_size;
        block_index += 1;
    }

    let xml = compression.decompress(&buf)?;

    Ok((config, inner_decryptor, xml))
}
