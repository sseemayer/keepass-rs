use crate::{
    config::{Compression, InnerCipherSuite, OuterCipherSuite},
    crypt::{self, kdf::Kdf},
    db::{Database, Group, Header, InnerHeader, Meta, Node},
    result::{DatabaseIntegrityError, Error, Result},
    xml_parse,
};

use byteorder::{ByteOrder, LittleEndian};

use std::convert::TryFrom;

#[derive(Debug)]
pub struct KDBX3Header {
    // https://gist.github.com/msmuenchen/9318327
    pub version: u32,
    pub file_major_version: u16,
    pub file_minor_version: u16,
    pub outer_cipher: OuterCipherSuite,
    pub compression: Compression,
    pub master_seed: Vec<u8>,
    pub transform_seed: Vec<u8>,
    pub transform_rounds: u64,
    pub outer_iv: Vec<u8>,
    pub protected_stream_key: Vec<u8>,
    pub stream_start: Vec<u8>,
    pub inner_cipher: InnerCipherSuite,
    pub body_start: usize,
}

fn parse_header(data: &[u8]) -> Result<KDBX3Header> {
    let (version, file_major_version, file_minor_version) = crate::parse::get_kdbx_version(data)?;

    if version != 0xb54b_fb67 || file_major_version != 3 {
        return Err(DatabaseIntegrityError::InvalidKDBXVersion {
            version,
            file_major_version,
            file_minor_version,
        }
        .into());
    }

    let mut outer_cipher: Option<OuterCipherSuite> = None;
    let mut compression: Option<Compression> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut transform_seed: Option<Vec<u8>> = None;
    let mut transform_rounds: Option<u64> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut protected_stream_key: Option<Vec<u8>> = None;
    let mut stream_start: Option<Vec<u8>> = None;
    let mut inner_cipher: Option<InnerCipherSuite> = None;

    // parse header
    let mut pos = 12;

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
                outer_cipher = Some(OuterCipherSuite::try_from(entry_buffer)?);
            }

            // COMPRESSIONFLAGS - first byte determines compression of payload
            3 => {
                compression = Some(Compression::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
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
                inner_cipher = Some(InnerCipherSuite::try_from(LittleEndian::read_u32(
                    entry_buffer,
                ))?);
            }

            _ => {
                return Err(DatabaseIntegrityError::InvalidOuterHeaderEntry { entry_type }.into());
            }
        };
    }

    // at this point, the header needs to be fully defined - unwrap options and return errors if
    // something is missing

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
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

    Ok(KDBX3Header {
        version,
        file_major_version,
        file_minor_version,
        outer_cipher,
        compression,
        master_seed,
        transform_seed,
        transform_rounds,
        outer_iv,
        protected_stream_key,
        stream_start,
        inner_cipher,
        body_start: pos,
    })
}

/// Open, decrypt and parse a KeePass database from a source and a password
pub(crate) fn parse(data: &[u8], key_elements: &[Vec<u8>]) -> Result<Database> {
    let (header, xml_blocks) = decrypt_xml(data, key_elements)?;

    // Derive stream key for decrypting inner protected values and set up decryption context
    let stream_key = crypt::calculate_sha256(&[header.protected_stream_key.as_ref()])?;
    let mut inner_decryptor = header.inner_cipher.get_cipher(&stream_key)?;
    let mut meta = Meta {
        recyclebin_uuid: Default::default(),
    };

    let mut root = Group {
        name: "Root".to_owned(),
        children: Default::default(),
        expires: Default::default(),
        times: Default::default(),
        uuid: Default::default(),
    };

    // Parse XML data blocks
    for block_buffer in xml_blocks {
        let (block_group, _meta) =
            xml_parse::parse_xml_block(&block_buffer, &mut *inner_decryptor)?;
        // FIXME: This should only be done when _meta has a meaningful value
        meta = _meta;
        root.children.push(Node::Group(block_group));
    }

    // Re-root db.root if it contains only one child (if there was only one block)
    if root.children.len() == 1 {
        let new_root = if let Node::Group(g) = root.children.drain(..).next().unwrap() {
            Some(g)
        } else {
            None
        };
        if let Some(g) = new_root {
            root = g;
        }
    }

    let db = Database {
        header: Header::KDBX3(header),
        inner_header: InnerHeader::None,
        root,
        meta,
    };

    Ok(db)
}

/// Open and decrypt a KeePass KDBX3 database from a source and a password
pub(crate) fn decrypt_xml(
    data: &[u8],
    key_elements: &[Vec<u8>],
) -> Result<(KDBX3Header, Vec<Vec<u8>>)> {
    // parse header
    let header = parse_header(data)?;

    let mut pos = header.body_start;

    // Turn enums into appropriate trait objects
    let compression = header.compression.get_compression();

    // Rest of file after header is payload
    let payload_encrypted = &data[pos..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;

    // KDF is hard coded for KDBX 3
    let transformed_key = crypt::kdf::AesKdf {
        seed: header.transform_seed.clone(),
        rounds: header.transform_rounds,
    }
    .transform_key(&composite_key)?;

    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // Decrypt payload
    let payload = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .decrypt(payload_encrypted)?;

    // Check if we decrypted correctly
    if &payload[0..header.stream_start.len()] != header.stream_start.as_slice() {
        return Err(Error::IncorrectKey);
    }

    let mut xml_blocks = Vec::new();

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
        let block_hash_check = crypt::calculate_sha256(&[&block_buffer_compressed])?;
        if block_hash != block_hash_check.as_slice() {
            return Err(DatabaseIntegrityError::BlockHashMismatch { block_index }.into());
        }

        // Decompress block_buffer_compressed
        let block_buffer = compression.decompress(block_buffer_compressed)?;

        xml_blocks.push(block_buffer.to_vec());

        pos += 40 + block_size;
        block_index += 1;
    }

    Ok((header, xml_blocks))
}
