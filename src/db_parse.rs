use byteorder::{ByteOrder, LittleEndian};
use std;

use super::crypt;
use super::db::{Database, Group, Header};
use super::decompress;
use super::result::{ErrorKind, Result};
use super::xml_parse;

const KDBX_IDENTIFIER: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const CIPHERSUITE_AES256: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];

/// Open, decrypt and parse a KeePass database from a source and a password
pub fn open_db(source: &mut std::io::Read, password: &str) -> Result<Database> {
    let mut data = Vec::new();
    source.read_to_end(&mut data)?;

    // check identifier
    if data[0..4] != KDBX_IDENTIFIER {
        return Err(ErrorKind::InvalidIdentifier.into());
    }

    let mut db = Database {
        root: Group {
            name: "Root".to_owned(),
            child_groups: Vec::new(),
            entries: Vec::new(),
        },
    };

    // parse header
    let header = parse_header(data.as_ref())?;

    let mut pos = header.body_start;
    let inner_iv = &[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

    let compression: Box<decompress::Decompress> = match header.compression_flag {
        0 => Box::new(decompress::NoCompression),
        1 => Box::new(decompress::GZipCompression),
        _ => return Err(ErrorKind::InvalidCompressionSuite.into()),
    };
    let outer_cipher: Box<crypt::Cipher> = Box::new(crypt::AES256Cipher);
    let inner_cipher: Box<crypt::Cipher> = match header.inner_cipher_id {
        0 => Box::new(crypt::PlainCipher),
        2 => Box::new(crypt::Salsa20Cipher),
        _ => {
            return Err(ErrorKind::InvalidInnerRandomStreamId.into());
        }
    };

    // Rest of file after header is payload
    let payload_encrypted = &data[pos..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let composite_key = crypt::derive_composite_key(&[password.as_bytes()]);
    let transformed_key = crypt::derive_transformed_key(
        header.transform_seed.as_ref(),
        header.transform_rounds,
        composite_key,
    )?;

    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key]);

    // Decrypt payload
    let mut outer_decryptor = outer_cipher.new(&master_key, header.outer_iv.as_ref());
    let payload = crypt::decrypt(&mut *outer_decryptor, payload_encrypted)?;

    // Check if we decrypted correctly
    let ss: &[u8] = header.stream_start.as_ref();
    if &payload[0..header.stream_start.len()] != ss {
        return Err(ErrorKind::IncorrectKey.into());
    }

    // Derive stream key for decrypting inner protected values and set up decryption context
    let stream_key = crypt::calculate_sha256(&[header.protected_stream_key.as_ref()]);
    let mut inner_decryptor = inner_cipher.new(&stream_key, inner_iv);

    pos = 32;
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
        let block_hash_check = crypt::calculate_sha256(&[&block_buffer_compressed]);
        if block_hash != block_hash_check {
            return Err(ErrorKind::BlockHashMismatch.into());
        }

        // Decompress block_buffer_compressed
        let block_buffer = compression.decompress(block_buffer_compressed)?;

        // Parse XML data
        let block_group = xml_parse::parse_xml_block(&block_buffer, &mut *inner_decryptor);
        db.root.child_groups.push(block_group);

        pos += 40 + block_size;
    }

    // Re-root db.root if it contains only one child (if there was only one block)
    if db.root.child_groups.len() == 1 {
        db.root = db.root.child_groups.pop().unwrap();
    }

    Ok(db)
}

fn parse_header(data: &[u8]) -> Result<Header> {
    let version: u32 = LittleEndian::read_u32(&data[4..8]);
    let file_minor_version: u16 = LittleEndian::read_u16(&data[8..10]);
    let file_major_version: u16 = LittleEndian::read_u16(&data[10..12]);

    let mut outer_cipher_id: Option<Vec<u8>> = None;
    let mut compression_flag: Option<u32> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut transform_seed: Option<Vec<u8>> = None;
    let mut transform_rounds: Option<u64> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut protected_stream_key: Option<Vec<u8>> = None;
    let mut stream_start: Option<Vec<u8>> = None;
    let mut inner_cipher_id: Option<u32> = None;

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
                if entry_buffer != CIPHERSUITE_AES256 {
                    return Err(ErrorKind::InvalidCompressionSuite.into());
                }
                outer_cipher_id = Some(entry_buffer.clone().to_vec());
            }

            // COMPRESSIONFLAGS - first byte determines compression of payload
            3 => {
                compression_flag = Some(LittleEndian::read_u32(&entry_buffer));
            }

            // MASTERSEED - Master seed for deriving the master key
            4 => master_seed = Some(entry_buffer.clone().to_vec()),

            // TRANSFORMSEED - Seed used in deriving the transformed key
            5 => transform_seed = Some(entry_buffer.clone().to_vec()),

            // TRANSFORMROUNDS - Number of rounds used in derivation of transformed key
            6 => transform_rounds = Some(LittleEndian::read_u64(entry_buffer)),

            // ENCRYPTIONIV - Initialization Vector for decrypting the payload
            7 => outer_iv = Some(entry_buffer.clone().to_vec()),

            // PROTECTEDSTREAMKEY - Key for decrypting the inner protected values
            8 => protected_stream_key = Some(entry_buffer.clone().to_vec()),

            // STREAMSTARTBYTES - First bytes of decrypted payload (to check correct decryption)
            9 => stream_start = Some(entry_buffer.clone().to_vec()),

            // INNERRANDOMSTREAMID - specifies which cipher suite
            //                       to use for decrypting the inner protected values
            10 => {
                inner_cipher_id = Some(LittleEndian::read_u32(entry_buffer));
            }
            _ => {
                return Err(ErrorKind::InvalidHeaderEntry(entry_type).into());
            }
        };
    }

    let outer_cipher_id = error_if_not_exists(outer_cipher_id)?;
    let compression_flag = error_if_not_exists(compression_flag)?;
    let master_seed = error_if_not_exists(master_seed)?;
    let transform_seed = error_if_not_exists(transform_seed)?;
    let transform_rounds = error_if_not_exists(transform_rounds)?;
    let outer_iv = error_if_not_exists(outer_iv)?;
    let protected_stream_key = error_if_not_exists(protected_stream_key)?;
    let stream_start = error_if_not_exists(stream_start)?;
    let inner_cipher_id = error_if_not_exists(inner_cipher_id)?;

    Ok(Header {
        version,
        file_major_version,
        file_minor_version,
        outer_cipher_id,
        compression_flag,
        master_seed,
        transform_seed,
        transform_rounds,
        outer_iv,
        protected_stream_key,
        stream_start,
        inner_cipher_id,
        body_start: pos,
    })
}

fn error_if_not_exists<T>(val: Option<T>) -> Result<T> {
    if let Some(ret) = val {
        Ok(ret)
    } else {
        bail!("Incorrect file header")
    }
}

impl Database {
    pub fn open(source: &mut std::io::Read, password: &str) -> Result<Database> {
        open_db(source, password)
    }
}
