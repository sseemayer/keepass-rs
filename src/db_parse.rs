use byteorder::{ByteOrder, LittleEndian};
use std;

use super::decrypt;
use super::decompress;
use super::xml_parse;
use super::error::*;
use super::db::{Database, Group};


const KDBX_IDENTIFIER: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];
const CIPHERSUITE_AES256: [u8; 16] = [
    0x31,
    0xc1,
    0xf2,
    0xe6,
    0xbf,
    0x71,
    0x43,
    0x50,
    0xbe,
    0x58,
    0x05,
    0x21,
    0x6a,
    0xfc,
    0x5a,
    0xff,
];


/// Open, decrypt and parse a KeePass database from a source and a password
pub fn open_db(source: &mut std::io::Read, password: &str) -> Result<Database, OpenDBError> {
    let mut data = Vec::new();
    try!(source.read_to_end(&mut data));

    // check identifier
    if data[0..4] != KDBX_IDENTIFIER {
        return Err(OpenDBError::InvalidIdentifier);
    }

    let mut db = Database {
        root: Group {
            name: "Root".to_owned(),
            child_groups: Vec::new(),
            entries: Vec::new(),
        },
    };

    // parse header
    let mut pos = 12;

    let mut compression: Box<decompress::Decompress> = Box::new(decompress::NoCompression);
    let mut outer_cipher: Box<decrypt::Cipher> = Box::new(decrypt::AES256Cipher);
    let mut inner_cipher: Box<decrypt::Cipher> = Box::new(decrypt::Salsa20Cipher);
    let mut master_seed: &[u8] = &[];
    let mut transform_seed: &[u8] = &[];
    let mut transform_rounds = 0u64;
    let mut outer_iv: &[u8] = &[];
    let inner_iv = &[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
    let mut protected_stream_key: &[u8] = &[];
    let mut stream_start: &[u8] = &[];

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

            // COMMENT

                // CIPHERID - a UUID specifying which cipher suite
                //            should be used to encrypt the payload
            2 => {
                if entry_buffer != CIPHERSUITE_AES256 {
                    return Err(OpenDBError::InvalidCompressionSuite);
                }
                outer_cipher = Box::new(decrypt::AES256Cipher);
            }

            // COMPRESSIONFLAGS - first byte determines compression of payload
            3 => {
                compression = match entry_buffer[0] {
                    0 => Box::new(decompress::NoCompression),
                    1 => Box::new(decompress::GZipCompression),
                    _ => return Err(OpenDBError::InvalidCompressionSuite),
                }
            }

            // MASTERSEED - Master seed for deriving the master key
            4 => master_seed = entry_buffer,

            // TRANSFORMSEED - Seed used in deriving the transformed key
            5 => transform_seed = entry_buffer,

            // TRANSFORMROUNDS - Number of rounds used in derivation of transformed key
            6 => transform_rounds = LittleEndian::read_u64(entry_buffer),

            // ENCRYPTIONIV - Initialization Vector for decrypting the payload
            7 => outer_iv = entry_buffer,

            // PROTECTEDSTREAMKEY - Key for decrypting the inner protected values
            8 => protected_stream_key = entry_buffer,

            // STREAMSTARTBYTES - First bytes of decrypted payload (to check correct decryption)
            9 => stream_start = entry_buffer,

            // INNERRANDOMSTREAMID - specifies which cipher suite
            //                       to use for decrypting the inner protected values
            10 => {
                inner_cipher = match LittleEndian::read_u32(entry_buffer) {
                    0 => Box::new(decrypt::PlainCipher),
                    2 => Box::new(decrypt::Salsa20Cipher),
                    _ => {
                        return Err(OpenDBError::InvalidInnerRandomStreamId);
                    }
                }
            }

            _ => {
                return Err(OpenDBError::InvalidHeaderEntry(entry_type));
            }
        };
    }

    // Rest of file after header is payload
    let payload_encrypted = &data[pos..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let composite_key = decrypt::derive_composite_key(&[password.as_bytes()]);
    let transformed_key = try!(decrypt::derive_transformed_key(
        transform_seed,
        transform_rounds,
        composite_key
    ));
    let master_key = decrypt::calculate_sha256(&[master_seed, &transformed_key]);

    // Decrypt payload
    let mut outer_decryptor = outer_cipher.new(&master_key, outer_iv);
    let payload = try!(decrypt::decrypt(&mut *outer_decryptor, payload_encrypted));

    // Check if we decrypted correctly
    if &payload[0..stream_start.len()] != stream_start {
        return Err(OpenDBError::IncorrectKey);
    }

    // Derive stream key for decrypting inner protected values and set up decryption context
    let stream_key = decrypt::calculate_sha256(&[protected_stream_key]);
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
        let block_hash_check = decrypt::calculate_sha256(&[&block_buffer_compressed]);
        if block_hash != block_hash_check {
            return Err(OpenDBError::BlockHashMismatch);
        }

        // Decompress block_buffer_compressed
        let block_buffer = try!(compression.decompress(block_buffer_compressed));

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


impl Database {
    pub fn open(source: &mut std::io::Read, password: &str) -> Result<Database, OpenDBError> {
        open_db(source, password)
    }
}
