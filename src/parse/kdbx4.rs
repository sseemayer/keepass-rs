use std::collections::HashMap;
use std::convert::TryFrom;

use crate::{
    crypt,
    db::{
        Compression, Database, Group, Header, KDFSettings, OuterCipherSuite, VariantDictionaryValue,
    },
    result::{ErrorKind, Result},
    xml_parse,
};

use byteorder::{ByteOrder, LittleEndian};

#[derive(Debug)]
pub struct KDBX4Header {
    // https://gist.github.com/msmuenchen/9318327
    pub version: u32,
    pub file_major_version: u16,
    pub file_minor_version: u16,
    pub outer_cipher: OuterCipherSuite,
    pub compression: Compression,
    pub master_seed: Vec<u8>,
    pub outer_iv: Vec<u8>,
    pub kdf: KDFSettings,
    pub body_start: usize,
}

fn parse_header<'a>(data: &[u8]) -> Result<KDBX4Header> {
    let (version, file_major_version, file_minor_version) = crate::parse::get_kdbx_version(data)?;

    if version != 0xb54bfb67 || file_major_version != 4 {
        return Err(ErrorKind::InvalidKDBXVersion.into());
    }

    let mut outer_cipher: Option<OuterCipherSuite> = None;
    let mut compression: Option<Compression> = None;
    let mut master_seed: Option<Vec<u8>> = None;
    let mut outer_iv: Option<Vec<u8>> = None;
    let mut kdf: Option<KDFSettings> = None;

    // parse header
    let mut pos = 12;

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
            4 => master_seed = Some(entry_buffer.clone().to_vec()),

            // ENCRYPTIONIV - Initialization Vector for decrypting the payload
            7 => outer_iv = Some(entry_buffer.clone().to_vec()),

            // KdfParameters
            11 => {
                let kdf_params = parse_variant_dictionary(entry_buffer)?;
                kdf = Some(KDFSettings::try_from(&kdf_params)?);
            }

            _ => {
                return Err(ErrorKind::InvalidHeaderEntry(entry_type).into());
            }
        };
    }

    // at this point, the header needs to be fully defined - unwrap options and return errors if
    // something is missing

    let outer_cipher = outer_cipher.ok_or(ErrorKind::IncompleteHeader)?;
    let compression = compression.ok_or(ErrorKind::IncompleteHeader)?;
    let master_seed = master_seed.ok_or(ErrorKind::IncompleteHeader)?;
    let outer_iv = outer_iv.ok_or(ErrorKind::IncompleteHeader)?;
    let kdf = kdf.ok_or(ErrorKind::IncompleteHeader)?;

    println!("KDF {:x?}", kdf);

    Ok(KDBX4Header {
        version,
        file_major_version,
        file_minor_version,
        outer_cipher,
        compression,
        master_seed,
        outer_iv,
        kdf,
        body_start: pos,
    })
}

/// Open, decrypt and parse a KeePass database from a source and a password
pub(crate) fn parse(data: &[u8], key_elements: &Vec<Vec<u8>>) -> Result<Database> {
    // parse header
    let header = parse_header(data)?;

    let mut pos = header.body_start;

    // Turn enums into appropriate trait objects
    let compression = header.compression.get_compression();
    let outer_cipher = header.outer_cipher.get_cipher();

    // Rest of file after header is payload
    let payload_encrypted = &data[pos..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let composite_key = crypt::derive_composite_key(key_elements);
    let transformed_key = header.kdf.derive_key(&composite_key)?;
    println!("transformed key is {:x?}", transformed_key);

    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key]);

    println!("Master key is {:x?}", master_key);

    // TODO check hmac

    // Decrypt payload
    let mut outer_decryptor = outer_cipher.new(&master_key, header.outer_iv.as_ref());
    let payload = crypt::decrypt(&mut *outer_decryptor, payload_encrypted)?;

    // No inner decryptor for KDBX4
    let mut inner_decryptor = Box::new(crypt::NoOpDecryptor);

    let mut db = Database {
        header: Header::KDBX4(header),
        root: Group {
            name: "Root".to_owned(),
            child_groups: Default::default(),
            entries: Default::default(),
        },
    };

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
        db.root
            .child_groups
            .insert(block_group.name.clone(), block_group);

        pos += 40 + block_size;
    }

    // Re-root db.root if it contains only one child (if there was only one block)
    if db.root.child_groups.len() == 1 {
        let mut new_root = Default::default();
        for (_, v) in db.root.child_groups.drain() {
            new_root = v
        }
        db.root = new_root;
    }

    Ok(db)
}

/// Read KDBX4 VariantDictionary data structures
fn parse_variant_dictionary(data: &[u8]) -> Result<HashMap<String, VariantDictionaryValue>> {
    let version = LittleEndian::read_u16(&data[0..2]);

    if version != 0x100 {
        return Err(ErrorKind::InvalidVariantDictionaryVersion.into());
    }

    let mut pos = 2;
    let mut out = HashMap::new();

    while pos < data.len() - 9 {
        let value_type = data[pos];
        pos += 1;

        let key_length = LittleEndian::read_u32(&data[pos..(pos + 4)]) as usize;
        pos += 4;

        let key = std::str::from_utf8(&data[pos..(pos + key_length)])?.to_owned();
        pos += key_length;

        let value_length = LittleEndian::read_u32(&data[pos..(pos + 4)]) as usize;
        pos += 4;

        let value_buffer = &data[pos..(pos + value_length)];
        pos += value_length;

        let value = match value_type {
            0x04 => VariantDictionaryValue::UInt32(LittleEndian::read_u32(value_buffer)),
            0x05 => VariantDictionaryValue::UInt64(LittleEndian::read_u64(value_buffer)),
            0x08 => VariantDictionaryValue::Bool(value_buffer != [0]),
            0x0c => VariantDictionaryValue::Int32(LittleEndian::read_i32(value_buffer)),
            0x0d => VariantDictionaryValue::Int64(LittleEndian::read_i64(value_buffer)),
            0x18 => VariantDictionaryValue::String(std::str::from_utf8(value_buffer)?.into()),
            0x42 => VariantDictionaryValue::ByteArray(value_buffer.to_vec()),
            _ => {
                return Err(ErrorKind::InvalidVariantDictionaryValueType.into());
            }
        };

        out.insert(key, value);
    }

    Ok(out)
}
