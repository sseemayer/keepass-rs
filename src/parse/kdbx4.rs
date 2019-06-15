use std::collections::HashMap;
use std::convert::TryFrom;

use crate::{
    crypt,
    db::{
        Compression, Database, Group, Header, InnerCipherSuite, KDFSettings, OuterCipherSuite,
        VariantDictionaryValue,
    },
    hmac_block_stream,
    result::{Error, ErrorKind, Result},
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

struct Binary {
    flags: u8,
    content: Vec<u8>,
}

impl TryFrom<&[u8]> for Binary {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let flags = data[0];
        let content = data[1..].to_vec();

        Ok(Binary { flags, content })
    }
}

struct KDBX4InnerHeader {
    inner_random_stream: InnerCipherSuite,
    inner_random_stream_key: Vec<u8>,
    binaries: Vec<Binary>,
    body_start: usize,
}

fn parse_outer_header<'a>(data: &[u8]) -> Result<KDBX4Header> {
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

fn parse_inner_header(data: &[u8]) -> Result<KDBX4InnerHeader> {
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
            // end of header
            0x00 => break,

            // inner random stream ID
            0x01 => {
                inner_random_stream = Some(InnerCipherSuite::try_from(LittleEndian::read_u32(
                    &entry_buffer,
                ))?);
            }

            // inner random stream key
            0x02 => inner_random_stream_key = Some(entry_buffer.clone().to_vec()),

            // binary attachment
            0x03 => {
                let binary = Binary::try_from(entry_buffer)?;
                binaries.push(binary);
            }

            _ => {
                return Err(ErrorKind::InvalidHeaderEntry(entry_type).into());
            }
        }
    }

    let inner_random_stream = inner_random_stream.ok_or(ErrorKind::IncompleteHeader)?;
    let inner_random_stream_key = inner_random_stream_key.ok_or(ErrorKind::IncompleteHeader)?;

    Ok(KDBX4InnerHeader {
        inner_random_stream,
        inner_random_stream_key,
        binaries,
        body_start: pos,
    })
}

/// Open, decrypt and parse a KeePass database from a source and key elements
pub(crate) fn parse(data: &[u8], key_elements: &Vec<Vec<u8>>) -> Result<Database> {
    // parse header
    let header = parse_outer_header(data)?;
    let pos = header.body_start;

    // split file into segments:
    //      header_data         - The outer header data
    //      header_sha256       - A Sha256 hash of header_data (for verification of header integrity)
    //      header_hmac         - A HMAC of the header_data (for verification of the key_elements)
    //      hmac_block_stream   - A HMAC-verified block stream of encrypted and compressed blocks
    let header_data = &data[0..pos];
    let header_sha256 = &data[pos..(pos + 32)];
    let header_hmac = &data[(pos + 32)..(pos + 64)];
    let hmac_block_stream = &data[(pos + 64)..];

    // Turn enums into appropriate trait objects
    let compression = header.compression.get_compression();
    let outer_cipher = header.outer_cipher.get_cipher();

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let composite_key = crypt::derive_composite_key(key_elements);
    let transformed_key = header.kdf.derive_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key]);

    // verify header
    if header_sha256 != crypt::calculate_sha256(&[&data[0..pos]]) {
        return Err(ErrorKind::HeaderHashMismatch.into());
    }

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"]);
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(usize::max_value(), &hmac_key);
    if header_hmac != crypt::calculate_hmac(&[header_data], &header_hmac_key) {
        return Err(ErrorKind::IncorrectKey.into());
    }

    // read encrypted payload from hmac-verified block stream
    let payload_encrypted =
        hmac_block_stream::read_hmac_block_stream(&hmac_block_stream, &master_key);

    // Decrypt and decompress encrypted payload
    let mut outer_decryptor = outer_cipher.new(&master_key, header.outer_iv.as_ref());
    let payload_compressed = crypt::decrypt(&mut *outer_decryptor, &payload_encrypted)?;
    let payload = compression.decompress(&payload_compressed)?;

    // KDBX4 has inner header, too - parse it
    let inner_header = parse_inner_header(&payload)?;

    // Initialize inner decryptor from inner header params
    let inner_cipher = inner_header.inner_random_stream.get_cipher();
    let mut inner_decryptor = inner_cipher.new(&inner_header.inner_random_stream_key);

    let mut db = Database {
        header: Header::KDBX4(header),
        root: Group {
            name: "Root".to_owned(),
            child_groups: Default::default(),
            entries: Default::default(),
        },
    };

    // after inner header is one XML document
    let xml = &payload[inner_header.body_start..];
    db.root = xml_parse::parse_xml_block(&xml, &mut *inner_decryptor);

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
