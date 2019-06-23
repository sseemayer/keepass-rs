use std::collections::HashMap;
use std::convert::TryFrom;

use crate::{
    crypt,
    db::{
        Compression, Database, Header, InnerCipherSuite, InnerHeader, KDFSettings,
        OuterCipherSuite, VariantDictionaryValue,
    },
    hmac_block_stream,
    result::{DatabaseIntegrityError, Error, Result},
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

#[derive(Debug)]
pub struct BinaryAttachment {
    flags: u8,
    content: Vec<u8>,
}

impl TryFrom<&[u8]> for BinaryAttachment {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let flags = data[0];
        let content = data[1..].to_vec();

        Ok(BinaryAttachment { flags, content })
    }
}

#[derive(Debug)]
pub struct KDBX4InnerHeader {
    inner_random_stream: InnerCipherSuite,
    inner_random_stream_key: Vec<u8>,
    binaries: Vec<BinaryAttachment>,
    body_start: usize,
}

fn parse_outer_header<'a>(data: &[u8]) -> Result<KDBX4Header> {
    let (version, file_major_version, file_minor_version) = crate::parse::get_kdbx_version(data)?;

    if version != 0xb54bfb67 || file_major_version != 4 {
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
                return Err(DatabaseIntegrityError::InvalidOuterHeaderEntry { entry_type }.into());
            }
        };
    }

    // at this point, the header needs to be fully defined - unwrap options and return errors if
    // something is missing

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
        v.ok_or(
            DatabaseIntegrityError::IncompleteOuterHeader {
                missing_field: err.into(),
            }
            .into(),
        )
    }

    let outer_cipher = get_or_err(outer_cipher, "Outer Cipher ID")?;
    let compression = get_or_err(compression, "Compression ID")?;
    let master_seed = get_or_err(master_seed, "Master seed")?;
    let outer_iv = get_or_err(outer_iv, "Outer IV")?;
    let kdf = get_or_err(kdf, "Key Derivation Function Parameters")?;

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
                let binary = BinaryAttachment::try_from(entry_buffer)?;
                binaries.push(binary);
            }

            _ => {
                return Err(DatabaseIntegrityError::InvalidInnerHeaderEntry { entry_type }.into());
            }
        }
    }

    fn get_or_err<T>(v: Option<T>, err: &str) -> Result<T> {
        v.ok_or(
            DatabaseIntegrityError::IncompleteInnerHeader {
                missing_field: err.into(),
            }
            .into(),
        )
    }

    let inner_random_stream = get_or_err(inner_random_stream, "Inner random stream UUID")?;
    let inner_random_stream_key = get_or_err(inner_random_stream_key, "Inner random stream key")?;

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

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = header.kdf.derive_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify header
    if header_sha256 != crypt::calculate_sha256(&[&data[0..pos]])?.as_slice() {
        return Err(DatabaseIntegrityError::HeaderHashMismatch.into());
    }

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(usize::max_value(), &hmac_key)?;
    if header_hmac != crypt::calculate_hmac(&[header_data], &header_hmac_key)?.as_slice() {
        return Err(Error::IncorrectKey.into());
    }

    // read encrypted payload from hmac-verified block stream
    let payload_encrypted =
        hmac_block_stream::read_hmac_block_stream(&hmac_block_stream, &hmac_key)?;

    // Decrypt and decompress encrypted payload
    let mut outer_decryptor = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?;
    let payload_compressed = outer_decryptor.decrypt(&payload_encrypted)?;
    let payload = compression.decompress(&payload_compressed)?;

    // KDBX4 has inner header, too - parse it
    let inner_header = parse_inner_header(&payload)?;

    // Initialize inner decryptor from inner header params
    let mut inner_decryptor = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    // after inner header is one XML document
    let xml = &payload[inner_header.body_start..];
    let root = xml_parse::parse_xml_block(&xml, &mut *inner_decryptor)?;

    let db = Database {
        header: Header::KDBX4(header),
        inner_header: InnerHeader::KDBX4(inner_header),
        root,
    };

    Ok(db)
}

/// Read KDBX4 VariantDictionary data structures
fn parse_variant_dictionary(data: &[u8]) -> Result<HashMap<String, VariantDictionaryValue>> {
    let version = LittleEndian::read_u16(&data[0..2]);

    if version != 0x100 {
        return Err(DatabaseIntegrityError::InvalidVariantDictionaryVersion { version }.into());
    }

    let mut pos = 2;
    let mut out = HashMap::new();

    while pos < data.len() - 9 {
        let value_type = data[pos];
        pos += 1;

        let key_length = LittleEndian::read_u32(&data[pos..(pos + 4)]) as usize;
        pos += 4;

        let key = std::str::from_utf8(&data[pos..(pos + key_length)])
            .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
            .to_owned();
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
            0x18 => VariantDictionaryValue::String(
                std::str::from_utf8(value_buffer)
                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
                    .into(),
            ),
            0x42 => VariantDictionaryValue::ByteArray(value_buffer.to_vec()),
            _ => {
                return Err(DatabaseIntegrityError::InvalidVariantDictionaryValueType {
                    value_type,
                }
                .into());
            }
        };

        out.insert(key, value);
    }

    Ok(out)
}
