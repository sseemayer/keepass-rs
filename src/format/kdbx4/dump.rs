use std::convert::TryInto;

use byteorder::{ByteOrder, LittleEndian};

use crate::{
    crypt,
    db::{Database, Header, InnerHeader},
    format::kdbx4::{
        KDBX4Header, KDBX4InnerHeader, HEADER_COMPRESSION_ID, HEADER_ENCRYPTION_IV, HEADER_END,
        HEADER_KDF_PARAMS, HEADER_MASTER_SEED, HEADER_OUTER_ENCRYPTION_ID,
        INNER_HEADER_BINARY_ATTACHMENTS, INNER_HEADER_END, INNER_HEADER_RANDOM_STREAM_ID,
        INNER_HEADER_RANDOM_STREAM_KEY,
    },
    hmac_block_stream,
    meta::BinaryAttachment,
    variant_dictionary::VariantDictionary,
    DatabaseSaveError,
};

/// Dump a KeePass database using the key elements
pub fn dump_kdbx4(db: &Database, key_elements: &[Vec<u8>]) -> Result<Vec<u8>, DatabaseSaveError> {
    let mut data: Vec<u8> = vec![];

    let header = match &db.header {
        Header::KDBX4(h) => h,
        _ => return Err(DatabaseSaveError::UnsupportedVersion.into()),
    };

    let header_data = dump_outer_header(&header)?;
    data.extend_from_slice(&header_data);

    let header_sha256 = crypt::calculate_sha256(&[&header_data])?;
    data.extend_from_slice(&header_sha256);

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = header.kdf.get_kdf().transform_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::max_value(), &hmac_key)?;
    let header_hmac = crypt::calculate_hmac(&[&header_data], &header_hmac_key)?;
    data.extend_from_slice(&header_hmac);

    let mut payload: Vec<u8> = vec![];
    let inner_header = match &db.inner_header {
        InnerHeader::KDBX4(h) => h,
        _ => return Err(DatabaseSaveError::UnsupportedVersion.into()),
    };
    let inner_header_data = dump_inner_header(&inner_header);
    payload.extend_from_slice(&inner_header_data);

    // Initialize inner decryptor from inner header params
    let mut inner_cipher = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    // after inner header is one XML document
    let xml = crate::xml_db::dump::dump(&db, &mut *inner_cipher)?;
    payload.extend_from_slice(&xml);

    let payload_compressed = header.compression.get_compression().compress(&payload)?;

    let payload_encrypted = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .encrypt(&payload_compressed)?;

    let payload_hmac = hmac_block_stream::write_hmac_block_stream(&payload_encrypted, &hmac_key)?;
    data.extend_from_slice(&payload_hmac);

    Ok(data)
}

impl BinaryAttachment {
    fn dump(&self) -> Vec<u8> {
        let mut attachment: Vec<u8> = vec![self.flags];
        attachment.extend_from_slice(&self.content.clone());
        attachment
    }
}

fn write_header_field(header_data: &mut Vec<u8>, field_id: u8, field_value: &[u8]) {
    header_data.push(field_id);
    let pos = header_data.len();
    header_data.resize(pos + 4, 0);
    LittleEndian::write_u32(
        &mut header_data[pos..pos + 4],
        field_value.len().try_into().unwrap(),
    );
    header_data.extend_from_slice(field_value);
}

fn dump_outer_header(header: &KDBX4Header) -> Result<Vec<u8>, DatabaseSaveError> {
    let mut header_data: Vec<u8> = vec![];
    header_data.extend_from_slice(&header.version.dump());

    write_header_field(
        &mut header_data,
        HEADER_OUTER_ENCRYPTION_ID,
        &header.outer_cipher.dump(),
    );

    write_header_field(
        &mut header_data,
        HEADER_COMPRESSION_ID,
        &header.compression.dump(),
    );

    write_header_field(&mut header_data, HEADER_ENCRYPTION_IV, &header.outer_iv);

    write_header_field(&mut header_data, HEADER_MASTER_SEED, &header.master_seed);

    let vd: VariantDictionary = header.kdf.dump();
    write_header_field(&mut header_data, HEADER_KDF_PARAMS, &vd.dump());

    write_header_field(&mut header_data, HEADER_END, &[]);

    Ok(header_data)
}

fn dump_inner_header(inner_header: &KDBX4InnerHeader) -> Vec<u8> {
    let mut header_data: Vec<u8> = vec![];

    let mut random_stream_data: Vec<u8> = vec![];
    random_stream_data.resize(4, 0);
    LittleEndian::write_u32(
        &mut random_stream_data[0..4],
        inner_header.inner_random_stream.dump(),
    );
    write_header_field(
        &mut header_data,
        INNER_HEADER_RANDOM_STREAM_ID,
        &random_stream_data,
    );

    write_header_field(
        &mut header_data,
        INNER_HEADER_RANDOM_STREAM_KEY,
        &inner_header.inner_random_stream_key,
    );

    for binary in &inner_header.binaries {
        write_header_field(
            &mut header_data,
            INNER_HEADER_BINARY_ATTACHMENTS,
            &binary.dump(),
        );
    }

    write_header_field(&mut header_data, INNER_HEADER_END, &[]);

    header_data
}
