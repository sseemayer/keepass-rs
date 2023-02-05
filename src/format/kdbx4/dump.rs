use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};

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
    io::WriteLengthTaggedExt,
    meta::BinaryAttachment,
    variant_dictionary::VariantDictionary,
    DatabaseSaveError,
};

/// Dump a KeePass database using the key elements
pub fn dump_kdbx4(
    db: &Database,
    key_elements: &[Vec<u8>],
    writer: &mut dyn Write,
) -> Result<(), DatabaseSaveError> {
    let header = match &db.header {
        Header::KDBX4(h) => h,
        _ => return Err(DatabaseSaveError::UnsupportedVersion.into()),
    };

    // dump the outer header - need to buffer so that SHA256 can be computed
    let mut header_data = Vec::new();
    header.dump(&mut header_data)?;

    let header_sha256 = crypt::calculate_sha256(&[&header_data])?;

    // write out header and header hash
    writer.write(&header_data)?;
    writer.write(&header_sha256)?;

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = header.kdf.get_kdf().transform_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[header.master_seed.as_ref(), &transformed_key])?;

    // verify credentials
    let hmac_key = crypt::calculate_sha512(&[&header.master_seed, &transformed_key, b"\x01"])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::max_value(), &hmac_key)?;
    let header_hmac = crypt::calculate_hmac(&[&header_data], &header_hmac_key)?;

    writer.write(&header_hmac)?;

    let inner_header = match &db.inner_header {
        InnerHeader::KDBX4(h) => h,
        _ => return Err(DatabaseSaveError::UnsupportedVersion.into()),
    };

    // dump inner header into buffer
    let mut payload = Vec::new();
    inner_header.dump(&mut payload)?;

    // Initialize inner decryptor from inner header params
    let mut inner_cipher = inner_header
        .inner_random_stream
        .get_cipher(&inner_header.inner_random_stream_key)?;

    // after inner header is one XML document
    crate::xml_db::dump::dump(&db, &mut *inner_cipher, &mut payload)?;

    let payload_compressed = header.compression.get_compression().compress(&payload)?;

    let payload_encrypted = header
        .outer_cipher
        .get_cipher(&master_key, header.outer_iv.as_ref())?
        .encrypt(&payload_compressed)?;

    let payload_hmac = hmac_block_stream::write_hmac_block_stream(&payload_encrypted, &hmac_key)?;
    writer.write(&payload_hmac)?;

    Ok(())
}

impl BinaryAttachment {
    fn dump(&self, writer: &mut dyn Write) -> Result<(), std::io::Error> {
        writer.write_u8(self.flags)?;
        writer.write(&self.content)?;
        Ok(())
    }
}

impl KDBX4Header {
    fn dump(&self, writer: &mut dyn Write) -> Result<(), DatabaseSaveError> {
        self.version.dump(writer)?;

        writer.write_u8(HEADER_OUTER_ENCRYPTION_ID)?;
        writer.write_with_len(&self.outer_cipher.dump())?;

        writer.write_u8(HEADER_COMPRESSION_ID)?;
        writer.write_with_len(&self.compression.dump())?;

        writer.write_u8(HEADER_ENCRYPTION_IV)?;
        writer.write_with_len(&self.outer_iv)?;

        writer.write_u8(HEADER_MASTER_SEED)?;
        writer.write_with_len(&self.master_seed)?;

        let vd: VariantDictionary = self.kdf.to_variant_dictionary();
        let mut vd_buffer = Vec::new();
        vd.dump(&mut vd_buffer)?;

        writer.write_u8(HEADER_KDF_PARAMS)?;
        writer.write_with_len(&vd_buffer)?;

        writer.write_u8(HEADER_END)?;
        writer.write_with_len(&[])?;

        Ok(())
    }
}

impl KDBX4InnerHeader {
    fn dump(&self, writer: &mut dyn Write) -> Result<(), DatabaseSaveError> {
        writer.write(&[INNER_HEADER_RANDOM_STREAM_ID])?;
        writer.write_u32::<LittleEndian>(4)?;
        writer.write_u32::<LittleEndian>(self.inner_random_stream.dump())?;

        writer.write_u8(INNER_HEADER_RANDOM_STREAM_KEY)?;
        writer.write_with_len(&self.inner_random_stream_key)?;

        for binary in &self.binaries {
            writer.write_u8(INNER_HEADER_BINARY_ATTACHMENTS)?;
            writer.write_u32::<LittleEndian>((binary.content.len() + 1) as u32)?;
            binary.dump(writer)?;
        }

        writer.write_u8(INNER_HEADER_END)?;
        writer.write_with_len(&[])?;

        Ok(())
    }
}
