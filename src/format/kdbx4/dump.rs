use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};

use crate::{
    crypt,
    db::{Database, HeaderAttachment},
    error::DatabaseSaveError,
    format::{
        kdbx4::{
            KDBX4InnerHeader, KDBX4OuterHeader, HEADER_COMPRESSION_ID, HEADER_ENCRYPTION_IV, HEADER_END,
            HEADER_KDF_PARAMS, HEADER_MASTER_SEED, HEADER_MASTER_SEED_SIZE, HEADER_OUTER_ENCRYPTION_ID,
            INNER_HEADER_BINARY_ATTACHMENTS, INNER_HEADER_END, INNER_HEADER_RANDOM_STREAM_ID,
            INNER_HEADER_RANDOM_STREAM_KEY,
        },
        DatabaseVersion,
    },
    hmac_block_stream,
    io::WriteLengthTaggedExt,
    key::DatabaseKey,
    variant_dictionary::VariantDictionary,
};

/// Dump a KeePass database using the key elements
pub fn dump_kdbx4(
    db: &Database,
    db_key: &DatabaseKey,
    writer: &mut dyn Write,
) -> Result<(), DatabaseSaveError> {
    if !matches!(db.config.version, DatabaseVersion::KDB4(_)) {
        return Err(DatabaseSaveError::UnsupportedVersion.into());
    }

    // generate encryption keys and seeds on the fly when saving
    let mut master_seed = vec![0; HEADER_MASTER_SEED_SIZE];
    getrandom::getrandom(&mut master_seed)?;

    let mut outer_iv = vec![0; db.config.outer_cipher_config.get_iv_size()];
    getrandom::getrandom(&mut outer_iv)?;

    let mut inner_random_stream_key = vec![0; db.config.inner_cipher_config.get_key_size()];
    getrandom::getrandom(&mut inner_random_stream_key)?;

    let (kdf, kdf_seed) = db.config.kdf_config.get_kdf_and_seed()?;

    #[cfg(feature = "challenge_response")]
    let db_key = db_key.clone().perform_challenge(&kdf_seed)?;

    // dump the outer header - need to buffer so that SHA256 can be computed
    let mut header_data = Vec::new();
    KDBX4OuterHeader {
        version: db.config.version.clone(),
        outer_cipher_config: db.config.outer_cipher_config.clone(),
        compression_config: db.config.compression_config.clone(),
        master_seed: master_seed.clone(),
        outer_iv: outer_iv.clone(),
        kdf_config: db.config.kdf_config.clone(),
        kdf_seed,
    }
    .dump(&mut header_data)?;

    let header_sha256 = crypt::calculate_sha256(&[&header_data])?;

    // write out header and header hash
    writer.write(&header_data)?;
    writer.write(&header_sha256)?;

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements = db_key.get_key_elements()?;
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = crypt::calculate_sha256(&key_elements)?;
    let transformed_key = kdf.transform_key(&composite_key)?;
    let master_key = crypt::calculate_sha256(&[&master_seed, &transformed_key])?;

    // verify credentials
    let hmac_key =
        crypt::calculate_sha512(&[&master_seed, &transformed_key, &hmac_block_stream::HMAC_KEY_END])?;
    let header_hmac_key = hmac_block_stream::get_hmac_block_key(u64::max_value(), &hmac_key)?;
    let header_hmac = crypt::calculate_hmac(&[&header_data], &header_hmac_key)?;

    writer.write(&header_hmac)?;

    // Initialize inner encryptor from inner header params
    let mut inner_cipher = db
        .config
        .inner_cipher_config
        .get_cipher(&inner_random_stream_key)?;

    // dump inner header into buffer
    let mut payload = Vec::new();
    KDBX4InnerHeader {
        inner_random_stream: db.config.inner_cipher_config.clone(),
        inner_random_stream_key,
    }
    .dump(&db.header_attachments, &mut payload)?;

    // after inner header is one XML document
    crate::xml_db::dump::dump(&db, &mut *inner_cipher, &mut payload)?;

    let payload_compressed = db
        .config
        .compression_config
        .get_compression()
        .compress(&payload)?;

    let payload_encrypted = db
        .config
        .outer_cipher_config
        .get_cipher(&master_key, &outer_iv)?
        .encrypt(&payload_compressed)?;

    let payload_hmac = hmac_block_stream::write_hmac_block_stream(&payload_encrypted, &hmac_key)?;
    writer.write(&payload_hmac)?;

    Ok(())
}

impl HeaderAttachment {
    fn dump(&self, writer: &mut dyn Write) -> Result<(), std::io::Error> {
        writer.write_u8(self.flags)?;
        writer.write(&self.content)?;
        Ok(())
    }
}

impl KDBX4OuterHeader {
    fn dump(&self, writer: &mut dyn Write) -> Result<(), DatabaseSaveError> {
        self.version.dump(writer)?;

        writer.write_u8(HEADER_OUTER_ENCRYPTION_ID)?;
        writer.write_with_len(&self.outer_cipher_config.dump())?;

        writer.write_u8(HEADER_COMPRESSION_ID)?;
        writer.write_with_len(&self.compression_config.dump())?;

        writer.write_u8(HEADER_ENCRYPTION_IV)?;
        writer.write_with_len(&self.outer_iv)?;

        writer.write_u8(HEADER_MASTER_SEED)?;
        writer.write_with_len(&self.master_seed)?;

        let vd: VariantDictionary = self.kdf_config.to_variant_dictionary(&self.kdf_seed);
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
    fn dump(
        &self,
        header_attachments: &[HeaderAttachment],
        writer: &mut dyn Write,
    ) -> Result<(), DatabaseSaveError> {
        writer.write(&[INNER_HEADER_RANDOM_STREAM_ID])?;
        writer.write_u32::<LittleEndian>(4)?;
        writer.write_u32::<LittleEndian>(self.inner_random_stream.dump())?;

        writer.write_u8(INNER_HEADER_RANDOM_STREAM_KEY)?;
        writer.write_with_len(&self.inner_random_stream_key)?;

        for attachment in header_attachments {
            writer.write_u8(INNER_HEADER_BINARY_ATTACHMENTS)?;
            writer.write_u32::<LittleEndian>((attachment.content.len() + 1) as u32)?;
            attachment.dump(writer)?;
        }

        writer.write_u8(INNER_HEADER_END)?;
        writer.write_with_len(&[])?;

        Ok(())
    }
}
