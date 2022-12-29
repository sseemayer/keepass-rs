use crate::result::{DatabaseIntegrityError, Result};
use byteorder::{ByteOrder, LittleEndian};

use cipher::generic_array::{typenum::U64, GenericArray};

/// Read from a HMAC block stream into a raw buffer
pub(crate) fn read_hmac_block_stream(data: &[u8], key: &GenericArray<u8, U64>) -> Result<Vec<u8>> {
    // keepassxc src/streams/HmacBlockStream.cpp

    let mut out = Vec::new();

    let mut pos = 0;
    let mut block_index: u64 = 0;

    while pos < data.len() {
        let hmac = &data[pos..(pos + 32)];
        let size_bytes = &data[(pos + 32)..(pos + 36)];
        let size = LittleEndian::read_u32(size_bytes) as usize;
        let block = &data[(pos + 36)..(pos + 36 + size)];

        // verify block hmac
        let hmac_block_key = get_hmac_block_key(block_index, key)?;
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index as u64);

        if hmac
            != crate::crypt::calculate_hmac(
                &[&block_index_buf, size_bytes, &block],
                &hmac_block_key,
            )?
            .as_slice()
        {
            return Err(DatabaseIntegrityError::BlockHashMismatch { block_index }.into());
        }

        pos += 36 + size;
        block_index += 1;

        out.extend_from_slice(block);
    }

    Ok(out)
}

pub(crate) fn get_hmac_block_key(
    block_index: u64,
    key: &GenericArray<u8, U64>,
) -> Result<GenericArray<u8, U64>> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, block_index as u64);
    crate::crypt::calculate_sha512(&[&buf, key])
}
