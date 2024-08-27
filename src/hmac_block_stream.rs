use byteorder::{ByteOrder, LittleEndian};
use cipher::generic_array::{typenum::U64, GenericArray};
use hex_literal::hex;

use crate::error::{BlockStreamError, CryptographyError};

pub const HMAC_KEY_END: [u8; 1] = hex!("01");

/// Read from a HMAC block stream into a raw buffer
pub(crate) fn read_hmac_block_stream(
    data: &[u8],
    key: &GenericArray<u8, U64>,
) -> Result<Vec<u8>, BlockStreamError> {
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
            != crate::crypt::calculate_hmac(&[&block_index_buf, size_bytes, &block], &hmac_block_key)?
                .as_slice()
        {
            return Err(BlockStreamError::BlockHashMismatch { block_index }.into());
        }

        pos += 36 + size;
        block_index += 1;

        if size == 0 {
            break;
        }

        out.extend_from_slice(block);
    }

    Ok(out)
}

#[cfg(feature = "save_kdbx4")]
/// Write a raw buffer as a HMAC block stream
pub(crate) fn write_hmac_block_stream(
    data: &[u8],
    key: &GenericArray<u8, U64>,
) -> Result<Vec<u8>, CryptographyError> {
    let mut out = Vec::new();

    let mut pos = 0;
    let mut block_index = 0;

    while pos < data.len() {
        let size = data.len() - pos;

        let block = &data[pos..(pos + size)];

        let mut size_bytes: Vec<u8> = vec![];
        size_bytes.resize(4, 0);
        LittleEndian::write_u32(&mut size_bytes, size as u32);

        // Generate block hmac
        let hmac_block_key = get_hmac_block_key(block_index, key)?;
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index as u64);

        let hmac = crate::crypt::calculate_hmac(&[&block_index_buf, &size_bytes, &block], &hmac_block_key)?;

        pos += 36 + size;
        block_index += 1;

        out.extend_from_slice(&hmac);
        out.extend_from_slice(&size_bytes);
        out.extend_from_slice(&block);
    }

    // the end of the HMAC block stream should be an empty block, but with a valid HMAC
    let hmac_block_key = get_hmac_block_key(block_index, key)?;
    let mut block_index_buf = [0u8; 8];
    LittleEndian::write_u64(&mut block_index_buf, block_index as u64);

    let size_bytes = vec![0; 4];
    let hmac = crate::crypt::calculate_hmac(&[&block_index_buf, &size_bytes, &[]], &hmac_block_key)?;

    out.extend_from_slice(&hmac);
    out.extend_from_slice(&size_bytes);

    Ok(out)
}

pub(crate) fn get_hmac_block_key(
    block_index: u64,
    key: &GenericArray<u8, U64>,
) -> Result<GenericArray<u8, U64>, CryptographyError> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, block_index as u64);
    crate::crypt::calculate_sha512(&[&buf, key])
}
