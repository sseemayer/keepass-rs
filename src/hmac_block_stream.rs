use byteorder::{ByteOrder, LittleEndian};
use cipher::generic_array::{typenum::U64, GenericArray};
use hex_literal::hex;
use thiserror::Error;

pub const HMAC_KEY_END: [u8; 1] = hex!("01");

/// Read from a HMAC block stream into a raw buffer
pub(crate) fn read_hmac_block_stream(
    data: &[u8],
    key: &GenericArray<u8, U64>,
) -> Result<Vec<u8>, BlockHashMismatchError> {
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
        let hmac_block_key = get_hmac_block_key(block_index, key);
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index);

        if hmac
            != crate::crypt::calculate_hmac(&[&block_index_buf, size_bytes, block], &hmac_block_key)
                .expect("HMAC block key calculated correctly")
                .as_slice()
        {
            return Err(BlockHashMismatchError { block_index });
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

#[derive(Debug, Error)]
#[error("Block hash mismatch at block index {block_index}")]
pub struct BlockHashMismatchError {
    pub block_index: u64,
}

#[cfg(feature = "save_kdbx4")]
/// Write a raw buffer as a HMAC block stream
pub(crate) fn write_hmac_block_stream(data: &[u8], key: &GenericArray<u8, U64>) -> Vec<u8> {
    let mut out = Vec::new();

    let mut pos = 0;
    let mut block_index = 0;

    while pos < data.len() {
        let size = data.len() - pos;

        let block = &data[pos..(pos + size)];

        let mut size_bytes: Vec<u8> = vec![0; 4];
        LittleEndian::write_u32(&mut size_bytes, size as u32);

        // Generate block hmac
        let hmac_block_key = get_hmac_block_key(block_index, key);
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index);

        let hmac = crate::crypt::calculate_hmac(&[&block_index_buf, &size_bytes, block], &hmac_block_key)
            .expect("Correctly constructed HMAC block key");

        pos += 36 + size;
        block_index += 1;

        out.extend_from_slice(&hmac);
        out.extend_from_slice(&size_bytes);
        out.extend_from_slice(block);
    }

    // the end of the HMAC block stream should be an empty block, but with a valid HMAC
    let hmac_block_key = get_hmac_block_key(block_index, key);
    let mut block_index_buf = [0u8; 8];
    LittleEndian::write_u64(&mut block_index_buf, block_index);

    let size_bytes = vec![0; 4];
    let hmac = crate::crypt::calculate_hmac(&[&block_index_buf, &size_bytes, &[]], &hmac_block_key)
        .expect("Correctly constructed HMAC block key");

    out.extend_from_slice(&hmac);
    out.extend_from_slice(&size_bytes);

    out
}

pub(crate) fn get_hmac_block_key(block_index: u64, key: &GenericArray<u8, U64>) -> GenericArray<u8, U64> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, block_index);
    crate::crypt::calculate_sha512(&[&buf, key])
}
