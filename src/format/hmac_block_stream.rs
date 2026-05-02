use byteorder::{ByteOrder, LittleEndian};
use hex_literal::hex;
use hybrid_array::{typenum::U64, Array as GenericArray};
use thiserror::Error;

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
        let hmac = data.get(pos..(pos + 32)).ok_or(BlockStreamError::Eof)?;
        let size_bytes = data.get((pos + 32)..(pos + 36)).ok_or(BlockStreamError::Eof)?;
        let size = LittleEndian::read_u32(size_bytes) as usize;
        let block = data
            .get((pos + 36)..(pos + 36 + size))
            .ok_or(BlockStreamError::Eof)?;

        // verify block hmac
        let hmac_block_key = get_hmac_block_key(block_index, key);
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index);

        #[allow(clippy::expect_used)] // Block stream key is always correctly sized, so this can't fail
        if hmac
            != crate::crypt::calculate_hmac(&[&block_index_buf, size_bytes, block], &hmac_block_key)
                .expect("Block stream key always correctly sized")
                .as_slice()
        {
            return Err(BlockStreamError::BlockHashMismatch { block_index });
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
pub(crate) fn write_hmac_block_stream(data: &[u8], key: &GenericArray<u8, U64>) -> Vec<u8> {
    let mut out = Vec::new();

    let mut pos = 0;
    let mut block_index = 0;

    while pos < data.len() {
        let size = data.len() - pos;

        #[allow(clippy::indexing_slicing)] // we check slice length at the beginning of the loop
        let block = &data[pos..(pos + size)];

        let mut size_bytes: Vec<u8> = vec![0; 4];
        LittleEndian::write_u32(&mut size_bytes, size as u32);

        // Generate block hmac
        let hmac_block_key = get_hmac_block_key(block_index, key);
        let mut block_index_buf = [0u8; 8];
        LittleEndian::write_u64(&mut block_index_buf, block_index);

        #[allow(clippy::expect_used)] // Block stream key is always correctly sized, so this can't fail
        let hmac = crate::crypt::calculate_hmac(&[&block_index_buf, &size_bytes, block], &hmac_block_key)
            .expect("Block stream key always correctly sized");

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

    #[allow(clippy::expect_used)] // Block stream key is always correctly sized, so this can't fail
    let hmac = crate::crypt::calculate_hmac(&[&block_index_buf, &size_bytes, &[]], &hmac_block_key)
        .expect("Block stream key always correctly sized");

    out.extend_from_slice(&hmac);
    out.extend_from_slice(&size_bytes);

    out
}

pub(crate) fn get_hmac_block_key(block_index: u64, key: &GenericArray<u8, U64>) -> GenericArray<u8, U64> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, block_index);
    crate::crypt::calculate_sha512(&[&buf, key])
}

/// Errors reading from the HMAC block stream
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BlockStreamError {
    /// The HMAC of a block did not match the expected value, indicating that the data may be
    /// corrupted or tampered with.
    #[error("Block hash mismatch for block {}", block_index)]
    BlockHashMismatch {
        /// The index of the block that failed the HMAC verification
        block_index: u64,
    },

    /// The end of the file was reached unexpectedly while reading a block, indicating that the
    /// data may be incomplete or corrupted.
    #[error("unexpected end of file")]
    Eof,
}
