pub(crate) mod kdb;
pub(crate) mod kdbx3;
pub(crate) mod kdbx4;

use byteorder::{ByteOrder, LittleEndian};

use crate::result::{DatabaseIntegrityError, Result};

const KDBX_IDENTIFIER: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];

/// Read the KDBX header to get the file version
pub fn get_kdbx_version(data: &[u8]) -> Result<(u32, u16, u16)> {
    // check identifier
    if data[0..4] != KDBX_IDENTIFIER {
        return Err(DatabaseIntegrityError::InvalidKDBXIdentifier.into());
    }

    let version = LittleEndian::read_u32(&data[4..8]);
    let file_minor_version = LittleEndian::read_u16(&data[8..10]);
    let file_major_version = LittleEndian::read_u16(&data[10..12]);

    Ok((version, file_major_version, file_minor_version))
}
