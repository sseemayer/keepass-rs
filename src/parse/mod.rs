pub(crate) mod kdbx3;

use byteorder::{ByteOrder, LittleEndian};

/// Read the KDBX header to get the file version
pub fn get_kdbx_version(data: &[u8]) -> (u32, u16, u16) {
    let version = LittleEndian::read_u32(&data[4..8]);
    let file_minor_version = LittleEndian::read_u16(&data[8..10]);
    let file_major_version = LittleEndian::read_u16(&data[10..12]);

    (version, file_major_version, file_minor_version)
}
