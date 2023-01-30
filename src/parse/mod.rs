pub(crate) mod kdb;
pub(crate) mod kdbx3;
pub(crate) mod kdbx4;

use byteorder::{ByteOrder, LittleEndian};

use crate::DatabaseIntegrityError;

const KDBX_IDENTIFIER: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];

/// Identifier for KeePass 1 format.
pub const KEEPASS_1_ID: u32 = 0xb54bfb65;
/// Identifier for KeePass 2 pre-release format.
pub const KEEPASS_2_ID: u32 = 0xb54bfb66;
/// Identifier for the latest KeePass formats.
pub const KEEPASS_LATEST_ID: u32 = 0xb54bfb67;

pub const KDBX3_MAJOR_VERSION: u16 = 3;
pub const KDBX4_MAJOR_VERSION: u16 = 4;

/// Supported KDB database versions, with the associated
/// minor version.
#[derive(Debug)]
pub enum DatabaseVersion {
    KDB(u16),
    KDB2(u16),
    KDB3(u16),
    KDB4(u16),
}

impl DatabaseVersion {
    pub fn parse(data: &[u8]) -> Result<DatabaseVersion, DatabaseIntegrityError> {
        // check identifier
        if data[0..4] != KDBX_IDENTIFIER {
            return Err(DatabaseIntegrityError::InvalidKDBXIdentifier.into());
        }

        let version = LittleEndian::read_u32(&data[4..8]);
        let file_minor_version = LittleEndian::read_u16(&data[8..10]);
        let file_major_version = LittleEndian::read_u16(&data[10..12]);

        let response = match version {
            KEEPASS_1_ID => DatabaseVersion::KDB(file_minor_version),
            KEEPASS_2_ID => DatabaseVersion::KDB2(file_minor_version),
            KEEPASS_LATEST_ID if file_major_version == KDBX3_MAJOR_VERSION => {
                DatabaseVersion::KDB3(file_minor_version)
            }
            KEEPASS_LATEST_ID if file_major_version == KDBX4_MAJOR_VERSION => {
                DatabaseVersion::KDB4(file_minor_version)
            }
            _ => {
                return Err(DatabaseIntegrityError::InvalidKDBXVersion {
                    version,
                    file_major_version: file_major_version as u32,
                    file_minor_version: file_minor_version as u32,
                }
                .into())
            }
        };

        Ok(response)
    }

    fn dump(&self) -> Vec<u8> {
        if let DatabaseVersion::KDB4(minor_version) = self {
            let mut header_data: Vec<u8> = vec![];
            header_data.extend_from_slice(&crate::parse::KDBX_IDENTIFIER);
            header_data.resize(DatabaseVersion::get_version_header_size(), 0);
            LittleEndian::write_u32(&mut header_data[4..8], KEEPASS_LATEST_ID);
            LittleEndian::write_u16(&mut header_data[8..10], *minor_version);
            LittleEndian::write_u16(&mut header_data[10..12], KDBX4_MAJOR_VERSION);

            return header_data;
        } else {
            panic!("DatabaseVersion::dump only supports dumping KDBX4.");
        }
    }

    pub fn get_version_header_size() -> usize {
        12
    }
}

impl ToString for DatabaseVersion {
    fn to_string(&self) -> String {
        match self {
            DatabaseVersion::KDB(_) => "KDB".to_string(),
            DatabaseVersion::KDB2(_) => "KDBX2".to_string(),
            DatabaseVersion::KDB3(minor_version) => format!("KDBX3.{}", minor_version),
            DatabaseVersion::KDB4(minor_version) => format!("KDBX4.{}", minor_version),
        }
    }
}

/// Read the KDBX header to get the file version
pub fn get_kdbx_version(data: &[u8]) -> Result<(u32, u16, u16), DatabaseIntegrityError> {
    // check identifier
    if data[0..4] != KDBX_IDENTIFIER {
        return Err(DatabaseIntegrityError::InvalidKDBXIdentifier.into());
    }

    let version = LittleEndian::read_u32(&data[4..8]);
    let file_minor_version = LittleEndian::read_u16(&data[8..10]);
    let file_major_version = LittleEndian::read_u16(&data[10..12]);

    Ok((version, file_major_version, file_minor_version))
}
