pub(crate) mod kdb;
pub(crate) mod kdbx3;
pub(crate) mod kdbx4;

#[cfg(feature = "save_kdbx4")]
use std::io::Write;

#[cfg(feature = "save_kdbx4")]
use byteorder::WriteBytesExt;
use byteorder::{ByteOrder, LittleEndian};

use crate::error::DatabaseIntegrityError;

const KDBX_IDENTIFIER: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];

/// Identifier for KeePass 1 format.
pub const KEEPASS_1_ID: u32 = 0xb54bfb65;
/// Identifier for KeePass 2 pre-release format.
pub const KEEPASS_2_ID: u32 = 0xb54bfb66;
/// Identifier for the latest KeePass formats.
pub const KEEPASS_LATEST_ID: u32 = 0xb54bfb67;

pub const KDBX3_MAJOR_VERSION: u16 = 3;
pub const KDBX4_MAJOR_VERSION: u16 = 4;

pub const KDBX4_CURRENT_MINOR_VERSION: u16 = 0;

/// Supported KDB database versions, with the associated
/// minor version.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum DatabaseVersion {
    KDB(u16),
    KDB2(u16),
    KDB3(u16),
    KDB4(u16),
}

impl DatabaseVersion {
    pub fn parse(data: &[u8]) -> Result<DatabaseVersion, DatabaseIntegrityError> {
        if data.len() < DatabaseVersion::get_version_header_size() {
            return Err(DatabaseIntegrityError::InvalidKDBXIdentifier.into());
        }

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

    #[cfg(feature = "save_kdbx4")]
    fn dump(&self, writer: &mut dyn Write) -> Result<(), std::io::Error> {
        if let DatabaseVersion::KDB4(minor_version) = self {
            writer.write(&crate::format::KDBX_IDENTIFIER)?;
            writer.write_u32::<LittleEndian>(KEEPASS_LATEST_ID)?;
            writer.write_u16::<LittleEndian>(*minor_version)?;
            writer.write_u16::<LittleEndian>(KDBX4_MAJOR_VERSION)?;

            Ok(())
        } else {
            panic!("DatabaseVersion::dump only supports dumping KDBX4.");
        }
    }

    pub(crate) fn get_version_header_size() -> usize {
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
