use crate::{
    config::{CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    crypt::calculate_sha256,
    db::{fields, Database, DatabaseFormatError, DatabaseOpenError, GroupId, Value},
    format::DatabaseVersion,
    key::{DatabaseKey, DatabaseKeyError},
};

use byteorder::{ByteOrder, LittleEndian};
use cipher::generic_array::GenericArray;
use thiserror::Error;

use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
};

#[derive(Debug)]
struct KDBHeader {
    // https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45
    pub flags: u32,
    pub subversion: u32,
    pub master_seed: Vec<u8>,   // 16 bytes
    pub encryption_iv: Vec<u8>, // 16 bytes
    pub num_groups: u32,
    pub num_entries: u32,
    pub contents_hash: Vec<u8>,  // 32 bytes
    pub transform_seed: Vec<u8>, // 32 bytes
    pub transform_rounds: u32,
}

const HEADER_SIZE: usize = 4 + 4 + 4 + 4 + 16 + 16 + 4 + 4 + 32 + 32 + 4; // first 4 bytes are the KeePass magic

impl TryFrom<&[u8]> for KDBHeader {
    type Error = DatabaseOpenError;

    #[allow(clippy::indexing_slicing)] // data length is checked
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < HEADER_SIZE {
            return Err(DatabaseOpenError::UnexpectedEof);
        }

        Ok(KDBHeader {
            flags: LittleEndian::read_u32(&data[8..]),
            subversion: LittleEndian::read_u32(&data[12..]),
            master_seed: data[16..32].to_vec(),
            encryption_iv: data[32..48].to_vec(),
            num_groups: LittleEndian::read_u32(&data[48..]),
            num_entries: LittleEndian::read_u32(&data[52..]),
            contents_hash: data[56..88].to_vec(),
            transform_seed: data[88..120].to_vec(),
            transform_rounds: LittleEndian::read_u32(&data[120..]),
        })
    }
}

fn from_utf8(data: &[u8]) -> String {
    String::from_utf8_lossy(data).trim_end_matches('\0').to_owned()
}

fn expected_group_field_size(ftype: u16) -> Option<u32> {
    match ftype {
        0x0001 => Some(4), // GroupId
        0x0002 => None,    // GroupName (variable length)
        0x0003 => Some(5), // CreationTime
        0x0004 => Some(5), // LastModTime
        0x0005 => Some(5), // LastAccessTime
        0x0006 => Some(5), // ExpireTime
        0x0007 => Some(4), // ImageId
        0x0008 => Some(2), // Level
        0x0009 => Some(4), // Flags
        0xffff => Some(0), // End of group
        _ => None,         // Unknown field type
    }
}

fn parse_groups(
    db: &mut Database,
    header_num_groups: u32,
    data: &mut &[u8],
) -> Result<HashMap<u32, GroupId>, DatabaseOpenError> {
    let mut gid_map: HashMap<u32, GroupId> = HashMap::new();
    gid_map.insert(0, db.root);

    // current branch of the group tree being parsed
    let mut branch: Vec<GroupId> = Vec::new();
    branch.push(db.root);

    // state variables for the current group being parsed
    let mut parsing_name: Option<String> = None;
    let mut parsing_level: Option<u16> = None;
    let mut parsing_gid: Option<u32> = None;

    // the total number of parsed groups
    let mut num_groups = 0;
    while num_groups < header_num_groups as usize {
        // Read group TLV
        let field_type = data
            .get(0..2)
            .map(LittleEndian::read_u16)
            .ok_or(DatabaseOpenError::UnexpectedEof)?;

        let field_size = data
            .get(2..6)
            .map(LittleEndian::read_u32)
            .ok_or(DatabaseOpenError::UnexpectedEof)?;

        let field_value = data
            .get(6..6 + field_size as usize)
            .ok_or(DatabaseOpenError::UnexpectedEof)?;

        if let Some(expected_field_size) = expected_group_field_size(field_type) {
            if expected_field_size != field_size {
                return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                    KdbOpenError::InvalidFieldLength {
                        field_type,
                        field_size,
                        expected_field_size,
                    },
                )));
            }
        }

        match field_type {
            0x0000 => {} // KeePass ignores this field type

            // GroupId
            0x0001 => parsing_gid = Some(LittleEndian::read_u32(field_value)),

            // GroupName
            0x0002 => parsing_name = Some(from_utf8(field_value)),

            // Creation/LastMod/LastAccess/Expire times
            0x0003..=0x0006 => {}

            // ImageId
            0x0007 => {}

            // Level
            0x0008 => parsing_level = Some(LittleEndian::read_u16(field_value)),

            // Flags
            0x0009 => {}

            // End of group
            0xffff => {
                let group_id = parsing_gid.ok_or(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                    KdbOpenError::InvalidGroupId(None),
                )))?;

                let level = parsing_level.ok_or(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                    KdbOpenError::InvalidGroupLevel {
                        current: None,
                        expected: branch.len() as u16,
                    },
                )))? as usize;

                let name = parsing_name.clone().unwrap_or_else(|| String::from(""));

                let parent_id: GroupId = if level <= branch.len() {
                    branch.truncate(level);
                    *branch.last().unwrap_or(&db.root().id())
                } else {
                    // Level is beyond the current depth, missing intermediate levels?
                    return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                        KdbOpenError::InvalidGroupLevel {
                            current: Some(level as u16),
                            expected: branch.len() as u16,
                        },
                    )));
                };

                #[allow(clippy::expect_used)] // parent_id is guaranteed to exist
                let mut parent = db.group_mut(parent_id).expect("parent group must exist");

                let mut group = parent.add_group();
                group.name = name;

                parsing_gid = None;
                parsing_name = None;
                parsing_level = None;

                gid_map.insert(group_id, group.id());

                branch.push(group.id());

                num_groups += 1;
            }
            _ => {
                return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                    KdbOpenError::InvalidGroupFieldType(field_type),
                )));
            }
        }

        *data = &data[6 + field_size as usize..];
    }

    if parsing_gid.is_some() {
        return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
            KdbOpenError::IncompleteGroup,
        )));
    }

    Ok(gid_map)
}

fn expected_entry_field_size(ftype: u16) -> Option<u32> {
    match ftype {
        0x0000 => None,     // KeePass ignores this field type
        0x0001 => Some(16), // uuid
        0x0002 => Some(4),  // GroupId
        0x0003 => Some(4),  // ImageId
        0x0004 => None,     // Title (variable length)
        0x0005 => None,     // URL (variable length)
        0x0006 => None,     // UserName (variable length)
        0x0007 => None,     // Password (variable length)
        0x0008 => None,     // Additional (variable length)
        0x0009 => Some(5),  // CreationTime
        0x000a => Some(5),  // LastModTime
        0x000b => Some(5),  // LastAccessTime
        0x000c => Some(5),  // ExpireTime
        0x000d => None,     // BinaryDesc (variable length)
        0x000e => None,     // BinaryData (variable length)
        0xffff => Some(0),  // End of entry
        _ => None,          // Unknown field type
    }
}

fn parse_entries(
    db: &mut Database,
    gid_map: HashMap<u32, GroupId>,
    header_num_entries: u32,
    data: &mut &[u8],
) -> Result<(), DatabaseOpenError> {
    let mut parsing_gid: Option<u32> = None;
    let mut parsing_fields: HashMap<String, Value<String>> = HashMap::new();

    let mut parsing_binary_desc: Option<String> = None;
    let mut parsing_binary_data: Option<Vec<u8>> = None;

    let mut entry_attachments: HashMap<String, Vec<u8>> = HashMap::new();

    let mut num_entries = 0;
    while num_entries < header_num_entries {
        let field_type = data.get(0..2).ok_or(DatabaseOpenError::UnexpectedEof)?;
        let field_type = LittleEndian::read_u16(field_type);

        let field_size = data.get(2..6).ok_or(DatabaseOpenError::UnexpectedEof)?;
        let field_size = LittleEndian::read_u32(field_size);

        let field_value = data
            .get(6..6 + field_size as usize)
            .ok_or(DatabaseOpenError::UnexpectedEof)?;

        if let Some(expected_field_size) = expected_entry_field_size(field_type) {
            if expected_field_size != field_size {
                return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                    KdbOpenError::InvalidFieldLength {
                        field_type,
                        field_size,
                        expected_field_size,
                    },
                )));
            }
        }

        match field_type {
            // ignored by KeePass
            0x0000 => {} // KeePass ignores this field type

            // UUID
            0x0001 => {}

            // GroupId
            0x0002 => parsing_gid = Some(LittleEndian::read_u32(field_value)),

            // ImageId
            0x0003 => {}

            // Title
            0x0004 => {
                parsing_fields.insert(
                    String::from(fields::TITLE),
                    Value::unprotected(from_utf8(field_value)),
                );
            }

            // URL
            0x0005 => {
                parsing_fields.insert(
                    String::from(fields::URL),
                    Value::unprotected(from_utf8(field_value)),
                );
            }

            // UserName
            0x0006 => {
                parsing_fields.insert(
                    String::from(fields::USERNAME),
                    Value::unprotected(from_utf8(field_value)),
                );
            }

            // Password
            0x0007 => {
                parsing_fields.insert(
                    String::from(fields::PASSWORD),
                    Value::protected(from_utf8(field_value)),
                );
            }

            // Additional
            0x0008 => {
                parsing_fields.insert(
                    String::from(fields::NOTES),
                    Value::unprotected(from_utf8(field_value)),
                );
            }

            // Creation/LastMod/LastAccess/Expire times
            0x0009..=0x000c => {}

            // BinaryDesc
            0x000d => {
                if let Some(ref data) = parsing_binary_data {
                    entry_attachments.insert(from_utf8(field_value), data.clone());
                    parsing_binary_desc = None;
                } else {
                    parsing_binary_desc = Some(from_utf8(field_value));
                }
            }

            // BinaryData
            0x000e => {
                if let Some(ref desc) = parsing_binary_desc {
                    entry_attachments.insert(desc.clone(), field_value.to_vec());
                    parsing_binary_data = None;
                } else {
                    parsing_binary_data = Some(field_value.to_vec());
                }
            }

            0xffff => {
                let gid = parsing_gid.ok_or(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                    KdbOpenError::InvalidGroupId(None),
                )))?;
                let group_id =
                    *gid_map
                        .get(&gid)
                        .ok_or(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                            KdbOpenError::InvalidGroupId(Some(gid)),
                        )))?;

                #[allow(clippy::expect_used)] // group_id was checked before
                let mut group = db.group_mut(group_id).expect("group must exist");

                let mut entry = group.add_entry();
                entry.fields = parsing_fields.clone();

                for (desc, data) in entry_attachments.drain() {
                    entry.add_attachment(desc, Value::protected(data));
                }

                parsing_fields.clear();

                parsing_gid = None;
                num_entries += 1;
            }

            _ => {
                return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
                    KdbOpenError::InvalidEntryFieldType(field_type),
                )));
            }
        }

        *data = data
            .get(6 + field_size as usize..)
            .ok_or(DatabaseOpenError::UnexpectedEof)?;
    }

    if parsing_gid.is_some() {
        return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
            KdbOpenError::IncompleteEntry,
        )));
    }

    Ok(())
}

pub(crate) fn parse_kdb(data: &[u8], db_key: &DatabaseKey) -> Result<Database, DatabaseOpenError> {
    let header = KDBHeader::try_from(data)?;
    let version = DatabaseVersion::KDB(header.subversion as u16);

    // Rest of file after header is payload
    let payload_encrypted = data.get(HEADER_SIZE..).ok_or(DatabaseOpenError::UnexpectedEof)?;

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements = db_key.get_key_elements()?;
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = if key_elements.len() == 1 {
        #[allow(clippy::indexing_slicing, clippy::expect_used)] // key_elements is guaranteed to be 1 byte
        let key_element: [u8; 32] = key_elements[0]
            .try_into()
            .expect("initializing from single element should always succeed");
        GenericArray::from(key_element) // single pass of SHA256, already done before the call to parse()
    } else {
        calculate_sha256(&key_elements) // second pass of SHA256
    };

    // KDF is always AES
    let kdf_config = KdfConfig::Aes {
        rounds: u64::from(header.transform_rounds),
    };

    let transformed_key = kdf_config
        .get_kdf_seeded(&header.transform_seed)
        .transform_key(&composite_key)?;

    let master_key = calculate_sha256(&[&header.master_seed, &transformed_key]);

    let outer_cipher_config = if header.flags & 2 != 0 {
        OuterCipherConfig::AES256
    } else if header.flags & 8 != 0 {
        OuterCipherConfig::Twofish
    } else {
        return Err(DatabaseOpenError::Format(DatabaseFormatError::Kdb(
            KdbOpenError::InvalidFixedCipherID(header.flags),
        )));
    };

    // Decrypt payload
    #[allow(clippy::expect_used)] // master key is fixed-length, should never fail
    let payload_padded = outer_cipher_config
        .get_cipher(&master_key, header.encryption_iv.as_ref())
        .expect("Database key correctly derived")
        .decrypt(payload_encrypted)?;

    let padlen = payload_padded
        .last()
        .copied()
        .ok_or(DatabaseOpenError::UnexpectedEof)? as usize;
    let payload = payload_padded
        .get(..payload_padded.len() - padlen)
        .ok_or(DatabaseOpenError::UnexpectedEof)?;

    // Check if we decrypted correctly
    let hash = calculate_sha256(&[payload]);
    if header.contents_hash != hash.as_slice() {
        return Err(DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey));
    }

    let config = DatabaseConfig {
        version,
        outer_cipher_config,
        compression_config: CompressionConfig::None,
        inner_cipher_config: InnerCipherConfig::Plain,
        kdf_config,
        public_custom_data: Default::default(),
    };

    let mut db = Database::with_data(config, GroupId::new());
    db.root_mut().name = String::from("Root");

    let mut pos = payload;

    let gid_map = parse_groups(&mut db, header.num_groups, &mut pos)?;
    parse_entries(&mut db, gid_map, header.num_entries, &mut pos)?;

    Ok(db)
}

/// Errors that can occur when opening a KeePass 1 database
#[derive(Debug, Error)]
pub enum KdbOpenError {
    #[error("Field of type {field_type} has invalid length {field_size}, expected {expected_field_size}")]
    InvalidFieldLength {
        field_type: u16,
        field_size: u32,
        expected_field_size: u32,
    },

    #[error("Invalid group level: got {current:?}, expected {expected}")]
    InvalidGroupLevel { current: Option<u16>, expected: u16 },

    #[error("Invalid group ID: {0:?}")]
    InvalidGroupId(Option<u32>),

    #[error("Invalid group field type: {0}")]
    InvalidGroupFieldType(u16),

    #[error("Group was not terminated before end of file")]
    IncompleteGroup,

    #[error("Entry is missing group ID")]
    EntryMissingGroupId,

    #[error("Invalid entry field type: {0}")]
    InvalidEntryFieldType(u16),

    #[error("Entry was not terminated before end of file")]
    IncompleteEntry,

    #[error("Invalid fixed cipher ID: {0}")]
    InvalidFixedCipherID(u32),
}
