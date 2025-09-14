use crate::{
    config::{CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    crypt::calculate_sha256,
    db::{Database, GroupId, Value},
    format::DatabaseVersion,
    key::{DatabaseKey, GetKeyElementsError},
};

use byteorder::{ByteOrder, LittleEndian};
use cipher::{block_padding::UnpadError, generic_array::GenericArray};
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
    type Error = InvalidFixedHeader;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < HEADER_SIZE {
            return Err(InvalidFixedHeader(data.len()));
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

#[derive(Error, Debug)]
#[error("Fixed header is too small ({0} bytes)")]
pub struct InvalidFixedHeader(usize);

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
) -> Result<HashMap<u32, GroupId>, KdbParseGroupError> {
    // mapping from KDBX numeric group IDs to the corresponding GroupId in the database
    let mut gid_map: HashMap<u32, GroupId> = HashMap::new();

    gid_map.insert(0, db.root().id()); // KDB group ID 0 is always the root group

    // current branch of the group tree being parsed
    let mut branch: Vec<GroupId> = Vec::new();

    // state variables for the current group being parsed
    let mut parsing_name: Option<String> = None;
    let mut parsing_level: Option<u16> = None;
    let mut parsing_gid: Option<u32> = None;

    // the total number of parsed groups
    let mut num_groups = 0;
    while num_groups < header_num_groups as usize {
        // Field type (2 bytes), Field size (4 bytes), Field value (variable size)
        let ftype = LittleEndian::read_u16(&data[0..]);
        let size = LittleEndian::read_u32(&data[2..]);
        let value = &data[6..6 + size as usize];

        if let Some(expected_size) = expected_group_field_size(ftype) {
            if expected_size != size {
                return Err(KdbParseGroupError::InvalidFieldLength {
                    ftype,
                    size,
                    expected_size,
                });
            }
        }

        match ftype {
            // Ignored field
            0x0000 => {} // KeePass ignores this field type

            // GroupId
            0x0001 => parsing_gid = Some(LittleEndian::read_u32(value)),

            // GroupName
            0x0002 => parsing_name = Some(from_utf8(value)), // GroupName

            // Creation/LastMod/LastAccess/Expire times
            0x0003..=0x0006 => {}

            // ImageId
            0x0007 => {}

            // Level
            0x0008 => parsing_level = Some(LittleEndian::read_u16(value)),

            // Flags
            0x0009 => {}

            // End of group
            0xffff => {
                let group_id = parsing_gid.ok_or(KdbParseGroupError::MissingKDBGroupId)?;
                let level = parsing_level.ok_or(KdbParseGroupError::MissingKDBGroupLevel(group_id))? as usize;
                let name = parsing_name.clone().unwrap_or_else(|| String::from(""));

                let parent_id: GroupId = if (level as usize) <= branch.len() {
                    branch.truncate(level);

                    *branch.last().unwrap_or(&db.root().id())
                } else {
                    // Level is beyond the current depth, missing intermediate levels?
                    return Err(KdbParseGroupError::InvalidKDBGroupLevel {
                        group_level: level as u16,
                        current_level: branch.len() as u16,
                    });
                };

                let mut parent = db.group_mut(parent_id).expect("parent group must exist");

                let mut group = parent.add_group();
                group.name = name;

                parsing_gid = None;
                parsing_name = None;
                parsing_level = None;

                gid_map.insert(group_id, group.id());

                num_groups += 1;
            }
            _ => {
                return Err(KdbParseGroupError::InvalidFieldType(ftype));
            }
        }

        *data = &data[6 + size as usize..];
    }

    if let Some(g) = parsing_gid {
        return Err(KdbParseGroupError::IncompleteKDBGroup(g));
    }

    Ok(gid_map)
}

#[derive(Error, Debug)]
pub enum KdbParseGroupError {
    #[error("Invalid group field type: {0}")]
    InvalidFieldType(u16),

    #[error("Invalid group field length for type {ftype}: got {size}, expected {expected_size}")]
    InvalidFieldLength {
        ftype: u16,
        size: u32,
        expected_size: u32,
    },

    #[error("A group with ID {0} was started that was never closed")]
    IncompleteKDBGroup(u32),

    #[error("A group with was finished without specifying its ID")]
    MissingKDBGroupId,

    #[error("A group with ID {0} was finished without specifying its level")]
    MissingKDBGroupLevel(u32),

    #[error("Invalid group level {group_level} (current level is {current_level})")]
    InvalidKDBGroupLevel { group_level: u16, current_level: u16 },
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
) -> Result<(), KdbParseEntryError> {
    let mut parsing_gid: Option<u32> = None;
    let mut parsing_fields: HashMap<String, Value> = HashMap::new();

    let mut num_entries = 0;
    while num_entries < header_num_entries {
        let field_type = LittleEndian::read_u16(&data[0..]);
        let field_size = LittleEndian::read_u32(&data[2..]);
        let field_value = &data[6..6 + field_size as usize];

        if let Some(expected_size) = expected_entry_field_size(field_type) {
            if expected_size != field_size {
                return Err(KdbParseEntryError::InvalidFieldLength {
                    field_type,
                    size: field_size,
                    expected_size,
                });
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
                parsing_fields.insert(String::from("Title"), Value::string(from_utf8(field_value)));
            }

            // URL
            0x0005 => {
                parsing_fields.insert(String::from("URL"), Value::string(from_utf8(field_value)));
            }

            // UserName
            0x0006 => {
                parsing_fields.insert(String::from("UserName"), Value::string(from_utf8(field_value)));
            }

            // Password
            0x0007 => {
                parsing_fields.insert(
                    String::from("Password"),
                    Value::protected_string(from_utf8(field_value)),
                );
            }

            // Additional
            0x0008 => {
                parsing_fields.insert(String::from("Additional"), Value::string(from_utf8(field_value)));
            }

            // Creation/LastMod/LastAccess/Expire times
            0x0009..=0x000c => {}

            // BinaryDesc
            0x000d => {
                parsing_fields.insert(String::from("BinaryDesc"), Value::string(from_utf8(field_value)));
            }

            // BinaryData
            0x000e => {
                parsing_fields.insert(String::from("BinaryData"), Value::bytes(field_value.to_vec()));
            }

            0xffff => {
                let gid = parsing_gid.ok_or(KdbParseEntryError::MissingGroupId)?;
                let group_id = *gid_map.get(&gid).ok_or(KdbParseEntryError::UnknownGroupId(gid))?;

                let mut group = db.group_mut(group_id).expect("group must exist");

                let mut entry = group.add_entry();
                entry.fields = parsing_fields.clone();

                parsing_fields.clear();

                parsing_gid = None;
                num_entries += 1;
            }

            _ => {
                return Err(KdbParseEntryError::InvalidFieldType(field_type));
            }
        }

        *data = &data[6 + field_size as usize..];
    }

    if parsing_gid.is_some() {
        return Err(KdbParseEntryError::IncompleteEntry);
    }

    Ok(())
}

#[derive(Error, Debug)]
pub enum KdbParseEntryError {
    #[error("Invalid entry field type: {0}")]
    InvalidFieldType(u16),

    #[error("Invalid entry field length for type {field_type}: got {size}, expected {expected_size}")]
    InvalidFieldLength {
        field_type: u16,
        size: u32,
        expected_size: u32,
    },

    #[error("Entry is missing group ID")]
    MissingGroupId,

    #[error("Entry is pointing to unknown group ID {0}")]
    UnknownGroupId(u32),

    #[error("Incomplete Entry")]
    IncompleteEntry,
}

pub(crate) fn parse_kdb(data: &[u8], db_key: &DatabaseKey) -> Result<Database, ParseKdbError> {
    let header = KDBHeader::try_from(data)?;
    let version = DatabaseVersion::KDB(header.subversion as u16);

    // Rest of file after header is payload
    let payload_encrypted = &data[HEADER_SIZE..];

    // derive master key from composite key, transform_seed, transform_rounds and master_seed
    let key_elements = db_key.get_key_elements()?;
    let key_elements: Vec<&[u8]> = key_elements.iter().map(|v| &v[..]).collect();
    let composite_key = if key_elements.len() == 1 {
        let key_element: [u8; 32] = key_elements[0].try_into().unwrap();
        GenericArray::from(key_element) // single pass of SHA256, already done before the call to parse()
    } else {
        calculate_sha256(&key_elements) // second pass of SHA256
    };

    // KDF is always AES
    let kdf_config = KdfConfig::Aes {
        rounds: header.transform_rounds as u64,
    };

    let transformed_key = kdf_config
        .get_kdf_seeded(&header.transform_seed)
        .transform_key(&composite_key)
        .map_err(|e| ParseKdbError::KeyDerivation(format!("{}", e)))?;

    let master_key = calculate_sha256(&[&header.master_seed, &transformed_key]);

    let outer_cipher_config = if header.flags & 2 != 0 {
        OuterCipherConfig::AES256
    } else if header.flags & 8 != 0 {
        OuterCipherConfig::Twofish
    } else {
        return Err(ParseKdbError::InvalidFixedCipherID(header.flags));
    };

    // Decrypt payload
    let payload_padded = outer_cipher_config
        .get_cipher(&master_key, header.encryption_iv.as_ref())
        .expect("Database key correctly derived")
        .decrypt(payload_encrypted)?;
    let padlen = payload_padded[payload_padded.len() - 1] as usize;
    let payload = &payload_padded[..payload_padded.len() - padlen];

    // Check if we decrypted correctly
    let hash = calculate_sha256(&[payload]);
    if header.contents_hash != hash.as_slice() {
        return Err(ParseKdbError::IncorrectKey);
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

    let mut pos = data;

    let gid_map = parse_groups(&mut db, header.num_groups, &mut pos)?;
    parse_entries(&mut db, gid_map, header.num_entries, &mut pos)?;

    Ok(db)
}

#[derive(Error, Debug)]
pub enum ParseKdbError {
    #[error("Invalid fixed header: {0}")]
    InvalidFixedHeader(#[from] InvalidFixedHeader),

    #[error("Invalid fixed cipher ID: {0}")]
    InvalidFixedCipherID(u32),

    #[error("Error getting key elements: {0}")]
    Key(#[from] GetKeyElementsError),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    #[error("Invalid payload padding: {0}")]
    InvalidPayloadPadding(#[from] UnpadError),

    #[error("Incorrect key")]
    IncorrectKey,

    #[error("Error parsing groups: {0}")]
    KdbParseGroupError(#[from] KdbParseGroupError),

    #[error("Error parsing entries: {0}")]
    KdbParseEntryError(#[from] KdbParseEntryError),
}
