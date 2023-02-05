pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod meta;
pub(crate) mod node;

#[cfg(feature = "totp")]
pub(crate) mod otp;

use std::collections::HashMap;

use chrono::NaiveDateTime;
use thiserror::Error;

pub use crate::db::{
    entry::{AutoType, AutoTypeAssociation, Entry, Value},
    group::Group,
    meta::{BinaryAttachment, Meta},
    node::{Node, NodeIter, NodeRef, NodeRefMut},
};

#[cfg(feature = "totp")]
pub use crate::otp::{TOTPError, TOTP};

use crate::{
    config::{
        Compression, CompressionError, InnerCipherSuite, InnerCipherSuiteError, KdfSettings,
        KdfSettingsError, OuterCipherSuite, OuterCipherSuiteError,
    },
    crypt::{calculate_sha256, CryptographyError},
    format::{
        kdb::KDBHeader,
        kdbx3::KDBX3Header,
        kdbx4::{KDBX4Header, KDBX4InnerHeader},
        DatabaseVersion, KDBX4_CURRENT_MINOR_VERSION,
    },
    hmac_block_stream::BlockStreamError,
    keyfile::KeyfileError,
    variant_dictionary::VariantDictionaryError,
    xml_db::parse::XmlParseError,
};

#[derive(Debug)]
pub enum Header {
    KDB(KDBHeader),
    KDBX3(KDBX3Header),
    KDBX4(KDBX4Header),
}

#[derive(Debug)]
pub enum InnerHeader {
    None,
    KDBX4(KDBX4InnerHeader),
}

/// A decrypted KeePass database
#[derive(Debug)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Database {
    /// Header information of the KeePass database
    #[cfg_attr(feature = "serialization", serde(skip))]
    pub header: Header,

    /// Optional inner header information
    #[cfg_attr(feature = "serialization", serde(skip))]
    pub inner_header: InnerHeader,

    /// Root node of the KeePass database
    pub root: Group,

    /// Metadata of the KeePass database
    pub meta: Meta,
}

#[derive(Debug, Error)]
pub enum DatabaseKeyError {
    #[error("Incorrect key")]
    IncorrectKey,

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error(transparent)]
    Keyfile(#[from] KeyfileError),
}

#[derive(Debug, Error)]
pub enum DatabaseOpenError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Key(#[from] DatabaseKeyError),

    #[error(transparent)]
    DatabaseIntegrity(#[from] DatabaseIntegrityError),

    #[error("Opening this database version is not supported")]
    UnsupportedVersion,
}

#[derive(Debug, Error)]
pub enum DatabaseIntegrityError {
    #[error("Invalid KDBX identifier")]
    InvalidKDBXIdentifier,

    #[error(
        "Invalid KDBX version: {}.{}.{}",
        version,
        file_major_version,
        file_minor_version
    )]
    InvalidKDBXVersion {
        version: u32,
        file_major_version: u32,
        file_minor_version: u32,
    },

    #[error("Invalid header size: {}", size)]
    InvalidFixedHeader { size: usize },

    #[error(
        "Invalid field length for type {}: {} (expected {})",
        field_type,
        field_size,
        expected_field_size
    )]
    InvalidKDBFieldLength {
        field_type: u16,
        field_size: u32,
        expected_field_size: u32,
    },

    #[error("Missing group level")]
    MissingKDBGroupLevel,

    #[error(
        "Invalid group level {} (current level {})",
        group_level,
        current_level
    )]
    InvalidKDBGroupLevel {
        group_level: u16,
        current_level: u16,
    },

    #[error("Missing group ID")]
    MissingKDBGroupId,

    #[error("Invalid group ID {}", group_id)]
    InvalidKDBGroupId { group_id: u32 },

    #[error("Invalid group field type: {}", field_type)]
    InvalidKDBGroupFieldType { field_type: u16 },

    #[error("Invalid entry field type: {}", field_type)]
    InvalidKDBEntryFieldType { field_type: u16 },

    #[error("Incomplete group")]
    IncompleteKDBGroup,

    #[error("Incomplete entry")]
    IncompleteKDBEntry,

    #[error("Invalid fixed cipher ID: {}", cid)]
    InvalidFixedCipherID { cid: u32 },

    #[error("Header hash masmatch")]
    HeaderHashMismatch,

    #[error("Invalid outer header entry: {}", entry_type)]
    InvalidOuterHeaderEntry { entry_type: u8 },

    #[error("Incomplete outer header: Missing {}", missing_field)]
    IncompleteOuterHeader { missing_field: String },

    #[error("Invalid inner header entry: {}", entry_type)]
    InvalidInnerHeaderEntry { entry_type: u8 },

    #[error("Incomplete outer header: Missing {}", missing_field)]
    IncompleteInnerHeader { missing_field: String },

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error(transparent)]
    Xml(#[from] XmlParseError),

    #[error(transparent)]
    OuterCipher(#[from] OuterCipherSuiteError),

    #[error(transparent)]
    InnerCipher(#[from] InnerCipherSuiteError),

    #[error(transparent)]
    Compression(#[from] CompressionError),

    #[error(transparent)]
    BlockStream(#[from] BlockStreamError),

    #[error(transparent)]
    VariantDictionary(#[from] VariantDictionaryError),

    #[error(transparent)]
    KdfSettings(#[from] KdfSettingsError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum DatabaseSaveError {
    #[error("Saving this database version is not supported")]
    UnsupportedVersion,

    #[error("Error while generating XML")]
    Xml(#[from] xml::writer::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Key(#[from] DatabaseKeyError),

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Error generating random data: {}", _0)]
    Random(String),
}

impl From<getrandom::Error> for DatabaseSaveError {
    fn from(e: getrandom::Error) -> Self {
        DatabaseSaveError::Random(format!("{}", e))
    }
}

impl From<CryptographyError> for DatabaseOpenError {
    fn from(e: CryptographyError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<BlockStreamError> for DatabaseOpenError {
    fn from(e: BlockStreamError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<XmlParseError> for DatabaseOpenError {
    fn from(e: XmlParseError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<InnerCipherSuiteError> for DatabaseOpenError {
    fn from(e: InnerCipherSuiteError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<OuterCipherSuiteError> for DatabaseOpenError {
    fn from(e: OuterCipherSuiteError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<KdfSettingsError> for DatabaseOpenError {
    fn from(e: KdfSettingsError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<VariantDictionaryError> for DatabaseOpenError {
    fn from(e: VariantDictionaryError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<CompressionError> for DatabaseOpenError {
    fn from(e: CompressionError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

#[derive(Debug, Error)]
pub enum DatabaseNewError {
    #[error("Error generating random data: {}", _0)]
    Random(String),
}

impl From<getrandom::Error> for DatabaseNewError {
    fn from(e: getrandom::Error) -> Self {
        DatabaseNewError::Random(format!("{}", e))
    }
}

#[derive(Debug)]
pub struct NewDatabaseSettings {
    pub outer_cipher_suite: OuterCipherSuite,
    pub compression: Compression,
    pub inner_cipher_suite: InnerCipherSuite,
    pub kdf_setting: KdfSettings,
}

impl Default for NewDatabaseSettings {
    fn default() -> Self {
        Self {
            outer_cipher_suite: OuterCipherSuite::AES256,
            compression: Compression::GZip,
            inner_cipher_suite: InnerCipherSuite::ChaCha20,
            kdf_setting: KdfSettings::Argon2 {
                salt: Vec::new(), // will get filled by new function
                iterations: 50,
                memory: 1024 * 1024,
                parallelism: 4,
                version: argon2::Version::Version13,
            },
        }
    }
}

impl Database {
    /// Parse a database from a std::io::Read
    pub fn open(
        source: &mut dyn std::io::Read,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Database, DatabaseOpenError> {
        let key_elements = Database::get_key_elements(password, keyfile)?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        match database_version {
            DatabaseVersion::KDB(_) => crate::format::kdb::parse(data.as_ref(), &key_elements),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion.into()),
            DatabaseVersion::KDB3(_) => crate::format::kdbx3::parse(data.as_ref(), &key_elements),
            DatabaseVersion::KDB4(_) => crate::format::kdbx4::parse(data.as_ref(), &key_elements),
        }
    }

    /// Save a database to a std::io::Write
    #[cfg(feature = "save_kdbx4")]
    pub fn save(
        &mut self,
        destination: &mut dyn std::io::Write,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<(), DatabaseSaveError> {
        let data = self.dump(password, keyfile);
        destination.write_all(&data?)?;
        Ok(())
    }

    #[cfg(feature = "save_kdbx4")]
    pub fn dump(
        &mut self,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Vec<u8>, DatabaseSaveError> {
        let key_elements = Database::get_key_elements(password, keyfile)?;

        let encrypted_db = match self.header {
            Header::KDB(_) => {
                return Err(DatabaseSaveError::UnsupportedVersion.into());
            }
            Header::KDBX3(_) => {
                return Err(DatabaseSaveError::UnsupportedVersion.into());
            }
            Header::KDBX4(_) => {
                self.generate_ivs()?;
                crate::format::kdbx4::dump(self, &key_elements)
            }
        };

        encrypted_db
    }

    pub fn get_key_elements(
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Vec<Vec<u8>>, DatabaseKeyError> {
        let mut key_elements: Vec<Vec<u8>> = Vec::new();

        if let Some(p) = password {
            key_elements.push(calculate_sha256(&[p.as_bytes()])?.as_slice().to_vec());
        }

        if let Some(f) = keyfile {
            key_elements.push(crate::keyfile::parse(f)?);
        }

        if key_elements.is_empty() {
            return Err(DatabaseKeyError::IncorrectKey);
        }

        Ok(key_elements)
    }

    /// Helper function to load a database into its internal XML chunks
    pub fn get_xml_chunks(
        source: &mut dyn std::io::Read,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Vec<Vec<u8>>, DatabaseOpenError> {
        let key_elements = Database::get_key_elements(password, keyfile)?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        let data = match database_version {
            DatabaseVersion::KDB(_) => panic!("Dumping XML from KDB databases not supported"),
            DatabaseVersion::KDB2(_) => panic!("Dumping XML from KDB2 databases not supported"),
            DatabaseVersion::KDB3(_) => {
                crate::format::kdbx3::decrypt_xml(data.as_ref(), &key_elements)?.1
            }
            DatabaseVersion::KDB4(_) => {
                vec![crate::format::kdbx4::decrypt_xml(data.as_ref(), &key_elements)?.2]
            }
        };

        Ok(data)
    }

    /// Get the version of a database.
    pub fn get_version(
        source: &mut dyn std::io::Read,
    ) -> Result<DatabaseVersion, DatabaseIntegrityError> {
        let mut data = Vec::new();
        data.resize(DatabaseVersion::get_version_header_size(), 0);
        source.read(&mut data)?;
        DatabaseVersion::parse(data.as_ref())
    }

    pub fn new(settings: NewDatabaseSettings) -> std::result::Result<Database, DatabaseNewError> {
        let mut database = Database {
            header: Header::KDBX4(KDBX4Header {
                version: DatabaseVersion::KDB4(KDBX4_CURRENT_MINOR_VERSION),
                outer_cipher: settings.outer_cipher_suite,
                compression: settings.compression,
                master_seed: vec![],
                outer_iv: vec![],
                kdf: settings.kdf_setting,
            }),
            inner_header: InnerHeader::KDBX4(KDBX4InnerHeader {
                inner_random_stream: settings.inner_cipher_suite,
                inner_random_stream_key: vec![],
                binaries: Default::default(),
            }),
            root: Group::new("Root"),
            meta: Default::default(),
        };
        database.generate_ivs()?;
        Ok(database)
    }

    fn generate_ivs(&mut self) -> std::result::Result<(), getrandom::Error> {
        let mut master_seed: Vec<u8> = vec![];
        master_seed.resize(crate::format::kdbx4::HEADER_MASTER_SEED_SIZE.into(), 0);
        getrandom::getrandom(&mut master_seed)?;

        if let Header::KDBX4(header) = &mut self.header {
            header.master_seed = master_seed;

            header
                .outer_iv
                .resize(header.outer_cipher.get_iv_size().into(), 0);
            getrandom::getrandom(&mut header.outer_iv)?;

            let mut kdf_seed: Vec<u8> = vec![];
            kdf_seed.resize(header.kdf.seed_size().into(), 0);
            getrandom::getrandom(&mut kdf_seed)?;

            header.kdf.set_seed(kdf_seed);
        } else {
            panic!("Function only supports KDBX4.");
        }

        if let InnerHeader::KDBX4(inner_header) = &mut self.inner_header {
            inner_header
                .inner_random_stream_key
                .resize(inner_header.inner_random_stream.get_key_size().into(), 0);
            getrandom::getrandom(&mut inner_header.inner_random_stream_key)?;
        } else {
            panic!("Function only supports KDBX4.");
        }

        Ok(())
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Times {
    /// Does this node expire
    pub expires: bool,

    /// Number of usages
    pub usage_count: usize,

    /// Using chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub times: HashMap<String, NaiveDateTime>,
}

impl Times {
    fn get(&self, key: &str) -> Option<&NaiveDateTime> {
        self.times.get(key)
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomData {
    pub items: Vec<CustomDataItem>,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct CustomDataItem {
    pub key: String,
    pub value: Option<Value>,
    pub last_modification_time: Option<NaiveDateTime>,
}

#[cfg(test)]
mod db_tests {
    use super::*;

    #[test]
    #[cfg(feature = "save_kdbx4")]
    pub fn generate_ivs() {
        let mut db = Database::new(NewDatabaseSettings::default()).unwrap();

        let mut entry = Entry::new();
        entry.fields.insert(
            "Title".to_string(),
            Value::Unprotected("Demo entry".to_string()),
        );

        db.root.children.push(Node::Entry(entry));

        let mut master_seed: Vec<u8> = vec![];
        if let Header::KDBX4(header) = &db.header {
            master_seed = header.master_seed.clone();
        } else {
            panic!("This should never happen.")
        }

        db.dump(Some("test"), None).unwrap();

        let mut updated_master_seed: Vec<u8> = vec![];
        if let Header::KDBX4(header) = &db.header {
            updated_master_seed = header.master_seed.clone();
        } else {
            panic!("This should never happen.")
        }

        assert_ne!(master_seed, updated_master_seed);
    }
}