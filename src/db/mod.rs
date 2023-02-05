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
        kdb::parse_kdb,
        kdbx3::{decrypt_kdbx3, parse_kdbx3},
        kdbx4::{decrypt_kdbx4, parse_kdbx4},
        DatabaseVersion, KDBX4_CURRENT_MINOR_VERSION,
    },
    hmac_block_stream::BlockStreamError,
    keyfile::KeyfileError,
    variant_dictionary::VariantDictionaryError,
    xml_db::parse::XmlParseError,
};

/// A decrypted KeePass database
#[derive(Debug)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Database {
    /// Settings of the database such as encryption and compression algorithms
    pub settings: DatabaseSettings,

    /// Binary attachments in the inner header
    pub header_attachments: Vec<HeaderAttachment>,

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
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct DatabaseSettings {
    pub version: DatabaseVersion,

    pub outer_cipher_suite: OuterCipherSuite,
    pub compression: Compression,
    pub inner_cipher_suite: InnerCipherSuite,
    pub kdf_settings: KdfSettings,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            version: DatabaseVersion::KDB4(KDBX4_CURRENT_MINOR_VERSION),
            outer_cipher_suite: OuterCipherSuite::AES256,
            compression: Compression::GZip,
            inner_cipher_suite: InnerCipherSuite::ChaCha20,
            kdf_settings: KdfSettings::Argon2 {
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
            DatabaseVersion::KDB(_) => parse_kdb(data.as_ref(), &key_elements),
            DatabaseVersion::KDB2(_) => Err(DatabaseOpenError::UnsupportedVersion.into()),
            DatabaseVersion::KDB3(_) => parse_kdbx3(data.as_ref(), &key_elements),
            DatabaseVersion::KDB4(_) => parse_kdbx4(data.as_ref(), &key_elements),
        }
    }

    /// Save a database to a std::io::Write
    #[cfg(feature = "save_kdbx4")]
    pub fn save(
        &self,
        destination: &mut dyn std::io::Write,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<(), DatabaseSaveError> {
        use crate::format::kdbx4::dump_kdbx4;

        let key_elements = Database::get_key_elements(password, keyfile)?;

        match self.settings.version {
            DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion.into()),
            DatabaseVersion::KDB4(_) => dump_kdbx4(self, &key_elements, destination),
        }
    }

    #[cfg(feature = "save_kdbx4")]
    pub fn dump(
        &self,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Vec<u8>, DatabaseSaveError> {
        let mut data = Vec::new();
        self.save(&mut data, password, keyfile)?;
        Ok(data)
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
    pub fn get_xml(
        source: &mut dyn std::io::Read,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Vec<u8>, DatabaseOpenError> {
        let key_elements = Database::get_key_elements(password, keyfile)?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let database_version = DatabaseVersion::parse(data.as_ref())?;

        let data = match database_version {
            DatabaseVersion::KDB(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB2(_) => return Err(DatabaseOpenError::UnsupportedVersion),
            DatabaseVersion::KDB3(_) => decrypt_kdbx3(data.as_ref(), &key_elements)?.2,
            DatabaseVersion::KDB4(_) => decrypt_kdbx4(data.as_ref(), &key_elements)?.3,
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

    pub fn new(settings: DatabaseSettings) -> std::result::Result<Database, DatabaseNewError> {
        let database = Database {
            settings,
            header_attachments: Vec::new(),
            root: Group::new("Root"),
            meta: Default::default(),
        };
        Ok(database)
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

#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct HeaderAttachment {
    pub flags: u8,
    pub content: Vec<u8>,
}
