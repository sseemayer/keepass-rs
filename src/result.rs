pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum CryptoError {
    Argon2 {
        e: argon2::Error,
    },
    InvalidKeyLength {
        e: hmac::crypto_mac::InvalidKeyLength,
    },
    InvalidKeyIvLength {
        e: block_modes::InvalidKeyIvLength,
    },
    InvalidKeyNonceLength {
        e: cipher::errors::InvalidLength,
    },
    BlockMode {
        e: block_modes::BlockModeError,
    },
}

#[derive(Debug)]
pub enum DatabaseIntegrityError {
    Compression,
    Crypto {
        e: CryptoError,
    },
    HeaderHashMismatch,
    BlockHashMismatch {
        block_index: u64,
    },
    InvalidKDBXIdentifier,
    InvalidKDBXVersion {
        version: u32,
        file_major_version: u16,
        file_minor_version: u16,
    },
    InvalidFixedHeader {
        size: usize,
    },
    InvalidOuterHeaderEntry {
        entry_type: u8,
    },
    IncompleteOuterHeader {
        missing_field: String,
    },
    InvalidInnerHeaderEntry {
        entry_type: u8,
    },
    IncompleteInnerHeader {
        missing_field: String,
    },
    InvalidKDFVersion {
        version: u32,
    },
    InvalidKDFUUID {
        uuid: Vec<u8>,
    },
    MissingKDFParams {
        key: String,
    },
    MistypedKDFParam {
        key: String,
    },
    InvalidFixedCipherID {
        cid: u32,
    },
    InvalidOuterCipherID {
        cid: Vec<u8>,
    },
    InvalidInnerCipherID {
        cid: u32,
    },
    InvalidCompressionSuite {
        cid: u32,
    },
    InvalidVariantDictionaryVersion {
        version: u16,
    },
    InvalidVariantDictionaryValueType {
        value_type: u8,
    },
    InvalidKDBFieldLength {
        field_type: u16,
        field_size: u32,
        expected_field_size: u32,
    },
    InvalidKDBGroupFieldType {
        field_type: u16,
    },
    InvalidKDBEntryFieldType {
        field_type: u16,
    },
    MissingKDBGroupId,
    InvalidKDBGroupId {
        group_id: u32,
    },
    MissingKDBGroupLevel,
    InvalidKDBGroupLevel {
        group_level: u16,
        current_level: u16,
    },
    IncompleteKDBGroup,
    IncompleteKDBEntry,
    MissingKDBEntryTitle,
    XMLParsing {
        e: xml::reader::Error,
    },
    Base64 {
        e: base64::DecodeError,
    },
    UTF8 {
        e: std::str::Utf8Error,
    },
}

#[derive(Debug)]
pub enum Error {
    IO { e: std::io::Error },
    DatabaseIntegrity { e: DatabaseIntegrityError },
    IncorrectKey,
    InvalidKeyFile,
}

#[cfg_attr(tarpaulin, skip)]
impl std::fmt::Display for DatabaseIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Database integrity error: {}",
            match self {
                DatabaseIntegrityError::Compression => "(De)compression error".to_owned(),
                DatabaseIntegrityError::Crypto { e } => format!("Cryptography error: {:?}", e),
                DatabaseIntegrityError::HeaderHashMismatch => {
                    "Hash mismatch when verifying header".to_owned()
                }
                DatabaseIntegrityError::BlockHashMismatch { block_index } => {
                    format!("Error when verifying integrity of block {}", block_index)
                }
                DatabaseIntegrityError::InvalidKDBXIdentifier => {
                    "Invalid KDBX Identifier".to_owned()
                }
                DatabaseIntegrityError::InvalidKDBXVersion {
                    version,
                    file_major_version,
                    file_minor_version,
                } => format!(
                    "Invalid KDBX Version (version: {:0x} file version {}.{})",
                    version, file_major_version, file_minor_version
                ),
                DatabaseIntegrityError::InvalidFixedHeader { size } =>
                    format!("Invalid KBD Header (size: {})", size),
                DatabaseIntegrityError::InvalidOuterHeaderEntry { entry_type } => format!(
                    "Encountered an invalid outer header entry with type {}",
                    entry_type
                ),
                DatabaseIntegrityError::InvalidInnerHeaderEntry { entry_type } => format!(
                    "Encountered an invalid inner header entry with type {}",
                    entry_type
                ),
                DatabaseIntegrityError::IncompleteOuterHeader { missing_field } => {
                    format!("Missing field in outer header: {}", missing_field)
                }
                DatabaseIntegrityError::IncompleteInnerHeader { missing_field } => {
                    format!("Missing field in inner header: {}", missing_field)
                }
                DatabaseIntegrityError::MissingKDFParams { key } => {
                    format!("Missing field in KDF parameters: {}", key)
                }
                DatabaseIntegrityError::MistypedKDFParam { key } => {
                    format!("KDF parameter {} has wrong type", key)
                }
                DatabaseIntegrityError::InvalidKDFVersion { version } => {
                    format!("Encountered an invalid KDF version: {}", version)
                }
                DatabaseIntegrityError::InvalidKDFUUID { uuid } => {
                    format!("Encountered an invalid KDF UUID: {:0x?}", uuid)
                }
                DatabaseIntegrityError::InvalidFixedCipherID { cid } => {
                    format!("Encountered an invalid KBD cipher ID: {:0x?}", cid)
                }
                DatabaseIntegrityError::InvalidOuterCipherID { cid } => {
                    format!("Encountered an invalid outer cipher ID: {:0x?}", cid)
                }
                DatabaseIntegrityError::InvalidInnerCipherID { cid } => {
                    format!("Encountered an invalid inner cipher ID: {}", cid)
                }
                DatabaseIntegrityError::InvalidCompressionSuite { cid } => {
                    format!("Encountered an invalid compression suite ID: {}", cid)
                }
                DatabaseIntegrityError::InvalidVariantDictionaryVersion { version } => format!(
                    "Encountered a VariantDictionary with an invalid version: {}",
                    version
                ),
                DatabaseIntegrityError::InvalidVariantDictionaryValueType { value_type } => {
                    format!(
                        "Encountered an invalid VariantDictionary value type: {}",
                        value_type
                    )
                }
                DatabaseIntegrityError::InvalidKDBFieldLength { field_type, field_size, expected_field_size } =>
                    format!("Encountered a field with an invalid size: expected {}, got {} for field type {}", expected_field_size, field_size, field_type),
                DatabaseIntegrityError::InvalidKDBGroupFieldType { field_type } =>
                    format!("Encountered an invalid group field type: {}", field_type),
                DatabaseIntegrityError::InvalidKDBEntryFieldType { field_type } =>
                    format!("Encountered an invalid entry field type: {}", field_type),
                DatabaseIntegrityError::MissingKDBGroupId =>
                    "Encountered a group/entry without a GroupId".to_string(),
                DatabaseIntegrityError::InvalidKDBGroupId { group_id } =>
                    format!("Encountered an entry with an invalid GroupId: {}", group_id),
                DatabaseIntegrityError::MissingKDBGroupLevel =>
                    "Encountered a group without a Level".to_string(),
                DatabaseIntegrityError::InvalidKDBGroupLevel {
                    group_level,
                    current_level,
                } => format!(
                    "Encountered a group with an invalid Level: {} (current: {})",
                    group_level, current_level
                ),
                DatabaseIntegrityError::IncompleteKDBGroup =>
                    "Encountered an incomplete group".to_string(),
                DatabaseIntegrityError::IncompleteKDBEntry =>
                    "Encountered an incomplete entry".to_string(),
                DatabaseIntegrityError::MissingKDBEntryTitle =>
                    "Encountered an entry without a title".to_string(),
                DatabaseIntegrityError::XMLParsing { e } => format!(
                    "Encountered an error when parsing the inner XML payload: {}",
                    e
                ),
                DatabaseIntegrityError::UTF8 { e } => format!(
                    "Encountering an error when parsing an UTF-8 formatted string: {}",
                    e
                ),
                DatabaseIntegrityError::Base64 { e } => format!(
                    "Encountered an error when parsing a base64-encoded string: {}",
                    e
                ),
            }
        )
    }
}

impl std::fmt::Display for Error {
    #[cfg_attr(tarpaulin, skip)]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "KDBX error: {}",
            match self {
                Error::IO { e } => format!("IO error: {}", e),
                Error::IncorrectKey => "Incorrect key specified".to_owned(),
                Error::InvalidKeyFile => "Keyfile format invalid".to_owned(),
                Error::DatabaseIntegrity { e } => format!("{}", e),
            }
        )
    }
}

impl std::fmt::Display for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Crypto Error: {}",
            match self {
                CryptoError::Argon2 { e } => format!("Problem deriving key with Argon2: {}", e),
                CryptoError::InvalidKeyIvLength { e } => format!("Invalid key / IV length: {}", e),
                CryptoError::InvalidKeyLength { e } => format!("Invalid key length: {}", e),
                CryptoError::InvalidKeyNonceLength { e } => {
                    format!("Invalid key / nonce length: {}", e)
                }
                CryptoError::BlockMode { e } => format!("Block mode error: {}", e),
            }
        )
    }
}

impl std::error::Error for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::Argon2 { e } => Some(e),
            CryptoError::InvalidKeyIvLength { e } => Some(e),
            CryptoError::InvalidKeyNonceLength { .. } => None, // TODO pass this through once e implements Error
            CryptoError::InvalidKeyLength { .. } => None, // TODO pass this through once e implements Error
            CryptoError::BlockMode { e } => Some(e),
        }
    }
}

impl std::error::Error for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DatabaseIntegrityError::Crypto { e } => Some(e),
            DatabaseIntegrityError::XMLParsing { e } => Some(e),
            DatabaseIntegrityError::Base64 { e } => Some(e),
            DatabaseIntegrityError::UTF8 { e } => Some(e),
            _ => None,
        }
    }
}

impl std::error::Error for Error {
    #[cfg_attr(tarpaulin, skip)]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO { e } => Some(e),
            Error::DatabaseIntegrity { e } => e.source(),
            _ => None,
        }
    }
}

impl From<DatabaseIntegrityError> for Error {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: DatabaseIntegrityError) -> Self {
        Error::DatabaseIntegrity { e }
    }
}

impl From<CryptoError> for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: CryptoError) -> Self {
        DatabaseIntegrityError::Crypto { e }
    }
}

impl From<std::io::Error> for Error {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: std::io::Error) -> Self {
        Error::IO { e }
    }
}

impl From<argon2::Error> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: argon2::Error) -> Self {
        CryptoError::Argon2 { e }
    }
}

impl From<hmac::crypto_mac::InvalidKeyLength> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: hmac::crypto_mac::InvalidKeyLength) -> Self {
        CryptoError::InvalidKeyLength { e }
    }
}

impl From<cipher::errors::InvalidLength> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: cipher::errors::InvalidLength) -> Self {
        CryptoError::InvalidKeyNonceLength { e }
    }
}

impl From<block_modes::InvalidKeyIvLength> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: block_modes::InvalidKeyIvLength) -> Self {
        CryptoError::InvalidKeyIvLength { e }
    }
}

impl From<block_modes::BlockModeError> for CryptoError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: block_modes::BlockModeError) -> Self {
        CryptoError::BlockMode { e }
    }
}

impl From<xml::reader::Error> for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: xml::reader::Error) -> Self {
        DatabaseIntegrityError::XMLParsing { e }
    }
}

impl From<std::str::Utf8Error> for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: std::str::Utf8Error) -> Self {
        DatabaseIntegrityError::UTF8 { e }
    }
}

impl From<base64::DecodeError> for DatabaseIntegrityError {
    #[cfg_attr(tarpaulin, skip)]
    fn from(e: base64::DecodeError) -> Self {
        DatabaseIntegrityError::Base64 { e }
    }
}
