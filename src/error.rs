//! Error types that this crate can return

use thiserror::Error;

#[cfg(feature = "totp")]
pub use crate::db::otp::TOTPError;

/// Errors upon reading a Database
#[derive(Debug, Error)]
pub enum DatabaseOpenError {
    /// An I/O error has occurred while reading the database
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An error with the database's key has occurred
    #[error(transparent)]
    Key(#[from] DatabaseKeyError),

    /// The database is corrupted
    #[error(transparent)]
    DatabaseIntegrity(#[from] DatabaseIntegrityError),

    /// The database version cannot be read by this library
    #[error("Opening this database version is not supported")]
    UnsupportedVersion,
}

/// Errors stemming from corrupted databases
#[derive(Debug, Error)]
pub enum DatabaseIntegrityError {
    /// The database does not have a valid KDBX identifier
    #[error("Invalid KDBX identifier")]
    InvalidKDBXIdentifier,

    /// The version of the KDBX file is invalid
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

    /// The fixed header has an invalid size
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

    #[error("Invalid group level {} (current level {})", group_level, current_level)]
    InvalidKDBGroupLevel { group_level: u16, current_level: u16 },

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
    OuterCipher(#[from] OuterCipherConfigError),

    #[error(transparent)]
    InnerCipher(#[from] InnerCipherConfigError),

    #[error(transparent)]
    Compression(#[from] CompressionConfigError),

    #[error(transparent)]
    BlockStream(#[from] BlockStreamError),

    #[error(transparent)]
    VariantDictionary(#[from] VariantDictionaryError),

    #[error(transparent)]
    KdfSettings(#[from] KdfConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Errors occurring when saving a Database
#[derive(Debug, Error)]
pub enum DatabaseSaveError {
    /// The current database version cannot be saved by this library
    #[error("Saving this database version is not supported")]
    UnsupportedVersion,

    /// Error while writing out the inner XML database
    #[error("Error while generating XML")]
    Xml(#[from] xml::writer::Error),

    /// General I/O issues while writing the database
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An error with the key occurred while writing the database
    #[error(transparent)]
    Key(#[from] DatabaseKeyError),

    /// A cryptography error occurred while writing the database
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    /// An error getting randomness for keys occurred
    #[error(transparent)]
    Random(#[from] getrandom::Error),
}

/// Errors related to the database key
#[derive(Debug, Error)]
pub enum DatabaseKeyError {
    /// The key specified was incorrect, e.g. because of a wrong password
    #[error("Incorrect key")]
    IncorrectKey,

    /// An error occurred in an underlying cryptographic operation while computing the key
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    /// An I/O error occurred while loading the keyfile
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An XML error occurred while loading the keyfile
    #[error(transparent)]
    Xml(#[from] xml::reader::Error),

    /// The keyfile is invalid and did not contain a key
    #[error("Could not obtain a key from the keyfile")]
    InvalidKeyFile,

    /// Could not get challenge response key.
    #[error("Error with the challenge-response key: {0}")]
    ChallengeResponseKeyError(String),
}

/// Errors with the configuration of the outer encryption
#[derive(Debug, Error)]
pub enum OuterCipherConfigError {
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Invalid outer cipher ID: {:?}", cid)]
    InvalidOuterCipherID { cid: Vec<u8> },
}

/// Errors with the configuration of the inner encryption
#[derive(Debug, Error)]
pub enum InnerCipherConfigError {
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Invalid inner cipher ID: {}", cid)]
    InvalidInnerCipherID { cid: u32 },
}

/// Errors with the configuration of the compression algorithm
#[derive(Debug, Error)]
pub enum CompressionConfigError {
    /// The identifier for the compression algorithm specified in the database is invalid
    #[error("Invalid compression algorithm: {}", cid)]
    InvalidCompressionSuite { cid: u32 },
}

/// Errors with the configuration of the Key Derivation Function
#[derive(Debug, Error)]
pub enum KdfConfigError {
    #[error("Invalid KDF version: {}", version)]
    InvalidKDFVersion { version: u32 },

    #[error("Invalid KDF UUID: {:?}", uuid)]
    InvalidKDFUUID { uuid: Vec<u8> },

    #[error(transparent)]
    VariantDictionary(#[from] VariantDictionaryError),
}

/// Errors while performing cryptographic operations
#[derive(Debug, Error)]
pub enum CryptographyError {
    #[error(transparent)]
    InvalidLength(#[from] cipher::InvalidLength),

    #[error(transparent)]
    Unpadding(#[from] cipher::block_padding::UnpadError),

    #[error(transparent)]
    Padding(#[from] cipher::inout::PadError),

    #[error(transparent)]
    Argon2(#[from] argon2::Error),
}

/// Errors reading from the HMAC block stream
#[derive(Debug, Error)]
pub enum BlockStreamError {
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Block hash mismatch for block {}", block_index)]
    BlockHashMismatch { block_index: u64 },
}

/// Errors while parsing a VariantDictionary
#[derive(Debug, Error)]
pub enum VariantDictionaryError {
    #[error("Invalid variant dictionary version: {}", version)]
    InvalidVersion { version: u16 },

    #[error("Invalid value type: {}", value_type)]
    InvalidValueType { value_type: u8 },

    #[error("Missing key: {}", key)]
    MissingKey { key: String },

    #[error("Mistyped value: {}", key)]
    Mistyped { key: String },

    #[error("VariantDictionary did not end with null byte, when it should")]
    NotTerminated,
}

/// Errors while parsing the XML document inside of a KeePass database
#[derive(Debug, Error)]
pub enum XmlParseError {
    #[error(transparent)]
    Xml(#[from] xml::reader::Error),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    TimestampFormat(#[from] chrono::ParseError),

    #[error(transparent)]
    IntFormat(#[from] std::num::ParseIntError),

    #[error(transparent)]
    BoolFormat(#[from] std::str::ParseBoolError),

    #[error(transparent)]
    Uuid(#[from] uuid::Error),

    #[error(transparent)]
    Color(#[from] ParseColorError),

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Decompression error: {}", _0)]
    Compression(#[source] std::io::Error),

    /// An unexpected XML event occurred, such as opening an unexpected tag, or an error in the
    /// underlying XML reader
    #[error("Bad XML event: expected {}, got {:?}", expected, event)]
    BadEvent {
        expected: &'static str,
        event: crate::xml_db::parse::SimpleXmlEvent,
    },

    /// The stream of XML events ended when more events were expected
    #[error("Unexpected end of XML document")]
    Eof,
}

/// Error parsing a color code
#[derive(Debug, Error)]
#[error("Cannot parse color: '{}'", _0)]
pub struct ParseColorError(pub String);

// move error type conversions to a module and exclude them from coverage counting.
#[cfg(not(tarpaulin_include))]
mod conversions {
    use super::*;

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

    impl From<InnerCipherConfigError> for DatabaseOpenError {
        fn from(e: InnerCipherConfigError) -> Self {
            DatabaseIntegrityError::from(e).into()
        }
    }

    impl From<OuterCipherConfigError> for DatabaseOpenError {
        fn from(e: OuterCipherConfigError) -> Self {
            DatabaseIntegrityError::from(e).into()
        }
    }

    impl From<KdfConfigError> for DatabaseOpenError {
        fn from(e: KdfConfigError) -> Self {
            DatabaseIntegrityError::from(e).into()
        }
    }

    impl From<VariantDictionaryError> for DatabaseOpenError {
        fn from(e: VariantDictionaryError) -> Self {
            DatabaseIntegrityError::from(e).into()
        }
    }

    impl From<CompressionConfigError> for DatabaseOpenError {
        fn from(e: CompressionConfigError) -> Self {
            DatabaseIntegrityError::from(e).into()
        }
    }
}
