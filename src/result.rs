use crate::crypto::symmetriccipher::SymmetricCipherError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum DatabaseIntegrityError {
    Compression,
    Argon2 {
        e: argon2::Error,
    },
    Crypto {
        e: SymmetricCipherError,
    },
    HeaderHashMismatch,
    BlockHashMismatch {
        block_index: usize,
    },
    InvalidKDBXIdentifier,
    InvalidKDBXVersion {
        version: u32,
        file_major_version: u16,
        file_minor_version: u16,
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
    XMLParsing {
        e: xml::reader::Error,
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

impl std::fmt::Display for DatabaseIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Database integrity error: {}",
            match self {
                DatabaseIntegrityError::Argon2 { e } => {
                    format!("Problem deriving key with Argon2: {}", e)
                }
                DatabaseIntegrityError::Compression => "(De)compression error".to_owned(),
                DatabaseIntegrityError::Crypto { e } => format!("(De)cryption error: {:?}", e),
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
                DatabaseIntegrityError::InvalidKDFVersion { version } => {
                    format!("Encountered an invalid KDF version: {}", version)
                }
                DatabaseIntegrityError::InvalidKDFUUID { uuid } => {
                    format!("Encountered an invalid KDF UUID: {:0x?}", uuid)
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
                DatabaseIntegrityError::XMLParsing { e } => format!(
                    "Encountered an error when parsing the inner XML payload: {}",
                    e
                ),
                DatabaseIntegrityError::UTF8 { e } => format!(
                    "Encountering an error when parsing an UTF-8 formatted string: {}",
                    e
                ),
            }
        )
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "KDBX error: {}",
            match self {
                Error::IO { e } => format!("IO error: {}", e),
                Error::IncorrectKey => "Incorrect password key specified".to_owned(),
                Error::InvalidKeyFile => "Keyfile format invalid".to_owned(),
                Error::DatabaseIntegrity { e } => format!("{}", e),
            }
        )
    }
}

impl std::error::Error for DatabaseIntegrityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DatabaseIntegrityError::Argon2 { e } => Some(e),
            DatabaseIntegrityError::Crypto { .. } => None, // TODO pass this through once https://github.com/DaGenix/rust-crypto/pull/452 is merged
            DatabaseIntegrityError::XMLParsing { e } => Some(e),
            DatabaseIntegrityError::UTF8 { e } => Some(e),
            _ => None,
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::IO { e } => Some(e),
            Error::DatabaseIntegrity { e } => e.source(),
            _ => None,
        }
    }
}

impl From<DatabaseIntegrityError> for Error {
    fn from(e: DatabaseIntegrityError) -> Self {
        Error::DatabaseIntegrity { e }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IO { e }
    }
}

impl From<argon2::Error> for DatabaseIntegrityError {
    fn from(e: argon2::Error) -> Self {
        DatabaseIntegrityError::Argon2 { e }
    }
}

impl From<SymmetricCipherError> for DatabaseIntegrityError {
    fn from(e: SymmetricCipherError) -> Self {
        DatabaseIntegrityError::Crypto { e }
    }
}

impl From<xml::reader::Error> for DatabaseIntegrityError {
    fn from(e: xml::reader::Error) -> Self {
        DatabaseIntegrityError::XMLParsing { e }
    }
}

impl From<std::str::Utf8Error> for DatabaseIntegrityError {
    fn from(e: std::str::Utf8Error) -> Self {
        DatabaseIntegrityError::UTF8 { e }
    }
}

/*
error_chain! {
    foreign_links {
        Io(::std::io::Error);
        XML(::xml::reader::Error);
        UTF8(::std::str::Utf8Error);
        Argon2(::argon2::Error);
    }

    errors {
        Compression(v: String) {
            description("Decompression error"),
        }
        Crypto {
            description("Cryptography error")
            display("Cryptography error")
        }
        IncorrectKey {
            description("Incorrect key")
        }
        InvalidIdentifier {
            description("Invalid file header - not a .kdbx file?")
        }
        InvalidHeaderEntry(h: u8)  {
            description("Encountered invalid header entry")
        }
        InvalidKeyFile {
            description("Key file invalid")
        }
        IncompleteHeader {
            description("Invalid file header - missing some required entries")
        }
        InvalidOuterCipherID(cid: Vec<u8>) {
            description ("Encountered an invalid outer cipher ID")
        }
        InvalidInnerCipherID(cid: u32) {
            description ("Encountered an invalid inner cipher ID")
        }
        InvalidCompressionSuite {
            description("Encountered an invalid compression suite")
        }
        InvalidInnerRandomStreamId {
            description("Encountered an invalid inner stream cipher")
        }
        InvalidVariantDictionaryVersion {
            description("Encountered an invalid VariantDictionary version")
        }
        InvalidVariantDictionaryValueType {
            description("Encountered an invalid VariantDictionary value type")
        }
        InvalidKDBXVersion {
            description("Invalid KDBX database file version")
        }
        InvalidKdfParams {
            description("KDF parameters invalid")
        }
        HeaderHashMismatch {
            description("Header hash mismatch")
        }
        HmacBlockHashMismatch {
            description("Encountered a HMAC Block with an unvalid HMAC")
        }
        BlockHashMismatch {
            description( "Block hash verification failed"),
        }
    }

}

impl ::std::convert::From<::crypto::symmetriccipher::SymmetricCipherError> for self::Error {
    fn from(_ce: ::crypto::symmetriccipher::SymmetricCipherError) -> Self {
        self::ErrorKind::Crypto.into()
    }
}
*/
