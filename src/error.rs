use crypto::symmetriccipher::SymmetricCipherError;
use std::fmt::Display;
use std;

#[derive(Debug)]
pub enum OpenDBError {
    Io(std::io::Error),
    Compression(DecompressionError),
    Crypto(SymmetricCipherError),
    IncorrectKey,
    InvalidIdentifier,
    InvalidHeaderEntry(u8),
    InvalidCipherID,
    InvalidCompressionSuite,
    InvalidInnerRandomStreamId,
    BlockHashMismatch,
}

impl Display for OpenDBError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &OpenDBError::Io(ref e) => write!(f, "I/O error: {}", e),
            &OpenDBError::Compression(_) => write!(f, "Decompression error"),
            &OpenDBError::Crypto(_) => write!(f, "Decryption error"),
            &OpenDBError::IncorrectKey => write!(f, "Incorrect key"),
            &OpenDBError::InvalidIdentifier => write!(f, "Invalid file header - not a .kdbx file?"),
            &OpenDBError::InvalidHeaderEntry(h) => {
                write!(f, "Encountered invalid header entry {}", h)
            }
            &OpenDBError::InvalidCipherID => write!(f, "Encountered an invalid cipher ID"),
            &OpenDBError::InvalidCompressionSuite => {
                write!(f, "Encountered an invalid compression suite")
            }
            &OpenDBError::InvalidInnerRandomStreamId => {
                write!(f, "Encountered an invalid inner stream cipher")
            }
            &OpenDBError::BlockHashMismatch => write!(f, "Block hash verification failed"),
        }
    }
}

impl std::error::Error for OpenDBError {
    fn description(&self) -> &str {
        match self {
            &OpenDBError::Io(ref e) => e.description(),
            &OpenDBError::Compression(ref e) => e.description(),
            &OpenDBError::Crypto(_) => "decryption error",
            &OpenDBError::IncorrectKey => "incorrect key",
            &OpenDBError::InvalidIdentifier => "invalid file header",
            &OpenDBError::InvalidHeaderEntry(_) => "invalid header entry",
            &OpenDBError::InvalidCipherID => "invalid cipher ID",
            &OpenDBError::InvalidCompressionSuite => "invalid compression suite ID",
            &OpenDBError::InvalidInnerRandomStreamId => "invalid inner cipher ID",
            &OpenDBError::BlockHashMismatch => "block hash verification failed",
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            &OpenDBError::Io(ref e) => Some(e),
            &OpenDBError::Compression(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for OpenDBError {
    fn from(e: std::io::Error) -> OpenDBError {
        OpenDBError::Io(e)
    }
}

impl From<SymmetricCipherError> for OpenDBError {
    fn from(e: SymmetricCipherError) -> OpenDBError {
        OpenDBError::Crypto(e)
    }
}

impl From<DecompressionError> for OpenDBError {
    fn from(e: DecompressionError) -> OpenDBError {
        OpenDBError::Compression(e)
    }
}


#[derive(Debug)]
pub enum DecompressionError {
    Io(std::io::Error),
}

impl std::fmt::Display for DecompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &DecompressionError::Io(ref e) => write!(f, "I/O error during decompression: {}", e),
        }
    }
}

impl std::error::Error for DecompressionError {
    fn description(&self) -> &str {
        match self {
            &DecompressionError::Io(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            &DecompressionError::Io(ref e) => Some(e),
        }
    }
}


impl From<std::io::Error> for DecompressionError {
    fn from(e: std::io::Error) -> DecompressionError {
        DecompressionError::Io(e)
    }
}