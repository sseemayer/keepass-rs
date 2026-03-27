//! Error types that this crate can return

pub use crate::{
    config::{CompressionConfigError, InnerCipherConfigError, KdfConfigError, OuterCipherConfigError},
    crypt::CryptographyError,
    db::{
        CustomIconNotFoundError, DatabaseFormatError, DatabaseOpenError, DestinationGroupNotFoundError,
        MoveGroupError, ParseColorError,
    },
    format::{
        hmac_block_stream::BlockStreamError,
        kdb::KdbOpenError,
        kdbx3::{Kdbx3OpenError, Kdbx3OuterHeaderError},
        kdbx4::{Kdbx4InnerHeaderError, Kdbx4OpenError, Kdbx4OuterHeaderError},
        variant_dictionary::VariantDictionaryError,
        xml_db::ParseXmlError,
        DatabaseVersionParseError,
    },
    key::{DatabaseKeyError, ParseXmlKeyFileError},
};

#[cfg(feature = "challenge_response")]
pub use crate::key::ChallengeResponseKeyError;

#[cfg(feature = "save_kdbx4")]
pub use crate::db::DatabaseSaveError;

#[cfg(feature = "totp")]
pub use crate::db::TOTPError;
