#![doc = include_str!("../README.md")]
#![recursion_limit = "1024"]

mod compression;
pub mod config;
pub(crate) mod crypt;
pub mod db;
pub mod error;
pub(crate) mod format;

mod key;

pub use self::db::Database;
pub use self::format::DatabaseVersion;

/// Current database format version supported for saving.
pub const CURRENT_TARGET_DATABASE_VERSION: DatabaseVersion =
    DatabaseVersion::KDB4(self::format::KDBX4_CURRENT_MINOR_VERSION);

#[cfg(feature = "challenge_response")]
pub use self::key::ChallengeResponseKey;
pub use self::key::DatabaseKey;
