#![doc = include_str!("../README.md")]
#![recursion_limit = "1024"]

mod compression;
mod key;

#[cfg(feature = "save_kdbx4")]
mod io;

pub mod config;
pub mod db;

pub(crate) mod crypt;
pub(crate) mod format;
pub(crate) mod hmac_block_stream;
pub(crate) mod variant_dictionary;

pub use self::db::{Database, DatabaseOpenError, Value};
pub use self::key::DatabaseKey;

#[cfg(feature = "challenge_response")]
pub use self::key::ChallengeResponseKey;
