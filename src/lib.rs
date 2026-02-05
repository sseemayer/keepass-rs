#![doc = include_str!("../README.md")]
#![recursion_limit = "1024"]
#![warn(clippy::all, rust_2018_idioms)]
#![deny(
    // missing_docs,
    clippy::all,
    // clippy::missing_errors_doc,
    clippy::cargo,
    clippy::expect_used,
    clippy::cast_lossless,
    // clippy::indexing_slicing,
)]

mod compression;
pub mod config;
pub(crate) mod crypt;
pub mod db;
pub mod error;
pub(crate) mod format;
pub(crate) mod hmac_block_stream;
#[cfg(feature = "save_kdbx4")]
mod io;
mod key;
pub(crate) mod variant_dictionary;
pub(crate) mod xml_db;

pub use self::db::Database;
#[cfg(feature = "challenge_response")]
pub use self::key::ChallengeResponseKey;
pub use self::key::DatabaseKey;
