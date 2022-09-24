#![doc = include_str!("../README.md")]
#![recursion_limit = "1024"]

mod config;
mod crypt;
mod db;
mod decompress;
mod hmac_block_stream;
mod keyfile;
pub mod result;
mod variant_dictionary;
mod xml_parse;

pub(crate) mod parse;

pub use self::db::*;
pub use self::result::{CryptoError, DatabaseIntegrityError, Error, Result};
// see https://gist.github.com/msmuenchen/9318327 for file format details
