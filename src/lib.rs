#![doc = include_str!("../README.md")]
#![recursion_limit = "1024"]

mod compression;
mod config;
pub(crate) mod crypt;
mod db;
pub(crate) mod hmac_block_stream;
mod keyfile;
pub(crate) mod parse;
pub(crate) mod variant_dictionary;
pub(crate) mod xml_db;

pub use self::db::*;
// see https://gist.github.com/msmuenchen/9318327 for file format details
