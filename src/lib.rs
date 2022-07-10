#![doc = include_str!("../README.md")]
#![recursion_limit = "1024"]

mod config;
pub(crate) mod crypt;
mod db;
mod decompress;
pub(crate) mod hmac_block_stream;
mod keyfile;
pub(crate) mod variant_dictionary;
pub(crate) mod xml_parse;

pub mod otp;
pub(crate) mod parse;

pub use self::db::*;
// see https://gist.github.com/msmuenchen/9318327 for file format details
