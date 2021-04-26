//! keepass: KeePass .kdbx database file parser for Rust
//!
//!
//! ```
//! extern crate keepass;
//!
//! use keepass::{Database, NodeRef, Result, Error};
//! use std::fs::File;
//!
//! fn main() -> Result<()> {
//!     // Open KeePass database
//!     let path = std::path::Path::new("tests/resources/test_db_with_password.kdbx");
//!     let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;
//!
//!     // Iterate over all Groups and Nodes
//!     for node in &db.root {
//!         match node {
//!             NodeRef::Group(g) => {
//!                 println!("Saw group '{0}'", g.name);
//!             },
//!             NodeRef::Entry(e) => {
//!                 let title = e.get_title().unwrap();
//!                 let user = e.get_username().unwrap();
//!                 let pass = e.get_password().unwrap();
//!                 println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
//!             }
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```

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
