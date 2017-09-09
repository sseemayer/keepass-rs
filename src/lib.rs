//! keepass: KeePass .kdbx database file parser for Rust
//!
//!
//! ```
//! extern crate keepass;
//!
//! use keepass::{Database, Node, ErrorKind};
//! use std::fs::File;
//!
//! fn main() {
//!     // Open KeePass database
//!     let db = File::open(std::path::Path::new("tests/resources/sample.kdbx"))
//!                  .map_err(|e| ErrorKind::from(e))
//!                  .and_then(|mut db_file| Database::open(&mut db_file, "demopass"))
//!                  .unwrap();
//!
//!     // Iterate over all Groups and Nodes
//!     for node in &db.root {
//!         match node {
//!             Node::Group(g) => {
//!                 println!("Saw group '{0}'", g.name);
//!             },
//!             Node::Entry(e) => {
//!                 let title = e.get_title().unwrap();
//!                 let user = e.get_username().unwrap();
//!                 let pass = e.get_password().unwrap();
//!                 println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
//!             }
//!         }
//!     }
//! }
//! ```

#![recursion_limit = "1024"]


extern crate byteorder;
extern crate crypto;
extern crate base64;
extern crate secstr;
extern crate flate2;
extern crate xml;


#[macro_use]
extern crate error_chain;


mod crypt;
mod decompress;
mod xml_parse;
pub mod result;
mod db;
mod db_parse;

pub use self::db::*;
pub use self::db_parse::*;
// see https://gist.github.com/msmuenchen/9318327 for file format details


