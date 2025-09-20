//! Types representing an opened KeePass database
//!
//! The main entry point is the [Database] struct, which can be created with [Database::new] or
//! loaded from a file using [Database::open]. The example uses explicit type annotations to show
//! what is happening, but these can be omitted in your own code.
//!
//! ```
//! use keepass::{Database, Value, db::{fields, AttachmentMut, EntryMut, GroupMut}};
//! # fn main() {
//! let mut db = Database::new();
//! let mut root: GroupMut = db.root_mut();
//!
//! // Add a new child group to the root group
//! let mut group: GroupMut = root.add_group();
//!
//! // GroupMut dereferences to &mut Group, so you can access most of its fields directly
//! group.name = "My Group".into();
//! group.notes = Some("This is an example group".into());
//!
//! // Add a new entry to the group
//! let mut entry: EntryMut = root.add_entry();
//!
//! // EntryMut dereferences to &mut Entry, so you can access most of its fields directly
//! entry.set(fields::TITLE, Value::string("My Entry"));
//! entry.set(fields::USERNAME, Value::string("jdoe"));
//! entry.set(fields::PASSWORD, Value::protected_string("hunter2"));
//! entry.tags.insert("example".into());
//!
//! // Adding the attachment to an entry will store it in the associated database and add a
//! // reference to the entry.
//! let mut attachment: AttachmentMut = entry.add_attachment();
//! attachment.name = "myfile.txt".into();
//! attachment.set_data(b"Hello, world!".to_vec());
//!
//! # }
//! ```

mod open;

#[cfg(feature = "save_kdbx4")]
mod save;
mod types;

#[cfg(feature = "_merge")]
mod merge;

pub use open::{DatabaseOpenError, DatabaseParseError, GetDatabaseVersionError};
pub use types::*;

pub mod fields;
