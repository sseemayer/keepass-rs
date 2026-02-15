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
//! let mut root: GroupMut<'_> = db.root_mut();
//!
//! // Add a new child group to the root group
//! let mut group: GroupMut<'_> = root.add_group();
//!
//! // GroupMut dereferences to &mut Group, so you can access most of its fields directly
//! group.name = "My Group".into();
//! group.notes = Some("This is an example group".into());
//!
//! // Add a new entry to the group
//! let mut entry: EntryMut<'_> = root.add_entry();
//!
//! // EntryMut dereferences to &mut Entry, so you can access most of its fields directly
//! entry.set_unprotected(fields::TITLE, "My Entry");
//! entry.set_unprotected(fields::USERNAME, "jdoe");
//! entry.set_protected(fields::PASSWORD, "hunter2");
//! entry.tags.insert("example".into());
//!
//! // Adding the attachment to an entry will store it in the associated database and add a
//! // reference to the entry.
//! let mut attachment: AttachmentMut = entry.add_attachment();
//! attachment.name = "myfile.txt".into();
//! attachment.set_data(b"Hello, world!".to_vec());
//!
//!
//! // You can also use the fluent API to chain method calls together.
//! let entry_id = root.add_group()
//!     .edit(|g: &mut GroupMut| {
//!         g.name = "Another Group".into();
//!         g.notes = Some("This is another example group".into());
//!     })
//!     .add_entry()
//!     .edit(|e: &mut EntryMut<'_>| {
//!         e.set_unprotected(fields::TITLE, "Another Entry");
//!         e.set_unprotected(fields::USERNAME, "asmith");
//!         e.set_protected(fields::PASSWORD, "password123");
//!         e.tags.insert("example".into());
//!     }).id();
//! # }
//! ```

mod open;

#[cfg(feature = "save_kdbx4")]
mod save;
mod types;

#[cfg(feature = "_merge")]
mod merge;

#[cfg(feature = "serialization")]
mod serialization;

pub use open::{DatabaseOpenError, DatabaseParseError, GetDatabaseVersionError};
pub use types::*;

pub mod fields;
