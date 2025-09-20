//! Standard field names for entries.
//!
//! This can be used with [Entry::get][crate::db::Entry::get] and [Entry::set][crate::db::Entry::set].

/// The title of the entry
pub const TITLE: &str = "Title";

/// The user name associated with the entry
pub const USERNAME: &str = "UserName";

/// The password associated with the entry
pub const PASSWORD: &str = "Password";

/// The primary URL associated with the entry
pub const URL: &str = "URL";

/// Notes associated with the entry
pub const NOTES: &str = "Notes";

/// Collection of known field names, for more convenient iteration
pub const KNOWN_FIELDS: [&str; 5] = [TITLE, USERNAME, PASSWORD, URL, NOTES];
