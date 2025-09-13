//! Standard field names for entries.
//!
//! This can be used with `Entry::get` and `Entry::set`.

pub const TITLE: &str = "Title";
pub const USERNAME: &str = "UserName";
pub const PASSWORD: &str = "Password";
pub const URL: &str = "URL";
pub const NOTES: &str = "Notes";

pub const KNOWN_FIELDS: [&str; 5] = [TITLE, USERNAME, PASSWORD, URL, NOTES];
