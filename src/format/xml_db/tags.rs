//! Shared (de)serialization of the `<Tags>` element used by both entry and group XML.
//!
//! KeePass stores tags as a delimited string. The canonical delimiter used by KeePass
//! when writing the XML is `;`, but both KeePass and KeePassXC also accept `,` on
//! read. Centralizing this here keeps entry and group behavior in lockstep.

/// Canonical tag delimiter used when writing tags into the KeePass XML.
pub const TAG_DELIMITER: &str = ";";

/// Delimiters accepted when parsing a `<Tags>` element value.
pub const TAG_DELIMITERS: &str = ";,";

/// Parse a `<Tags>` element value into a list of tags.
///
/// Splits on either `;` or `,` and trims surrounding whitespace.
pub fn split_tags(raw: &str) -> Vec<String> {
    raw.split(|c| TAG_DELIMITERS.contains(c))
        .map(str::trim)
        .map(str::to_string)
        .collect()
}

/// Render a list of tags as a `<Tags>` element value, or `None` if there are no tags.
pub fn join_tags(tags: &[String]) -> Option<String> {
    if tags.is_empty() {
        None
    } else {
        Some(tags.join(TAG_DELIMITER))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_empty_string_preserves_empty_tag() {
        assert_eq!(split_tags(""), vec![""]);
    }

    #[test]
    fn split_on_semicolons() {
        assert_eq!(split_tags("a;b;c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn split_on_commas_for_keepassxc_compat() {
        assert_eq!(split_tags("keepass-rs,test"), vec!["keepass-rs", "test"]);
    }

    #[test]
    fn split_accepts_mixed_delimiters() {
        assert_eq!(split_tags("a;b,c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn split_trims_whitespace_and_preserves_empties() {
        assert_eq!(split_tags(" a ; ; b ,, c "), vec!["a", "", "b", "", "c"]);
    }

    #[test]
    fn join_empty_returns_none() {
        let tags: Vec<String> = Vec::new();
        assert_eq!(join_tags(&tags), None);
    }

    #[test]
    fn join_single_tag_has_no_delimiter() {
        assert_eq!(join_tags(&["only".into()]), Some("only".into()));
    }

    #[test]
    fn join_uses_canonical_delimiter() {
        assert_eq!(
            join_tags(&["a".into(), "b".into(), "c".into()]),
            Some("a;b;c".into())
        );
    }

    #[test]
    fn round_trip_canonical_form_is_stable() {
        let tags = vec!["alpha".to_string(), "beta".to_string()];
        let joined = join_tags(&tags).unwrap();
        assert_eq!(split_tags(&joined), tags);
    }
}
