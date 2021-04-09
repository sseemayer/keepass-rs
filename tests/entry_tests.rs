extern crate keepass;

mod tests {
    use keepass::{result::*, *};
    use std::{fs::File, path::Path};

    #[test]
    fn entry() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        // get an entry on the root node
        if let Some(Node::Entry(e)) = db.root.get(&["Sample Entry"]) {
            assert_eq!(e.get_title(), Some("Sample Entry"));
            assert_eq!(e.get_username(), Some("User Name"));
            assert_eq!(e.get_password(), Some("Password"));
            assert_eq!(e.get("custom attribute"), Some("data for custom attribute"));
            assert_eq!(e.db_report_exclude, false);
            assert_eq!(e.expiration.enabled, false);

            assert_eq!(
                match &e.expiration.time {
                    TimeKDBX::Iso8601(t) => t,
                    _ => panic!("Expected an Iso8601 time"),
                },
                "2016-01-06T09:43:01Z"
            );

            if let Some(ref at) = e.autotype {
                if let Some(ref s) = at.sequence {
                    assert_eq!(s, "{USERNAME}{TAB}{TAB}{PASSWORD}{ENTER}");
                } else {
                    panic!("Expected a sequenceQ")
                }
            } else {
                panic!("Expected an AutoType entry");
            }
        } else {
            panic!("Expected an entry");
        }

        if let Some(Node::Entry(e)) = db.root.get(&["General", "Subgroup", "test entry"]) {
            assert_eq!(e.get_title(), Some("test entry"));
            assert_eq!(e.get_username(), Some("jdoe"));
            assert_eq!(e.get_password(), Some("nWuu5AtqsxqNhnYgLwoB"));
            assert_eq!(e.db_report_exclude, true);
            assert_eq!(e.expiration.enabled, true);

            assert_eq!(
                match &e.expiration.time {
                    TimeKDBX::Iso8601(t) => t,
                    _ => panic!("Expected an Iso8601 time"),
                },
                "2021-04-08T19:56:00Z"
            );
        } else {
            panic!("Expected an entry");
        }

        Ok(())
    }
}
