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
        } else {
            panic!("Expected an entry");
        }

        Ok(())
    }
}
