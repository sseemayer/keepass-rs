extern crate keepass;

mod tests {
    use keepass::result::*;
    use keepass::*;
    use std::{fs::File, path::Path};

    #[test]
    fn open_with_password() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_password.kdbx");
        let db = Database::open(&mut File::open(path)?, Some("demopass"), None)?;

        println!("{:?} DB Opened", db);
        assert_eq!(db.root.name, "sample");
        assert_eq!(db.root.child_groups.len(), 3);
        assert_eq!(db.root.entries.len(), 1);

        let mut total_groups = 0;
        let mut total_entries = 0;
        for node in &db.root {
            match node {
                Node::GroupNode(g) => {
                    println!("Saw group '{0}'", g.name);
                    total_groups += 1;
                }
                Node::EntryNode(e) => {
                    let title = e.get_title().unwrap();
                    let user = e.get_username().unwrap();
                    let pass = e.get_password().unwrap();
                    println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
                    total_entries += 1;
                }
            }
        }

        assert_eq!(total_groups, 5);
        assert_eq!(total_entries, 5);

        println!("{:?}", db);

        Ok(())
    }

    #[test]
    fn open_with_keyfile() -> Result<()> {
        let path = Path::new("tests/resources/test_db_with_keyfile.kdbx");
        let kf_path = Path::new("tests/resources/test_key.key");
        let db = Database::open(
            &mut File::open(path)?,
            None,
            Some(&mut File::open(kf_path)?),
        )?;

        println!("{:?} DB Opened", db);
        assert_eq!(db.root.name, "Root");
        assert_eq!(db.root.child_groups.len(), 0);
        assert_eq!(db.root.entries.len(), 1);

        let mut total_groups = 0;
        let mut total_entries = 0;
        for node in &db.root {
            match node {
                Node::GroupNode(g) => {
                    println!("Saw group '{0}'", g.name);
                    total_groups += 1;
                }
                Node::EntryNode(e) => {
                    let title = e.get_title().unwrap();
                    let user = e.get_username().unwrap();
                    let pass = e.get_password().unwrap();
                    println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
                    total_entries += 1;
                }
            }
        }

        assert_eq!(total_groups, 1);
        assert_eq!(total_entries, 1);

        println!("{:?}", db);

        Ok(())
    }
}
