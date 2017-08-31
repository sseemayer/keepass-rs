extern crate keepass;

mod tests {
    use std;
    use keepass::*;
    #[test]
    fn open_db() {
        let db = std::fs::File::open(std::path::Path::new("tests/resources/sample.kdbx"))
            .map_err(|e| OpenDBError::from(e))
            .and_then(|mut db_file| Database::open(&mut db_file, "demopass"))
            .unwrap();

        println!("{:?} DB Opened", db);
        assert_eq!(db.root.name, "sample");
        assert_eq!(db.root.child_groups.len(), 3);
        assert_eq!(db.root.entries.len(), 1);

        let mut total_groups = 0;
        let mut total_entries = 0;
        for node in &db.root {
            match node {
                Node::Group(g) => {
                    println!("Saw group '{0}'", g.name);
                    total_groups += 1;
                }
                Node::Entry(e) => {
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
    }
}
