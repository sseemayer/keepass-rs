# keepass
KeePass .kdbx database file parser for Rust

## Example
```rust
extern crate keepass;

use keepass::{Database, Node};
use keepass::result::{Result, ResultExt, Error};
use std::fs::File;

fn main() -> Result<()> {
    // Open KeePass database
    let path = std::path::Path::new("tests/resources/test_db_with_password.kdbx");
    let db = Database::open(
		&mut File::open(path)?,			// the database
		Some("demopass"),				// password
		None							// keyfile
	)?;

    // Iterate over all Groups and Nodes
    for node in &db.root {
        match node {
            Node::GroupNode(g) => {
                println!("Saw group '{0}'", g.name);
            },
            Node::EntryNode(e) => {
                let title = e.get_title().unwrap();
                let user = e.get_username().unwrap();
                let pass = e.get_password().unwrap();
                println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
            }
        }
    }

    Ok(())
}
```

## Installation
Add the following to the `dependencies` section of your `Cargo.toml`:

```
[dependencies]
keepass = "*"
```

## [Documentation](https://docs.rs/keepass)

## License
MIT
