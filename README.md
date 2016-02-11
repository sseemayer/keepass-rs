# keepass
KeePass .kdbx database file parser for Rust

## Example
```rust
extern crate keepass;

use keepass::{Database, Node, OpenDBError};
use std::fs::File;

fn main() {
    // Open KeePass database
    let db = File::open(std::path::Path::new("test/sample.kdbx"))
                 .map_err(|e| OpenDBError::Io(e))
                 .and_then(|mut db_file| Database::open(&mut db_file, "demopass"))
                 .unwrap();

    // Iterate over all Groups and Nodes
    for node in &db.root {
        match node {
            Node::Group(g) => {
                println!("Saw group '{0}'", g.name);
            },
            Node::Entry(e) => {
                let title = e.get_title().unwrap();
                let user = e.get_username().unwrap();
                let pass = e.get_password().unwrap();
                println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
            }
        }
    }
}
```

## Installation
Add the following to the `dependencies` section of your `Cargo.toml`:

```
[dependencies]
keepass = "*"
```

## [Documentation](https://sseemayer.github.io/keepass-rs)

## License
MIT
