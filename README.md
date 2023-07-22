# keepass-rs

[![Crates.io](https://img.shields.io/crates/v/keepass.svg)](https://crates.io/crates/keepass)
[![Documentation](https://docs.rs/keepass/badge.svg)](https://docs.rs/keepass/)
[![Build Status](https://github.com/sseemayer/keepass-rs/actions/workflows/merge.yml/badge.svg?branch=master)](https://github.com/sseemayer/keepass-rs/actions/workflows/merge.yml)
[![codecov](https://codecov.io/gh/sseemayer/keepass-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/sseemayer/keepass-rs)
[![dependency status](https://deps.rs/repo/github/sseemayer/keepass-rs/status.svg)](https://deps.rs/repo/github/sseemayer/keepass-rs)
[![License file](https://img.shields.io/github/license/sseemayer/keepass-rs)](https://github.com/sseemayer/keepass-rs/blob/master/LICENSE)

Rust KeePass database file parser for KDB, KDBX3 and KDBX4, with experimental support for KDBX4 writing.

## Usage
<details>
<summary>

### Open a database
</summary>

```rust
use keepass::{
    db::NodeRef,
    Database,
    DatabaseKey,
    error::DatabaseOpenError
};
use std::fs::File;

fn main() -> Result<(), DatabaseOpenError> {
    // Open KeePass database using a password (keyfile is also supported)
    let mut file = File::open("tests/resources/test_db_with_password.kdbx")?;
    let key = DatabaseKey::new().with_password("demopass");
    let db = Database::open(&mut file, key)?;

    // Iterate over all `Group`s and `Entry`s
    for node in &db.root {
        match node {
            NodeRef::Group(g) => {
                println!("Saw group '{0}'", g.name);
            },
            NodeRef::Entry(e) => {
                let title = e.get_title().unwrap_or("(no title)");
                let user = e.get_username().unwrap_or("(no username)");
                let pass = e.get_password().unwrap_or("(no password)");
                println!("Entry '{0}': '{1}' : '{2}'", title, user, pass);
            }
        }
    }

    Ok(())
}
```
</details>

<details>
<summary>

### Save a KDBX4 database (EXPERIMENTAL)

</summary>

**IMPORTANT:** The inner XML data structure will be re-written from scratch from the internal object representation of this crate, so any field that is not parsed by the library will be lost in the written output file! Please make sure to back up your database before trying this feature.

You can enable the experimental support for saving KDBX4 databases using the `save_kdbx4` feature.

```rust
use keepass::{
    db::{Database, Entry, Group, Node, NodeRef, Value},
    DatabaseKey,
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db = Database::new(Default::default());

    db.meta.database_name = Some("Demo database".to_string());

    let mut group = Group::new("Demo group");

    let mut entry = Entry::new();
    entry.fields.insert("Title".to_string(), Value::Unprotected("Demo entry".to_string()));
    entry.fields.insert("UserName".to_string(), Value::Unprotected("jdoe".to_string()));
    entry.fields.insert("Password".to_string(), Value::Protected("hunter2".as_bytes().into()));

    group.add_child(entry);

    db.root.add_child(group);

    #[cfg(feature = "save_kdbx4")]
    db.save(
        &mut File::create("demo.kdbx")?,
        DatabaseKey::new().with_password("demopass"),
    )?;

    Ok(())
}
```

</details>

<details>
<summary>

### Use developer tools

</summary>

This crate contains several command line tools that can be enabled with the `utilities` feature flag.
See the `[[bin]]` sections in [Cargo.toml](Cargo.toml) for a complete list.

An example command line for running the `kp-dump-xml` command would be:

```bash
cargo run --release --features "utilities" --bin kp-dump-xml -- path/to/database.kdbx
```

</details>


## Installation
Add the following to the `dependencies` section of your `Cargo.toml`:

```ignore
[dependencies]
keepass = "*" # TODO replace with current version
```

### Performance Notes

Please set the `RUSTFLAGS` environment variable when compiling to enable CPU-specific optimizations (this greatly affects the speed of the AES key derivation):

```bash
export RUSTFLAGS='-C target-cpu=native'
```

For best results, also compile in Release mode.

Alternatively, you can add a `.cargo/config.toml` like in this project to ensure that rustflags are always set.

#### For AArch64 / ARMv8:

The `aes` optimizations are not yet enabled on stable rust. If you want a big performance boost you can build using nightly and enabling the `armv8` feature of the `aes` crate:

```ignore
[dependencies.aes]
# Needs at least 0.7.5 for the feature
version = "0.7.5"
features = ["armv8"]
```

## License
MIT
