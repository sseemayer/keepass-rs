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
    Database,
    DatabaseKey,
    DatabaseOpenError,
    db::fields,
};
use std::fs::File;

fn main() -> Result<(), DatabaseOpenError> {
    // Open KeePass database using a password (keyfile is also supported)
    let mut file = File::open("tests/resources/test_db_with_password.kdbx")?;
    let key = DatabaseKey::new().with_password("demopass");
    let db = Database::open(&mut file, key)?;

    for entry in db.iter_all_entries() {
        if let Some(title) = entry.get(fields::TITLE) {
            println!("Title: {}", title);
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
    db::{Database, Value, fields},
    DatabaseKey,
};
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db = Database::new();

    db.meta.database_name = Some("Demo database".to_string());

    let mut root = db.root_mut();

    let mut group = root.add_group();
    group.name = "Demo group".to_string();

    let mut entry = group.add_entry();
    entry.set(fields::TITLE, Value::string("Demo entry"));
    entry.set(fields::USERNAME, Value::string("jdoe"));
    entry.set(fields::PASSWORD, Value::protected_string("hunter2"));

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

```toml
[dependencies]
keepass = "*" # TODO replace with current version
```

### Performance Notes
For the best performance, this crate requires specific cargo configuration to enable CPU-specific optimizations, especially for AES key derivation.

Please see the recommended settings in the [.cargo/config.toml](https://github.com/sseemayer/keepass-rs/blob/master/.cargo/config.toml) file in this repository.

## License
MIT
