# keepass

[![Crates.io](https://img.shields.io/crates/v/keepass.svg)](https://crates.io/crates/keepass)
[![Documentation](https://docs.rs/keepass/badge.svg)](https://docs.rs/keepass/)
[![Build Status](https://github.com/sseemayer/keepass-rs/actions/workflows/rust-ci.yml/badge.svg?branch=master)](https://github.com/sseemayer/keepass-rs/actions/workflows/rust-ci.yml)
[![codecov](https://codecov.io/gh/sseemayer/keepass-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/sseemayer/keepass-rs)
[![dependency status](https://deps.rs/repo/github/sseemayer/keepass-rs/status.svg)](https://deps.rs/repo/github/sseemayer/keepass-rs)
[![License file](https://img.shields.io/github/license/sseemayer/keepass-rs)](https://github.com/sseemayer/keepass-rs/blob/master/LICENSE)

KeePass .kdbx database file parser for Rust

## Example
```rust
extern crate keepass;

use keepass::{Database, DatabaseOpenError, NodeRef};
use std::fs::File;

fn main() -> Result<(), DatabaseOpenError> {
    // Open KeePass database
    let path = std::path::Path::new("tests/resources/test_db_with_password.kdbx");
    let db = Database::open(
        &mut File::open(path)?,         // the database
        Some("demopass"),               // password
        None                            // keyfile
    )?;

    // Iterate over all Groups and Nodes
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

## Installation
Add the following to the `dependencies` section of your `Cargo.toml`:

```ignore
[dependencies]
keepass = "*"
```

**Performance note:** Please set the `RUSTFLAGS` environment variable when compiling to enable CPU-specific optimizations (this greatly affects the speed of the AES key derivation):

```bash
export RUSTFLAGS='-C target-cpu=native'
```

For best results, also compile in Release mode.

Alternatively, you can add a `.cargo/config.toml` like in this project to ensure that rustflags are always set.

For AArch64 / ARMv8:

The `aes` optimizations are not yet enabled on stable rust. If you want a big performance boost you can build using nightly and enabling the `armv8` feature of the `aes` crate:

```ignore
[dependencies.aes]
# Needs at least 0.7.5 for the feature
version = "0.7.5"
features = ["armv8"]
```

## [Documentation](https://docs.rs/keepass)

## Developer Tools

### `kp-dump-xml`
This library contains an optionally-compiled command line application to dump out the internal XML representation from a KDBX database. This can be useful for implementing additional features for the XML parser.

Since the tool depends on additional crates, it is not compiled until you specify the `utilities` feature, e.g.

```ignore
cargo run --release --features "utilities" --bin kp-dump-xml -- path/to/database.kdbx
```

## License
MIT
