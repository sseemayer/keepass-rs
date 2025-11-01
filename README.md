# keepass-rs

[![Crates.io](https://img.shields.io/crates/v/keepass.svg)](https://crates.io/crates/keepass)
[![Documentation](https://docs.rs/keepass/badge.svg)](https://docs.rs/keepass/)
[![Build Status](https://github.com/sseemayer/keepass-rs/actions/workflows/merge.yml/badge.svg?branch=master)](https://github.com/sseemayer/keepass-rs/actions/workflows/merge.yml)
[![codecov](https://codecov.io/gh/sseemayer/keepass-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/sseemayer/keepass-rs)
[![dependency status](https://deps.rs/repo/github/sseemayer/keepass-rs/status.svg)](https://deps.rs/repo/github/sseemayer/keepass-rs)
[![License file](https://img.shields.io/github/license/sseemayer/keepass-rs)](https://github.com/sseemayer/keepass-rs/blob/master/LICENSE)

Rust KeePass database file parser for KDB, KDBX3 and KDBX4, with experimental support for KDBX4 writing.

## Usage

Examples are available in the [`examples`](./examples) directory of this repository.

### Use developer tools

This crate contains several command line tools that can be enabled with the `utilities` feature flag.
See the `[[bin]]` sections in [Cargo.toml](Cargo.toml) for a complete list.

An example command line for running the `kp-dump-xml` command would be:

```bash
cargo run --release --features "utilities" --bin kp-dump-xml -- path/to/database.kdbx
```


## Installation
Add the following to the `dependencies` section of your `Cargo.toml`:

```ignore
[dependencies]
keepass = "*" # TODO replace with current version
```

### Performance Notes

For the best performance, this crate requires specific cargo configuration to enable CPU-specific optimizations, especially for AES key derivation.

Please see the recommended settings in the [.cargo/config.toml](https://github.com/sseemayer/keepass-rs/blob/master/.cargo/config.toml) file in this repository.

## License
MIT
