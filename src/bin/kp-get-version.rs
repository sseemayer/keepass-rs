/// utility to get the version of a KeePass database.
use std::fs::File;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Provide a .kdbx database
    in_kdbx: String,
}

pub fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(args.in_kdbx)?;

    let version = keepass::Database::get_version(&mut source)?;
    println!("{}", version.to_string());
    Ok(())
}
