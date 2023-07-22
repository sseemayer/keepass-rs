/// utility to dump keepass database internal XML data.
use std::fs::File;
use std::io::Write;

use anyhow::Result;
use clap::Parser;

use keepass::{Database, DatabaseKey};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Provide a .kdbx database
    in_kdbx: String,

    /// Output XML filename
    out_xml: String,

    /// Provide a keyfile
    #[arg(short = 'k', long)]
    keyfile: Option<String>,
}

pub fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(args.in_kdbx)?;
    let mut key = DatabaseKey::new();

    if let Some(f) = args.keyfile {
        key = key.with_keyfile(&mut File::open(f)?)?;
    }

    let password =
        rpassword::prompt_password("Password (or blank for none): ").expect("Read password");

    if !password.is_empty() {
        key = key.with_password(&password);
    };

    let xml = Database::get_xml(&mut source, key)?;

    File::create(args.out_xml)?.write_all(&xml)?;

    Ok(())
}
