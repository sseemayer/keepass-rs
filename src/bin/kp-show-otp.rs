/// utility to dump keepass database internal XML data.
use std::fs::File;

use anyhow::Result;
use clap::Parser;
use keepass::{db::NodeRef, Database, DatabaseKey};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Provide a .kdbx database
    in_kdbx: String,

    /// Provide a keyfile
    #[arg(short = 'k', long)]
    keyfile: Option<String>,

    /// Provide the entry to read
    entry: String,
}

pub fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(args.in_kdbx)?;
    let mut key = DatabaseKey::new();

    if let Some(f) = args.keyfile {
        key = key.with_keyfile(&mut File::open(f)?)?;
    }

    key = key.with_password_from_prompt("Password (or blank for none): ")?;

    let db = Database::open(&mut source, key)?;

    if let Some(NodeRef::Entry(e)) = db.root.get(&[&args.entry]) {
        let totp = e.get_otp().unwrap();
        println!("Token is {}", totp.value_now().unwrap().code);
        Ok(())
    } else {
        panic!("Could not find entry with provided name")
    }
}
