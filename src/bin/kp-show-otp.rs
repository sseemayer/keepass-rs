//! utility to show TOTP code for an entry in a KeePass database
use std::fs::File;

use anyhow::Result;
use clap::Parser;
use keepass::{Database, DatabaseKey};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Provide a .kdbx database
    in_kdbx: String,

    /// Provide a keyfile
    #[arg(short = 'k', long)]
    keyfile: Option<String>,

    /// Do not use a password to decrypt the database
    #[arg(short = 'n', long)]
    no_password: bool,

    /// Provide the entry to read
    entry: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(args.in_kdbx)?;
    let mut key = DatabaseKey::new();

    if let Some(f) = args.keyfile {
        key = key.with_keyfile(&mut File::open(f)?)?;
    }

    if !args.no_password {
        key = key.with_password_from_prompt("Password: ")?;
    }

    if key.is_empty() {
        return Err(anyhow::format_err!("No database key was provided."));
    }

    let db = Database::open(&mut source, key)?;
    let root = db.root();

    let entry = root
        .entry_by_name(args.entry.as_str())
        .ok_or_else(|| anyhow::format_err!("No entry found"))?;

    let totp = entry.get_otp()?;
    println!("Token is {}", totp.value_now()?.code);
    Ok(())
}
