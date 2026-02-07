//! utility to purge the history of the entries in the database
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
}

#[allow(missing_docs)]
pub fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(&args.in_kdbx)?;
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

    let mut db = Database::open(&mut source, key.clone())?;

    db.foreach_entry_mut(|mut entry| {
        if let Some(history) = &entry.history {
            let history_size = history.entries().len();
            if history_size != 0 {
                println!("Removing {} history entries from {}", history_size, entry.id());
            }
        }
        entry.history = None;
    });

    db.save(&mut File::options().write(true).open(&args.in_kdbx)?, key)?;

    Ok(())
}
