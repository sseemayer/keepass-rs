/// utility to purge the history of the entries in the database
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
}

pub fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(&args.in_kdbx)?;
    let mut key = DatabaseKey::new();

    if let Some(f) = args.keyfile {
        key = key.with_keyfile(&mut File::open(f)?)?;
    }

    let password =
        rpassword::prompt_password("Password (or blank for none): ").expect("Read password");

    if !password.is_empty() {
        key = key.with_password(&password);
    };

    let mut db = Database::open(&mut source, key.clone())?;

    purge_history(&mut db.root)?;

    db.save(&mut File::options().write(true).open(&args.in_kdbx)?, key)?;

    Ok(())
}

fn purge_history_for_entry(entry: &mut keepass::db::Entry) -> Result<()> {
    if let Some(history) = &entry.history {
        let history_size = history.get_entries().len();
        if history_size != 0 {
            println!(
                "Removing {} history entries from {}",
                history_size,
                entry.uuid.to_string()
            );
        }
    }
    entry.history = None;
    Ok(())
}

fn purge_history(group: &mut keepass::db::Group) -> Result<()> {
    for node in &mut group.children {
        match node {
            keepass::db::Node::Entry(ref mut e) => purge_history_for_entry(e)?,
            keepass::db::Node::Group(ref mut g) => purge_history(g)?,
        };
    }
    Ok(())
}
