//! utility to parse a KeePass database, and then write it out again, to see if anything is lost.
use std::{fs::File, path::Path};

use anyhow::Result;
use clap::Parser;

use keepass::{Database, DatabaseKey};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Provide a .kdbx database
    in_kdbx: String,

    /// Output file to write
    out_kdbx: String,

    /// Provide a keyfile
    #[arg(short = 'k', long)]
    keyfile: Option<String>,

    /// Do not use a password to decrypt the database
    #[arg(short = 'n', long)]
    no_password: bool,
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

    let db = Database::open(&mut source, key.clone())?;

    save(&db, Path::new(&args.out_kdbx), key)
}

fn save(db: &Database, out_kdbx: &Path, key: DatabaseKey) -> Result<()> {
    let mut out_file = File::create(out_kdbx)?;
    db.save(&mut out_file, key)?;

    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use std::fs;

    use keepass::config::DatabaseVersion;

    use super::*;

    fn database() -> (Database, DatabaseKey) {
        let mut db = Database::new();
        db.meta.database_name = Some("rewritten".to_string());
        (db, DatabaseKey::new().with_password("demopass"))
    }

    #[test]
    fn failed_save_leaves_output_untouched() {
        let (mut db, key) = database();
        // only KDBX 4.1 databases can be saved
        db.config.version = DatabaseVersion::KDB3(1);
        let dir = tempfile::tempdir().unwrap();
        let out_kdbx = dir.path().join("out.kdbx");
        fs::write(&out_kdbx, b"previous contents").unwrap();

        assert!(save(&db, &out_kdbx, key).is_err());

        assert_eq!(fs::read(&out_kdbx).unwrap(), b"previous contents");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn save_replaces_output() {
        let (db, key) = database();
        let dir = tempfile::tempdir().unwrap();
        let out_kdbx = dir.path().join("out.kdbx");
        fs::write(&out_kdbx, b"previous contents").unwrap();

        save(&db, &out_kdbx, key.clone()).unwrap();

        let saved = Database::open(&mut File::open(&out_kdbx).unwrap(), key).unwrap();
        assert_eq!(saved.meta.database_name.as_deref(), Some("rewritten"));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
