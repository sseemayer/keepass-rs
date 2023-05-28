/// utility to parse a KeePass database, and then write it out again, to see if anything is lost.
use std::fs::File;
use std::io::{Cursor, Read};

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
}

pub fn main() -> Result<()> {
    let args = Args::parse();

    let mut source = File::open(args.in_kdbx)?;

    let password = rpassword::prompt_password("Password (or blank for none): ")
        .expect("Could not read password from TTY");

    let password = if password.is_empty() {
        None
    } else {
        Some(&password[..])
    };

    let mut keyfile: Option<Cursor<_>> = if let Some(kf) = args.keyfile {
        let mut f = File::open(kf)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Some(Cursor::new(buf))
    } else {
        None
    };

    let kf = keyfile.as_mut().map(|kf| kf as &mut dyn Read);
    let db = Database::open(&mut source, DatabaseKey::new(password, kf))?;

    let mut out_file = File::create(args.out_kdbx)?;
    let kf = keyfile.as_mut().map(|kf| kf as &mut dyn Read);
    db.save(&mut out_file, DatabaseKey::new(password, kf))?;

    Ok(())
}
