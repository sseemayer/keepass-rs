/// utility to add a Yubikey to a database's key
use std::fs::File;

use anyhow::Result;
use clap::Parser;

use keepass::{ChallengeResponseKey, Database, DatabaseKey};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Provide a .kdbx database
    in_kdbx: String,

    /// Output file to write
    out_kdbx: String,

    /// The slot number of the yubikey to add to the Database
    slot: String,

    /// The serial number of the yubikey to add to the Database
    #[arg(short = 'n', long)]
    serial_number: Option<u32>,

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

    key = key.with_password_from_prompt("Password (or blank for none): ")?;

    let db = Database::open(&mut source, key.clone())?;

    let yubikey = ChallengeResponseKey::get_yubikey(args.serial_number)?;

    let new_key = key.with_challenge_response_key(ChallengeResponseKey::YubikeyChallenge(yubikey, args.slot));

    let mut out_file = File::create(args.out_kdbx)?;

    db.save(&mut out_file, new_key)?;

    println!("Yubikey was added to the database key.");

    Ok(())
}
