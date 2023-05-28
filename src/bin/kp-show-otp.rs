/// utility to dump keepass database internal XML data.
use std::fs::File;
use std::io::Read;

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

    let mut keyfile: Option<File> = args.keyfile.and_then(|f| File::open(f).ok());

    let password =
        rpassword::prompt_password("Password (or blank for none): ").expect("Read password");

    let password = if password.is_empty() {
        None
    } else {
        Some(&password[..])
    };

    let keyfile = keyfile.as_mut().map(|kf| kf as &mut dyn Read);

    let db = Database::open(&mut source, DatabaseKey::new(password, keyfile))?;

    if let Some(NodeRef::Entry(e)) = db.root.get(&[&args.entry]) {
        let totp = e.get_otp().unwrap();
        println!("Token is {}", totp.value_now().unwrap().code);
        Ok(())
    } else {
        panic!("Could not find entry with provided name")
    }
}
