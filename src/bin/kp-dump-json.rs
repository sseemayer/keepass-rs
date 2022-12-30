/// utility to dump keepass database as JSON document
use std::{fs::File, io::Read};

use anyhow::Result;
use clap::Parser;

use keepass::Database;

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

    let mut source = File::open(args.in_kdbx)?;
    let mut keyfile: Option<File> = args.keyfile.and_then(|f| File::open(f).ok());

    let password =
        rpassword::prompt_password("Password (or blank for none): ").expect("Read password");

    let password = if password.is_empty() {
        None
    } else {
        Some(&password[..])
    };

    let db = Database::open(
        &mut source,
        password,
        keyfile.as_mut().map(|kf| kf as &mut dyn Read),
    )?;

    let stdout = std::io::stdout().lock();
    serde_json::ser::to_writer(stdout, &db)?;

    Ok(())
}
