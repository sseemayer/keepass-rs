/// utility to dump keepass database internal XML data.
use std::fs::File;
use std::io::{Read, Write};

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

    let password = rpassword::prompt_password("Password (or blank for none): ")
        .expect("Could not read password from TTY");

    let password = if password.is_empty() {
        None
    } else {
        Some(&password[..])
    };

    let chunks = Database::get_xml_chunks(
        &mut source,
        password,
        keyfile.as_mut().map(|kf| kf as &mut dyn Read),
    )?;

    for (i, chunk) in chunks.iter().enumerate() {
        let chunk_fn = format!("db-{}.xml", i);
        let mut chunk_file = File::create(chunk_fn).expect("Open chunk XML file");

        chunk_file.write(chunk)?;
    }

    println!("Wrote {} chunks", chunks.len());

    Ok(())
}
