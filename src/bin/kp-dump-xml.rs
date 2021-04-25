/// utility to dump keepass database internal XML data.
extern crate clap;
extern crate keepass;
extern crate rpassword;

use std::fs::File;
use std::io::{Read, Write};

use keepass::Result;

pub fn parse_args() -> clap::ArgMatches<'static> {
    use clap::{App, Arg};

    App::new("kp-dump-xml")
        .arg(
            Arg::with_name("in_kdbx")
                .value_name("KDBXFILE")
                .required(true)
                .help("Provide a .kdbx database"),
        )
        .arg(
            Arg::with_name("keyfile")
                .value_name("KEYFILE")
                .short("k")
                .long("keyfile")
                .help("Provide a key file"),
        )
        .get_matches()
}

pub fn main() -> Result<()> {
    let args = parse_args();

    let source_fn = args.value_of("in_kdbx").unwrap();
    let mut source = File::open(source_fn)?;

    let mut keyfile: Option<File> = args.value_of("keyfile").and_then(|f| File::open(f).ok());

    let password = rpassword::read_password_from_tty(Some("Password (or blank for none): "))
        .expect("Read password");

    let password = if password.is_empty() {
        None
    } else {
        Some(&password[..])
    };

    let chunks = keepass::Database::get_xml_chunks(
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
