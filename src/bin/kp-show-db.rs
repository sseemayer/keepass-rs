/// utility to show a parsed KeePass database
use std::fs::File;
use std::io::Read;

use keepass::Result;

pub fn parse_args() -> clap::ArgMatches<'static> {
    use clap::{App, Arg};

    App::new("kp-show-db")
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

    let password = rpassword::prompt_password("Password (or blank for none): ")
        .expect("Could not read password from TTY");

    let password = if password.is_empty() {
        None
    } else {
        Some(&password[..])
    };

    let db = keepass::Database::open(
        &mut source,
        password,
        keyfile.as_mut().map(|kf| kf as &mut dyn Read),
    )?;

    println!("{:#?}", db);

    Ok(())
}
