/// utility to dump keepass database internal XML data.
use std::fs::File;
use std::io::Read;

use keepass::NodeRef;
use keepass::Result;

pub fn parse_args() -> clap::ArgMatches<'static> {
    use clap::{App, Arg};

    App::new("kp-show-otp")
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
        .arg(
            Arg::with_name("entry")
                .value_name("ENTRY")
                .required(true)
                .help("Entry to show TOTP from"),
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

    let db = keepass::Database::open(
        &mut source,
        password,
        keyfile.as_mut().map(|kf| kf as &mut dyn Read),
    )?;

    if let Some(NodeRef::Entry(e)) = db.root.get(&[args.value_of("entry").unwrap()]) {
        let totp = e.get_otp().unwrap();
        println!("Token is {}", totp.current_value());
        Ok(())
    } else {
        panic!("Could not find entry with provided name")
    }
}
