use std::time::Duration;

use clap::Parser;
use keepass::crypt::kdf::{AesKdf, Argon2Kdf, Kdf};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Duration for each KDF in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    msecs: u64,
}

fn main() {
    let args = Args::parse();
    let duration = Duration::from_millis(args.msecs);

    let kdf = AesKdf {
        seed: vec![0; 32],
        rounds: 100_000,
    };
    println!("Benchmarking AES KDF for {} ms...", args.msecs);
    let rounds = kdf.benchmark(duration);
    println!("AES KDF: {} rounds in {} ms", rounds, args.msecs);
}
