use std::time::Duration;

use clap::{Parser, ValueEnum};
use keepass::crypt::kdf::{AesKdf, Argon2Kdf, Kdf};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// KDF to benchmark
    #[arg(value_enum)]
    kdf: KdfChoice,

    /// Duration for each KDF in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    msecs: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum KdfChoice {
    Aes,
    Argon2,
}

fn main() {
    let args = Args::parse();
    let duration = Duration::from_millis(args.msecs);

    match args.kdf {
        KdfChoice::Aes => {
            let kdf = AesKdf {
                seed: vec![0; 32],
                rounds: 100_000,
            };
            println!("Benchmarking AES KDF for {} ms...", args.msecs);
            let rounds = kdf.benchmark(duration);
            println!("AES KDF: {} rounds in {} ms", rounds, args.msecs);
        }
        KdfChoice::Argon2 => {
            let kdf = Argon2Kdf {
                salt: vec![0; 32],
                parallelism: 1,
                memory: 1024 * 1024, // 1 MiB
                iterations: 1,
                variant: argon2::Variant::Argon2id,
                version: argon2::Version::Version13,
            };
            println!(
                "Benchmarking Argon2id KDF with {} KiB memory and parallelism {} for {} ms...",
                kdf.memory / 1024,
                kdf.parallelism,
                args.msecs
            );
            let iterations = kdf.benchmark(duration);
            println!("Argon2id KDF: {} iterations in {} ms", iterations, args.msecs);
        }
    }
}
