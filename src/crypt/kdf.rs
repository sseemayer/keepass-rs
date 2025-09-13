use std::convert::TryInto;
use std::time::Duration;

use aes::Aes256;
use cipher::{BlockCipherEncrypt, KeyInit};
use hybrid_array::{typenum::U32, Array as GenericArray};
use sha2::{Digest, Sha256};

use super::CryptographyError;

/// Trait for Key Derivation Functions
pub trait Kdf {
    /// Transform a composite key into a final key
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError>;

    /// Benchmark the KDF for a given duration
    fn benchmark(&self, duration: Duration) -> Result<usize, CryptographyError>;
}

/// AES-based Key Derivation Function
pub struct AesKdf {
    /// Seed for the AES KDF
    pub seed: Vec<u8>,
    /// Number of rounds to perform
    pub rounds: u64,
}

impl Kdf for AesKdf {
    #[allow(clippy::indexing_slicing)] // Slicing is safe because composite_key is always 32 bytes
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        let seed_arr = self
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        let cipher = Aes256::new(&seed_arr);
        let mut block1: GenericArray<u8, _> = composite_key[..16]
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        let mut block2: GenericArray<u8, _> = composite_key[16..]
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        for _ in 0..self.rounds {
            cipher.encrypt_block(&mut block1);
            cipher.encrypt_block(&mut block2);
        }

        let mut digest = Sha256::new();

        digest.update(block1);
        digest.update(block2);

        Ok(digest.finalize())
    }

    fn benchmark(&self, duration: Duration) -> Result<usize, CryptographyError> {
        let composite_key: GenericArray<u8, U32> = [0; 32].into();
        let trials = 3;
        let rounds_per_trial = 1_000_000;

        let seed_arr: GenericArray<u8, U32> = self
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        let cipher = Aes256::new(&seed_arr);
        let mut block1: GenericArray<u8, _> = composite_key[..16]
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        let mut block2: GenericArray<u8, _> = composite_key[16..]
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;

        let start_time = std::time::Instant::now();
        for _ in 0..trials {
            for _ in 0..rounds_per_trial {
                cipher.encrypt_block(&mut block1);
                cipher.encrypt_block(&mut block2);
            }
        }
        let elapsed = start_time.elapsed();

        if elapsed.is_zero() {
            return Err(CryptographyError::BenchmarkError);
        }

        let total_rounds = rounds_per_trial * trials;
        Ok((total_rounds as u128 * duration.as_nanos() / elapsed.as_nanos()) as usize)
    }
}

/// Argon2-based Key Derivation Function
pub struct Argon2Kdf {
    /// Memory cost in bytes
    pub memory: u64,
    /// Salt for the Argon2 KDF
    pub salt: Vec<u8>,
    /// Number of iterations
    pub iterations: u64,
    /// Degree of parallelism
    pub parallelism: u32,
    /// Argon2 version
    pub version: argon2::Version,
    /// Argon2 variant
    pub variant: argon2::Variant,
}

impl Kdf for Argon2Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        // Disable Argon2 multithreading on wasm32 targets to avoid panics on platforms without thread support.
        let thread_mode = if cfg!(target_arch = "wasm32") {
            argon2::ThreadMode::Sequential
        } else {
            argon2::ThreadMode::Parallel
        };

        let config = argon2::Config {
            thread_mode,
            ad: &[],
            hash_length: 32,
            lanes: self.parallelism,
            mem_cost: (self.memory / 1024) as u32,
            secret: &[],
            time_cost: self.iterations as u32,
            variant: self.variant,
            version: self.version,
        };

        let key = argon2::hash_raw(composite_key, &self.salt, &config)?;

        key.as_slice()
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))
    }

    fn benchmark(&self, duration: Duration) -> Result<usize, CryptographyError> {
        let composite_key: GenericArray<u8, U32> = [0; 32].into();

        let config = argon2::Config {
            thread_mode: if cfg!(target_arch = "wasm32") {
                argon2::ThreadMode::Sequential
            } else {
                argon2::ThreadMode::Parallel
            },
            ad: &[],
            hash_length: 32,
            lanes: self.parallelism,
            mem_cost: (self.memory / 1024) as u32,
            secret: &[],
            time_cost: 1, // benchmark for one iteration
            variant: self.variant,
            version: self.version,
        };

        let start_time = std::time::Instant::now();
        let _ = argon2::hash_raw(&composite_key, &self.salt, &config)?;
        let elapsed = start_time.elapsed();

        if elapsed.is_zero() {
            return Err(CryptographyError::BenchmarkError);
        }

        Ok((duration.as_nanos() / elapsed.as_nanos()) as usize)
    }
}
