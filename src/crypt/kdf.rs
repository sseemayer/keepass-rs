use std::time::Duration;

use aes::Aes256;
use cipher::{
    generic_array::{typenum::U32, GenericArray},
    BlockEncrypt, KeyInit,
};
use sha2::{Digest, Sha256};

use super::CryptographyError;

pub trait Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError>;

    fn benchmark(&self, duration: Duration) -> usize;
}

pub struct AesKdf {
    pub seed: Vec<u8>,
    pub rounds: u64,
}

impl Kdf for AesKdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        let cipher = Aes256::new(&GenericArray::clone_from_slice(&self.seed));
        let mut block1 = GenericArray::clone_from_slice(&composite_key[..16]);
        let mut block2 = GenericArray::clone_from_slice(&composite_key[16..]);
        for _ in 0..self.rounds {
            cipher.encrypt_block(&mut block1);
            cipher.encrypt_block(&mut block2);
        }

        let mut digest = Sha256::new();

        digest.update(block1);
        digest.update(block2);

        Ok(digest.finalize())
    }

    fn benchmark(&self, duration: Duration) -> usize {
        let composite_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&[0; 32]);
        let mut rounds = 0;

        let cipher = Aes256::new(&GenericArray::clone_from_slice(&self.seed));
        let mut block1 = GenericArray::clone_from_slice(&composite_key[..16]);
        let mut block2 = GenericArray::clone_from_slice(&composite_key[16..]);

        let start_time = std::time::Instant::now();
        while start_time.elapsed() < duration {
            cipher.encrypt_block(&mut block1);
            cipher.encrypt_block(&mut block2);
            rounds = rounds + 1;
        }
        rounds
    }
}

pub struct Argon2Kdf {
    pub memory: u64,
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub parallelism: u32,
    pub version: argon2::Version,
    pub variant: argon2::Variant,
}

impl Kdf for Argon2Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        let config = argon2::Config {
            thread_mode: argon2::ThreadMode::Parallel,
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

        Ok(*GenericArray::from_slice(&key))
    }

    fn benchmark(&self, duration: Duration) -> usize {
        let composite_key: GenericArray<u8, U32> = GenericArray::clone_from_slice(&[0; 32]);

        let config = argon2::Config {
            thread_mode: argon2::ThreadMode::Parallel,
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
        let _ = argon2::hash_raw(&composite_key, &self.salt, &config);
        let elapsed = start_time.elapsed();

        if elapsed.is_zero() {
            // Should not happen, but to be safe
            return 0;
        }

        (duration.as_nanos() / elapsed.as_nanos()) as usize
    }
}
