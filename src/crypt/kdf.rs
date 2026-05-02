use std::convert::TryInto;

use aes::Aes256;
use cipher::{BlockCipherEncrypt, KeyInit};
use hybrid_array::{typenum::U32, Array as GenericArray};
use sha2::{Digest, Sha256};

use super::CryptographyError;

pub(crate) trait Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError>;
}

pub struct AesKdf {
    pub seed: Vec<u8>,
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
}
