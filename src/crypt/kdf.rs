use aes::block_cipher_trait::generic_array::{typenum::U32, GenericArray};
use aes::Aes256;
use block_modes::{block_padding::ZeroPadding, BlockMode, Ecb};

use crate::result::{CryptoError, DatabaseIntegrityError, Error, Result};

pub(crate) trait Kdf {
    fn transform_key(&self, composite_key: &GenericArray<u8, U32>)
        -> Result<GenericArray<u8, U32>>;
}

pub struct AesKdf {
    pub seed: Vec<u8>,
    pub rounds: u64,
}

impl Kdf for AesKdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>> {
        type Aes256Ecb = Ecb<Aes256, ZeroPadding>;

        let mut key: Vec<u8> = Vec::from(composite_key.as_slice());

        // encrypt the key repeatedly
        for _ in 0..self.rounds {
            let cipher = Aes256Ecb::new_var(&self.seed, Default::default())
                .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

            let key_len = key.len();
            let new_key = cipher
                .encrypt(&mut key, key_len)
                .map(Vec::from)
                .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

            key = new_key;
        }

        crate::crypt::calculate_sha256(&[&key])
    }
}

pub struct Argon2Kdf {
    pub memory: u64,
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub parallelism: u32,
    pub version: argon2::Version,
}

impl Kdf for Argon2Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>> {
        let config = argon2::Config {
            ad: &[],
            hash_length: 32,
            lanes: self.parallelism,
            mem_cost: (self.memory / 1024) as u32,
            secret: &[],
            thread_mode: argon2::ThreadMode::default(),
            time_cost: self.iterations as u32,
            variant: argon2::Variant::Argon2d,
            version: self.version,
        };

        let key = argon2::hash_raw(composite_key, &self.salt, &config)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        Ok(*GenericArray::from_slice(&key))
    }
}

/*
pub(crate) fn transform_key_argon2(
    composite_key: &GenericArray<u8, U32>,
) -> Result<GenericArray<u8, U32>> {
    let version = match version {
        0x10 => argon2::Version::Version10,
        0x13 => argon2::Version::Version13,
        _ => return Err(DatabaseIntegrityError::InvalidKDFVersion { version: version }.into()),
    };
}
*/
