use hex_literal::hex;

use std::convert::TryFrom;
use thiserror::Error;

use crate::crypt::ciphers::Cipher;
use crate::{
    compression,
    crypt::{ciphers, kdf, CryptographyError},
    variant_dictionary::VariantDictionary,
};

const _CIPHERSUITE_AES128: [u8; 16] = hex!("61ab05a1946441c38d743a563df8dd35");
const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
const CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
const CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

// Internal IDs for the ciphers
const PLAIN: u32 = 0;
const SALSA_20: u32 = 2;
const CHA_CHA_20: u32 = 3;

/// Choices for outer encryption
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum OuterCipherConfig {
    AES256,
    Twofish,
    ChaCha20,
}

/// Errors for outer encryption configuration
#[derive(Debug, Error)]
pub enum OuterCipherConfigError {
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Invalid outer cipher ID: {:?}", cid)]
    InvalidOuterCipherID { cid: Vec<u8> },
}

impl OuterCipherConfig {
    pub(crate) fn get_cipher(
        &self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Box<dyn ciphers::Cipher>, CryptographyError> {
        match self {
            OuterCipherConfig::AES256 => Ok(Box::new(ciphers::AES256Cipher::new(key, iv)?)),
            OuterCipherConfig::Twofish => Ok(Box::new(ciphers::TwofishCipher::new(key, iv)?)),
            OuterCipherConfig::ChaCha20 => {
                Ok(Box::new(ciphers::ChaCha20Cipher::new_key_iv(key, iv)?))
            }
        }
    }

    pub(crate) fn get_iv_size(&self) -> usize {
        match self {
            OuterCipherConfig::AES256 => ciphers::AES256Cipher::iv_size(),
            OuterCipherConfig::Twofish => ciphers::TwofishCipher::iv_size(),
            OuterCipherConfig::ChaCha20 => ciphers::ChaCha20Cipher::iv_size(),
        }
    }

    pub(crate) fn dump(&self) -> [u8; 16] {
        match self {
            OuterCipherConfig::AES256 => CIPHERSUITE_AES256,
            OuterCipherConfig::Twofish => CIPHERSUITE_TWOFISH,
            OuterCipherConfig::ChaCha20 => CIPHERSUITE_CHACHA20,
        }
    }
}

impl TryFrom<&[u8]> for OuterCipherConfig {
    type Error = OuterCipherConfigError;
    fn try_from(v: &[u8]) -> Result<OuterCipherConfig, Self::Error> {
        if v == CIPHERSUITE_AES256 {
            Ok(OuterCipherConfig::AES256)
        } else if v == CIPHERSUITE_TWOFISH {
            Ok(OuterCipherConfig::Twofish)
        } else if v == CIPHERSUITE_CHACHA20 {
            Ok(OuterCipherConfig::ChaCha20)
        } else {
            Err(OuterCipherConfigError::InvalidOuterCipherID { cid: v.to_vec() }.into())
        }
    }
}

/// Choices for encrypting protected values inside of databases
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum InnerCipherConfig {
    Plain,
    Salsa20,
    ChaCha20,
}

/// Errors with inner protected value encryption
#[derive(Debug, Error)]
pub enum InnerCipherConfigError {
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Invalid inner cipher ID: {}", cid)]
    InvalidInnerCipherID { cid: u32 },
}

impl InnerCipherConfig {
    pub(crate) fn get_cipher(
        &self,
        key: &[u8],
    ) -> Result<Box<dyn ciphers::Cipher>, CryptographyError> {
        match self {
            InnerCipherConfig::Plain => Ok(Box::new(ciphers::PlainCipher::new(key)?)),
            InnerCipherConfig::Salsa20 => Ok(Box::new(ciphers::Salsa20Cipher::new(key)?)),
            InnerCipherConfig::ChaCha20 => Ok(Box::new(ciphers::ChaCha20Cipher::new(key)?)),
        }
    }

    pub(crate) fn dump(&self) -> u32 {
        match self {
            InnerCipherConfig::Plain => PLAIN,
            InnerCipherConfig::Salsa20 => SALSA_20,
            InnerCipherConfig::ChaCha20 => CHA_CHA_20,
        }
    }

    pub(crate) fn get_key_size(&self) -> usize {
        match self {
            InnerCipherConfig::Plain => ciphers::PlainCipher::key_size(),
            InnerCipherConfig::Salsa20 => ciphers::Salsa20Cipher::key_size(),
            InnerCipherConfig::ChaCha20 => ciphers::ChaCha20Cipher::key_size(),
        }
    }
}

impl TryFrom<u32> for InnerCipherConfig {
    type Error = InnerCipherConfigError;

    fn try_from(v: u32) -> Result<InnerCipherConfig, Self::Error> {
        match v {
            PLAIN => Ok(InnerCipherConfig::Plain),
            SALSA_20 => Ok(InnerCipherConfig::Salsa20),
            CHA_CHA_20 => Ok(InnerCipherConfig::ChaCha20),
            _ => Err(InnerCipherConfigError::InvalidInnerCipherID { cid: v }.into()),
        }
    }
}

// Name of the KDF fields in the variant dictionaries.
const KDF_ID: &str = "$UUID";
// KDF fields used by Argon2.
const KDF_MEMORY: &str = "M";
const KDF_SALT: &str = "S";
const KDF_ITERATIONS: &str = "I";
const KDF_PARALLELISM: &str = "P";
const KDF_VERSION: &str = "V";
// KDF fields used by AES.
const KDF_SEED: &str = "S";
const KDF_ROUNDS: &str = "R";

/// Choices for Key Derivation Functions (KDFs)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum KdfConfig {
    /// Derive keys with repeated AES encryption
    Aes { rounds: u64 },
    /// Derive keys with Argon2
    Argon2 {
        iterations: u64,
        memory: u64,
        parallelism: u32,

        #[cfg_attr(
            feature = "serialization",
            serde(serialize_with = "serialize_argon2_version")
        )]
        version: argon2::Version,
    },
}

#[cfg(feature = "serialization")]
fn serialize_argon2_version<S: serde::Serializer>(
    version: &argon2::Version,
    serializer: S,
) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error> {
    serializer.serialize_u32(version.as_u32())
}

impl KdfConfig {
    fn seed_size(&self) -> usize {
        match self {
            KdfConfig::Aes { .. } => 32,
            KdfConfig::Argon2 { .. } => 32,
        }
    }

    /// For writing out a database, generate a new KDF seed from the settings and return the KDF
    /// and the generated seed
    pub(crate) fn get_kdf_and_seed(
        &self,
    ) -> Result<(Box<dyn kdf::Kdf>, Vec<u8>), getrandom::Error> {
        let mut kdf_seed = vec![0; self.seed_size()];
        getrandom::getrandom(&mut kdf_seed)?;

        let kdf = self.get_kdf_seeded(&kdf_seed);

        Ok((kdf, kdf_seed))
    }

    /// For reading a database, generate a KDF from the KDF settings and a provided seed
    pub(crate) fn get_kdf_seeded(&self, seed: &[u8]) -> Box<dyn kdf::Kdf> {
        match self {
            KdfConfig::Aes { rounds } => Box::new(kdf::AesKdf {
                seed: seed.to_vec(),
                rounds: *rounds,
            }),
            KdfConfig::Argon2 {
                memory,
                iterations,
                parallelism,
                version,
            } => Box::new(kdf::Argon2Kdf {
                memory: *memory,
                salt: seed.to_vec(),
                iterations: *iterations,
                parallelism: *parallelism,
                version: *version,
            }),
        }
    }

    pub(crate) fn to_variant_dictionary(&self, seed: &[u8]) -> VariantDictionary {
        let mut vd = VariantDictionary::new();

        match self {
            KdfConfig::Aes { rounds } => {
                vd.set(KDF_ID, KDF_AES_KDBX4.to_vec());
                vd.set(KDF_ROUNDS, *rounds);
                vd.set(KDF_SEED, seed.to_vec());
            }
            KdfConfig::Argon2 {
                memory,
                iterations,
                parallelism,
                version,
            } => {
                vd.set(KDF_ID, KDF_ARGON2.to_vec());
                vd.set(KDF_MEMORY, *memory);
                vd.set(KDF_SALT, seed.to_vec());
                vd.set(KDF_ITERATIONS, *iterations);
                vd.set(KDF_PARALLELISM, *parallelism);
                vd.set(KDF_VERSION, version.as_u32());
            }
        }

        vd
    }
}

const KDF_AES_KDBX3: [u8; 16] = hex!("c9d9f39a628a4460bf740d08c18a4fea");
const KDF_AES_KDBX4: [u8; 16] = hex!("7c02bb8279a74ac0927d114a00648238");
const KDF_ARGON2: [u8; 16] = hex!("ef636ddf8c29444b91f7a9a403e30a0c");

/// Configuration errors for Key Derivation Function
#[derive(Debug, Error)]
pub enum KdfConfigError {
    #[error("Invalid KDF version: {}", version)]
    InvalidKDFVersion { version: u32 },

    #[error("Invalid KDF UUID: {:?}", uuid)]
    InvalidKDFUUID { uuid: Vec<u8> },

    #[error(transparent)]
    VariantDictionary(#[from] crate::variant_dictionary::VariantDictionaryError),
}

impl TryFrom<VariantDictionary> for (KdfConfig, Vec<u8>) {
    type Error = KdfConfigError;

    fn try_from(vd: VariantDictionary) -> Result<(KdfConfig, Vec<u8>), Self::Error> {
        let uuid = vd.get::<Vec<u8>>(KDF_ID)?;

        if uuid == &KDF_ARGON2 {
            let memory: u64 = *vd.get(KDF_MEMORY)?;
            let salt: Vec<u8> = vd.get::<Vec<u8>>(KDF_SALT)?.clone();
            let iterations: u64 = *vd.get(KDF_ITERATIONS)?;
            let parallelism: u32 = *vd.get(KDF_PARALLELISM)?;
            let version: u32 = *vd.get(KDF_VERSION)?;

            let version = match version {
                0x10 => argon2::Version::Version10,
                0x13 => argon2::Version::Version13,
                _ => return Err(KdfConfigError::InvalidKDFVersion { version }),
            };

            Ok((
                KdfConfig::Argon2 {
                    memory,
                    iterations,
                    parallelism,
                    version,
                },
                salt,
            ))
        } else if uuid == &KDF_AES_KDBX4 || uuid == &KDF_AES_KDBX3 {
            let rounds: u64 = *vd.get(KDF_ROUNDS)?;
            let seed: Vec<u8> = vd.get::<Vec<u8>>(KDF_SEED)?.clone();

            Ok((KdfConfig::Aes { rounds }, seed))
        } else {
            Err(KdfConfigError::InvalidKDFUUID { uuid: uuid.clone() })
        }
    }
}

/// Choices of compression algorithm
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum CompressionConfig {
    None,
    GZip,
}

/// Errors with compression choice
#[derive(Debug, Error)]
pub enum CompressionConfigError {
    /// The identifier for the compression algorithm specified in the database is invalid
    #[error("Invalid compression suite: {}", cid)]
    InvalidCompressionSuite { cid: u32 },
}

impl CompressionConfig {
    pub(crate) fn get_compression(&self) -> Box<dyn compression::Compression> {
        match self {
            CompressionConfig::None => Box::new(compression::NoCompression),
            CompressionConfig::GZip => Box::new(compression::GZipCompression),
        }
    }

    pub(crate) fn dump(&self) -> [u8; 4] {
        match self {
            CompressionConfig::None => [0, 0, 0, 0],
            CompressionConfig::GZip => [1, 0, 0, 0],
        }
    }
}

impl TryFrom<u32> for CompressionConfig {
    type Error = CompressionConfigError;

    fn try_from(v: u32) -> Result<CompressionConfig, Self::Error> {
        match v {
            0 => Ok(CompressionConfig::None),
            1 => Ok(CompressionConfig::GZip),
            _ => Err(CompressionConfigError::InvalidCompressionSuite { cid: v }.into()),
        }
    }
}
