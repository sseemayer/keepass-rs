//! Configuration options for how to compress and encrypt databases
use hex_literal::hex;
use thiserror::Error;

use std::convert::TryFrom;

pub use crate::format::DatabaseVersion;

#[cfg(feature = "save_kdbx4")]
use crate::crypt::ciphers::Cipher;
use crate::{
    compression,
    crypt::{
        ciphers::{self},
        kdf, CryptographyError,
    },
    format::{
        variant_dictionary::{VariantDictionary, VariantDictionaryError},
        KDBX4_CURRENT_MINOR_VERSION,
    },
};

const _CIPHERSUITE_AES128: [u8; 16] = hex!("61ab05a1946441c38d743a563df8dd35");
const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
const CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
const CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

// Internal IDs for the ciphers
const PLAIN: u32 = 0;
const SALSA_20: u32 = 2;
const CHA_CHA_20: u32 = 3;

/// Configuration of how a database should be stored
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
#[non_exhaustive]
pub struct DatabaseConfig {
    /// Version of the outer database file
    pub version: DatabaseVersion,

    /// What encryption to use for the outer encryption
    pub outer_cipher_config: OuterCipherConfig,

    /// What algorithm to use to compress the inner data
    pub compression_config: CompressionConfig,

    /// What encryption to use for protected fields inside the database
    pub inner_cipher_config: InnerCipherConfig,

    /// Settings for the Key Derivation Function (KDF)
    pub kdf_config: KdfConfig,

    /// Custom data of plugins/ports.
    pub public_custom_data: Option<VariantDictionary>,
}

/// Sensible default configuration for new databases
impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            version: DatabaseVersion::KDB4(KDBX4_CURRENT_MINOR_VERSION),
            outer_cipher_config: OuterCipherConfig::AES256,
            compression_config: CompressionConfig::GZip,
            inner_cipher_config: InnerCipherConfig::ChaCha20,
            kdf_config: KdfConfig::Argon2 {
                iterations: 50,
                memory: 1024 * 1024,
                parallelism: 4,
                version: argon2::Version::Version13,
            },
            public_custom_data: None,
        }
    }
}

/// Choices for outer encryption
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
#[non_exhaustive]
pub enum OuterCipherConfig {
    /// Encrypt the database with AES-256 in CBC mode.
    AES256,

    /// Encrypt the database with Twofish in CBC mode.
    Twofish,

    /// Encrypt the database with ChaCha20.
    ChaCha20,
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
            OuterCipherConfig::ChaCha20 => Ok(Box::new(ciphers::ChaCha20Cipher::new_key_iv(key, iv)?)),
        }
    }

    #[cfg(feature = "save_kdbx4")]
    pub(crate) fn get_iv_size(&self) -> usize {
        match self {
            OuterCipherConfig::AES256 => ciphers::AES256Cipher::iv_size(),
            OuterCipherConfig::Twofish => ciphers::TwofishCipher::iv_size(),
            OuterCipherConfig::ChaCha20 => ciphers::ChaCha20Cipher::iv_size(),
        }
    }

    #[cfg(feature = "save_kdbx4")]
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
            Err(OuterCipherConfigError::InvalidOuterCipherID { cid: v.to_vec() })
        }
    }
}

/// Errors with the configuration of the outer encryption
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OuterCipherConfigError {
    /// Errors with cryptographic operations
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    /// The identifier for the outer cipher specified in the database is invalid
    #[error("Invalid outer cipher ID: {:?}", cid)]
    InvalidOuterCipherID {
        /// The invalid cipher ID that was encountered, as a byte vector
        cid: Vec<u8>,
    },
}

/// Choices for encrypting protected values inside of databases
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
#[non_exhaustive]
pub enum InnerCipherConfig {
    /// Don't encrypt proected values
    Plain,

    /// Encrypt protected values with Salsa20
    Salsa20,

    /// Encrypt protected values with ChaCha20
    ChaCha20,
}

impl InnerCipherConfig {
    pub(crate) fn get_cipher(
        &self,
        protected_stream_key: &[u8],
    ) -> Result<Box<dyn ciphers::Cipher>, CryptographyError> {
        match self {
            InnerCipherConfig::Plain => Ok(Box::new(ciphers::PlainCipher::new(protected_stream_key)?)),
            InnerCipherConfig::Salsa20 => Ok(Box::new(ciphers::Salsa20Cipher::new(protected_stream_key)?)),
            InnerCipherConfig::ChaCha20 => Ok(Box::new(ciphers::ChaCha20Cipher::new(protected_stream_key)?)),
        }
    }

    #[cfg(feature = "save_kdbx4")]
    pub(crate) fn dump(&self) -> u32 {
        match self {
            InnerCipherConfig::Plain => PLAIN,
            InnerCipherConfig::Salsa20 => SALSA_20,
            InnerCipherConfig::ChaCha20 => CHA_CHA_20,
        }
    }

    #[cfg(feature = "save_kdbx4")]
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
            _ => Err(InnerCipherConfigError::InvalidInnerCipherID { cid: v }),
        }
    }
}

/// Errors with the configuration of the inner encryption
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InnerCipherConfigError {
    /// A cryptographic error occurred while configuring the inner cipher
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    /// The identifier for the inner cipher specified in the database is invalid
    #[error("Invalid inner cipher ID: {}", cid)]
    InvalidInnerCipherID {
        /// The invalid cipher ID that was encountered
        cid: u32,
    },
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
#[non_exhaustive]
pub enum KdfConfig {
    /// Derive keys with repeated AES encryption
    Aes {
        /// The number of rounds of AES encryption to perform when deriving keys
        rounds: u64,
    },
    /// Derive keys with Argon2d
    Argon2 {
        /// The number of iterations to perform when deriving keys
        iterations: u64,

        /// The amount of memory (in KiB) to use when deriving keys
        memory: u64,

        /// The degree of parallelism to use when deriving keys
        parallelism: u32,

        /// The version of the Argon2 algorithm to use when deriving keys
        #[cfg_attr(feature = "serialization", serde(serialize_with = "serialize_argon2_version"))]
        version: argon2::Version,
    },

    /// Derive keys with Argon2id
    Argon2id {
        /// The number of iterations to perform when deriving keys
        iterations: u64,

        /// The amount of memory (in KiB) to use when deriving keys
        memory: u64,

        /// The degree of parallelism to use when deriving keys
        parallelism: u32,

        /// The version of the Argon2 algorithm to use when deriving keys
        #[cfg_attr(feature = "serialization", serde(serialize_with = "serialize_argon2_version"))]
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
    #[cfg(feature = "save_kdbx4")]
    fn seed_size(&self) -> usize {
        match self {
            KdfConfig::Aes { .. } => 32,
            KdfConfig::Argon2 { .. } => 32,
            KdfConfig::Argon2id { .. } => 32,
        }
    }

    /// For writing out a database, generate a new KDF seed from the config and return the KDF
    /// and the generated seed
    #[cfg(feature = "save_kdbx4")]
    pub(crate) fn get_kdf_and_seed(&self) -> Result<(Box<dyn kdf::Kdf>, Vec<u8>), getrandom::Error> {
        let mut kdf_seed = vec![0; self.seed_size()];
        getrandom::fill(&mut kdf_seed)?;

        let kdf = self.get_kdf_seeded(&kdf_seed);

        Ok((kdf, kdf_seed))
    }

    /// For reading a database, generate a KDF from the KDF config and a provided seed
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
                variant: argon2::Variant::Argon2d,
            }),
            KdfConfig::Argon2id {
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
                variant: argon2::Variant::Argon2id,
            }),
        }
    }

    #[cfg(feature = "save_kdbx4")]
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
            KdfConfig::Argon2id {
                memory,
                iterations,
                parallelism,
                version,
            } => {
                vd.set(KDF_ID, KDF_ARGON2ID.to_vec());
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
const KDF_ARGON2ID: [u8; 16] = hex!("9e298b1956db4773b23dfc3ec6f0a1e6");

impl TryFrom<VariantDictionary> for (KdfConfig, Vec<u8>) {
    type Error = KdfConfigError;

    fn try_from(vd: VariantDictionary) -> Result<(KdfConfig, Vec<u8>), Self::Error> {
        let uuid = vd.get::<Vec<u8>>(KDF_ID)?;

        if uuid == &KDF_ARGON2ID {
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
                KdfConfig::Argon2id {
                    memory,
                    iterations,
                    parallelism,
                    version,
                },
                salt,
            ))
        } else if uuid == &KDF_ARGON2 {
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

/// Errors with the configuration of the Key Derivation Function
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KdfConfigError {
    /// An invalid KDF version was specified in the database
    #[error("Invalid KDF version: {}", version)]
    InvalidKDFVersion {
        /// The invalid KDF version that was encountered
        version: u32,
    },

    /// An invalid KDF UUID was specified in the database
    #[error("Invalid KDF UUID: {:?}", uuid)]
    InvalidKDFUUID {
        /// The invalid KDF UUID that was encountered, as a byte vector
        uuid: Vec<u8>,
    },

    /// Errors parsing KDF parameters from the variant dictionary
    #[error(transparent)]
    VariantDictionary(#[from] VariantDictionaryError),
}

/// Choices of compression algorithm
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
#[non_exhaustive]
pub enum CompressionConfig {
    /// Don't compress the inner data
    None,

    /// Compress the inner data with GZip
    GZip,
}

impl CompressionConfig {
    pub(crate) fn get_compression(&self) -> Box<dyn compression::Compression> {
        match self {
            CompressionConfig::None => Box::new(compression::NoCompression),
            CompressionConfig::GZip => Box::new(compression::GZipCompression),
        }
    }

    #[cfg(feature = "save_kdbx4")]
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
            _ => Err(CompressionConfigError::InvalidCompressionSuite { cid: v }),
        }
    }
}

/// Errors with the configuration of the compression algorithm
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CompressionConfigError {
    /// The identifier for the compression algorithm specified in the database is invalid
    #[error("Invalid compression algorithm: {}", cid)]
    InvalidCompressionSuite {
        /// The invalid compression suite ID that was encountered
        cid: u32,
    },
}
