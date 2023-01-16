use hex_literal::hex;

use std::collections::HashMap;
use std::convert::TryFrom;
use thiserror::Error;

use crate::crypt::ciphers::Cipher;
use crate::{
    compression,
    crypt::{ciphers, kdf, CryptographyError},
    variant_dictionary::{VariantDictionary, VariantDictionaryValue},
};

const _CIPHERSUITE_AES128: [u8; 16] = hex!("61ab05a1946441c38d743a563df8dd35");
const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
const CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
const CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

// Internal IDs for the ciphers
const PLAIN: u32 = 0;
const SALSA_20: u32 = 2;
const CHA_CHA_20: u32 = 3;

#[derive(Debug)]
pub enum OuterCipherSuite {
    AES256,
    Twofish,
    ChaCha20,
}

#[derive(Debug, Error)]
pub enum OuterCipherSuiteError {
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Invalid outer cipher ID: {:?}", cid)]
    InvalidOuterCipherID { cid: Vec<u8> },
}

impl OuterCipherSuite {
    pub(crate) fn get_cipher(
        &self,
        key: &[u8],
        iv: &[u8],
    ) -> Result<Box<dyn ciphers::Cipher>, CryptographyError> {
        match self {
            OuterCipherSuite::AES256 => Ok(Box::new(ciphers::AES256Cipher::new(key, iv)?)),
            OuterCipherSuite::Twofish => Ok(Box::new(ciphers::TwofishCipher::new(key, iv)?)),
            OuterCipherSuite::ChaCha20 => {
                Ok(Box::new(ciphers::ChaCha20Cipher::new_key_iv(key, iv)?))
            }
        }
    }

    pub fn get_iv_size(&self) -> u8 {
        match self {
            OuterCipherSuite::AES256 => ciphers::AES256Cipher::iv_size(),
            OuterCipherSuite::Twofish => ciphers::TwofishCipher::iv_size(),
            OuterCipherSuite::ChaCha20 => ciphers::ChaCha20Cipher::iv_size(),
        }
    }

    pub(crate) fn dump(&self) -> [u8; 16] {
        match self {
            OuterCipherSuite::AES256 => CIPHERSUITE_AES256,
            OuterCipherSuite::Twofish => CIPHERSUITE_TWOFISH,
            OuterCipherSuite::ChaCha20 => CIPHERSUITE_CHACHA20,
        }
    }
}

impl TryFrom<&[u8]> for OuterCipherSuite {
    type Error = OuterCipherSuiteError;
    fn try_from(v: &[u8]) -> Result<OuterCipherSuite, Self::Error> {
        if v == CIPHERSUITE_AES256 {
            Ok(OuterCipherSuite::AES256)
        } else if v == CIPHERSUITE_TWOFISH {
            Ok(OuterCipherSuite::Twofish)
        } else if v == CIPHERSUITE_CHACHA20 {
            Ok(OuterCipherSuite::ChaCha20)
        } else {
            Err(OuterCipherSuiteError::InvalidOuterCipherID { cid: v.to_vec() }.into())
        }
    }
}

#[derive(Debug)]
pub enum InnerCipherSuite {
    Plain,
    Salsa20,
    ChaCha20,
}

#[derive(Debug, Error)]
pub enum InnerCipherSuiteError {
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Invalid inner cipher ID: {}", cid)]
    InvalidInnerCipherID { cid: u32 },
}

impl InnerCipherSuite {
    pub(crate) fn get_cipher(
        &self,
        key: &[u8],
    ) -> Result<Box<dyn ciphers::Cipher>, CryptographyError> {
        match self {
            InnerCipherSuite::Plain => Ok(Box::new(ciphers::PlainCipher::new(key)?)),
            InnerCipherSuite::Salsa20 => Ok(Box::new(ciphers::Salsa20Cipher::new(key)?)),
            InnerCipherSuite::ChaCha20 => Ok(Box::new(ciphers::ChaCha20Cipher::new(key)?)),
        }
    }

    pub(crate) fn dump(&self) -> u32 {
        match self {
            InnerCipherSuite::Plain => PLAIN,
            InnerCipherSuite::Salsa20 => SALSA_20,
            InnerCipherSuite::ChaCha20 => CHA_CHA_20,
        }
    }

    pub fn get_iv_size(&self) -> u8 {
        match self {
            InnerCipherSuite::Plain => ciphers::PlainCipher::iv_size(),
            InnerCipherSuite::Salsa20 => ciphers::Salsa20Cipher::iv_size(),
            InnerCipherSuite::ChaCha20 => ciphers::ChaCha20Cipher::iv_size(),
        }
    }
}

impl TryFrom<u32> for InnerCipherSuite {
    type Error = InnerCipherSuiteError;

    fn try_from(v: u32) -> Result<InnerCipherSuite, Self::Error> {
        match v {
            PLAIN => Ok(InnerCipherSuite::Plain),
            SALSA_20 => Ok(InnerCipherSuite::Salsa20),
            CHA_CHA_20 => Ok(InnerCipherSuite::ChaCha20),
            _ => Err(InnerCipherSuiteError::InvalidInnerCipherID { cid: v }.into()),
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

#[derive(Debug)]
pub enum KdfSettings {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        salt: Vec<u8>,
        iterations: u64,
        memory: u64,
        parallelism: u32,
        version: argon2::Version,
    },
}

impl KdfSettings {
    pub fn seed_size(&self) -> u8 {
        match self {
            KdfSettings::Aes { .. } => 32,
            KdfSettings::Argon2 { .. } => 32,
        }
    }
    pub(crate) fn get_kdf(&self) -> Box<dyn kdf::Kdf> {
        match self {
            KdfSettings::Aes { seed, rounds } => Box::new(kdf::AesKdf {
                seed: seed.clone(),
                rounds: *rounds,
            }),
            KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            } => Box::new(kdf::Argon2Kdf {
                memory: *memory,
                salt: salt.clone(),
                iterations: *iterations,
                parallelism: *parallelism,
                version: *version,
            }),
        }
    }

    pub(crate) fn dump(&self) -> VariantDictionary {
        let mut data: HashMap<String, VariantDictionaryValue> = HashMap::new();

        match self {
            KdfSettings::Aes { seed, rounds } => {
                data.insert(
                    KDF_ID.to_string(),
                    VariantDictionaryValue::ByteArray(KDF_AES_KDBX4.to_vec()),
                );
                data.insert(
                    KDF_ROUNDS.to_string(),
                    VariantDictionaryValue::UInt64(rounds.clone()),
                );
                data.insert(
                    KDF_SEED.to_string(),
                    VariantDictionaryValue::ByteArray(seed.to_vec()),
                );
            }
            KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            } => {
                data.insert(
                    KDF_ID.to_string(),
                    VariantDictionaryValue::ByteArray(KDF_ARGON2.to_vec()),
                );
                data.insert(
                    KDF_MEMORY.to_string(),
                    VariantDictionaryValue::UInt64(memory.clone()),
                );
                data.insert(
                    KDF_SALT.to_string(),
                    VariantDictionaryValue::ByteArray(salt.to_vec()),
                );
                data.insert(
                    KDF_ITERATIONS.to_string(),
                    VariantDictionaryValue::UInt64(iterations.clone()),
                );
                data.insert(
                    KDF_PARALLELISM.to_string(),
                    VariantDictionaryValue::UInt32(parallelism.clone()),
                );
                match version {
                    argon2::Version::Version10 => {
                        data.insert(
                            KDF_VERSION.to_string(),
                            VariantDictionaryValue::UInt32(0x10),
                        );
                    }
                    argon2::Version::Version13 => {
                        data.insert(
                            KDF_VERSION.to_string(),
                            VariantDictionaryValue::UInt32(0x13),
                        );
                    }
                }
            }
        }
        VariantDictionary { data }
    }
}

const KDF_AES_KDBX3: [u8; 16] = hex!("c9d9f39a628a4460bf740d08c18a4fea");
const KDF_AES_KDBX4: [u8; 16] = hex!("7c02bb8279a74ac0927d114a00648238");
const KDF_ARGON2: [u8; 16] = hex!("ef636ddf8c29444b91f7a9a403e30a0c");

#[derive(Debug, Error)]
pub enum KdfSettingsError {
    #[error("Invalid KDF version: {}", version)]
    InvalidKDFVersion { version: u32 },

    #[error("Invalid KDF UUID: {:?}", uuid)]
    InvalidKDFUUID { uuid: Vec<u8> },

    #[error(transparent)]
    VariantDictionary(#[from] crate::variant_dictionary::VariantDictionaryError),
}

impl TryFrom<VariantDictionary> for KdfSettings {
    type Error = KdfSettingsError;

    fn try_from(vd: VariantDictionary) -> Result<KdfSettings, Self::Error> {
        let uuid: Vec<u8> = vd.get(KDF_ID)?;

        if uuid == KDF_ARGON2 {
            let memory: u64 = vd.get(KDF_MEMORY)?;
            let salt: Vec<u8> = vd.get(KDF_SALT)?;
            let iterations: u64 = vd.get(KDF_ITERATIONS)?;
            let parallelism: u32 = vd.get(KDF_PARALLELISM)?;
            let version: u32 = vd.get(KDF_VERSION)?;

            let version = match version {
                0x10 => argon2::Version::Version10,
                0x13 => argon2::Version::Version13,
                _ => return Err(KdfSettingsError::InvalidKDFVersion { version }),
            };

            Ok(KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            })
        } else if uuid == KDF_AES_KDBX4 || uuid == KDF_AES_KDBX3 {
            let rounds: u64 = vd.get(KDF_ROUNDS)?;
            let seed: Vec<u8> = vd.get(KDF_SEED)?;

            Ok(KdfSettings::Aes { rounds, seed })
        } else {
            Err(KdfSettingsError::InvalidKDFUUID { uuid })
        }
    }
}

#[derive(Debug)]
pub enum Compression {
    None,
    GZip,
}

#[derive(Debug, Error)]
pub enum CompressionError {
    #[error("Invalid compression suite: {}", cid)]
    InvalidCompressionSuite { cid: u32 },
}

impl Compression {
    pub(crate) fn get_compression(&self) -> Box<dyn compression::Decompress> {
        match self {
            Compression::None => Box::new(compression::NoCompression),
            Compression::GZip => Box::new(compression::GZipCompression),
        }
    }

    pub(crate) fn dump(&self) -> [u8; 4] {
        match self {
            Compression::None => [0, 0, 0, 0],
            Compression::GZip => [1, 0, 0, 0],
        }
    }
}

impl TryFrom<u32> for Compression {
    type Error = CompressionError;

    fn try_from(v: u32) -> Result<Compression, Self::Error> {
        match v {
            0 => Ok(Compression::None),
            1 => Ok(Compression::GZip),
            _ => Err(CompressionError::InvalidCompressionSuite { cid: v }.into()),
        }
    }
}
