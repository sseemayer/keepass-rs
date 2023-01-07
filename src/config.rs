use hex_literal::hex;
use std::convert::TryFrom;
use thiserror::Error;

use crate::{
    crypt::{ciphers, kdf, CryptographyError},
    decompress,
    variant_dictionary::VariantDictionary,
};

const _CIPHERSUITE_AES128: [u8; 16] = hex!("61ab05a1946441c38d743a563df8dd35");
const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
const CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
const CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

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
}

impl TryFrom<u32> for InnerCipherSuite {
    type Error = InnerCipherSuiteError;

    fn try_from(v: u32) -> Result<InnerCipherSuite, Self::Error> {
        match v {
            0 => Ok(InnerCipherSuite::Plain),
            2 => Ok(InnerCipherSuite::Salsa20),
            3 => Ok(InnerCipherSuite::ChaCha20),
            _ => Err(InnerCipherSuiteError::InvalidInnerCipherID { cid: v }.into()),
        }
    }
}

#[derive(Debug)]
pub enum KdfSettings {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        memory: u64,
        salt: Vec<u8>,
        iterations: u64,
        parallelism: u32,
        version: argon2::Version,
    },
}

impl KdfSettings {
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
        let uuid: Vec<u8> = vd.get("$UUID")?;

        if uuid == KDF_ARGON2 {
            let memory: u64 = vd.get("M")?;
            let salt: Vec<u8> = vd.get("S")?;
            let iterations: u64 = vd.get("I")?;
            let parallelism: u32 = vd.get("P")?;
            let version: u32 = vd.get("V")?;

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
            let rounds: u64 = vd.get("R")?;
            let seed: Vec<u8> = vd.get("S")?;

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
    pub(crate) fn get_compression(&self) -> Box<dyn decompress::Decompress> {
        match self {
            Compression::None => Box::new(decompress::NoCompression),
            Compression::GZip => Box::new(decompress::GZipCompression),
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
