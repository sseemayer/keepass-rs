use super::result::{DatabaseIntegrityError, Error, Result};
use argon2;
use crypto::aes::{cbc_decryptor, ecb_encryptor, KeySize};
use crypto::blockmodes::{NoPadding, PkcsPadding};
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::chacha20::ChaCha20;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::salsa20::Salsa20;
use crypto::sha2::{Sha256, Sha512};
use crypto::symmetriccipher::{Decryptor, SymmetricCipherError};
use hex_literal::hex;
use std::convert::Into;
use std::convert::TryFrom;

const _CIPHERSUITE_AES128: [u8; 16] = hex!("61ab05a1946441c38d743a563df8dd35");
const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
const _CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
const _CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

#[derive(Debug)]
pub enum OuterCipherSuite {
    AES256,
}

impl OuterCipherSuite {
    pub(crate) fn get_decryptor(&self, key: &[u8], iv: &[u8]) -> Box<Decryptor> {
        match self {
            OuterCipherSuite::AES256 => cbc_decryptor(KeySize::KeySize256, key, iv, PkcsPadding),
        }
    }
}

impl TryFrom<&[u8]> for OuterCipherSuite {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<OuterCipherSuite> {
        if v == CIPHERSUITE_AES256 {
            Ok(OuterCipherSuite::AES256)
        } else {
            Err(DatabaseIntegrityError::InvalidOuterCipherID { cid: v.to_vec() }.into())
        }
    }
}

pub(crate) fn u8_32_from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

#[derive(Debug)]
pub enum InnerCipherSuite {
    Plain,
    Salsa20,
    ChaCha20,
}

impl InnerCipherSuite {
    pub(crate) fn get_decryptor(&self, key: &[u8]) -> Box<Decryptor> {
        match self {
            InnerCipherSuite::Plain => Box::new(NoOpDecryptor),
            InnerCipherSuite::Salsa20 => {
                let iv = &[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
                Box::new(Salsa20::new(key, iv))
            }
            InnerCipherSuite::ChaCha20 => {
                let iv = calculate_sha512(&[key]);
                Box::new(ChaCha20::new(&iv[0..32], &iv[32..44]))
            }
        }
    }
}

impl TryFrom<u32> for InnerCipherSuite {
    type Error = Error;

    fn try_from(v: u32) -> Result<InnerCipherSuite> {
        match v {
            0 => Ok(InnerCipherSuite::Plain),
            2 => Ok(InnerCipherSuite::Salsa20),
            3 => Ok(InnerCipherSuite::ChaCha20),
            _ => Err(DatabaseIntegrityError::InvalidInnerCipherID { cid: v }.into()),
        }
    }
}

pub(crate) struct NoOpDecryptor;

impl Decryptor for NoOpDecryptor {
    fn decrypt(
        &mut self,
        input: &mut RefReadBuffer,
        output: &mut RefWriteBuffer,
        _: bool,
    ) -> ::std::result::Result<BufferResult, SymmetricCipherError> {
        input.push_to(output);
        Ok(BufferResult::BufferUnderflow)
    }
}

pub(crate) fn calculate_hmac(elements: &[&[u8]], key: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::new(Sha256::new(), key);
    for element in elements {
        mac.input(element);
    }

    let mut hash = [0u8; 32];
    mac.raw_result(&mut hash);

    hash
}

pub(crate) fn calculate_sha256(elements: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();

    for element in elements {
        digest.input(element);
    }

    let mut hash = [0u8; 32];
    digest.result(&mut hash);
    hash
}

pub(crate) fn calculate_sha512(elements: &[&[u8]]) -> [u8; 64] {
    let mut digest = Sha512::new();

    for element in elements {
        digest.input(element);
    }

    let mut hash = [0u8; 64];
    digest.result(&mut hash);
    hash
}

pub(crate) fn decrypt(decryptor: &mut Decryptor, data: &[u8]) -> Result<Vec<u8>> {
    let mut final_result = Vec::new();
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0u8; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result: Result<BufferResult> = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .map_err(|e| DatabaseIntegrityError::from(e).into());

        if let Err(e) = result {
            return Err(e);
        }

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .cloned(),
        );

        match result {
            Ok(BufferResult::BufferUnderflow) => break,
            Ok(BufferResult::BufferOverflow) => {}
            Err(e) => return Err(e),
        }
    }

    Ok(final_result)
}

pub(crate) fn derive_composite_key(elements: &[Vec<u8>]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for element in elements {
        digest.input(&element);
    }

    let mut hash = [0u8; 32];
    digest.result(&mut hash);
    hash
}

pub(crate) fn transform_key_aes(
    transform_seed: &[u8],
    transform_rounds: u64,
    composite_key: [u8; 32],
) -> Result<[u8; 32]> {
    let mut key: [u8; 32] = composite_key;

    for _ in 0..transform_rounds {
        let mut buffer = [0u8; 32];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        {
            let mut encryptor = ecb_encryptor(KeySize::KeySize256, transform_seed, NoPadding);
            let mut read_buffer = RefReadBuffer::new(&key);
            encryptor
                .encrypt(&mut read_buffer, &mut write_buffer, true)
                .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;
        }

        for (&x, k) in write_buffer
            .take_read_buffer()
            .take_remaining()
            .iter()
            .zip(key.iter_mut())
        {
            *k = x;
        }
    }

    Ok(calculate_sha256(&[&key]))
}

pub(crate) fn transform_key_argon2(
    memory: u64,
    salt: &[u8],
    iterations: u64,
    parallelism: u32,
    version: u32,
    composite_key: &[u8],
) -> Result<[u8; 32]> {
    let version = match version {
        0x10 => argon2::Version::Version10,
        0x13 => argon2::Version::Version13,
        _ => return Err(DatabaseIntegrityError::InvalidKDFVersion { version }.into()),
    };

    let config = argon2::Config {
        ad: &[],
        hash_length: 32,
        lanes: parallelism,
        mem_cost: (memory / 1024) as u32,
        secret: &[],
        thread_mode: argon2::ThreadMode::default(),
        time_cost: iterations as u32,
        variant: argon2::Variant::Argon2d,
        version,
    };

    let key = argon2::hash_raw(composite_key, salt, &config)
        .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

    Ok(u8_32_from_slice(&key))
}
