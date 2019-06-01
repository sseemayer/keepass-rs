use super::result::{ErrorKind, Result};
use argon2;
use crypto::aes::{cbc_decryptor, ecb_encryptor, KeySize};
use crypto::blockmodes::{NoPadding, PkcsPadding};
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::salsa20::Salsa20;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::{Decryptor, SymmetricCipherError};

pub(crate) fn u8_32_from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

pub(crate) trait Cipher {
    fn new(&self, key: &[u8], iv: &[u8]) -> Box<Decryptor>;
}

pub(crate) struct AES256Cipher;

impl Cipher for AES256Cipher {
    fn new(&self, key: &[u8], iv: &[u8]) -> Box<Decryptor> {
        cbc_decryptor(KeySize::KeySize256, key, iv, PkcsPadding)
    }
}

pub(crate) struct Salsa20Cipher;

impl Cipher for Salsa20Cipher {
    fn new(&self, key: &[u8], iv: &[u8]) -> Box<Decryptor> {
        Box::new(Salsa20::new(key, iv))
    }
}

pub(crate) struct PlainCipher;

impl Cipher for PlainCipher {
    fn new(&self, _: &[u8], _: &[u8]) -> Box<Decryptor> {
        Box::new(NoOpDecryptor)
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

pub(crate) fn calculate_sha256(elements: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();

    for element in elements {
        digest.input(element);
    }

    let mut hash = [0u8; 32];
    digest.result(&mut hash);
    hash
}

pub(crate) fn decrypt(decryptor: &mut Decryptor, data: &[u8]) -> Result<Vec<u8>> {
    let mut final_result = Vec::new();
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0u8; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .cloned(),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub(crate) fn derive_composite_key(elements: &Vec<Vec<u8>>) -> [u8; 32] {
    let credentials_hashes: Vec<[u8; 32]> =
        elements.iter().map(|c| calculate_sha256(&[c])).collect();

    let mut digest = Sha256::new();
    for element in credentials_hashes {
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
    let mut key: [u8; 32] = composite_key.clone();

    for _ in 0..transform_rounds {
        let mut buffer = [0u8; 32];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        {
            let mut encryptor = ecb_encryptor(KeySize::KeySize256, transform_seed, NoPadding);
            let mut read_buffer = RefReadBuffer::new(&key);
            encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
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
    println!("Version of argon2 is {}", version);
    let version = match version {
        0x10 => argon2::Version::Version10,
        0x13 => argon2::Version::Version13,
        _ => return Err(ErrorKind::InvalidKdfParams.into()),
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

    Ok(u8_32_from_slice(&argon2::hash_raw(
        composite_key,
        salt,
        &config,
    )?))
}
