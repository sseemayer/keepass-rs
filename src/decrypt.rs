use crypto::aes::{cbc_decryptor, ecb_encryptor, KeySize};
use crypto::blockmodes::{NoPadding, PkcsPadding};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::salsa20::Salsa20;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::{Decryptor, SymmetricCipherError};

pub trait Cipher {
    fn new(&self, key: &[u8], iv: &[u8]) -> Box<Decryptor>;
}

pub struct AES256Cipher;

impl Cipher for AES256Cipher {
    fn new(&self, key: &[u8], iv: &[u8]) -> Box<Decryptor> {
        cbc_decryptor(KeySize::KeySize256, key, iv, PkcsPadding)
    }
}

pub struct Salsa20Cipher;

impl Cipher for Salsa20Cipher {
    fn new(&self, key: &[u8], iv: &[u8]) -> Box<Decryptor> {
        Box::new(Salsa20::new(key, iv))
    }
}

pub struct PlainCipher;

impl Cipher for PlainCipher {
    fn new(&self, _: &[u8], _: &[u8]) -> Box<Decryptor> {
        Box::new(NoOpDecryptor)
    }
}

struct NoOpDecryptor;

impl Decryptor for NoOpDecryptor {
    fn decrypt(&mut self,
               input: &mut RefReadBuffer,
               output: &mut RefWriteBuffer,
               _: bool)
               -> Result<BufferResult, SymmetricCipherError> {
        input.push_to(output);
        Ok(BufferResult::BufferUnderflow)
    }
}

pub fn calculate_sha256(elements: &[&[u8]]) -> [u8; 32] {

    let mut digest = Sha256::new();

    for element in elements {
        digest.input(element);
    }

    let mut hash = [0u8; 32];
    digest.result(&mut hash);
    hash
}

pub fn decrypt(decryptor: &mut Decryptor, data: &[u8]) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut final_result = Vec::new();
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0u8; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().cloned());

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

pub fn derive_composite_key(elements: &[&[u8]]) -> [u8; 32] {
    let credentials_hash = calculate_sha256(elements);
    calculate_sha256(&[&credentials_hash])
}

pub fn derive_transformed_key(transform_seed: &[u8],
                              transform_rounds: u64,
                              composite_key: [u8; 32])
                              -> Result<[u8; 32], SymmetricCipherError> {

    let mut key: [u8; 32] = composite_key.clone();

    for _ in 0..transform_rounds {

        let mut buffer = [0u8; 32];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        {
            let mut encryptor = ecb_encryptor(KeySize::KeySize256, transform_seed, NoPadding);
            let mut read_buffer = RefReadBuffer::new(&key);
            try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        }

        for (&x, k) in write_buffer.take_read_buffer().take_remaining().iter().zip(key.iter_mut()) {
            *k = x;
        }

    }

    Ok(calculate_sha256(&[&key]))
}
