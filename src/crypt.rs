use super::result::{CryptoError, DatabaseIntegrityError, Error, Result};
pub(crate) use aes::block_cipher_trait::generic_array::{
    typenum::{U32, U64},
    GenericArray,
};
use aes::Aes256;
use argon2;
use block_modes::{
    block_padding::{Pkcs7, ZeroPadding},
    BlockMode, Cbc, Ecb,
};
use crypto;
use crypto::buffer::{ReadBuffer, WriteBuffer};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub(crate) fn u8_32_from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

pub(crate) trait Cipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
pub(crate) struct AES256Cipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl AES256Cipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(AES256Cipher {
            key: Vec::from(key),
            iv: Vec::from(iv),
        })
    }
}

impl Cipher for AES256Cipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Cbc::new_var(&self.key, &self.iv)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        let mut buf = ciphertext.to_vec();
        cipher
            .decrypt(&mut buf)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        Ok(buf)
    }
}

pub(crate) struct Salsa20Cipher {
    cipher: crypto::salsa20::Salsa20,
}

impl Salsa20Cipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        let iv = &[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
        Ok(Salsa20Cipher {
            cipher: crypto::salsa20::Salsa20::new(key, iv),
        })
    }
}

fn decrypt_stream(
    decryptor: &mut crypto::symmetriccipher::Decryptor,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();

    let mut buf = [0u8; 4096];
    let mut reader = crypto::buffer::RefReadBuffer::new(data);
    let mut writer = crypto::buffer::RefWriteBuffer::new(&mut buf);

    loop {
        let res = {
            decryptor
                .decrypt(&mut reader, &mut writer, true)
                .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?
        };

        out.extend_from_slice(writer.take_read_buffer().take_remaining());

        if let crypto::buffer::BufferResult::BufferUnderflow = res {
            break;
        }
    }

    Ok(out)
}

impl Cipher for Salsa20Cipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_stream(&mut self.cipher, ciphertext)
    }
}

pub(crate) struct ChaCha20Cipher {
    cipher: crypto::chacha20::ChaCha20,
}

impl ChaCha20Cipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        let iv = calculate_sha512(&[key])?;
        Ok(ChaCha20Cipher {
            cipher: crypto::chacha20::ChaCha20::new(&iv[0..32], &iv[32..44]),
        })
    }
}

impl Cipher for ChaCha20Cipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_stream(&mut self.cipher, ciphertext)
    }
}

pub(crate) struct PlainCipher;
impl PlainCipher {
    pub(crate) fn new(_: &[u8]) -> Result<Self> {
        Ok(PlainCipher)
    }
}
impl Cipher for PlainCipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::from(ciphertext))
    }
}

pub(crate) fn calculate_hmac(elements: &[&[u8]], key: &[u8]) -> Result<GenericArray<u8, U32>> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_varkey(key)
        .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

    for element in elements {
        mac.input(element);
    }

    let result = mac.result();
    Ok(result.code())
}

pub(crate) fn calculate_sha256(elements: &[&[u8]]) -> Result<GenericArray<u8, U32>> {
    let mut digest = Sha256::new();

    for element in elements {
        digest.input(element);
    }

    Ok(digest.result())
}

pub(crate) fn calculate_sha512(elements: &[&[u8]]) -> Result<GenericArray<u8, U64>> {
    let mut digest = Sha512::new();

    for element in elements {
        digest.input(element);
    }

    Ok(digest.result())
}

type Aes256Ecb = Ecb<Aes256, ZeroPadding>;
pub(crate) fn transform_key_aes(
    transform_seed: &[u8],
    transform_rounds: u64,
    composite_key: &GenericArray<u8, U32>,
) -> Result<GenericArray<u8, U32>> {
    let mut key: Vec<u8> = Vec::from(composite_key.as_slice());

    // encrypt the key repeatedly
    for _ in 0..transform_rounds {
        let cipher = Aes256Ecb::new_var(transform_seed, Default::default())
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        let key_len = key.len();
        let new_key = cipher
            .encrypt(&mut key, key_len)
            .map(Vec::from)
            .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

        key = new_key;
    }

    calculate_sha256(&[&key])
}

pub(crate) fn transform_key_argon2(
    memory: u64,
    salt: &[u8],
    iterations: u64,
    parallelism: u32,
    version: u32,
    composite_key: &GenericArray<u8, U32>,
) -> Result<GenericArray<u8, U32>> {
    let version = match version {
        0x10 => argon2::Version::Version10,
        0x13 => argon2::Version::Version13,
        _ => return Err(DatabaseIntegrityError::InvalidKDFVersion { version: version }.into()),
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
        .map_err(|e| Error::from(DatabaseIntegrityError::from(CryptoError::from(e))))?;

    Ok(GenericArray::from_slice(&key).clone())
}
