use aes::Aes256;
#[cfg(feature = "save_kdbx4")]
use cipher::BlockEncryptMut;
use cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut};
use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    Salsa20,
};

use crate::crypt::CryptographyError;

pub(crate) trait Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError>;

    #[cfg(feature = "save_kdbx4")]
    /// The number of bytes expected by the cipher as an initialization vector.
    fn iv_size() -> usize
    where
        Self: Sized;

    #[cfg(feature = "save_kdbx4")]
    /// The number of bytes expected by the cipher as a key.
    fn key_size() -> usize
    where
        Self: Sized;
}

#[cfg(feature = "save_kdbx4")]
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;
pub(crate) struct AES256Cipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl AES256Cipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(AES256Cipher {
            key: Vec::from(key),
            iv: Vec::from(iv),
        })
    }
}

impl Cipher for AES256Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = Aes256CbcEncryptor::new_from_slices(&self.key, &self.iv)?;

        let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        Ok(ciphertext)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut out = vec![0; ciphertext.len()];

        let cipher = Aes256CbcDecryptor::new_from_slices(&self.key[..], &self.iv[..])?;

        let len = cipher
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut out)?
            .len();

        out.truncate(len);

        Ok(out)
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        16
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

#[cfg(feature = "save_kdbx4")]
type TwofishCbcEncryptor = cbc::Encryptor<twofish::Twofish>;
type TwofishCbcDecryptor = cbc::Decryptor<twofish::Twofish>;
pub(crate) struct TwofishCipher {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl TwofishCipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(TwofishCipher {
            key: Vec::from(key),
            iv: Vec::from(iv),
        })
    }
}

impl Cipher for TwofishCipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = TwofishCbcEncryptor::new_from_slices(&self.key, &self.iv)?;

        let ciphertext = cipher.encrypt_padded_vec_mut::<twofish::cipher::block_padding::Pkcs7>(plaintext);

        Ok(ciphertext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = TwofishCbcDecryptor::new_from_slices(&self.key, &self.iv)?;

        let mut buf = ciphertext.to_vec();
        cipher.decrypt_padded_mut::<twofish::cipher::block_padding::Pkcs7>(&mut buf)?;
        Ok(buf)
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        16
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct Salsa20Cipher {
    cipher: salsa20::Salsa20,
}

impl Salsa20Cipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self, CryptographyError> {
        let key = GenericArray::from_slice(key);
        let iv = GenericArray::from([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);

        Ok(Salsa20Cipher {
            cipher: Salsa20::new(&key, &iv),
        })
    }
}

impl Cipher for Salsa20Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = Vec::from(plaintext);
        self.cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = Vec::from(ciphertext);
        self.cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        // or 16
        32
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct ChaCha20Cipher {
    cipher: chacha20::ChaCha20,
}

impl ChaCha20Cipher {
    /// Create as an inner cipher by splitting up a SHA512 hash
    pub(crate) fn new(key: &[u8]) -> Result<Self, CryptographyError> {
        let iv = crate::crypt::calculate_sha512(&[key])?;

        let key = GenericArray::from_slice(&iv[0..32]);
        let nonce = GenericArray::from_slice(&iv[32..44]);

        Ok(ChaCha20Cipher {
            cipher: chacha20::ChaCha20::new(&key, &nonce),
        })
    }

    /// Create as an outer cipher by separately-specified key and iv
    pub(crate) fn new_key_iv(key: &[u8], iv: &[u8]) -> Result<Self, CryptographyError> {
        Ok(ChaCha20Cipher {
            cipher: chacha20::ChaCha20::new_from_slices(&key, &iv)?,
        })
    }
}

impl Cipher for ChaCha20Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = Vec::from(plaintext);
        self.cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = Vec::from(ciphertext);
        self.cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        12
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        32
    }
}

pub(crate) struct PlainCipher;
impl PlainCipher {
    pub(crate) fn new(_: &[u8]) -> Result<Self, CryptographyError> {
        Ok(PlainCipher)
    }
}
impl Cipher for PlainCipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        Ok(Vec::from(plaintext))
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        Ok(Vec::from(ciphertext))
    }

    #[cfg(feature = "save_kdbx4")]
    fn iv_size() -> usize {
        1
    }

    #[cfg(feature = "save_kdbx4")]
    fn key_size() -> usize {
        1
    }
}
