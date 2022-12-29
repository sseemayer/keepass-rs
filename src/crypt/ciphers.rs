use aes::Aes256;
use cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut};
use salsa20::{
    cipher::{KeyIvInit, StreamCipher},
    Salsa20,
};

use crate::crypt::CryptographyError;

pub(crate) trait Cipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError>;
}

type Aes256Cbc = cbc::Decryptor<Aes256>;
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
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut out = vec![0; ciphertext.len()];

        let cipher = Aes256Cbc::new_from_slices(&self.key[..], &self.iv[..])?;

        let len = cipher
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut out)?
            .len();

        out.truncate(len);

        Ok(out)
    }
}

type TwofishCbc = cbc::Decryptor<twofish::Twofish>;
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
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let cipher = TwofishCbc::new_from_slices(&self.key, &self.iv)?;

        let mut buf = ciphertext.to_vec();
        cipher.decrypt_padded_mut::<twofish::cipher::block_padding::Pkcs7>(&mut buf)?;

        Ok(buf)
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
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = Vec::from(ciphertext);
        self.cipher.apply_keystream(&mut buffer);
        Ok(buffer)
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
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let mut buffer = Vec::from(ciphertext);
        self.cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }
}

pub(crate) struct PlainCipher;
impl PlainCipher {
    pub(crate) fn new(_: &[u8]) -> Result<Self, CryptographyError> {
        Ok(PlainCipher)
    }
}
impl Cipher for PlainCipher {
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        Ok(Vec::from(ciphertext))
    }
}
