#[cfg(feature = "save_kdbx4")]
use cipher::BlockEncryptMut;
use cipher::{
    block_padding::{Pkcs7, UnpadError},
    generic_array::GenericArray,
    BlockDecryptMut, InvalidLength, KeyIvInit, StreamCipher,
};

pub(crate) trait Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError>;

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

pub(crate) struct AES256Cipher {
    #[cfg(feature = "save_kdbx4")]
    encryptor: cbc::Encryptor<aes::Aes256>,
    decryptor: cbc::Decryptor<aes::Aes256>,
}

impl AES256Cipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        Ok(AES256Cipher {
            #[cfg(feature = "save_kdbx4")]
            encryptor: cipher::KeyIvInit::new_from_slices(key, iv)?,
            decryptor: cipher::KeyIvInit::new_from_slices(key, iv)?,
        })
    }
}

impl Cipher for AES256Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.encryptor.clone().encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
        let mut out = vec![0; ciphertext.len()];

        let len = self
            .decryptor
            .clone()
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

pub(crate) struct TwofishCipher {
    #[cfg(feature = "save_kdbx4")]
    encryptor: cbc::Encryptor<twofish::Twofish>,
    decryptor: cbc::Decryptor<twofish::Twofish>,
}

impl TwofishCipher {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        Ok(TwofishCipher {
            #[cfg(feature = "save_kdbx4")]
            encryptor: KeyIvInit::new_from_slices(key, iv)?,
            decryptor: KeyIvInit::new_from_slices(key, iv)?,
        })
    }
}

impl Cipher for TwofishCipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.encryptor.clone().encrypt_padded_vec_mut::<Pkcs7>(plaintext)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
        let mut buf = ciphertext.to_vec();
        self.decryptor.clone().decrypt_padded_mut::<Pkcs7>(&mut buf)?;
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
    pub(crate) fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        let key = GenericArray::from_slice(key);
        let iv = GenericArray::from([0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]);

        Ok(Salsa20Cipher {
            cipher: KeyIvInit::new(key, &iv),
        })
    }
}

impl Cipher for Salsa20Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::from(plaintext);
        self.cipher.apply_keystream(&mut buffer);
        buffer
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
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
    pub(crate) fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        let iv = crate::crypt::calculate_sha512(&[key]);
        let key = GenericArray::from_slice(&iv[0..32]);
        let nonce = GenericArray::from_slice(&iv[32..44]);

        Ok(ChaCha20Cipher {
            cipher: chacha20::ChaCha20::new(key, nonce),
        })
    }

    /// Create as an outer cipher by separately-specified key and iv
    pub(crate) fn new_key_iv(key: &[u8], iv: &[u8]) -> Result<Self, InvalidLength> {
        Ok(ChaCha20Cipher {
            cipher: chacha20::ChaCha20::new_from_slices(key, iv)?,
        })
    }
}

impl Cipher for ChaCha20Cipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut buffer = Vec::from(plaintext);
        self.cipher.apply_keystream(&mut buffer);
        buffer
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
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
    pub(crate) fn new(_: &[u8]) -> Result<Self, InvalidLength> {
        Ok(PlainCipher)
    }
}
impl Cipher for PlainCipher {
    #[cfg(feature = "save_kdbx4")]
    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        Vec::from(plaintext)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
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
