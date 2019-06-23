use crate::result::{CryptoError, DatabaseIntegrityError, Error, Result};

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use crypto;
use crypto::buffer::{ReadBuffer, WriteBuffer};

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
        let iv = crate::crypt::calculate_sha512(&[key])?;
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
