use super::result::{CryptoError, DatabaseIntegrityError, Error, Result};
pub(crate) use aes::block_cipher_trait::generic_array::{
    typenum::{U32, U64},
    GenericArray,
};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub(crate) mod cipher;
pub(crate) mod kdf;

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
