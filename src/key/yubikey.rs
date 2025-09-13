use challenge_response::{
    config::{Config, Mode, Slot},
    error::ChallengeResponseError,
    ChallengeResponse,
};

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key::KeyElement;

pub fn parse_yubikey_slot(slot_number: &str) -> Result<Slot, ParseYubikeySlotError> {
    Slot::from_str(slot_number).ok_or_else(|| ParseYubikeySlotError(slot_number.to_string()))
}

#[derive(Error, Debug)]
#[error("Invalid slot number: '{0}'")]
pub struct ParseYubikeySlotError(pub String);

#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub enum ChallengeResponseKey {
    LocalChallenge(String),
    YubikeyChallenge(Yubikey, String),
}

#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Yubikey {
    pub serial_number: u32,
    pub name: Option<String>,
}

impl ChallengeResponseKey {
    pub fn perform_challenge(&self, challenge: &[u8]) -> Result<KeyElement, KeyChallengeError> {
        match self {
            ChallengeResponseKey::LocalChallenge(secret) => {
                let secret_bytes = hex::decode(secret)?;
                let response = crate::crypt::calculate_hmac_sha1(&[challenge], &secret_bytes)?.to_vec();
                Ok(response)
            }

            ChallengeResponseKey::YubikeyChallenge(yubikey, slot_number) => {
                let mut challenge_response_client =
                    ChallengeResponse::new().map_err(|e| KeyChallengeError::CannotListKeys(e))?;

                let slot = parse_yubikey_slot(slot_number)?;

                let yubikey_device = challenge_response_client
                    .find_device_from_serial(yubikey.serial_number)
                    .map_err(|e| KeyChallengeError::KeyNotFound {
                        inner_error: e,
                        serial_number: yubikey.serial_number,
                    })?;

                let mut config = Config::new_from(yubikey_device);
                config = config.set_variable_size(true);
                config = config.set_mode(Mode::Sha1);
                config = config.set_slot(slot);

                let hmac = challenge_response_client
                    .challenge_response_hmac(challenge, config)
                    .map_err(|e| KeyChallengeError::KeyChallenge(e))?;

                Ok(hmac.to_vec())
            }
        }
    }

    pub fn get_available_yubikeys() -> Result<Vec<Yubikey>, ChallengeResponseError> {
        let mut challenge_response_client = ChallengeResponse::new()?;
        let mut response: Vec<Yubikey> = vec![];

        let yubikeys = challenge_response_client.find_all_devices()?;
        for yubikey in yubikeys {
            let serial_number = match yubikey.serial {
                Some(n) => n,
                None => continue,
            };

            response.push(Yubikey {
                serial_number,
                name: yubikey.name,
            });
        }
        Ok(response)
    }

    pub fn get_yubikey(serial_number: Option<u32>) -> Result<Yubikey, GetKeyError> {
        let all_yubikeys =
            ChallengeResponseKey::get_available_yubikeys().map_err(|e| GetKeyError::CannotListKeys(e))?;

        if all_yubikeys.is_empty() {
            return Err(GetKeyError::NoKeys);
        }

        if let Some(n) = serial_number {
            all_yubikeys
                .into_iter()
                .find(|k| k.serial_number == n)
                .ok_or_else(|| GetKeyError::KeyNotFound { serial_number: n })
        } else if all_yubikeys.len() == 1 {
            Ok(all_yubikeys[0].clone())
        } else {
            Err(GetKeyError::AmbiguousKey)
        }
    }
}

#[derive(Error, Debug)]
pub enum KeyChallengeError {
    #[error("Invalid local challenge key secret")]
    InvalidLocalSecret(#[from] hex::FromHexError),

    #[error("Local challenge key secret is valid hex data, but incorrect length")]
    InvalidLocalSecretLength(#[from] cipher::InvalidLength),

    #[error("Cannot list challenge-response keys: {0}")]
    CannotListKeys(ChallengeResponseError),

    #[error(transparent)]
    KeySlot(#[from] ParseYubikeySlotError),

    #[error("Cannot find key with serial number {serial_number} - {inner_error}")]
    KeyNotFound {
        serial_number: u32,
        inner_error: ChallengeResponseError,
    },

    #[error("Cannot perform challenge: {0}")]
    KeyChallenge(ChallengeResponseError),
}

#[derive(Error, Debug)]
pub enum GetKeyError {
    #[error("Cannot list challenge-response keys: {0}")]
    CannotListKeys(ChallengeResponseError),

    #[error("No keys connected to the system")]
    NoKeys,

    #[error("Multiple keys are connected - need to provide a serial number")]
    AmbiguousKey,

    #[error("Cannot find key with serial number {serial_number}")]
    KeyNotFound { serial_number: u32 },
}
