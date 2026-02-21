use challenge_response::{
    config::{Config, Mode, Slot},
    ChallengeResponse,
};
use cipher::InvalidLength;
use hex::FromHexError;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key::KeyElement;

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
    pub(crate) fn perform_challenge(&self, challenge: &[u8]) -> Result<KeyElement, ChallengeResponseKeyError> {
        match self {
            ChallengeResponseKey::LocalChallenge(secret) => {
                let secret_bytes = hex::decode(secret)?;
                let response = crate::crypt::calculate_hmac_sha1(&[challenge], &secret_bytes)?.to_vec();
                Ok(response)
            }
            ChallengeResponseKey::YubikeyChallenge(yubikey, slot_number) => {
                let mut challenge_response_client = ChallengeResponse::new()?;
                let slot = Slot::from_str(slot_number)
                    .ok_or(ChallengeResponseKeyError::InvalidSlot(slot_number.to_string()))?;

                let device = challenge_response_client.find_device_from_serial(yubikey.serial_number)?;

                let mut config = Config::new_from(device);
                config = config.set_variable_size(true);
                config = config.set_mode(Mode::Sha1);
                config = config.set_slot(slot);

                let key_element = challenge_response_client
                    .challenge_response_hmac(challenge, config)?
                    .to_vec();

                Ok(key_element)
            }
        }
    }

    pub fn get_available_yubikeys() -> Result<Vec<Yubikey>, ChallengeResponseKeyError> {
        let mut challenge_response_client = ChallengeResponse::new()?;

        let devices = challenge_response_client
            .find_all_devices()?
            .into_iter()
            .filter_map(|device| {
                let serial_number = device.serial?;
                let name = device.name;

                Some(Yubikey { serial_number, name })
            })
            .collect();

        Ok(devices)
    }

    pub fn get_yubikey(serial_number: Option<u32>) -> Result<Yubikey, ChallengeResponseKeyError> {
        let devices = ChallengeResponseKey::get_available_yubikeys()?;
        if devices.is_empty() {
            return Err(ChallengeResponseKeyError::NoKeys);
        }

        if let Some(serial_number) = serial_number {
            let key = devices
                .iter()
                .find(|y| y.serial_number == serial_number)
                .ok_or(ChallengeResponseKeyError::KeyNotFound(serial_number))?;

            Ok(key.clone())
        } else {
            if devices.len() > 1 {
                return Err(ChallengeResponseKeyError::AmbiguousKeys);
            }
            Ok(devices[0].clone())
        }
    }
}

#[derive(Debug, Error)]
pub enum ChallengeResponseKeyError {
    #[error("No challenge-respone keys are connected to the system.")]
    NoKeys,

    #[error("Multiple challenge-response keys are connected to the system. Please provide a serial number.")]
    AmbiguousKeys,

    #[error("Challenge-response key with serial number {0} not found.")]
    KeyNotFound(u32),

    #[error("Invalid key slot: {0}")]
    InvalidSlot(String),

    #[error(transparent)]
    Api(#[from] challenge_response::error::ChallengeResponseError),

    #[error("Error decoding local challenge secret: {0}")]
    Hex(#[from] FromHexError),

    #[error("Local secret has invalid length")]
    InvalidLength(#[from] InvalidLength),

    #[error("Challenge-response authentication was not performed")]
    NotPerformed,
}
