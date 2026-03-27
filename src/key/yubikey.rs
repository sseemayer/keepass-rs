use challenge_response::{
    config::{Config, Mode, Slot},
    ChallengeResponse,
};
use cipher::InvalidLength;
use hex::FromHexError;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key::KeyElement;

/// Represents a challenge-response key, which can be either a local secret or a Yubikey device.
#[derive(Debug, Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub enum ChallengeResponseKey {
    /// A local challenge-response key represented by a hexadecimal string secret.
    LocalChallenge(String),

    /// A Yubikey challenge-response key, consisting of a Yubikey device and a slot number.
    YubikeyChallenge(Yubikey, String),
}

/// Represents a Yubikey device with its serial number and optional name.
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

    /// Retrieves a list of all available Yubikey devices connected to the system.
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

    /// Retrieves a specific Yubikey device based on the provided serial number.
    ///
    /// If `serial_number` is `None` and only one Yubikey device is connected, that device will be
    /// returned.
    ///
    /// If `serial_number` is `None` and multiple Yubikey devices are connected, an error will be
    /// returned indicating that the selection is ambiguous.
    ///
    /// If `serial_number` is provided but no matching device is found, an error will be returned
    /// indicating that the specified key was not found.
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

            #[allow(clippy::indexing_slicing)] // Safe because we check that the list is not empty above
            Ok(devices[0].clone())
        }
    }
}

/// Errors that can occur during challenge-response key operations.
#[derive(Debug, Error)]
pub enum ChallengeResponseKeyError {
    /// No challenge-response keys are connected to the system.
    #[error("No challenge-respone keys are connected to the system.")]
    NoKeys,

    /// Multiple challenge-response keys are connected to the system, but no serial number was
    /// provided to disambiguate them.
    #[error("Multiple challenge-response keys are connected to the system. Please provide a serial number.")]
    AmbiguousKeys,

    /// A challenge-response key with the specified serial number was not found among the connected
    /// devices.
    #[error("Challenge-response key with serial number {0} not found.")]
    KeyNotFound(u32),

    /// The specified key slot is invalid or not supported by the Yubikey device.
    #[error("Invalid key slot: {0}")]
    InvalidSlot(String),

    /// Errors originating from the underlying challenge-response library, such as device
    /// communication failures or configuration issues.
    #[error(transparent)]
    Api(#[from] challenge_response::error::ChallengeResponseError),

    /// Errors that occur during the decoding of the local challenge secret from hexadecimal
    /// format.
    #[error("Error decoding local challenge secret: {0}")]
    Hex(#[from] FromHexError),

    /// Errors that occur during the calculation of the HMAC-SHA1 response for a local challenge.
    #[error("Local secret has invalid length")]
    InvalidLength(#[from] InvalidLength),

    /// Errors that occur when a challenge-response operation is attempted but the authentication
    /// process was not performed, such as when a required Yubikey device is not present or
    /// accessible.
    #[error("Challenge-response authentication was not performed")]
    NotPerformed,
}
