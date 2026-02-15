use challenge_response::{
    config::{Config, Mode, Slot},
    ChallengeResponse,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::DatabaseKeyError, key::KeyElement};

fn parse_yubikey_slot(slot_number: &str) -> Result<Slot, DatabaseKeyError> {
    if let Some(slot) = Slot::from_str(slot_number) {
        return Ok(slot);
    }
    Err(DatabaseKeyError::ChallengeResponseKeyError(
        "Invalid slot number".to_string(),
    ))
}

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
    pub(crate) fn perform_challenge(&self, challenge: &[u8]) -> Result<KeyElement, DatabaseKeyError> {
        match self {
            ChallengeResponseKey::LocalChallenge(secret) => {
                let secret_bytes = hex::decode(secret)
                    .map_err(|e| DatabaseKeyError::ChallengeResponseKeyError(e.to_string()))?;

                let response = crate::crypt::calculate_hmac_sha1(&[challenge], &secret_bytes)?.to_vec();
                Ok(response)
            }
            ChallengeResponseKey::YubikeyChallenge(yubikey, slot_number) => {
                let mut challenge_response_client = ChallengeResponse::new().map_err(|e| {
                    DatabaseKeyError::ChallengeResponseKeyError(format!("Could not search for yubikey: {}", e))
                })?;
                let slot = parse_yubikey_slot(slot_number)?;

                let yubikey_device =
                    match challenge_response_client.find_device_from_serial(yubikey.serial_number) {
                        Ok(d) => d,
                        Err(_e) => {
                            return Err(DatabaseKeyError::ChallengeResponseKeyError(
                                "Yubikey not found".to_string(),
                            ))
                        }
                    };

                let mut config = Config::new_from(yubikey_device);
                config = config.set_variable_size(true);
                config = config.set_mode(Mode::Sha1);
                config = config.set_slot(slot);

                match challenge_response_client.challenge_response_hmac(challenge, config) {
                    Ok(hmac_result) => Ok(hmac_result.to_vec()),
                    Err(e) => Err(DatabaseKeyError::ChallengeResponseKeyError(format!(
                        "Could not perform challenge response: {}",
                        e
                    ))),
                }
            }
        }
    }

    pub fn get_available_yubikeys() -> Result<Vec<Yubikey>, DatabaseKeyError> {
        let mut challenge_response_client = ChallengeResponse::new().map_err(|e| {
            DatabaseKeyError::ChallengeResponseKeyError(format!("Could not search for yubikey: {}", e))
        })?;
        let mut response: Vec<Yubikey> = vec![];
        let yubikeys = match challenge_response_client.find_all_devices() {
            Ok(y) => y,
            Err(e) => {
                return Err(DatabaseKeyError::ChallengeResponseKeyError(format!(
                    "Could not search for yubikeys: {}",
                    e
                )))
            }
        };
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

    pub fn get_yubikey(serial_number: Option<u32>) -> Result<Yubikey, DatabaseKeyError> {
        let all_yubikeys = ChallengeResponseKey::get_available_yubikeys()?;
        if all_yubikeys.is_empty() {
            return Err(DatabaseKeyError::ChallengeResponseKeyError(
                "No yubikey connected to the system".to_string(),
            ));
        }

        let serial_number = match serial_number {
            Some(n) => n,
            None => {
                if all_yubikeys.len() != 1 {
                    return Err(DatabaseKeyError::ChallengeResponseKeyError(
                        "Multiple yubikeys are connected to the system. Please provide a serial number."
                            .to_string(),
                    ));
                }
                return Ok(all_yubikeys[0].clone());
            }
        };

        for yubikey in all_yubikeys {
            if yubikey.serial_number == serial_number {
                return Ok(yubikey);
            }
        }
        Err(DatabaseKeyError::ChallengeResponseKeyError(format!(
            "Could not find yubikey with serial number {}",
            serial_number
        )))
    }
}
