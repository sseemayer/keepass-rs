use std::io::Read;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "challenge_response")]
use challenge_response::{
    config::{Config, Mode, Slot},
    ChallengeResponse,
};

use crate::{crypt::calculate_sha256, error::DatabaseKeyError};

pub type KeyElement = Vec<u8>;
pub type KeyElements = Vec<KeyElement>;

#[cfg(feature = "challenge_response")]
fn parse_yubikey_slot(slot_number: &str) -> Result<Slot, DatabaseKeyError> {
    if let Some(slot) = Slot::from_str(slot_number) {
        return Ok(slot);
    }
    return Err(DatabaseKeyError::ChallengeResponseKeyError(
        "Invalid slot number".to_string(),
    ));
}

fn parse_xml_keyfile(xml: &[u8]) -> Result<KeyElement, DatabaseKeyError> {
    let parser = EventReader::new(xml);

    let mut tag_stack = Vec::new();

    let mut key_version: Option<String> = None;
    let mut key_value: Option<String> = None;

    for ev in parser {
        match ev? {
            XmlEvent::StartElement {
                name: OwnedName { ref local_name, .. },
                ..
            } => {
                tag_stack.push(local_name.clone());
            }
            XmlEvent::EndElement { .. } => {
                tag_stack.pop();
            }
            XmlEvent::Characters(s) => {
                if tag_stack == ["KeyFile", "Meta", "Version"] {
                    key_version = Some(s);
                    continue;
                }

                if tag_stack == ["KeyFile", "Key", "Data"] {
                    key_value = Some(s);
                    continue;
                }
            }
            _ => {}
        }
    }

    let key_value = match key_value {
        Some(k) => k,
        None => return Err(DatabaseKeyError::InvalidKeyFile),
    };
    let key_bytes = key_value.as_bytes().to_vec();

    if key_version == Some("2.0".to_string()) {
        // TODO we should also validate the integrity of a v2 keyfile using the hash value

        let trimmed_key = key_value
            .trim()
            .replace(" ", "")
            .replace("\n", "")
            .replace("\r", "");

        return if let Ok(key) = hex::decode(&trimmed_key) {
            Ok(key)
        } else {
            Ok(key_bytes)
        };
    }

    // Check if the key is base64-encoded. If yes, return decoded bytes
    return if let Ok(key) = base64_engine::STANDARD.decode(&key_bytes) {
        Ok(key)
    } else {
        Ok(key_bytes)
    };
}

fn parse_keyfile(buffer: &[u8]) -> Result<KeyElement, DatabaseKeyError> {
    // try to parse the buffer as XML, if successful, use that data instead of full file
    if let Ok(v) = parse_xml_keyfile(&buffer) {
        Ok(v)
    } else if buffer.len() == 32 {
        // legacy binary key format
        Ok(buffer.to_vec())
    } else {
        Ok(calculate_sha256(&[&buffer])?.as_slice().to_vec())
    }
}

#[cfg(feature = "challenge_response")]
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

#[cfg(feature = "challenge_response")]
impl ChallengeResponseKey {
    fn perform_challenge(self: &Self, challenge: &[u8]) -> Result<KeyElement, DatabaseKeyError> {
        match self {
            ChallengeResponseKey::LocalChallenge(secret) => {
                let secret_bytes = hex::decode(&secret).map_err(|e| {
                    return DatabaseKeyError::ChallengeResponseKeyError(e.to_string());
                })?;

                let response = crate::crypt::calculate_hmac_sha1(&[&challenge], &secret_bytes)?.to_vec();
                Ok(response)
            }
            ChallengeResponseKey::YubikeyChallenge(yubikey, slot_number) => {
                let mut challenge_response_client = ChallengeResponse::new().map_err(|e| {
                    DatabaseKeyError::ChallengeResponseKeyError(format!(
                        "Could not search for yubikey: {}",
                        e.to_string()
                    ))
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
                        e.to_string(),
                    ))),
                }
            }
        }
    }

    pub fn get_available_yubikeys() -> Result<Vec<Yubikey>, DatabaseKeyError> {
        let mut challenge_response_client = ChallengeResponse::new().map_err(|e| {
            DatabaseKeyError::ChallengeResponseKeyError(format!(
                "Could not search for yubikey: {}",
                e.to_string()
            ))
        })?;
        let mut response: Vec<Yubikey> = vec![];
        let yubikeys = match challenge_response_client.find_all_devices() {
            Ok(y) => y,
            Err(e) => {
                return Err(DatabaseKeyError::ChallengeResponseKeyError(format!(
                    "Could not search for yubikeys: {}",
                    e.to_string()
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
        return Ok(response);
    }

    pub fn get_yubikey(serial_number: Option<u32>) -> Result<Yubikey, DatabaseKeyError> {
        let all_yubikeys = ChallengeResponseKey::get_available_yubikeys()?;
        if all_yubikeys.len() == 0 {
            return Err(DatabaseKeyError::ChallengeResponseKeyError(format!(
                "No yubikey connected to the system",
            )));
        }

        let serial_number = match serial_number {
            Some(n) => n,
            None => {
                if all_yubikeys.len() != 1 {
                    return Err(DatabaseKeyError::ChallengeResponseKeyError(format!(
                        "Multiple yubikeys are connected to the system. Please provide a serial number.",
                    )));
                }
                return Ok(all_yubikeys[0].clone());
            }
        };

        for yubikey in all_yubikeys {
            if yubikey.serial_number == serial_number {
                return Ok(yubikey);
            }
        }
        return Err(DatabaseKeyError::ChallengeResponseKeyError(format!(
            "Could not find yubikey with serial number {}",
            serial_number
        )));
    }
}

/// A KeePass key, which might consist of a password and/or a keyfile
#[derive(Debug, Clone, Default, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct DatabaseKey {
    password: Option<String>,
    keyfile: Option<Vec<u8>>,
    #[cfg(feature = "challenge_response")]
    challenge_response_key: Option<ChallengeResponseKey>,
    #[cfg(feature = "challenge_response")]
    challenge_response_result: Option<KeyElement>,
}

impl DatabaseKey {
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    #[cfg(feature = "utilities")]
    pub fn with_password_from_prompt(mut self, prompt_message: &str) -> Result<Self, std::io::Error> {
        self.password = Some(rpassword::prompt_password(prompt_message)?);
        Ok(self)
    }

    #[cfg(all(feature = "challenge_response", feature = "utilities"))]
    pub fn with_hmac_sha1_secret_from_prompt(mut self, prompt_message: &str) -> Result<Self, std::io::Error> {
        self.challenge_response_key = Some(ChallengeResponseKey::LocalChallenge(rpassword::prompt_password(
            prompt_message,
        )?));
        Ok(self)
    }

    pub fn with_keyfile(mut self, keyfile: &mut dyn Read) -> Result<Self, std::io::Error> {
        let mut buf = Vec::new();
        keyfile.read_to_end(&mut buf)?;

        self.keyfile = Some(buf);

        Ok(self)
    }

    #[cfg(feature = "challenge_response")]
    pub fn with_challenge_response_key(mut self, challenge_response_key: ChallengeResponseKey) -> Self {
        self.challenge_response_key = Some(challenge_response_key);
        self
    }

    #[cfg(feature = "challenge_response")]
    pub fn perform_challenge(mut self, kdf_seed: &[u8]) -> Result<Self, DatabaseKeyError> {
        if let Some(challenge_response_key) = &self.challenge_response_key {
            let response = challenge_response_key.perform_challenge(kdf_seed)?;
            self.challenge_response_result = Some(response);
        }

        Ok(self)
    }

    pub fn new() -> Self {
        Default::default()
    }

    pub(crate) fn get_key_elements(&self) -> Result<KeyElements, DatabaseKeyError> {
        let mut out = Vec::new();

        if let Some(p) = &self.password {
            out.push(calculate_sha256(&[p.as_bytes()])?.to_vec());
        }

        if let Some(ref f) = self.keyfile {
            out.push(parse_keyfile(f)?);
        }

        if out.is_empty() {
            return Err(DatabaseKeyError::IncorrectKey);
        }

        #[cfg(feature = "challenge_response")]
        if let Some(result) = &self.challenge_response_result {
            out.push(calculate_sha256(&[result])?.as_slice().to_vec());
        } else if self.challenge_response_key.is_some() {
            return Err(DatabaseKeyError::ChallengeResponseKeyError(
                "Challenge-response was not performed".to_string(),
            ));
        }

        Ok(out)
    }

    /// Returns true if the database key is not associated with any key component.
    pub fn is_empty(&self) -> bool {
        if self.password.is_some() || self.keyfile.is_some() {
            return false;
        }
        #[cfg(feature = "challenge_response")]
        if self.challenge_response_key.is_some() {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod key_tests {

    use crate::error::DatabaseKeyError;

    use super::DatabaseKey;

    #[test]
    fn test_key() -> Result<(), DatabaseKeyError> {
        let ke = DatabaseKey::new().with_password("asdf").get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::new()
            .with_keyfile(&mut "bare-key-file".as_bytes())?
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::new()
            .with_keyfile(&mut "0123456789ABCDEF0123456789ABCDEF".as_bytes())?
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::new()
            .with_password("asdf")
            .with_keyfile(&mut "bare-key-file".as_bytes())?
            .get_key_elements()?;
        assert_eq!(ke.len(), 2);

        let ke = DatabaseKey::new()
            .with_keyfile(
                &mut "<KeyFile><Key><Data>0!23456789ABCDEF0123456789ABCDEF</Data></Key></KeyFile>".as_bytes(),
            )?
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::new()
            .with_keyfile(
                &mut "<KeyFile><Key><Data>NXyYiJMHg3ls+eBmjbAjWec9lcOToJiofbhNiFMTJMw=</Data></Key></KeyFile>"
                    .as_bytes(),
            )?
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let xml_keyfile_v2 = r###"
            <?xml version="1.0" encoding="utf-8"?>
            <KeyFile>
                <Meta>
                    <Version>2.0</Version>
                </Meta>
                <Key>
                    <Data Hash="A65F0C2D">
                        36057B1C 35037FD9 62257893 C0A22403
                        EE3F8FBB 504D9981 08B821CB 00D28F89
                    </Data>
                </Key>
            </KeyFile>
        "###;
        let ke = DatabaseKey::new()
            .with_keyfile(&mut xml_keyfile_v2.trim().as_bytes())?
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        // other XML files will just be hashed as a "bare" keyfile
        let ke = DatabaseKey::new()
            .with_keyfile(&mut "<Not><A><KeyFile></KeyFile></A></Not>".as_bytes())?
            .get_key_elements()?;

        assert_eq!(ke.len(), 1);

        assert!(DatabaseKey {
            password: None,
            keyfile: None,
            #[cfg(feature = "challenge_response")]
            challenge_response_key: None,
            #[cfg(feature = "challenge_response")]
            challenge_response_result: None,
        }
        .get_key_elements()
        .is_err());

        Ok(())
    }
}
