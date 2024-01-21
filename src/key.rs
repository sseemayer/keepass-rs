use std::io::Read;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{crypt::calculate_sha256, error::DatabaseKeyError};

pub type KeyElement = Vec<u8>;
pub type KeyElements = Vec<KeyElement>;

fn parse_xml_keyfile(xml: &[u8]) -> Result<KeyElement, DatabaseKeyError> {
    let parser = EventReader::new(xml);

    let mut tag_stack = Vec::new();

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
                // Check if we are at KeyFile/Key/Data
                if tag_stack == ["KeyFile", "Key", "Data"] {
                    let key_base64 = s.as_bytes().to_vec();

                    // Check if the key is base64-encoded. If yes, return decoded bytes
                    return if let Ok(key) = base64_engine::STANDARD.decode(&key_base64) {
                        Ok(key)
                    } else {
                        Ok(key_base64)
                    };
                }
            }
            _ => {}
        }
    }

    Err(DatabaseKeyError::InvalidKeyFile)
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
    // YubikeyChallenge(String),
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
        }
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
        // FIXME This prevents using an empty password when using the password prompt.
        if self.password == Some("".to_string()) {
            self.password = None;
        }
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
