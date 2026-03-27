use std::io::Read;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use quick_xml::{encoding::EncodingError, events::Event, reader::Reader};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypt::calculate_sha256;

pub type KeyElement = Vec<u8>;
pub type KeyElements = Vec<KeyElement>;

#[cfg(feature = "challenge_response")]
mod yubikey;

#[cfg(feature = "challenge_response")]
pub use yubikey::{ChallengeResponseKey, ChallengeResponseKeyError};

fn parse_xml_keyfile(xml: &[u8]) -> Result<KeyElement, ParseXmlKeyFileError> {
    let mut tag_stack = Vec::new();

    let mut key_version: Option<String> = None;
    let mut key_value: Option<String> = None;

    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,

            Event::Start(e) => {
                tag_stack.push(String::from_utf8_lossy(e.name().as_ref()).to_string());
            }

            Event::End(_) => {
                tag_stack.pop();
            }

            Event::Text(e) => {
                let s = e.decode()?.into_owned();

                if tag_stack == ["KeyFile", "Meta", "Version"] {
                    key_version = Some(s);
                    continue;
                }

                if tag_stack == ["KeyFile", "Key", "Data"] {
                    key_value = Some(s);
                    continue;
                }
            }

            _ => (),
        }
    }

    let key_value = key_value.ok_or(ParseXmlKeyFileError::EmptyKey)?;

    let key_bytes = key_value.as_bytes().to_vec();

    if key_version == Some("2.0".to_string()) {
        // TODO we should also validate the integrity of a v2 keyfile using the hash value

        let trimmed_key = key_value
            .trim()
            .replace(" ", "")
            .replace("\n", "")
            .replace("\t", "")
            .replace("\r", "");

        return if let Ok(key) = hex::decode(&trimmed_key) {
            Ok(key)
        } else {
            Ok(key_bytes)
        };
    }

    // Check if the key is base64-encoded. If yes, return decoded bytes
    if let Ok(key) = base64_engine::STANDARD.decode(&key_bytes) {
        Ok(key)
    } else {
        Ok(key_bytes)
    }
}

/// Errors that can occur when parsing an XML keyfile
#[derive(Debug, Error)]
pub enum ParseXmlKeyFileError {
    /// No key data element was found in the XML keyfile
    #[error("The XML keyfile is missing a key data element")]
    EmptyKey,

    /// A tag in the XML keyfile contains text that cannot be decoded as UTF-8
    #[error(transparent)]
    Encoding(#[from] EncodingError),

    /// An error occurred while reading the XML keyfile
    #[error(transparent)]
    Xml(#[from] quick_xml::Error),
}

fn parse_keyfile(buffer: &[u8]) -> Result<KeyElement, DatabaseKeyError> {
    // try to parse the buffer as XML, if successful, use that data instead of full file
    if let Ok(v) = parse_xml_keyfile(buffer) {
        Ok(v)
    } else if buffer.len() == 32 {
        // legacy binary key format
        Ok(buffer.to_vec())
    } else {
        Ok(calculate_sha256(&[buffer]).as_slice().to_vec())
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
    /// Modify the database key to include a password
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = Some(password.to_string());
        self
    }

    /// Modify the database key to include a password, which is read from a prompt
    #[cfg(feature = "utilities")]
    pub fn with_password_from_prompt(mut self, prompt_message: &str) -> Result<Self, std::io::Error> {
        self.password = Some(rpassword::prompt_password(prompt_message)?);
        Ok(self)
    }

    /// Modify the database key to include a challenge-response key, where the secret is read from
    /// a prompt
    #[cfg(all(feature = "challenge_response", feature = "utilities"))]
    pub fn with_hmac_sha1_secret_from_prompt(mut self, prompt_message: &str) -> Result<Self, std::io::Error> {
        self.challenge_response_key = Some(ChallengeResponseKey::LocalChallenge(rpassword::prompt_password(
            prompt_message,
        )?));
        Ok(self)
    }

    /// Modify the database key to include a keyfile
    ///
    /// The keyfile is only read as raw data but not parsed until the actual key elements are
    /// requested, so errors with keyfile parsing will only be raised at that point, not when
    /// calling this method.
    pub fn with_keyfile(mut self, keyfile: &mut dyn Read) -> Result<Self, std::io::Error> {
        let mut buf = Vec::new();
        keyfile.read_to_end(&mut buf)?;

        self.keyfile = Some(buf);

        Ok(self)
    }

    /// Modify the database key to include a challenge-response key
    #[cfg(feature = "challenge_response")]
    pub fn with_challenge_response_key(mut self, challenge_response_key: ChallengeResponseKey) -> Self {
        self.challenge_response_key = Some(challenge_response_key);
        self
    }

    /// Perform the challenge-response operation for the database key, if a challenge-response key
    /// is present.
    #[cfg(feature = "challenge_response")]
    pub fn perform_challenge(mut self, kdf_seed: &[u8]) -> Result<Self, DatabaseKeyError> {
        if let Some(challenge_response_key) = &self.challenge_response_key {
            let response = challenge_response_key.perform_challenge(kdf_seed)?;
            self.challenge_response_result = Some(response);
        }

        Ok(self)
    }

    /// Create a new, empty database key
    pub fn new() -> Self {
        Default::default()
    }

    pub(crate) fn get_key_elements(&self) -> Result<KeyElements, DatabaseKeyError> {
        let mut out = Vec::new();

        if let Some(p) = &self.password {
            out.push(calculate_sha256(&[p.as_bytes()]).to_vec());
        }

        if let Some(ref f) = self.keyfile {
            out.push(parse_keyfile(f)?);
        }

        if out.is_empty() {
            return Err(DatabaseKeyError::EmptyKey);
        }

        #[cfg(feature = "challenge_response")]
        if let Some(result) = &self.challenge_response_result {
            out.push(calculate_sha256(&[result]).as_slice().to_vec());
        } else if self.challenge_response_key.is_some() {
            return Err(DatabaseKeyError::ChallengeResponse(
                crate::key::yubikey::ChallengeResponseKeyError::NotPerformed,
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

/// Errors that can occur when working with database keys
#[derive(Debug, Error)]
pub enum DatabaseKeyError {
    /// The database key contains no components, i.e. no password, keyfile or challenge-response key
    #[error("The key contains no components")]
    EmptyKey,

    /// The database key is incorrect
    #[error("Incorrect key")]
    IncorrectKey,

    /// An I/O error occurred while reading the keyfile
    #[error("I/O error reading keyfile: {0}")]
    Io(#[from] std::io::Error),

    /// An error occurred while parsing the XML keyfile
    #[error("XML error reading keyfile: {0}")]
    Xml(#[from] quick_xml::Error),

    /// An error occurred while parsing the non-XML keyfile
    #[error("Invalid keyfile format")]
    InvalidKeyFile,

    /// An error occurred during challenge-response authentication
    #[cfg(feature = "challenge_response")]
    #[error("Challenge-response key error: {0}")]
    ChallengeResponse(#[from] crate::key::yubikey::ChallengeResponseKeyError),
}

#[cfg(test)]
mod key_tests {

    use super::{DatabaseKey, DatabaseKeyError};

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
