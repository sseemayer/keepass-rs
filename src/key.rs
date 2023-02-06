use std::io::Read;

use crate::crypt::{calculate_sha256, CryptographyError};
use base64::{engine::general_purpose as base64_engine, Engine as _};
use thiserror::Error;
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};

/// Errors related to the database key
#[derive(Debug, Error)]
pub enum DatabaseKeyError {
    /// The key specified was incorrect, e.g. because of a wrong password
    #[error("Incorrect key")]
    IncorrectKey,

    /// An error occurred in an underlying cryptographic operation while computing the key
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    /// An I/O error occurred while loading the keyfile
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An XML error occurred while loading the keyfile
    #[error(transparent)]
    Xml(#[from] xml::reader::Error),

    /// The keyfile is invalid and did not contain a key
    #[error("Could not obtain a key from the keyfile")]
    InvalidKeyFile,
}

fn parse_xml_keyfile(xml: &[u8]) -> Result<Vec<u8>, DatabaseKeyError> {
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

fn parse_keyfile(source: &mut dyn std::io::Read) -> Result<Vec<u8>, DatabaseKeyError> {
    let mut buffer = Vec::new();
    source.read_to_end(&mut buffer)?;

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

/// A KeePass key, which might consist of a password and/or a keyfile
pub struct Key<'p, 'f> {
    pub password: Option<&'p str>,
    pub keyfile: Option<&'f mut dyn Read>,
}

impl<'p, 'f> Key<'p, 'f> {
    pub fn with_password(password: &'p str) -> Self {
        Self {
            password: Some(password),
            keyfile: None,
        }
    }

    pub fn with_keyfile(keyfile: &'f mut dyn Read) -> Self {
        Self {
            password: None,
            keyfile: Some(keyfile),
        }
    }

    pub fn with_password_and_keyfile(password: &'p str, keyfile: &'f mut dyn Read) -> Self {
        Self {
            password: Some(password),
            keyfile: Some(keyfile),
        }
    }

    pub(crate) fn get_key_elements(self) -> Result<Vec<Vec<u8>>, DatabaseKeyError> {
        let mut out = Vec::new();

        if let Some(p) = self.password {
            out.push(calculate_sha256(&[p.as_bytes()])?.to_vec());
        }

        if let Some(f) = self.keyfile {
            out.push(parse_keyfile(f)?);
        }

        if out.is_empty() {
            return Err(DatabaseKeyError::IncorrectKey);
        }

        Ok(out)
    }
}
