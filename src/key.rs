use std::io::Read;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};

use crate::{crypt::calculate_sha256, error::DatabaseKeyError};

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

fn parse_keyfile(buffer: &[u8]) -> Result<Vec<u8>, DatabaseKeyError> {
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
#[derive(Debug, Clone, Default)]
pub struct DatabaseKey {
    pub password: Option<String>,
    pub keyfile: Option<Vec<u8>>,
}

impl DatabaseKey {
    pub fn with_password(password: &str) -> Self {
        Self::new(Some(password), None)
    }

    pub fn with_keyfile(keyfile: &mut dyn Read) -> Self {
        Self::new(None, Some(keyfile))
    }

    pub fn with_password_and_keyfile(password: &str, keyfile: &mut dyn Read) -> Self {
        Self::new(Some(password), Some(keyfile))
    }

    pub fn new(password: Option<&str>, mut keyfile: Option<&mut dyn Read>) -> Self {
        let password = password.map(|p| p.to_string());

        let keyfile = keyfile.as_mut().and_then(|kf| {
            let mut buffer = Vec::new();
            kf.read_to_end(&mut buffer).ok().map(|_| buffer)
        });

        Self { password, keyfile }
    }

    pub(crate) fn get_key_elements(self) -> Result<Vec<Vec<u8>>, DatabaseKeyError> {
        let mut out = Vec::new();

        if let Some(p) = self.password {
            out.push(calculate_sha256(&[p.as_bytes()])?.to_vec());
        }

        if let Some(ref f) = self.keyfile {
            out.push(parse_keyfile(f)?);
        }

        if out.is_empty() {
            return Err(DatabaseKeyError::IncorrectKey);
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
        let ke = DatabaseKey::with_password("asdf").get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::with_keyfile(&mut "bare-key-file".as_bytes()).get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::with_keyfile(&mut "0123456789ABCDEF0123456789ABCDEF".as_bytes())
            .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::with_password_and_keyfile("asdf", &mut "bare-key-file".as_bytes())
            .get_key_elements()?;
        assert_eq!(ke.len(), 2);

        let ke = DatabaseKey::with_keyfile(
            &mut "<KeyFile><Key><Data>0!23456789ABCDEF0123456789ABCDEF</Data></Key></KeyFile>"
                .as_bytes(),
        )
        .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        let ke = DatabaseKey::with_keyfile(
            &mut "<KeyFile><Key><Data>NXyYiJMHg3ls+eBmjbAjWec9lcOToJiofbhNiFMTJMw=</Data></Key></KeyFile>".as_bytes(),
        )
        .get_key_elements()?;
        assert_eq!(ke.len(), 1);

        // other XML files will just be hashed as a "bare" keyfile
        let ke = DatabaseKey::with_keyfile(&mut "<Not><A><KeyFile></KeyFile></A></Not>".as_bytes())
            .get_key_elements()?;

        assert_eq!(ke.len(), 1);

        assert!(DatabaseKey {
            password: None,
            keyfile: None
        }
        .get_key_elements()
        .is_err());

        Ok(())
    }
}
