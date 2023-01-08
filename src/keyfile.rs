use crate::crypt::{calculate_sha256, CryptographyError};
use base64::{engine::general_purpose as base64_engine, Engine as _};
use thiserror::Error;
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};

#[derive(Debug, Error)]
pub enum KeyfileError {
    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Xml(#[from] xml::reader::Error),

    #[error("Could not obtain a key from the keyfile")]
    InvalidKeyFile,
}

fn parse_xml_keyfile(xml: &[u8]) -> Result<Vec<u8>, KeyfileError> {
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

    Err(KeyfileError::InvalidKeyFile)
}

pub fn parse(source: &mut dyn std::io::Read) -> Result<Vec<u8>, KeyfileError> {
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
