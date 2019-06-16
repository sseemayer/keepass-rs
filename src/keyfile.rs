use crypt;
use result::{Error, Result};
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};

fn parse_xml_keyfile(xml: &[u8]) -> Result<Vec<u8>> {
    let parser = EventReader::new(xml);

    let mut tag_stack = Vec::new();

    for ev in parser {
        match ev.map_err(|_e| Error::InvalidKeyFile)? {
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
                if tag_stack == &["KeyFile", "Key", "Data"] {
                    let key_base64 = s.as_bytes().to_vec();

                    // Check if the key is base64-encoded. If yes, return decoded bytes
                    return if let Ok(key) = ::base64::decode(&key_base64) {
                        Ok(key)
                    } else {
                        Ok(key_base64)
                    };
                }
            }
            _ => {}
        }
    }

    Err(Error::InvalidKeyFile.into())
}

pub fn parse(source: &mut std::io::Read) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    source.read_to_end(&mut buffer)?;

    // try to parse the buffer as XML, if successful, use that data instead of full file
    if let Ok(v) = parse_xml_keyfile(&buffer) {
        Ok(v)
    } else if buffer.len() == 32 {
        // legacy binary key format
        Ok(buffer.to_vec())
    } else {
        Ok(crypt::calculate_sha256(&[&buffer]).to_vec())
    }
}
