use crypt::cipher::Cipher;
use result::{DatabaseIntegrityError, Error, Result};

use base64;
use secstr::SecStr;

use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};

use super::db::{AutoType, AutoTypeAssociation, Entry, Group, TimeKDBX, Value};

#[derive(Debug)]
enum Node {
    Entry(Entry),
    Group(Group),
    KeyValue(String, Value),
    AutoType(AutoType),
    AutoTypeAssociation(AutoTypeAssociation),
    ExpiryTime(String),
    Expires(bool),
    CustomData(bool, bool, bool), // Minimal implemmentation just to get KnownBad value
}

pub(crate) fn parse_xml_block(xml: &[u8], inner_cipher: &mut dyn Cipher) -> Result<Group> {
    let parser = EventReader::new(xml);

    // Stack of parsed Node objects not yet associated with their parent
    let mut parsed_stack: Vec<Node> = vec![];

    // Stack of XML element names
    let mut xml_stack: Vec<String> = vec![];

    let mut root_group: Group = Default::default();

    for e in parser {
        match e.unwrap() {
            XmlEvent::StartElement {
                name: OwnedName { ref local_name, .. },
                ref attributes,
                ..
            } => {
                xml_stack.push(local_name.clone());

                match &local_name[..] {
                    "Group" => parsed_stack.push(Node::Group(Default::default())),
                    "Entry" => parsed_stack.push(Node::Entry(Default::default())),
                    "String" => parsed_stack.push(Node::KeyValue(
                        String::new(),
                        Value::Unprotected(String::new()),
                    )),
                    "Value" => {
                        // Are we encountering a protected value?
                        if attributes
                            .iter()
                            .find(|oa| oa.name.local_name == "Protected")
                            .map(|oa| &oa.value)
                            .map_or(false, |v| v.to_lowercase().parse::<bool>().unwrap_or(false))
                        {
                            // Transform value to a Value::Protected
                            if let Some(&mut Node::KeyValue(_, ref mut ev)) =
                                parsed_stack.last_mut()
                            {
                                *ev = Value::Protected(SecStr::new(vec![]));
                            }
                        }
                    }
                    "AutoType" => parsed_stack.push(Node::AutoType(Default::default())),
                    "Association" => {
                        parsed_stack.push(Node::AutoTypeAssociation(Default::default()))
                    }
                    "ExpiryTime" => parsed_stack.push(Node::ExpiryTime(String::new())),
                    "Expires" => parsed_stack.push(Node::Expires(bool::default())),
                    "CustomData" => parsed_stack.push(Node::CustomData(false,false,false)),
                    _ => {}
                }
            }

            XmlEvent::EndElement {
                name: OwnedName { ref local_name, .. },
            } => {
                xml_stack.pop();

                if ["Group", "Entry", "String", "AutoType", "Association", "ExpiryTime", "Expires", "CustomData"]
                    .contains(&&local_name[..])
                {
                    let finished_node = parsed_stack.pop().unwrap();
                    let parsed_stack_head = parsed_stack.last_mut();

                    match finished_node {
                        Node::KeyValue(k, v) => {
                            if let Some(&mut Node::Entry(Entry { ref mut fields, .. })) =
                                parsed_stack_head
                            {
                                // A KeyValue was finished inside of an Entry -> add a field
                                fields.insert(k, v);
                            }
                        }

                        Node::Group(finished_group) => {
                            match parsed_stack_head {
                                Some(&mut Node::Group(Group {
                                    ref mut child_groups,
                                    ..
                                })) => {
                                    // A Group was finished - add Group to parent Group's child groups
                                    child_groups
                                        .insert(finished_group.name.clone(), finished_group);
                                }
                                None => {
                                    // There is no more parent nodes left -> we are at the root
                                    root_group = finished_group;
                                }
                                _ => {}
                            }
                        }

                        Node::Entry(finished_entry) => {
                            if let Some(&mut Node::Group(Group {
                                ref mut entries, ..
                            })) = parsed_stack_head
                            {
                                // A Entry was finished - add Node to parent Group's entries
                                entries.insert(
                                    finished_entry.get_title().unwrap().to_owned(),
                                    finished_entry,
                                );
                            }
                        }

                        Node::AutoType(at) => {
                            if let Some(&mut Node::Entry(Entry {
                                ref mut autotype, ..
                            })) = parsed_stack_head
                            {
                                autotype.replace(at);
                            }
                        }

                        Node::AutoTypeAssociation(ata) => {
                            if let Some(&mut Node::AutoType(AutoType {
                                ref mut associations,
                                ..
                            })) = parsed_stack_head
                            {
                                associations.push(ata);
                            }
                        }

                        Node::ExpiryTime(et) => {
                            // Check if the key is base64-encoded. If not, assume Iso8601 String
                            let t = match ::base64::decode(&et.as_bytes().to_vec()) {
                                Ok(b64) => TimeKDBX::Base64(b64) ,
                                _  => TimeKDBX::Iso8601(et)
                            } ;
                            // ToDo:  Can this be colapsed to eliminate the else if?
                            if let Some(&mut Node::Entry(Entry { ref mut expiration, .. })) =
                                parsed_stack_head
                            {
                                expiration.time = t ;
                            } else if let Some(&mut Node::Group(Group { ref mut expiration, .. })) =
                                parsed_stack_head
                            {
                                expiration.time = t ;
                            }
                        }

                        Node::Expires(es) => {
                            if let Some(&mut Node::Entry(Entry { ref mut expiration, .. })) =
                                parsed_stack_head
                            {
                                expiration.enabled = es ;
                            } else if let Some(&mut Node::Group(Group { ref mut expiration, .. })) =
                                parsed_stack_head
                            {
                                expiration.enabled = es ;
                            }
                        }

                         Node::CustomData(_, cd, _) => { // Minimal implemmentation just to get KnownBad value
                            if let Some(&mut Node::Entry(Entry { ref mut db_report_exclude, .. })) =
                                parsed_stack_head
                            {
                                *db_report_exclude = cd ;
                            }
                        }
                    }
                }
            }

            XmlEvent::Characters(c) => {
                // Got some character data that need to be matched to a Node on the parsed_stack.

                match (xml_stack.last().map(|s| &s[..]), parsed_stack.last_mut()) {
                    (Some("Name"), Some(&mut Node::Group(Group { ref mut name, .. }))) => {
                        // Got a "Name" element with a Node::Group on the parsed_stack
                        // Update the Group's name
                        *name = c;
                    }
                    (Some("ExpiryTime"), Some(&mut Node::ExpiryTime(ref mut et))) => {
                        *et = c ;
                    }
                    (Some("Expires"), Some(&mut Node::Expires(ref mut es))) => {
                        *es = c == "True";
                    }
                    (Some("Key"), Some(&mut Node::KeyValue(ref mut k, _))) => {
                        // Got a "Key" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's key
                        *k = c;
                    }
                    (Some("Value"), Some(&mut Node::KeyValue(_, ref mut ev))) => {
                        // Got a "Value" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's value

                        match *ev {
                            Value::Bytes(_) => {} // not possible
                            Value::Unprotected(ref mut v) => {
                                *v = c;
                            }
                            Value::Protected(ref mut v) => {
                                // Use the decryptor to decrypt the protected
                                // and base64-encoded value
                                //
                                let buf = base64::decode(&c)
                                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

                                let buf_decode = inner_cipher.decrypt(&buf)?;

                                let c_decode = std::str::from_utf8(&buf_decode)
                                    .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?;

                                *v = SecStr::from(c_decode);
                            }
                        }
                    }
                    (Some("Enabled"), Some(&mut Node::AutoType(ref mut at))) => {
                        at.enabled = c.parse().unwrap_or(false);
                    }
                    (Some("DefaultSequence"), Some(&mut Node::AutoType(ref mut at))) => {
                        at.sequence = Some(c.to_owned());
                    }
                    (Some("Window"), Some(&mut Node::AutoTypeAssociation(ref mut ata))) => {
                        ata.window = Some(c.to_owned());
                    }
                    (
                        Some("KeystrokeSequence"),
                        Some(&mut Node::AutoTypeAssociation(ref mut ata)),
                    ) => {
                        ata.sequence = Some(c.to_owned());
                    }
                    // Minimal parsing for CustomData just to get KnownBad value
                    (Some("Key"), Some(&mut Node::CustomData(ref mut k, _, _))) => {
                        *k = c == "KnownBad" ; // Have we found a KnownBad Item/Key?
                    }
                    (Some("Value"), Some(&mut Node::CustomData(ref k, ref mut v, ref mut done))) => {
                        if *k && !*done {// Are we in the KnownBad Item/Key and looking for its value?
                            *v = c == "true" ;
                            *done = false ; // Stop looking for KnownBad value
                        }
                    } // End:  Minimal parsing for CustomData just to get KnownBad value
                    _ => {}
                }
            }

            _ => {}
        }
    }

    Ok(root_group)
}
