
use crypto::symmetriccipher::Decryptor;

use base64;
use secstr::SecStr;

use xml::reader::{EventReader, XmlEvent};
use xml::name::OwnedName;

use std::collections::HashMap;

use super::{Entry, Group, Value};


enum Node {
    Entry(Entry),
    Group(Group),
    KeyValue(String, Value),
}

pub fn parse_xml_block(xml: &[u8], decryptor: &mut Decryptor) -> Group {
    let parser = EventReader::new(xml);

    // Stack of parsed Node objects not yet associated with their parent
    let mut parsed_stack: Vec<Node> = vec![];

    // Stack of XML element names
    let mut xml_stack: Vec<String> = vec![];

    let mut root_group = Group {
        name: String::new(),
        child_groups: Vec::new(),
        entries: Vec::new(),
    };

    for e in parser {
        match e.unwrap() {
            XmlEvent::StartElement {
                name: OwnedName { ref local_name, .. },
                ref attributes,
                ..
            } => {
                xml_stack.push(local_name.clone());

                match &local_name[..] {
                    "Group" => {
                        parsed_stack.push(Node::Group(Group {
                            name: "".into(),
                            child_groups: Vec::new(),
                            entries: Vec::new(),
                        }));
                    }
                    "Entry" => {
                        parsed_stack.push(Node::Entry(Entry {
                            fields: HashMap::new(),
                        }));
                    }
                    "String" => {
                        parsed_stack.push(Node::KeyValue(
                            String::new(),
                            Value::Unprotected(String::new()),
                        ));
                    }
                    "Value" => {
                        // Are we encountering a protected value?
                        if attributes
                            .into_iter()
                            .filter(|oa| oa.name.local_name == "Protected")
                            .next()
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
                    _ => {}
                }
            }

            XmlEvent::EndElement {
                name: OwnedName { ref local_name, .. },
            } => {
                xml_stack.pop();

                if ["Group", "Entry", "String"].contains(&&local_name[..]) {
                    let finished_node = parsed_stack.pop().unwrap();
                    let parsed_stack_head = parsed_stack.last_mut();

                    match finished_node {
                        Node::KeyValue(k, v) => {
                            if let Some(&mut Node::Entry(Entry { ref mut fields })) =
                                parsed_stack_head
                            {
                                // A KeyValue was finished inside of an Entry -> add a field
                                fields.insert(k, v);
                            }
                        }

                        Node::Group(finished_group) => {
                            if let Some(
                                &mut Node::Group(Group {
                                    ref mut child_groups,
                                    ..
                                }),
                            ) = parsed_stack_head
                            {
                                // A Group was finished - add Group to parent Group's child groups
                                child_groups.push(finished_group);
                            } else if let None = parsed_stack_head {
                                // There is no more parent nodes left -> we are at the root
                                root_group = finished_group;
                            }
                        }

                        Node::Entry(finished_entry) => {
                            if let Some(
                                &mut Node::Group(Group {
                                    ref mut entries, ..
                                }),
                            ) = parsed_stack_head
                            {
                                // A Entry was finished - add Node to parent Group's entries
                                entries.push(finished_entry);
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
                    (Some("Key"), Some(&mut Node::KeyValue(ref mut k, _))) => {
                        // Got a "Key" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's key
                        *k = c;
                    }
                    (Some("Value"), Some(&mut Node::KeyValue(_, ref mut ev))) => {
                        // Got a "Value" element with a Node::KeyValue on the parsed_stack
                        // Update the KeyValue's value

                        match *ev {
                            Value::Unprotected(ref mut v) => {
                                *v = c;
                            }
                            Value::Protected(ref mut v) => {
                                // Use the decryptor to decrypt the protected
                                // and base64-encoded value
                                let buf = base64::decode(&c).unwrap();
                                let buf_decode = super::crypt::decrypt(decryptor, buf.as_ref()).unwrap();
                                let c_decode = String::from_utf8(buf_decode).unwrap();

                                *v = SecStr::from(c_decode);
                            }
                        }
                    }
                    _ => {}
                }
            }

            _ => {}
        }
    }

    root_group
}
