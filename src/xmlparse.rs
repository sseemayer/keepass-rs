extern crate crypto;
extern crate secstr;
extern crate quick_xml;

use crypto::symmetriccipher::Decryptor;

use rustc_serialize::base64::FromBase64;
use secstr::SecStr;

use self::quick_xml::{XmlReader, Event, AsStr};

use std::collections::HashMap;

use super::{Group, Entry, Value};

enum Node {
    Entry(Entry),
    Group(Group),
    KeyValue(String, Value),
}

pub fn parse_xml_block(xml: &[u8], decryptor: &mut Decryptor) -> Group {
    let parser = XmlReader::from_reader(xml).trim_text(true);

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
            Event::Start(ref e) => {

                let name = e.name();
                xml_stack.push(name.as_str().unwrap().to_owned());

                match name {
                    b"Group" => {
                        parsed_stack.push(Node::Group(Group {
                            name: "".into(),
                            child_groups: Vec::new(),
                            entries: Vec::new(),
                        }));
                    }
                    b"Entry" => {
                        parsed_stack.push(Node::Entry(Entry { fields: HashMap::new() }));
                    }
                    b"String" => {
                        parsed_stack.push(Node::KeyValue(String::new(),
                                                         Value::Unprotected(String::new())));
                    }
                    b"Value" => {

                        // Are we encountering a protected value?
                        if e.attributes()
                            .map(|a| a.unwrap())
                            .filter(|&(k, _)| k == b"Protected")
                                     .next()
                                     .map(|(_, v)| v.as_str().unwrap())
                                     .map_or(false, |v| {
                                         v.to_lowercase().parse::<bool>().unwrap_or(false)
                                     }) {

                            // Transform value to a Value::Protected
                            if let Some(&mut Node::KeyValue(_, ref mut ev)) =
                                   parsed_stack.last_mut() {
                                *ev = Value::Protected(SecStr::new(vec![]));
                            }
                        }

                    }
                    _ => {}
                }

            }

            Event::End(ref e) => {

                xml_stack.pop();

                if [b"Group" as &[u8], b"Entry", b"String"].contains(&e.name()) {

                    let finished_node = parsed_stack.pop().unwrap();
                    let mut parsed_stack_head = parsed_stack.last_mut();

                    match finished_node {
                        Node::KeyValue(k, v) => {
                            if let Some(&mut Node::Entry(Entry {ref mut fields})) =
                                   parsed_stack_head {
                                // A KeyValue was finished inside of an Entry -> add a field
                                fields.insert(k, v);
                            }
                        }

                        Node::Group(finished_group) => {
                            if let Some(&mut Node::Group(Group {ref mut child_groups, ..})) =
                                   parsed_stack_head {
                                // A Group was finished - add Group to parent Group's child groups
                                child_groups.push(finished_group);

                            } else if let None = parsed_stack_head {
                                // There is no more parent nodes left -> we are at the root
                                root_group = finished_group;
                            }
                        }

                        Node::Entry(finished_entry) => {
                            if let Some(&mut Node::Group(Group {ref mut entries, ..})) =
                                   parsed_stack_head {
                                // A Entry was finished - add Node to parent Group's entries
                                entries.push(finished_entry);
                            }
                        }
                    }

                }


            }

            Event::Text(e) => {

                // Got some character data that need to be matched to a Node on the parsed_stack.

                let c = e.into_string().unwrap();
                match (xml_stack.last().map(|s| &s[..]), parsed_stack.last_mut()) {
                    (Some("Name"),
                     Some(&mut Node::Group(Group {ref mut name, ..}))) => {
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
                                let buf = &c.from_base64().unwrap()[..];
                                let buf_decode = super::decrypt::decrypt(decryptor, buf).unwrap();
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
