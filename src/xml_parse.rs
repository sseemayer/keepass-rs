use crate::crypt::{ciphers::Cipher, CryptographyError};

use base64::{engine::general_purpose as base64_engine, Engine as _};
use secstr::SecStr;
use thiserror::Error;
use xml::name::OwnedName;
use xml::reader::{EventReader, XmlEvent};
use xml::writer::{EmitterConfig, EventWriter, XmlEvent as WriterEvent};

use super::db::{AutoType, AutoTypeAssociation, Database, Entry, Group, Meta, Value};

#[derive(Debug)]
enum Node {
    Entry(Entry),
    Group(Group),
    KeyValue(String, Value),
    AutoType(AutoType),
    AutoTypeAssociation(AutoTypeAssociation),
    ExpiryTime(String),
    Expires(bool),
    Tags(String),
    Meta(Meta),
    UUID(String),
    RecycleBinUUID(String),
}

/// In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00.
/// This function returns the epoch baseline used by KDBX for date serialization.
fn get_epoch_baseline() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap()
}

fn parse_xml_timestamp(t: &str) -> Result<chrono::NaiveDateTime, XmlParseError> {
    match chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%SZ") {
        // Prior to KDBX4 file format, timestamps were stored as ISO 8601 strings
        Ok(ndt) => Ok(ndt),
        // If we don't have a valid ISO 8601 string, assume we have found a Base64 encoded int.
        _ => {
            let v = base64_engine::STANDARD.decode(t)?;

            // Cast the decoded base64 Vec into the array expected by i64::from_le_bytes
            let mut a: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
            a.copy_from_slice(&v[0..8]);
            let ndt = get_epoch_baseline() + chrono::Duration::seconds(i64::from_le_bytes(a));
            Ok(ndt)
        }
    }
}

#[derive(Debug, Error)]
pub enum XmlParseError {
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    TimestampFormat(#[from] chrono::ParseError),

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),
}

fn dump_xml_timestamp(timestamp: &chrono::NaiveDateTime) -> String {
    let timestamp = timestamp.timestamp() - get_epoch_baseline().timestamp();
    let timestamp_bytes = i64::to_le_bytes(timestamp);
    base64_engine::STANDARD.encode(timestamp_bytes)
}

pub(crate) fn dump_database(
    db: &Database,
    inner_cipher: &mut dyn Cipher,
) -> std::result::Result<Vec<u8>, xml::writer::Error> {
    let mut data: Vec<u8> = vec![];
    let mut writer = EmitterConfig::new()
        .perform_indent(false)
        .create_writer(&mut data);

    writer.write(WriterEvent::start_element("KeePassFile"))?;

    writer.write(WriterEvent::start_element("Meta"))?;

    writer.write(WriterEvent::start_element("Generator"))?;
    writer.write(WriterEvent::characters("keepass-rs"))?;
    writer.write(WriterEvent::end_element())?;

    // TODO DatabaseName
    // TODO DatabaseNameChanged
    // TODO DatabaseDescription
    // TODO DatabaseDescriptionChanged
    // TODO DefaultUserName
    // TODO DefaultUserNameChanged
    // TODO DeletedObjects
    // TODO MaintenanceHistoryDays
    // TODO Color
    // TODO MasterKeyChanged
    // TODO MasterKeyChangeRec
    // TODO MasterKeyChangeForce
    // TODO MemoryProtection
    // TODO CustomIcons
    // TODO RecycleBinEnabled
    // TODO RecycleBinUUID
    // TODO RecycleBinChanged
    // TODO EntryTemplatesGroup
    // TODO EntryTemplatesGroupChanged
    // TODO LastSelectedGroup
    // TODO LastTopVisibleGroup
    // TODO HistoryMaxItems
    // TODO HistoryMaxSize
    // TODO SettingsChanged
    // TODO CustomData

    writer.write(WriterEvent::end_element())?;

    writer.write(WriterEvent::start_element("Root"))?;
    dump_xml_group(&mut writer, &db.root, inner_cipher)?;
    writer.write(WriterEvent::end_element())?;

    writer.write(WriterEvent::end_element())?;
    Ok(data)
}

pub(crate) fn dump_xml_group<E: std::io::Write>(
    writer: &mut EventWriter<E>,
    group: &Group,
    inner_cipher: &mut dyn Cipher,
) -> std::result::Result<(), xml::writer::Error> {
    writer.write(WriterEvent::start_element("Group"))?;

    // TODO IconId
    // TODO Notes

    writer.write(WriterEvent::start_element("Name"))?;
    writer.write(WriterEvent::characters(&group.name))?;
    writer.write(WriterEvent::end_element())?;

    writer.write(WriterEvent::start_element("UUID"))?;
    writer.write(WriterEvent::characters(&group.uuid))?;
    writer.write(WriterEvent::end_element())?;

    for child in &group.children {
        match child {
            crate::Node::Entry(e) => dump_xml_entry(writer, e, inner_cipher)?,
            crate::Node::Group(g) => dump_xml_group(writer, g, inner_cipher)?,
        };
    }
    writer.write(WriterEvent::end_element())?;

    Ok(())
}

pub(crate) fn dump_xml_entry<E: std::io::Write>(
    writer: &mut EventWriter<E>,
    entry: &Entry,
    inner_cipher: &mut dyn Cipher,
) -> std::result::Result<(), xml::writer::Error> {
    writer.write(WriterEvent::start_element("Entry"))?;

    // TODO IconId
    // TODO Times
    // TODO AutoType
    // TODO History
    // TODO ForegroundColor
    // TODO BackgroundColor
    //
    writer.write(WriterEvent::start_element("UUID"))?;
    writer.write(WriterEvent::characters(&entry.uuid))?;
    writer.write(WriterEvent::end_element())?;

    writer.write(WriterEvent::start_element("Expires"))?;
    if entry.expires {
        writer.write(WriterEvent::characters("True"))?;
    } else {
        writer.write(WriterEvent::characters("False"))?;
    }
    writer.write(WriterEvent::end_element())?;

    writer.write(WriterEvent::start_element("Tags"))?;
    writer.write(WriterEvent::characters(&entry.tags.join(";")))?;
    writer.write(WriterEvent::end_element())?;

    writer.write(WriterEvent::start_element("Times"))?;
    for time_name in entry.times.keys() {
        let time = entry.times.get(time_name).unwrap();
        writer.write(WriterEvent::start_element(time_name.as_ref()))?;
        writer.write(WriterEvent::characters(&dump_xml_timestamp(time)))?;
        writer.write(WriterEvent::end_element())?;
    }
    writer.write(WriterEvent::end_element())?;

    for field_name in entry.fields.keys() {
        let mut is_protected = true;
        let field_value: String = match entry.fields.get(field_name).unwrap() {
            Value::Bytes(b) => {
                is_protected = false;
                std::str::from_utf8(b).unwrap().to_string()
            }
            Value::Unprotected(s) => {
                is_protected = false;
                s.to_string()
            }
            Value::Protected(_) => entry.get(field_name).unwrap().to_string(),
        };
        writer.write(WriterEvent::start_element("String"))?;

        writer.write(WriterEvent::start_element("Key"))?;
        writer.write(WriterEvent::characters(&field_name))?;
        writer.write(WriterEvent::end_element())?;

        let mut start_element_builder = WriterEvent::start_element("Value");
        if is_protected {
            start_element_builder = start_element_builder.attr("Protected", "True");
        }
        writer.write(start_element_builder)?;

        if is_protected {
            let encrypted_value = inner_cipher.encrypt(field_value.as_bytes()).unwrap();

            let protected_value = base64_engine::STANDARD.encode(&encrypted_value);
            writer.write(WriterEvent::characters(&protected_value))?;
        } else {
            writer.write(WriterEvent::characters(&field_value))?;
        }
        writer.write(WriterEvent::end_element())?;

        writer.write(WriterEvent::end_element())?;
    }

    writer.write(WriterEvent::end_element())?;

    Ok(())
}

pub(crate) fn parse_xml_block(
    xml: &[u8],
    inner_cipher: &mut dyn Cipher,
) -> Result<(Group, Meta), XmlParseError> {
    let parser = EventReader::new(xml);

    // Stack of parsed Node objects not yet associated with their parent
    let mut parsed_stack: Vec<Node> = vec![];

    // Stack of XML element names
    let mut xml_stack: Vec<String> = vec![];

    let mut root_group: Group = Default::default();
    let mut meta: Meta = Default::default();

    for e in parser {
        match e.unwrap() {
            XmlEvent::StartElement {
                name: OwnedName { ref local_name, .. },
                ref attributes,
                ..
            } => {
                xml_stack.push(local_name.clone());

                match &local_name[..] {
                    "Meta" => parsed_stack.push(Node::Meta(Default::default())),
                    "UUID" => parsed_stack.push(Node::UUID(String::new())),
                    "RecycleBinUUID" => parsed_stack.push(Node::RecycleBinUUID(String::new())),
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
                    "Tags" => parsed_stack.push(Node::Tags(Default::default())),
                    _ => {}
                }
            }

            XmlEvent::EndElement {
                name: OwnedName { ref local_name, .. },
            } => {
                xml_stack.pop();

                if [
                    "Group",
                    "Entry",
                    "String",
                    "AutoType",
                    "Association",
                    "ExpiryTime",
                    "Expires",
                    "UUID",
                    "Tags",
                    "Meta",
                    "RecycleBinUUID",
                ]
                .contains(&&local_name[..])
                {
                    let finished_node = parsed_stack.pop().unwrap();
                    let parsed_stack_head = parsed_stack.last_mut();

                    match finished_node {
                        Node::KeyValue(k, v) => {
                            if let Some(&mut Node::Entry(Entry { ref mut fields, .. })) =
                                parsed_stack_head
                            {
                                if !v.is_empty() {
                                    // A KeyValue was finished inside of an Entry -> add a field
                                    fields.insert(k, v);
                                }
                            }
                        }

                        Node::Group(finished_group) => {
                            match parsed_stack_head {
                                Some(&mut Node::Group(Group {
                                    ref mut children, ..
                                })) => {
                                    // A Group was finished - add Group to children
                                    children.push(crate::Node::Group(finished_group));
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
                                ref mut children, ..
                            })) = parsed_stack_head
                            {
                                // A Entry was finished - add Node to parent Group's children
                                children.push(crate::Node::Entry(finished_entry))
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
                            // Currently ingoring any Err() from parse_xml_timestamp()
                            // Ignoring Err() to avoid possible regressions for existing users
                            if let Some(&mut Node::Entry(Entry { ref mut times, .. })) =
                                parsed_stack_head
                            {
                                match parse_xml_timestamp(&et) {
                                    Ok(t) => times.insert("ExpiryTime".to_owned(), t),
                                    _ => None,
                                };
                            } else if let Some(&mut Node::Group(Group { ref mut times, .. })) =
                                parsed_stack_head
                            {
                                match parse_xml_timestamp(&et) {
                                    Ok(t) => times.insert("ExpiryTime".to_owned(), t),
                                    _ => None,
                                };
                            }
                        }

                        Node::Expires(es) => {
                            if let Some(&mut Node::Entry(Entry {
                                ref mut expires, ..
                            })) = parsed_stack_head
                            {
                                *expires = es;
                            } else if let Some(&mut Node::Group(Group {
                                ref mut expires, ..
                            })) = parsed_stack_head
                            {
                                *expires = es;
                            }
                        }

                        Node::Tags(t) => {
                            if let Some(&mut Node::Entry(Entry { ref mut tags, .. })) =
                                parsed_stack_head
                            {
                                if !t.is_empty() {
                                    *tags = t
                                        .split(|c| c == ';' || c == ',')
                                        .map(|x| x.to_owned())
                                        .collect();

                                    tags.sort();
                                }
                            }
                        }

                        Node::RecycleBinUUID(r) => {
                            if let Some(&mut Node::Meta(Meta {
                                ref mut recyclebin_uuid,
                                ..
                            })) = parsed_stack_head
                            {
                                *recyclebin_uuid = r;
                            }
                        }

                        Node::Meta(m) => {
                            meta = m;
                        }

                        Node::UUID(u) => {
                            if let Some(&mut Node::Entry(Entry { ref mut uuid, .. })) =
                                parsed_stack_head
                            {
                                *uuid = u;
                            } else if let Some(&mut Node::Group(Group { ref mut uuid, .. })) =
                                parsed_stack_head
                            {
                                *uuid = u;
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
                        *et = c;
                    }
                    (Some("UUID"), Some(&mut Node::UUID(ref mut uuid))) => {
                        *uuid = c;
                    }
                    (Some("Expires"), Some(&mut Node::Expires(ref mut es))) => {
                        *es = c == "True";
                    }
                    (Some("Tags"), Some(&mut Node::Tags(ref mut tags))) => {
                        *tags = c;
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
                                let buf = base64_engine::STANDARD.decode(&c)?;

                                let buf_decode = inner_cipher.decrypt(&buf)?;

                                let c_decode = String::from_utf8_lossy(&buf_decode).to_string();

                                *v = SecStr::from(c_decode);
                            }
                        }
                    }
                    (Some("RecycleBinUUID"), Some(&mut Node::RecycleBinUUID(ref mut et))) => {
                        *et = c;
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
                    _ => {}
                }
            }

            _ => {}
        }
    }

    Ok((root_group, meta))
}

mod xml_tests {
    use crate::{
        config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
        parse::kdbx4,
        Database, Entry, Group, Node,
    };

    #[test]
    pub fn test_entry() {
        let mut root_group = Group::new("Root");
        let mut entry = Entry::new();
        let new_entry_uuid = entry.uuid.clone();

        entry.fields.insert(
            "Title".to_string(),
            crate::Value::Unprotected("ASDF".to_string()),
        );
        entry.fields.insert(
            "UserName".to_string(),
            crate::Value::Unprotected("ghj".to_string()),
        );
        entry.fields.insert(
            "Password".to_string(),
            crate::Value::Protected(std::str::from_utf8(b"klmno").unwrap().into()),
        );
        entry.tags.push("test".to_string());
        entry.tags.push("keepass-rs".to_string());
        entry.expires = true;

        root_group.children.push(Node::Entry(entry));

        let db = Database::create_database(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 1000,
                parallelism: 1,
                version: argon2::Version::Version13,
            },
            root_group,
            vec![],
        )
        .unwrap();

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = Database::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = kdbx4::dump(&db, &key_elements).unwrap();

        let decrypted_db = kdbx4::parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(_) => panic!("Was expecting an entry as the only child."),
        };

        assert_eq!(decrypted_entry.get_uuid(), new_entry_uuid);
        assert_eq!(decrypted_entry.get_title(), Some("ASDF"));
        assert_eq!(decrypted_entry.get_username(), Some("ghj"));
        assert_eq!(decrypted_entry.get("Password"), Some("klmno"));
        assert_eq!(
            decrypted_entry.tags,
            vec!["keepass-rs".to_string(), "test".to_string()]
        );
    }

    #[test]
    pub fn test_group() {
        let mut root_group = Group::new("Root");
        let mut entry = Entry::new();
        let new_entry_uuid = entry.uuid.clone();
        entry.fields.insert(
            "Title".to_string(),
            crate::Value::Unprotected("ASDF".to_string()),
        );

        root_group.children.push(Node::Entry(entry));

        let db = Database::create_database(
            OuterCipherSuite::AES256,
            Compression::GZip,
            InnerCipherSuite::Salsa20,
            KdfSettings::Argon2 {
                salt: vec![],
                iterations: 1000,
                memory: 1000,
                parallelism: 1,
                version: argon2::Version::Version13,
            },
            root_group,
            vec![],
        )
        .unwrap();

        let mut password_bytes: Vec<u8> = vec![];
        let mut password: String = "".to_string();
        password_bytes.resize(40, 0);
        getrandom::getrandom(&mut password_bytes).unwrap();
        for random_char in password_bytes {
            password += &std::char::from_u32(random_char as u32).unwrap().to_string();
        }

        let key_elements = Database::get_key_elements(Some(&password), None).unwrap();

        let encrypted_db = kdbx4::dump(&db, &key_elements).unwrap();

        let decrypted_db = kdbx4::parse(&encrypted_db, &key_elements).unwrap();

        assert_eq!(decrypted_db.root.children.len(), 1);

        let decrypted_entry = match &decrypted_db.root.children[0] {
            Node::Entry(e) => e,
            Node::Group(_) => panic!("Was expecting an entry as the only child."),
        };

        assert_eq!(decrypted_entry.get_title(), Some("ASDF"));
        assert_eq!(decrypted_entry.get_uuid(), new_entry_uuid);

        let decrypted_root_group = &decrypted_db.root;
        assert_eq!(decrypted_root_group.name, "Root");
    }
}
