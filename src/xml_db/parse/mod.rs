mod entry;
mod group;
mod meta;

use std::{collections::HashMap, iter::Peekable};

use base64::{engine::general_purpose as base64_engine, Engine as _};
use chrono::NaiveDateTime;
use thiserror::Error;
use xml::{name::OwnedName, reader::XmlEvent, EventReader};

use crate::{
    crypt::{ciphers::Cipher, CryptographyError},
    xml_db::get_epoch_baseline,
    Group, Meta, Times, Value,
};

#[derive(Debug, Error)]
pub enum XmlParseError {
    #[error(transparent)]
    Xml(#[from] xml::reader::Error),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    TimestampFormat(#[from] chrono::ParseError),

    #[error(transparent)]
    IntFormat(#[from] std::num::ParseIntError),

    #[error(transparent)]
    BoolFormat(#[from] std::str::ParseBoolError),

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error("Decompression error: {}", _0)]
    Compression(#[source] std::io::Error),

    #[error("Bad XML event: expected {}, got {:?}", expected, event)]
    BadEvent {
        expected: &'static str,
        event: SimpleXmlEvent,
    },

    #[error("Unexpected end of XML document")]
    Eof,
}

/// Parse a KeePass timestamp string
pub fn parse_xml_timestamp(t: &str) -> Result<chrono::NaiveDateTime, XmlParseError> {
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

/// Trait that denotes that a KeePass object can be parsed from a stream of `SimpleXmlEvent`.
///
/// The parser implementation should consume everything from the start tag of an object to the end
/// tag, both inclusive, and use the `Peekable::peek` method to decide when to call into
/// sub-parsers.
pub(crate) trait FromXml {
    type Parses;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError>;
}

/// Helper type to flatten out the Result<XmlEvent> types returned by the EventReader, since many
/// of the parsers need to do a lot of destructuring
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum SimpleXmlEvent {
    Start(String, HashMap<String, String>),
    End(String),
    Characters(String),
    Err(xml::reader::Error),
}

pub(crate) fn parse(
    xml: &[u8],
    inner_cipher: &mut dyn Cipher,
) -> Result<KeePassXml, XmlParseError> {
    let mut reader = EventReader::new(xml)
        .into_iter()
        .filter_map(|e| {
            dbg!(&e);
            // simplify iterator by ignoring unneeded events and flattening the structure
            match e {
                Ok(XmlEvent::StartElement {
                    name: OwnedName { local_name, .. },
                    attributes,
                    ..
                }) => Some(SimpleXmlEvent::Start(
                    local_name,
                    attributes
                        .into_iter()
                        .map(|a| (a.name.local_name, a.value))
                        .collect(),
                )),
                Ok(XmlEvent::EndElement {
                    name: OwnedName { local_name, .. },
                }) => Some(SimpleXmlEvent::End(local_name)),
                Ok(XmlEvent::Characters(c)) => Some(SimpleXmlEvent::Characters(c)),
                Err(e) => Some(SimpleXmlEvent::Err(e.into())),

                // ignore whitespace, comments, ...
                _ => None,
            }
        })
        .peekable();

    KeePassXml::from_xml(&mut reader, inner_cipher)
}

/// Helper trait for converting `SimpleXmlEvent::Characters` into types that can be parsed from
/// strings.
///
/// Note that we cannot use FromStr here since we need to be able to customize the code for some of
/// the types to account for how they are represented in the XML documents (e.g. bool, NaiveDateTime)
trait FromXmlCharacters: Sized {
    fn from_xml_characters(s: &str) -> Result<Self, XmlParseError>;
}

impl<T: FromXmlCharacters> FromXml for T {
    type Parses = T;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let event = iterator.next().ok_or(XmlParseError::Eof)?;
        if let SimpleXmlEvent::Characters(text) = event {
            T::from_xml_characters(&text)
        } else {
            return Err(XmlParseError::BadEvent {
                expected: "text containing a bool",
                event,
            });
        }
    }
}

impl<T: FromXmlCharacters> FromXml for Option<T> {
    type Parses = Option<T>;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let event = iterator.peek().ok_or(XmlParseError::Eof)?;
        if let SimpleXmlEvent::Characters(_) = event {
            // now that we know that characters are upcoming, proceed the iterator.
            if let SimpleXmlEvent::Characters(text) = iterator.next().ok_or(XmlParseError::Eof)? {
                return Ok(Some(T::from_xml_characters(&text)?));
            }
        }
        Ok(None)
    }
}

impl FromXmlCharacters for usize {
    fn from_xml_characters(s: &str) -> Result<Self, XmlParseError> {
        Ok(s.parse()?)
    }
}

impl FromXmlCharacters for isize {
    fn from_xml_characters(s: &str) -> Result<Self, XmlParseError> {
        Ok(s.parse()?)
    }
}

impl FromXmlCharacters for bool {
    fn from_xml_characters(s: &str) -> Result<Self, XmlParseError> {
        Ok(s.to_lowercase().parse()?)
    }
}

impl FromXmlCharacters for String {
    fn from_xml_characters(s: &str) -> Result<Self, XmlParseError> {
        Ok(s.to_string())
    }
}

impl FromXmlCharacters for NaiveDateTime {
    fn from_xml_characters(s: &str) -> Result<Self, XmlParseError> {
        parse_xml_timestamp(s)
    }
}

/// Helper type to denote a tag with a character content that can be parsed.
struct SimpleTag<V> {
    #[allow(dead_code)] // normally this is guaranteed from peeking
    name: String,
    value: V,
}

impl<V: FromXml> FromXml for SimpleTag<V> {
    type Parses = SimpleTag<<V as FromXml>::Parses>;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if let SimpleXmlEvent::Start(name, _) = open_tag {
            let value = V::from_xml(iterator, inner_cipher)?;

            let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
            if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == &name) {
                return Err(XmlParseError::BadEvent {
                    expected: "Close tag",
                    event: close_tag,
                });
            }

            Ok(SimpleTag { name, value })
        } else {
            return Err(XmlParseError::BadEvent {
                expected: "Open entry tag",
                event: open_tag,
            });
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct KeePassXml {
    pub(crate) meta: Meta,
    pub(crate) root: Root,
}

impl FromXml for KeePassXml {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "KeePassFile") {
            return Err(XmlParseError::BadEvent {
                expected: "Open KeePassFile tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Meta" => {
                        out.meta = Meta::from_xml(iterator, inner_cipher)?;
                    }
                    "Root" => {
                        out.root = Root::from_xml(iterator, inner_cipher)?;
                    }
                    _ => {
                        return Err(XmlParseError::BadEvent {
                            expected: "valid Root child",
                            event: event.clone(),
                        })
                    }
                },
                SimpleXmlEvent::End(name) if name == "KeePassFile" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close KeePassFile",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "KeePassFile") {
            return Err(XmlParseError::BadEvent {
                expected: "Close KeePassFile tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

impl FromXml for Times {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Times") {
            return Err(XmlParseError::BadEvent {
                expected: "Open Times tag",
                event: open_tag,
            });
        }

        let mut out = Times::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Expires" => {
                        out.expires = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "UsageCount" => {
                        out.usage_count =
                            SimpleTag::<usize>::from_xml(iterator, inner_cipher)?.value;
                    }

                    _ => {
                        let time = SimpleTag::<NaiveDateTime>::from_xml(iterator, inner_cipher)?;
                        out.times.insert(time.name, time.value);
                    }
                },
                SimpleXmlEvent::End(name) if name == "Times" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close Times",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "Times") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Times tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Default)]
pub(crate) struct Root {
    pub(crate) group: Group,
    pub(crate) deleted_objects: DeletedObjects,
}

impl FromXml for Root {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Root") {
            return Err(XmlParseError::BadEvent {
                expected: "Open Root tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Group" => {
                        out.group = Group::from_xml(iterator, inner_cipher)?;
                    }
                    "DeletedObjects" => {
                        out.deleted_objects = DeletedObjects::from_xml(iterator, inner_cipher)?;
                    }
                    _ => {
                        return Err(XmlParseError::BadEvent {
                            expected: "valid Root child",
                            event: event.clone(),
                        })
                    }
                },
                SimpleXmlEvent::End(name) if name == "Root" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close Root",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "Root") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Root tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Default)]
pub(crate) struct DeletedObjects {
    objects: Vec<DeletedObject>,
}

impl FromXml for DeletedObjects {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "DeletedObjects") {
            return Err(XmlParseError::BadEvent {
                expected: "Open DeletedObjects tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "DeletedObject" => {
                        let object = DeletedObject::from_xml(iterator, inner_cipher)?;
                        out.objects.push(object);
                    }
                    _ => {
                        return Err(XmlParseError::BadEvent {
                            expected: "valid DeletedObjects child",
                            event: event.clone(),
                        })
                    }
                },
                SimpleXmlEvent::End(name) if name == "DeletedObjects" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close DeletedObjects",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "DeletedObjects") {
            return Err(XmlParseError::BadEvent {
                expected: "Close DeletedObjects tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Default)]
pub(crate) struct DeletedObject {
    uuid: String,
    deletion_time: NaiveDateTime,
}

impl FromXml for DeletedObject {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "DeletedObject") {
            return Err(XmlParseError::BadEvent {
                expected: "Open DeletedObject tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "UUID" => {
                        out.uuid = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DeletionTime" => {
                        out.deletion_time =
                            SimpleTag::<NaiveDateTime>::from_xml(iterator, inner_cipher)?.value;
                    }
                    _ => {
                        return Err(XmlParseError::BadEvent {
                            expected: "valid DeletedObject child",
                            event: event.clone(),
                        })
                    }
                },
                SimpleXmlEvent::End(name) if name == "DeletedObject" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close DeletedObject",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "DeletedObject") {
            return Err(XmlParseError::BadEvent {
                expected: "Close DeletedObject tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Default)]
struct CustomData {
    items: Vec<CustomDataItem>,
}

impl FromXml for CustomData {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "CustomData") {
            return Err(XmlParseError::BadEvent {
                expected: "Open CustomData tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Item" => {
                        let item = CustomDataItem::from_xml(iterator, inner_cipher)?;
                        out.items.push(item);
                    }
                    _ => {
                        return Err(XmlParseError::BadEvent {
                            expected: "valid CustomData child",
                            event: event.clone(),
                        })
                    }
                },
                SimpleXmlEvent::End(name) if name == "CustomData" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close CustomData",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "CustomData") {
            return Err(XmlParseError::BadEvent {
                expected: "Close CustomData tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Default)]
struct CustomDataItem {
    key: String,
    value: Option<Value>,
    last_modification_time: Option<NaiveDateTime>,
}

impl FromXml for CustomDataItem {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Item") {
            return Err(XmlParseError::BadEvent {
                expected: "Open Item tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Key" => {
                        out.key = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Value" => {
                        out.value = Some(Value::from_xml(iterator, inner_cipher)?);
                    }
                    "LastModificationTime" => {
                        out.last_modification_time =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                    }
                    _ => {
                        return Err(XmlParseError::BadEvent {
                            expected: "valid Item child",
                            event: event.clone(),
                        })
                    }
                },
                SimpleXmlEvent::End(name) if name == "Item" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close Item",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "Item") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Item tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

/// A helper parser that will ignore everything in its tag.
pub(crate) struct IgnoreSubfield;

impl FromXml for IgnoreSubfield {
    type Parses = ();

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if let SimpleXmlEvent::Start(ref tag, _) = open_tag {
            let mut stack = Vec::new();

            while let Some(event) = iterator.next() {
                match event {
                    SimpleXmlEvent::Start(t, _) => stack.push(t),
                    SimpleXmlEvent::End(ref t) => {
                        if let Some(s) = stack.pop() {
                            // ascend the stack of inner elements
                            if &s != t {
                                return Err(XmlParseError::BadEvent {
                                    expected: "Close matching tag",
                                    event,
                                });
                            }
                        } else {
                            // we have an empty stack -- then the closing tag must match the
                            // original open tag
                            if t != tag {
                                return Err(XmlParseError::BadEvent {
                                    expected: "Close matching tag",
                                    event,
                                });
                            }

                            break;
                        }
                    }
                    SimpleXmlEvent::Characters(_) => {}
                    SimpleXmlEvent::Err(e) => return Err(e.into()),
                }
            }
        } else {
            return Err(XmlParseError::BadEvent {
                expected: "Open tag (to be ignored)",
                event: open_tag,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod parse_test {
    use crate::config::InnerCipherSuite;

    use super::{parse, XmlParseError};

    #[test]
    fn test_custom_xml_fields() -> Result<(), XmlParseError> {
        let xml = include_bytes!("../../../tests/resources/inner_xml_with_custom_fields.xml");

        let inner_cipher_suite = InnerCipherSuite::Salsa20;

        let mut inner_random_stream_key: Vec<u8> = vec![];
        inner_random_stream_key.resize(inner_cipher_suite.get_iv_size().into(), 0);
        getrandom::getrandom(&mut inner_random_stream_key).unwrap();

        let mut inner_cipher = inner_cipher_suite
            .get_cipher(&inner_random_stream_key)
            .unwrap();

        let _database_content = parse(&xml[..], &mut *inner_cipher)?;

        Ok(())
    }
}
