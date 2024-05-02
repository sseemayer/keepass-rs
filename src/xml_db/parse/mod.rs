mod entry;
mod group;
mod meta;

use std::{collections::HashMap, iter::Peekable};

use base64::{engine::general_purpose as base64_engine, Engine as _};
use chrono::NaiveDateTime;
use uuid::Uuid;
use xml::{name::OwnedName, reader::XmlEvent, EventReader};

use crate::{
    crypt::ciphers::Cipher,
    db::{
        Color, CustomData, CustomDataItem, CustomDataItemDenormalized, DeletedObject, DeletedObjects, Group,
        Meta, Times, Value,
    },
    error::XmlParseError,
    xml_db::get_epoch_baseline,
};

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

pub(crate) fn bad_event(expected: &'static str, event: SimpleXmlEvent) -> XmlParseError {
    XmlParseError::BadEvent { expected, event }
}

pub(crate) fn parse(xml: &[u8], inner_cipher: &mut dyn Cipher) -> Result<KeePassXml, XmlParseError> {
    parse_from_bytes::<KeePassXml>(xml, inner_cipher)
}

pub(crate) fn parse_from_bytes<P: FromXml>(
    xml: &[u8],
    inner_cipher: &mut dyn Cipher,
) -> Result<<P as FromXml>::Parses, XmlParseError> {
    let mut reader = EventReader::new(xml)
        .into_iter()
        .filter_map(|e| {
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

    P::from_xml(&mut reader, inner_cipher)
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
            return Err(bad_event("text containing a value", event));
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

impl FromXmlCharacters for Uuid {
    fn from_xml_characters(s: &str) -> Result<Self, XmlParseError> {
        let v = base64_engine::STANDARD.decode(s)?;
        let uuid = Uuid::from_slice(&v)?;
        Ok(uuid)
    }
}

impl FromXmlCharacters for Color {
    fn from_xml_characters(s: &str) -> Result<Self, XmlParseError> {
        Ok(s.parse()?)
    }
}

/// Helper type to denote a tag with a character content that can be parsed.
#[derive(Debug)]
struct SimpleTag<V> {
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
                return Err(bad_event("Close tag", close_tag));
            }

            Ok(SimpleTag { name, value })
        } else {
            return Err(bad_event("Open tag", open_tag));
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
            return Err(bad_event("Open KeePassFile tag", open_tag));
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
                    _ => return Err(bad_event("valid Root child", event.clone())),
                },
                SimpleXmlEvent::End(name) if name == "KeePassFile" => break,
                _ => return Err(bad_event("start tag or close KeePassFile", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

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
            return Err(bad_event("Open Times tag", open_tag));
        }

        let mut out = Times::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Expires" => {
                        out.expires = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "UsageCount" => {
                        out.usage_count = SimpleTag::<usize>::from_xml(iterator, inner_cipher)?.value;
                    }

                    _ => {
                        let time = SimpleTag::<NaiveDateTime>::from_xml(iterator, inner_cipher)?;
                        out.times.insert(time.name, time.value);
                    }
                },
                SimpleXmlEvent::End(name) if name == "Times" => break,
                _ => return Err(bad_event("start tag or close Times", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

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
            return Err(bad_event("Open Root tag", open_tag));
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
                    _ => return Err(bad_event("valid Root child", event.clone())),
                },
                SimpleXmlEvent::End(name) if name == "Root" => break,
                _ => return Err(bad_event("start tag or close Root", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

impl FromXml for DeletedObjects {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "DeletedObjects") {
            return Err(bad_event("Open DeletedObjects tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) if name == "DeletedObject" => {
                    let object = DeletedObject::from_xml(iterator, inner_cipher)?;
                    out.objects.push(object);
                }
                SimpleXmlEvent::End(name) if name == "DeletedObjects" => break,
                _ => return Err(bad_event("start tag or close DeletedObjects", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

impl FromXml for DeletedObject {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "DeletedObject") {
            return Err(bad_event("Open DeletedObject tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "UUID" => {
                        out.uuid = SimpleTag::<Uuid>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DeletionTime" => {
                        out.deletion_time = SimpleTag::<NaiveDateTime>::from_xml(iterator, inner_cipher)?.value;
                    }
                    _ => return Err(bad_event("valid DeletedObject child", event.clone())),
                },
                SimpleXmlEvent::End(name) if name == "DeletedObject" => break,
                _ => return Err(bad_event("start tag or close DeletedObject", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

impl FromXml for CustomData {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "CustomData") {
            return Err(bad_event("Open CustomData tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Item" => {
                        let item = CustomDataItemDenormalized::from_xml(iterator, inner_cipher)?;
                        out.items.insert(
                            item.key.to_string(),
                            CustomDataItem {
                                value: item.custom_data_item.value,
                                last_modification_time: item.custom_data_item.last_modification_time,
                            },
                        );
                    }
                    _ => return Err(bad_event("valid CustomData child", event.clone())),
                },
                SimpleXmlEvent::End(name) if name == "CustomData" => break,
                _ => return Err(bad_event("start tag or close CustomData", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

impl FromXml for CustomDataItemDenormalized {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Item") {
            return Err(bad_event("Open Item tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Key" => {
                        out.key = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Value" => {
                        out.custom_data_item.value = Some(Value::from_xml(iterator, inner_cipher)?);
                    }
                    "LastModificationTime" => {
                        out.custom_data_item.last_modification_time =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    _ => return Err(bad_event("valid Item child", event.clone())),
                },
                SimpleXmlEvent::End(name) if name == "Item" => break,
                _ => return Err(bad_event("start tag or close Item", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

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
        if let SimpleXmlEvent::Start(_, _) = open_tag {
            let mut stack = Vec::new();

            while let Some(event) = iterator.next() {
                match event {
                    SimpleXmlEvent::Start(t, _) => stack.push(t),
                    SimpleXmlEvent::End(_) => {
                        // ascend the stack of inner elements. matching closing tag is ensured
                        // by XmlReader
                        if stack.pop().is_none() {
                            // we are back at the root of the subparser
                            break;
                        }
                    }
                    SimpleXmlEvent::Characters(_) => {}
                    SimpleXmlEvent::Err(e) => return Err(e.into()),
                }
            }
        } else {
            return Err(bad_event("Open tag (to be ignored)", open_tag));
        }

        Ok(())
    }
}

#[cfg(test)]
mod parse_test {
    use crate::{
        config::InnerCipherConfig,
        crypt::ciphers::PlainCipher,
        db::{
            AutoType, AutoTypeAssociation, CustomData, CustomDataItemDenormalized, Entry, History, Times, Value,
        },
        xml_db::parse::{entry::StringField, DeletedObject, DeletedObjects, IgnoreSubfield, Root},
    };

    use super::{entry::BinaryField, parse, parse_from_bytes, FromXml, KeePassXml, SimpleTag, XmlParseError};

    pub(crate) fn parse_test_xml<P: FromXml>(xml: &str) -> Result<<P as FromXml>::Parses, XmlParseError> {
        parse_from_bytes::<P>(xml.as_bytes(), &mut PlainCipher)
    }

    #[test]
    fn test_custom_xml_fields() -> Result<(), XmlParseError> {
        let xml = include_bytes!("../../../tests/resources/inner_xml_with_custom_fields.xml");

        let mut inner_cipher = InnerCipherConfig::Plain.get_cipher(&[]).unwrap();

        let _database_content = parse(&xml[..], &mut *inner_cipher)?;

        Ok(())
    }

    #[test]
    fn test_simple_tag() -> Result<(), XmlParseError> {
        // String tag
        let value =
            parse_test_xml::<SimpleTag<String>>("<TestTag attribute=\"SomeValue\">Test-Value</TestTag>")?;
        assert_eq!(value.name, "TestTag");
        assert_eq!(value.value, "Test-Value");

        let value = parse_test_xml::<SimpleTag<String>>(
            "<TestTag attribute=\"SomeValue\">Test-Value<!-- a comment -->even more test data</TestTag>",
        )?;
        assert_eq!(value.name, "TestTag");
        assert_eq!(value.value, "Test-Valueeven more test data");

        let value = parse_test_xml::<SimpleTag<String>>("<TestTag attribute=\"SomeValue\"></TestTag>");
        assert!(value.is_err());

        // Option<String> tag
        let value = parse_test_xml::<SimpleTag<Option<String>>>(
            "<TestTag attribute=\"SomeValue\">Test-Value</TestTag>",
        )?;
        assert_eq!(value.name, "TestTag");
        assert_eq!(value.value, Some("Test-Value".to_string()));

        let value = parse_test_xml::<SimpleTag<Option<String>>>("<TestTag attribute=\"SomeValue\"></TestTag>")?;
        assert_eq!(value.name, "TestTag");
        assert_eq!(value.value, None);

        // bool tag
        let value = parse_test_xml::<SimpleTag<bool>>("<TestTag attribute=\"SomeValue\">True</TestTag>")?;
        assert_eq!(value.name, "TestTag");
        assert_eq!(value.value, true);

        // usize tag
        let value = parse_test_xml::<SimpleTag<usize>>("<TestTag attribute=\"SomeValue\">42</TestTag>")?;
        assert_eq!(value.name, "TestTag");
        assert_eq!(value.value, 42);

        // isize tag
        let value = parse_test_xml::<SimpleTag<isize>>("<TestTag attribute=\"SomeValue\">-42</TestTag>")?;
        assert_eq!(value.name, "TestTag");
        assert_eq!(value.value, -42);

        // reject invalid XML
        let value = parse_test_xml::<SimpleTag<String>>("");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<SimpleTag<String>>("Not a tag");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<SimpleTag<String>>("<OpenTag>Data</CloseTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<SimpleTag<String>>("<TestTag></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<SimpleTag<String>>("<TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<SimpleTag<String>>("<TestTag>SomeData<AnotherTag/></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_keepass_xml_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<KeePassXml>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<KeePassXml>("<KeePassFile></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<KeePassXml>("<KeePassFile>No-Characters-Allowed</KeePassFile>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<KeePassXml>("<KeePassFile><UnkownChildTag/></KeePassFile>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_times() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<Times>("<Times><TestTime>8i481Q4AAAA=</TestTime></Times>")?;
        assert_eq!(value.times.len(), 1);

        let value = parse_test_xml::<Times>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Times>("<Times></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Times>("<Times>No-Characters-Allowed</Times>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_root_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<Root>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Root>("<Root></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Root>("<Root>No-Characters-Allowed</Root>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Root>("<Root><UnkownChildTag/></Root>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_deleted_objects_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<DeletedObjects>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<DeletedObjects>("<DeletedObjects></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<DeletedObjects>("<DeletedObjects>No-Characters-Allowed</DeletedObjects>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<DeletedObjects>("<DeletedObjects><UnkownChildTag/></DeletedObjects>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_deleted_object_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<DeletedObject>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<DeletedObject>("<DeletedObject></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<DeletedObject>("<DeletedObject>No-Characters-Allowed</DeletedObject>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<DeletedObject>("<DeletedObject><UnkownChildTag/></DeletedObject>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_custom_data_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<CustomData>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomData>("<CustomData></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomData>("<CustomData>No-Characters-Allowed</CustomData>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomData>("<CustomData><UnkownChildTag/></CustomData>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_custom_data_item_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<CustomDataItemDenormalized>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomDataItemDenormalized>("<Item></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomDataItemDenormalized>("<Item>No-Characters-Allowed</Item>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomDataItemDenormalized>("<Item><UnkownChildTag/></Item>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomDataItemDenormalized>(
            "<Item><Key></Key><Value>EmptyKey</Value><LastModificationTime>1234</LastModificationTime></Item>",
        );
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_ignore_subfield() -> Result<(), XmlParseError> {
        let _value = parse_test_xml::<IgnoreSubfield>("<TestTag>SomeData</TestTag>")?;
        let _value =
            parse_test_xml::<IgnoreSubfield>("<TestTag>SomeData<More-Content></More-Content></TestTag>")?;

        let value = parse_test_xml::<IgnoreSubfield>("<Item></TestTag>");
        assert!(matches!(value, Err(XmlParseError::Xml(_))));

        let value = parse_test_xml::<IgnoreSubfield>("</Item>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<IgnoreSubfield>("Not a tag");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_binary_field() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<BinaryField>("<Binary><Key>MyField</Key><Value Ref=\"asdf\"/></Binary>")?;

        assert_eq!(value.key, "MyField");
        assert_eq!(value.identifier, "asdf");

        let value = parse_test_xml::<BinaryField>("<TestTag></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryField>("<Binary></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryField>("<Binary></Binary>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value =
            parse_test_xml::<BinaryField>("<Binary><WrongTag/><Key>asdf</Key><Value Ref=\"asdf\"/></Binary>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value =
            parse_test_xml::<BinaryField>("<Binary><Key>asdf</Key><WrongTag/><Value Ref=\"asdf\"/></Binary>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryField>(
            "<Binary><Key>mykey</Key><Value Ref=\"asdf\">Value data</Value></Binary>",
        );
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryField>("<Binary><Key></Key><Value Ref=\"asdf\"/></Binary>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryField>("<Binary><Key>mykey</Key><Value/></Binary>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryField>("</Binary>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryField>("Not a tag");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_entry_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<Entry>("<Entry>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Entry>("<WrongTag></WrongTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_string_field_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<StringField>("<String>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<StringField>("<WrongTag></WrongTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<StringField>("Not a tag");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<StringField>("<String><StrangeTag>Data</StrangeTag></String>");
        assert!(matches!(value, Ok(_)));

        Ok(())
    }

    #[test]
    fn test_value() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<Value>("<Value>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Value>("<Value></Value>");
        assert!(matches!(value, Ok(Value::Unprotected(_))));

        let value = parse_test_xml::<Value>("<WrongTag></WrongTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Value>("Not a tag");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Value>("<Value><StrangeTag>Data</StrangeTag></Value>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_autotype() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<AutoType>("<AutoType>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<AutoType>("<AutoType></AutoType>");
        assert!(matches!(value, Ok(_)));

        let value = parse_test_xml::<AutoType>("<AutoType><Enabled>True</Enabled><DefaultSequence>ASDF</DefaultSequence><DataTransferObfuscation>42</DataTransferObfuscation></AutoType>")?;
        assert_eq!(value.enabled, true);
        assert_eq!(value.sequence, Some("ASDF".to_string()));
        assert_eq!(value.associations.len(), 0);

        let value = parse_test_xml::<AutoType>("<WrongTag></WrongTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<AutoType>("Not a tag");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<AutoType>("<AutoType><StrangeTag>Data</StrangeTag></AutoType>");
        assert!(matches!(value, Ok(_)));

        Ok(())
    }

    #[test]
    fn test_autotype_association() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<AutoTypeAssociation>("<Association>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<AutoTypeAssociation>("<Association></Association>");
        assert!(matches!(value, Ok(_)));

        let value = parse_test_xml::<AutoTypeAssociation>(
            "<Association><Window>MyApp</Window><KeystrokeSequence>ASDF</KeystrokeSequence></Association>",
        )?;
        assert_eq!(value.window, Some("MyApp".to_string()));
        assert_eq!(value.sequence, Some("ASDF".to_string()));

        let value = parse_test_xml::<AutoTypeAssociation>("<WrongTag></WrongTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<AutoTypeAssociation>("Not a tag");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value =
            parse_test_xml::<AutoTypeAssociation>("<Association><StrangeTag>Data</StrangeTag></Association>");
        assert!(matches!(value, Ok(_)));

        Ok(())
    }

    #[test]
    fn test_history_failures() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<History>("<History>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<History>("<History></History>");
        assert!(matches!(value, Ok(_)));

        let value = parse_test_xml::<History>("<WrongTag></WrongTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<History>("Not a tag");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<History>("<History><StrangeTag>Data</StrangeTag></History>");
        assert!(matches!(value, Ok(_)));

        Ok(())
    }
}
