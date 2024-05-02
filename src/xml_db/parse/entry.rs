use std::iter::Peekable;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use secstr::SecStr;
use uuid::Uuid;

use crate::{
    crypt::ciphers::Cipher,
    db::{AutoType, AutoTypeAssociation, Color, Entry, History, Times, Value},
    xml_db::parse::{bad_event, CustomData, FromXml, IgnoreSubfield, SimpleTag, SimpleXmlEvent, XmlParseError},
};

impl FromXml for Entry {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Entry") {
            return Err(bad_event("Open entry tag", open_tag));
        }

        let mut out = Self::new();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "UUID" => {
                        out.uuid = SimpleTag::<Uuid>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Tags" => {
                        if let Some(tags) = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value
                        {
                            out.tags = tags
                                .split(|c| c == ';' || c == ',')
                                .map(|x| x.to_owned())
                                .collect();
                        }
                    }
                    "String" => {
                        let field = StringField::from_xml(iterator, inner_cipher)?;
                        if let Some(value) = field.value {
                            out.fields.insert(field.key, value);
                        }
                    }
                    "CustomData" => {
                        out.custom_data = CustomData::from_xml(iterator, inner_cipher)?;
                    }
                    "Binary" => {
                        let _field = BinaryField::from_xml(iterator, inner_cipher)?;
                        // TODO reference into a binary field from the Meta. Might only appear in
                        // kdbx3
                    }
                    "AutoType" => {
                        out.autotype = Some(AutoType::from_xml(iterator, inner_cipher)?);
                    }
                    "Times" => {
                        out.times = Times::from_xml(iterator, inner_cipher)?;
                    }
                    "IconID" => {
                        out.icon_id = SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "CustomIconUUID" => {
                        out.custom_icon_uuid =
                            SimpleTag::<Option<Uuid>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ForegroundColor" => {
                        out.foreground_color =
                            SimpleTag::<Option<Color>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "BackgroundColor" => {
                        out.background_color =
                            SimpleTag::<Option<Color>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "OverrideURL" => {
                        out.override_url = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "QualityCheck" => {
                        out.quality_check = SimpleTag::<Option<bool>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "History" => {
                        out.history = Some(History::from_xml(iterator, inner_cipher)?);
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "Entry" => break,
                _ => return Err(bad_event("start tag or close entry", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

#[derive(Debug, Default)]
pub(crate) struct StringField {
    key: String,
    value: Option<Value>,
}

impl FromXml for StringField {
    type Parses = StringField;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "String") {
            return Err(bad_event("Open string tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Key" => {
                        out.key = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Value" => {
                        let value = Value::from_xml(iterator, inner_cipher)?;
                        if !value.is_empty() {
                            out.value = Some(value)
                        }
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "String" => break,
                _ => return Err(bad_event("start tag or close String", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct BinaryField {
    pub key: String,
    pub identifier: String,
}

impl FromXml for BinaryField {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Binary") {
            return Err(bad_event("Open Binary tag", open_tag));
        }

        let key = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;

        let value_event = iterator.next().ok_or(XmlParseError::Eof)?;
        let identifier = match value_event {
            SimpleXmlEvent::Start(ref name, ref attributes) if name == "Value" => {
                attributes.get("Ref").cloned()
            }
            _ => None,
        }
        .ok_or_else(|| bad_event("Open Value tag with \"Ref\" attribute", value_event))?;

        let close_value_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_value_tag, SimpleXmlEvent::End(ref tag) if tag == "Value") {
            return Err(bad_event("Close Value tag", close_value_tag));
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(BinaryField { key, identifier })
    }
}

impl FromXml for Value {
    type Parses = Value;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        if let SimpleXmlEvent::Start(ref tag, ref attributes) = open_tag {
            if tag == "Value" {
                let protected: bool = attributes
                    .get("Protected")
                    .map(|v| v.to_lowercase().parse::<bool>())
                    .unwrap_or(Ok(false))?;

                let content = Option::<String>::from_xml(iterator, inner_cipher)?.unwrap_or(String::new());

                let value = if protected {
                    let buf = base64_engine::STANDARD.decode(&content)?;
                    let buf_decrypted = inner_cipher.decrypt(&buf)?;
                    let value = String::from_utf8_lossy(&buf_decrypted).to_string();
                    Value::Protected(SecStr::from(value))
                } else {
                    Value::Unprotected(content)
                };

                let close_value_tag = iterator.next().ok_or(XmlParseError::Eof)?;
                if !matches!(close_value_tag, SimpleXmlEvent::End(ref tag) if tag == "Value") {
                    return Err(bad_event("Close Value tag", close_value_tag));
                }

                return Ok(value);
            }
        }
        Err(bad_event("Open value tag", open_tag))
    }
}

impl FromXml for AutoType {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "AutoType") {
            return Err(bad_event("Open AutoType tag", open_tag));
        }

        let mut out = AutoType::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Enabled" => {
                        out.enabled = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DefaultSequence" => {
                        out.sequence = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DataTransferObfuscation" => {
                        let _value = SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO probably not needed?
                    }
                    "Association" => {
                        let ata = AutoTypeAssociation::from_xml(iterator, inner_cipher)?;
                        out.associations.push(ata);
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "AutoType" => break,
                _ => return Err(bad_event("start tag or close AutoType", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

impl FromXml for AutoTypeAssociation {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Association") {
            return Err(bad_event("Open Association tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Window" => {
                        out.window = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "KeystrokeSequence" => {
                        out.sequence = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "Association" => break,
                _ => return Err(bad_event("start tag or close Association", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

impl FromXml for History {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "History") {
            return Err(bad_event("Open History tag", open_tag));
        }

        let mut entries = Vec::new();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Entry" => {
                        let entry = Entry::from_xml(iterator, inner_cipher)?;
                        entries.push(entry);
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "History" => break,
                _ => return Err(bad_event("start tag or close History", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(Self { entries })
    }
}
