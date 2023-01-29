use std::iter::Peekable;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use secstr::SecStr;

use crate::{
    crypt::ciphers::Cipher,
    xml_db::parse::{CustomData, FromXml, SimpleTag, SimpleXmlEvent, XmlParseError},
    AutoType, AutoTypeAssociation, Entry, Times, Value,
};

use super::IgnoreSubfield;

impl FromXml for Entry {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Entry") {
            return Err(XmlParseError::BadEvent {
                expected: "Open entry tag",
                event: open_tag,
            });
        }

        let mut out = Self::new();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "UUID" => {
                        out.uuid = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Tags" => {
                        if let Some(tags) =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value
                        {
                            out.tags = tags
                                .split(|c| c == ';' || c == ',')
                                .map(|x| x.to_owned())
                                .collect();
                            out.tags.sort();
                        }
                    }
                    "String" => {
                        let field = StringField::from_xml(iterator, inner_cipher)?;
                        if let Some(value) = field.value {
                            out.fields.insert(field.key, value);
                        }
                    }
                    "CustomData" => {
                        let value = CustomData::from_xml(iterator, inner_cipher)?;
                        // TODO
                    }
                    "Binary" => {
                        let field = BinaryField::from_xml(iterator, inner_cipher)?;
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
                        let icon_id = SimpleTag::<usize>::from_xml(iterator, inner_cipher)?;
                        // TODO
                        // out.icon_id = icon_id;
                    }
                    "CustomIconUUID" => {
                        let icon_id = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "ForegroundColor" => {
                        let color = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?;
                        // TODO
                        // out.foregrpund_color = color;
                    }
                    "BackgroundColor" => {
                        let color = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?;
                        // TODO
                        // out.background_color = color;
                    }
                    "OverrideURL" => {
                        let url = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?;
                        // TODO
                        // out.override_url = color;
                    }
                    "QualityCheck" => {
                        let qc = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?;
                        // TODO
                        // out.quality_check = qc;
                    }
                    "History" => {
                        let history = History::from_xml(iterator, inner_cipher)?;
                        // TODO
                        // out.history = history;
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "Entry" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close entry",
                        event: event.clone(),
                    })
                }
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

#[derive(Debug, Default)]
struct StringField {
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
            return Err(XmlParseError::BadEvent {
                expected: "Open string tag",
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
                        let value = Value::from_xml(iterator, inner_cipher)?;
                        if !value.is_empty() {
                            out.value = Some(value)
                        }
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "String" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close String",
                        event: event.clone(),
                    })
                }
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

struct BinaryField {
    key: String,
    identifier: String,
}

impl FromXml for BinaryField {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Binary") {
            return Err(XmlParseError::BadEvent {
                expected: "Open Binary tag",
                event: open_tag,
            });
        }

        let key = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;

        let value_event = iterator.next().ok_or(XmlParseError::Eof)?;
        let identifier = if let SimpleXmlEvent::Start(ref name, ref attributes) = value_event {
            if name != "Value" {
                return Err(XmlParseError::BadEvent {
                    expected: "Open Value tag",
                    event: value_event,
                });
            }

            attributes
                .get("Ref")
                .ok_or_else(|| XmlParseError::BadEvent {
                    expected: "Value tag with Ref attribute",
                    event: value_event.clone(),
                })?
                .to_string()
        } else {
            return Err(XmlParseError::BadEvent {
                expected: "Open Value tag",
                event: value_event,
            });
        };

        let close_value_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_value_tag, SimpleXmlEvent::End(ref tag) if tag == "Value") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Value tag",
                event: close_value_tag,
            });
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

                let content =
                    Option::<String>::from_xml(iterator, inner_cipher)?.unwrap_or(String::new());

                let value = if protected {
                    let buf = base64_engine::STANDARD.decode(&content)?;
                    let buf_decrypted = inner_cipher.decrypt(&buf)?;
                    let value = String::from_utf8_lossy(&buf_decrypted).to_string();
                    Value::Protected(SecStr::from(value))
                } else {
                    Value::Unprotected(content)
                };

                // no need to check for the correct closing tag - checked by XmlReader
                let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

                return Ok(value);
            }
        }
        Err(XmlParseError::BadEvent {
            expected: "Open value tag",
            event: open_tag,
        })
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
            return Err(XmlParseError::BadEvent {
                expected: "Open AutoType tag",
                event: open_tag,
            });
        }

        let mut out = AutoType::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Enabled" => {
                        out.enabled = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DefaultSequence" => {
                        out.sequence =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DataTransferObfuscation" => {
                        let value =
                            SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "Association" => {
                        let ata = AutoTypeAssociation::from_xml(iterator, inner_cipher)?;
                        out.associations.push(ata);
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "AutoType" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close AutoType",
                        event: event.clone(),
                    })
                }
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
            return Err(XmlParseError::BadEvent {
                expected: "Open Association tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Window" => {
                        out.window =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "KeystrokeSequence" => {
                        out.sequence =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "Association" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close Association",
                        event: event.clone(),
                    })
                }
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

struct History {
    entries: Vec<Entry>,
}

impl FromXml for History {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut Peekable<I>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "History") {
            return Err(XmlParseError::BadEvent {
                expected: "Open History tag",
                event: open_tag,
            });
        }

        let mut entries = Vec::new();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Entry" => {
                        let entry = Entry::from_xml(iterator, inner_cipher)?;
                        entries.push(entry);
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "History" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close History",
                        event: event.clone(),
                    })
                }
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(Self { entries })
    }
}
