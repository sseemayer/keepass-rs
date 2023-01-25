use base64::{engine::general_purpose as base64_engine, Engine as _};
use chrono::NaiveDateTime;

use crate::{
    compression::{Decompress, GZipCompression},
    parse::kdbx4::BinaryAttachment,
    xml_db::parse::{CustomData, FromXml, SimpleTag, SimpleXmlEvent, XmlParseError},
    Meta,
};

use super::IgnoreSubfield;

impl FromXml for Meta {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = crate::xml_db::parse::SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, crate::xml_db::parse::XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Meta") {
            return Err(XmlParseError::BadEvent {
                expected: "Open Meta tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Generator" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "HeaderHash" => {
                        // this seems to be only present in kdbx3 databases.
                        let _header_hash =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DatabaseName" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "DatabaseNameChanged" => {
                        let value =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                        // TODO
                    }
                    "DatabaseDescription" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "DatabaseDescriptionChanged" => {
                        let value =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                        // TODO
                    }
                    "DefaultUserName" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "DefaultUserNameChanged" => {
                        let value =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                        // TODO
                    }
                    "MaintenanceHistoryDays" => {
                        let value =
                            SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "Color" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "MasterKeyChanged" => {
                        let value =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                        // TODO
                    }
                    "MasterKeyChangeRec" => {
                        let value =
                            SimpleTag::<Option<isize>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "MasterKeyChangeForce" => {
                        let value =
                            SimpleTag::<Option<isize>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "MemoryProtection" => {
                        let value = MemoryProtection::from_xml(iterator, inner_cipher)?;
                        // TODO
                    }
                    "CustomIcons" => {
                        let value = CustomIcons::from_xml(iterator, inner_cipher)?;
                        // TODO
                    }
                    "RecycleBinEnabled" => {
                        let value =
                            SimpleTag::<Option<bool>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "RecycleBinUUID" => {
                        out.recyclebin_uuid =
                            SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "RecycleBinChanged" => {
                        let value =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                        // TODO
                    }
                    "EntryTemplatesGroup" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "EntryTemplatesGroupChanged" => {
                        let value =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                        // TODO
                    }
                    "LastSelectedGroup" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "LastTopVisibleGroup" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "HistoryMaxItems" => {
                        let value =
                            SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "HistoryMaxSize" => {
                        let value =
                            SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                    }
                    "SettingsChanged" => {
                        let value =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                        // TODO
                    }
                    "Binaries" => {
                        let value = BinaryAttachments::from_xml(iterator, inner_cipher)?;
                        // TODO figure out where this is needed. Is it only in KDBX3? How to
                        // migrate to KDBX4?
                    }
                    "CustomData" => {
                        let value = CustomData::from_xml(iterator, inner_cipher)?;
                        // TODO
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "Meta" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close Meta",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "Meta") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Meta tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Default)]
struct MemoryProtection {
    protect_title: bool,
    protect_username: bool,
    protect_password: bool,
    protect_url: bool,
    protect_notes: bool,
}

impl FromXml for MemoryProtection {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "MemoryProtection") {
            return Err(XmlParseError::BadEvent {
                expected: "Open MemoryProtection tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "ProtectTitle" => {
                        out.protect_title =
                            SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ProtectUserName" => {
                        out.protect_username =
                            SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ProtectPassword" => {
                        out.protect_password =
                            SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ProtectURL" => {
                        out.protect_url =
                            SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ProtectNotes" => {
                        out.protect_notes =
                            SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "MemoryProtection" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close MemoryProtection",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "MemoryProtection") {
            return Err(XmlParseError::BadEvent {
                expected: "Close MemoryProtection tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Default)]
struct BinaryAttachments {
    binaries: Vec<BinaryAttachment>,
}

impl FromXml for BinaryAttachments {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Binaries") {
            return Err(XmlParseError::BadEvent {
                expected: "Open Binaries tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Binary" => {
                        let binary = BinaryAttachment::from_xml(iterator, inner_cipher)?;
                        out.binaries.push(binary);
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "Binaries" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close Binaries",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "Binaries") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Binaries tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

impl FromXml for BinaryAttachment {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        let mut out = Self::default();
        let compressed = if let SimpleXmlEvent::Start(ref name, ref attributes) = open_tag {
            if name != "Binary" {
                return Err(XmlParseError::BadEvent {
                    expected: "Open Binary tag",
                    event: open_tag,
                });
            }

            attributes
                .get("Compressed")
                .map(|v| v.to_lowercase().parse())
                .unwrap_or(Ok(false))?
        } else {
            return Err(XmlParseError::BadEvent {
                expected: "Open Binary tag",
                event: open_tag,
            });
        };

        let data = String::from_xml(iterator, inner_cipher)?;
        let buf = base64_engine::STANDARD.decode(&data)?;

        out.content = if compressed {
            Decompress::decompress(&GZipCompression, &buf).map_err(XmlParseError::Compression)?
        } else {
            buf
        };

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "Binary") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Binary tag",
                event: close_tag,
            });
        }
        Ok(out)
    }
}

#[derive(Debug, Default)]
struct CustomIcons {
    icons: Vec<Icon>,
}

impl FromXml for CustomIcons {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "CustomIcons") {
            return Err(XmlParseError::BadEvent {
                expected: "Open CustomIcons tag",
                event: open_tag,
            });
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Icon" => {
                        let icon = Icon::from_xml(iterator, inner_cipher)?;
                        out.icons.push(icon);
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "CustomIcons" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close CustomIcons",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "CustomIcons") {
            return Err(XmlParseError::BadEvent {
                expected: "Close CustomIcons tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Default)]
struct Icon {
    uuid: String,
    data: Vec<u8>,
}

impl FromXml for Icon {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Icon") {
            return Err(XmlParseError::BadEvent {
                expected: "Open Icon tag",
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
                    "Data" => {
                        let data = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                        let buf = base64_engine::STANDARD.decode(&data)?;
                        out.data = buf;
                    }
                    _ => {
                        IgnoreSubfield::from_xml(iterator, inner_cipher)?;
                    }
                },
                SimpleXmlEvent::End(name) if name == "Icon" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close Icon",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "Icon") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Icon tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}
