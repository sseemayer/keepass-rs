use base64::{engine::general_purpose as base64_engine, Engine as _};
use chrono::NaiveDateTime;

use crate::{
    compression::{Decompress, GZipCompression},
    meta::{BinaryAttachment, BinaryAttachments, CustomIcons, Icon, MemoryProtection},
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
                        out.generator =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "HeaderHash" => {
                        // this seems to be only present in kdbx3 databases.
                        let _header_hash =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DatabaseName" => {
                        out.database_name =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DatabaseNameChanged" => {
                        out.database_name_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                    }
                    "DatabaseDescription" => {
                        out.database_description =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DatabaseDescriptionChanged" => {
                        out.database_description_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                    }
                    "DefaultUserName" => {
                        out.default_username =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DefaultUserNameChanged" => {
                        out.default_username_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                    }
                    "MaintenanceHistoryDays" => {
                        out.maintenance_history_days =
                            SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Color" => {
                        out.color =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "MasterKeyChanged" => {
                        out.master_key_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                    }
                    "MasterKeyChangeRec" => {
                        out.master_key_change_rec =
                            SimpleTag::<Option<isize>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "MasterKeyChangeForce" => {
                        out.master_key_change_force =
                            SimpleTag::<Option<isize>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "MemoryProtection" => {
                        out.memory_protection =
                            Some(MemoryProtection::from_xml(iterator, inner_cipher)?);
                    }
                    "CustomIcons" => {
                        out.custom_icons = CustomIcons::from_xml(iterator, inner_cipher)?;
                    }
                    "RecycleBinEnabled" => {
                        out.recyclebin_enabled =
                            SimpleTag::<Option<bool>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "RecycleBinUUID" => {
                        out.recyclebin_uuid =
                            SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "RecycleBinChanged" => {
                        out.recyclebin_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                    }
                    "EntryTemplatesGroup" => {
                        out.entry_templates_group =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "EntryTemplatesGroupChanged" => {
                        out.entry_templates_group_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                    }
                    "LastSelectedGroup" => {
                        out.last_selected_group =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "LastTopVisibleGroup" => {
                        out.last_top_visible_group =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "HistoryMaxItems" => {
                        out.history_max_items =
                            SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "HistoryMaxSize" => {
                        out.history_max_size =
                            SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "SettingsChanged" => {
                        out.settings_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?
                                .value;
                    }
                    "Binaries" => {
                        out.binaries = BinaryAttachments::from_xml(iterator, inner_cipher)?;
                        // TODO figure out where this is needed. Is it only in KDBX3? How to
                        // migrate to KDBX4?
                    }
                    "CustomData" => {
                        out.custom_data = CustomData::from_xml(iterator, inner_cipher)?;
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
