use base64::{engine::general_purpose as base64_engine, Engine as _};
use chrono::NaiveDateTime;
use uuid::Uuid;

use crate::{
    compression::{Compression, GZipCompression},
    db::{
        meta::{BinaryAttachment, BinaryAttachments, CustomIcons, Icon, MemoryProtection, Meta},
        Color,
    },
    xml_db::parse::{bad_event, CustomData, FromXml, IgnoreSubfield, SimpleTag, SimpleXmlEvent, XmlParseError},
};

impl FromXml for Meta {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = crate::xml_db::parse::SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, crate::xml_db::parse::XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Meta") {
            return Err(bad_event("Open Meta tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Generator" => {
                        out.generator = SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DatabaseName" => {
                        out.database_name =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DatabaseNameChanged" => {
                        out.database_name_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DatabaseDescription" => {
                        out.database_description =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DatabaseDescriptionChanged" => {
                        out.database_description_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DefaultUserName" => {
                        out.default_username =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "DefaultUserNameChanged" => {
                        out.default_username_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "MaintenanceHistoryDays" => {
                        out.maintenance_history_days =
                            SimpleTag::<Option<usize>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Color" => {
                        out.color = SimpleTag::<Option<Color>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "MasterKeyChanged" => {
                        out.master_key_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?.value;
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
                        out.memory_protection = Some(MemoryProtection::from_xml(iterator, inner_cipher)?);
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
                            SimpleTag::<Option<Uuid>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "RecycleBinChanged" => {
                        out.recyclebin_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "EntryTemplatesGroup" => {
                        out.entry_templates_group =
                            SimpleTag::<Option<Uuid>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "EntryTemplatesGroupChanged" => {
                        out.entry_templates_group_changed =
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "LastSelectedGroup" => {
                        out.last_selected_group =
                            SimpleTag::<Option<Uuid>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "LastTopVisibleGroup" => {
                        out.last_top_visible_group =
                            SimpleTag::<Option<Uuid>>::from_xml(iterator, inner_cipher)?.value;
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
                            SimpleTag::<Option<NaiveDateTime>>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Binaries" => {
                        out.binaries = BinaryAttachments::from_xml(iterator, inner_cipher)?;
                        // TODO figure out where this is needed. Is it only in KDBX3? How to
                        // migrate to KDBX4?
                    }
                    "CustomData" => {
                        out.custom_data = CustomData::from_xml(iterator, inner_cipher)?;
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "Meta" => break,
                _ => return Err(bad_event("start tag or close Meta", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

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
            return Err(bad_event("Open MemoryProtection tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "ProtectTitle" => {
                        out.protect_title = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ProtectUserName" => {
                        out.protect_username = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ProtectPassword" => {
                        out.protect_password = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ProtectURL" => {
                        out.protect_url = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "ProtectNotes" => {
                        out.protect_notes = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "MemoryProtection" => break,
                _ => return Err(bad_event("start tag or close MemoryProtection", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

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
            return Err(bad_event("Open Binaries tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Binary" => {
                        let binary = BinaryAttachment::from_xml(iterator, inner_cipher)?;
                        out.binaries.push(binary);
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "Binaries" => break,
                _ => return Err(bad_event("start tag or close Binaries", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

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
        let (identifier, compressed) = if let SimpleXmlEvent::Start(ref name, ref attributes) = open_tag {
            if name != "Binary" {
                return Err(bad_event("Open Binary tag", open_tag));
            }

            let identifier = attributes.get("ID").map(|s| s.to_string());

            let compressed = attributes
                .get("Compressed")
                .map(|v| v.to_lowercase().parse())
                .unwrap_or(Ok(false))?;

            (identifier, compressed)
        } else {
            return Err(bad_event("Open Binary tag", open_tag));
        };

        let data = String::from_xml(iterator, inner_cipher)?;
        let buf = base64_engine::STANDARD.decode(&data)?;

        out.identifier = identifier;
        out.compressed = compressed;
        out.content = if compressed {
            Compression::decompress(&GZipCompression, &buf).map_err(XmlParseError::Compression)?
        } else {
            buf
        };

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

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
            return Err(bad_event("Open CustomIcons tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "Icon" => {
                        let icon = Icon::from_xml(iterator, inner_cipher)?;
                        out.icons.push(icon);
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "CustomIcons" => break,
                _ => return Err(bad_event("start tag or close CustomIcons", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

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
            return Err(bad_event("Open Icon tag", open_tag));
        }

        let mut out = Self::default();

        while let Some(event) = iterator.peek() {
            match event {
                SimpleXmlEvent::Start(name, _) => match &name[..] {
                    "UUID" => {
                        out.uuid = SimpleTag::<Uuid>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Data" => {
                        let data = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                        let buf = base64_engine::STANDARD.decode(&data)?;
                        out.data = buf;
                    }
                    _ => IgnoreSubfield::from_xml(iterator, inner_cipher)?,
                },
                SimpleXmlEvent::End(name) if name == "Icon" => break,
                _ => return Err(bad_event("start tag or close Icon", event.clone())),
            }
        }

        // no need to check for the correct closing tag - checked by XmlReader
        let _close_tag = iterator.next().ok_or(XmlParseError::Eof)?;

        Ok(out)
    }
}

#[cfg(test)]
mod parse_meta_test {

    use crate::{
        db::meta::{BinaryAttachment, BinaryAttachments, CustomIcons, Icon, MemoryProtection, Meta},
        xml_db::parse::{parse_test::parse_test_xml, XmlParseError},
    };

    use uuid::uuid;

    #[test]
    fn test_meta() -> Result<(), XmlParseError> {
        let _value = parse_test_xml::<Meta>("<Meta></Meta>")?;

        let value = parse_test_xml::<Meta>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Meta>("<Meta></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Meta>("<Meta>No-Characters-Allowed</Meta>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let _value = parse_test_xml::<Meta>("<Meta><UnkownChildTag/></Meta>")?;

        Ok(())
    }

    #[test]
    fn test_memory_protection() -> Result<(), XmlParseError> {
        let _value = parse_test_xml::<MemoryProtection>("<MemoryProtection></MemoryProtection>")?;

        let value = parse_test_xml::<MemoryProtection>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<MemoryProtection>("<MemoryProtection></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value =
            parse_test_xml::<MemoryProtection>("<MemoryProtection>No-Characters-Allowed</MemoryProtection>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let _value =
            parse_test_xml::<MemoryProtection>("<MemoryProtection><UnkownChildTag/></MemoryProtection>")?;

        Ok(())
    }

    #[test]
    fn test_binary_attachments() -> Result<(), XmlParseError> {
        let _value = parse_test_xml::<BinaryAttachments>("<Binaries></Binaries>")?;

        let value = parse_test_xml::<BinaryAttachments>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryAttachments>("<Binaries></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryAttachments>("<Binaries>No-Characters-Allowed</Binaries>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let _value = parse_test_xml::<BinaryAttachments>("<Binaries><UnkownChildTag/></Binaries>")?;

        Ok(())
    }

    #[test]
    fn test_binary_attachment() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<BinaryAttachment>("<Binary ID=\"1\">QmluYXJ5IERhdGE=</Binary>")?;
        assert_eq!(value.identifier, Some("1".to_string()));
        assert_eq!(value.content, r"Binary Data".as_bytes());

        let value = parse_test_xml::<BinaryAttachment>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryAttachment>("");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryAttachment>("<Binary></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryAttachment>("<Binary></Binary>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<BinaryAttachment>("<Binary><UnkownChildTag/></Binary>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        Ok(())
    }

    #[test]
    fn test_custom_icons() -> Result<(), XmlParseError> {
        let _value = parse_test_xml::<CustomIcons>("<CustomIcons></CustomIcons>")?;

        let value = parse_test_xml::<CustomIcons>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomIcons>("<CustomIcons></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<CustomIcons>("<CustomIcons>No-Characters-Allowed</CustomIcons>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let _value = parse_test_xml::<CustomIcons>("<CustomIcons><UnkownChildTag/></CustomIcons>")?;

        Ok(())
    }

    #[test]
    fn test_custom_icon() -> Result<(), XmlParseError> {
        let value = parse_test_xml::<Icon>("<Icon></Icon>")?;
        assert_eq!(value.uuid, Default::default());
        assert_eq!(value.data.len(), 0);

        let value = parse_test_xml::<Icon>(
            "<Icon><UUID>oaKjpLGywcLR0tPU1dbX2A==</UUID><Data>QmluYXJ5IERhdGE=</Data></Icon>",
        )?;
        assert_eq!(value.uuid, uuid!("a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"),);
        assert_eq!(value.data, r"Binary Data".as_bytes());

        let value = parse_test_xml::<Icon>("<TestTag>SomeData</TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Icon>("<Icon></TestTag>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let value = parse_test_xml::<Icon>("<Icon>No-Characters-Allowed</Icon>");
        assert!(matches!(value, Err(XmlParseError::BadEvent { .. })));

        let _value = parse_test_xml::<Icon>("<Icon><UnkownChildTag/></Icon>")?;

        Ok(())
    }
}
