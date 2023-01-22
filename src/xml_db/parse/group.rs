use crate::{
    xml_db::parse::{FromXml, SimpleTag, SimpleXmlEvent, XmlParseError},
    Entry, Group, Node, Times,
};

impl FromXml for Group {
    type Parses = Self;

    fn from_xml<I: Iterator<Item = super::SimpleXmlEvent>>(
        iterator: &mut std::iter::Peekable<I>,
        inner_cipher: &mut dyn crate::crypt::ciphers::Cipher,
    ) -> Result<Self::Parses, super::XmlParseError> {
        let open_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(open_tag, SimpleXmlEvent::Start(ref tag, _) if tag == "Group") {
            return Err(XmlParseError::BadEvent {
                expected: "Open Group tag",
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
                    "Name" => {
                        out.name = SimpleTag::<String>::from_xml(iterator, inner_cipher)?.value;
                    }
                    "Notes" => {
                        let notes =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                        // out.notes = notes;
                    }
                    "IconID" => {
                        let icon_id = SimpleTag::<usize>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                        // out.icon_id = icon_id;
                    }
                    "Times" => {
                        out.times = Times::from_xml(iterator, inner_cipher)?;
                    }
                    "IsExpanded" => {
                        let expanded = SimpleTag::<bool>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                        // out.is_expanded = expanded;
                    }
                    "DefaultAutoTypeSequence" => {
                        let ats =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                        // out.default_autotype_sequence = ats;
                    }
                    "EnableAutoType" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                        // out.enable_autotype = value;
                    }
                    "EnableSearching" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                        // out.enable_searching = value;
                    }
                    "LastTopVisibleEntry" => {
                        let value =
                            SimpleTag::<Option<String>>::from_xml(iterator, inner_cipher)?.value;
                        // TODO
                        // out.last_top_visible_entry = value;
                    }
                    "Entry" => {
                        let entry = Entry::from_xml(iterator, inner_cipher)?;
                        out.children.push(Node::Entry(entry));
                    }
                    "Group" => {
                        let group = Group::from_xml(iterator, inner_cipher)?;
                        out.children.push(Node::Group(group));
                    }
                    _ => {
                        return Err(XmlParseError::BadEvent {
                            expected: "valid Group child",
                            event: event.clone(),
                        })
                    }
                },
                SimpleXmlEvent::End(name) if name == "Group" => break,
                _ => {
                    return Err(XmlParseError::BadEvent {
                        expected: "start tag or close Group",
                        event: event.clone(),
                    })
                }
            }
        }

        let close_tag = iterator.next().ok_or(XmlParseError::Eof)?;
        if !matches!(close_tag, SimpleXmlEvent::End(ref tag) if tag == "Group") {
            return Err(XmlParseError::BadEvent {
                expected: "Close Group tag",
                event: close_tag,
            });
        }

        Ok(out)
    }
}
