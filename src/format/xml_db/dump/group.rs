use xml::writer::{EventWriter, XmlEvent as WriterEvent};

use crate::{
    crypt::ciphers::Cipher,
    db::{Group, Node},
    xml_db::dump::{DumpXml, SimpleTag},
};

impl DumpXml for Group {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Group"))?;

        SimpleTag("Name", &self.name).dump_xml(writer, inner_cipher)?;
        SimpleTag("UUID", &self.uuid).dump_xml(writer, inner_cipher)?;

        if let Some(ref value) = self.notes {
            SimpleTag("Notes", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(value) = self.icon_id {
            SimpleTag("IconID", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.custom_icon_uuid {
            SimpleTag("CustomIconUUID", value).dump_xml(writer, inner_cipher)?;
        }

        self.times.dump_xml(writer, inner_cipher)?;
        self.custom_data.dump_xml(writer, inner_cipher)?;

        SimpleTag("IsExpanded", self.is_expanded).dump_xml(writer, inner_cipher)?;

        if let Some(ref value) = self.default_autotype_sequence {
            SimpleTag("DefaultAutoTypeSequence", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.enable_autotype {
            SimpleTag("EnableAutoType", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.enable_searching {
            SimpleTag("EnableSearching", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.last_top_visible_entry {
            SimpleTag("LastTopVisibleEntry", value).dump_xml(writer, inner_cipher)?;
        }

        for child in &self.children {
            child.dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?; // Group

        Ok(())
    }
}

impl DumpXml for Node {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        match self {
            Node::Group(g) => g.dump_xml(writer, inner_cipher),
            Node::Entry(e) => e.dump_xml(writer, inner_cipher),
        }
    }
}
