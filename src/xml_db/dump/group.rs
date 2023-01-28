use xml::writer::{EventWriter, XmlEvent as WriterEvent};

use crate::{
    crypt::ciphers::Cipher,
    xml_db::dump::{DumpXml, SimpleTag},
    Group, Node,
};

impl DumpXml for Group {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Group"))?;

        // TODO IconId
        // TODO Notes

        SimpleTag("Name", &self.name).dump_xml(writer, inner_cipher)?;
        SimpleTag("UUID", &self.uuid).dump_xml(writer, inner_cipher)?;

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
