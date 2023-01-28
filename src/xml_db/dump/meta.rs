use xml::writer::{EventWriter, XmlEvent as WriterEvent};

use crate::{
    crypt::ciphers::Cipher,
    xml_db::dump::{DumpXml, SimpleTag},
    Meta,
};

impl DumpXml for Meta {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Meta"))?;

        SimpleTag("Generator", "keepass-rs").dump_xml(writer, inner_cipher)?;

        // TODO DatabaseName
        // TODO DatabaseNameChanged
        // TODO DatabaseDescription
        // TODO DatabaseDescriptionChanged
        // TODO DefaultUserName
        // TODO DefaultUserNameChanged
        // TODO DeletedObjects
        // TODO MaintenanceHistoryDays
        // TODO Color
        // TODO MasterKeyChanged
        // TODO MasterKeyChangeRec
        // TODO MasterKeyChangeForce
        // TODO MemoryProtection
        // TODO CustomIcons
        // TODO RecycleBinEnabled
        // TODO RecycleBinUUID
        // TODO RecycleBinChanged
        // TODO EntryTemplatesGroup
        // TODO EntryTemplatesGroupChanged
        // TODO LastSelectedGroup
        // TODO LastTopVisibleGroup
        // TODO HistoryMaxItems
        // TODO HistoryMaxSize
        // TODO SettingsChanged
        // TODO CustomData

        writer.write(WriterEvent::end_element())?;

        Ok(())
    }
}
