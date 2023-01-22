use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::{
    writer::{EventWriter, XmlEvent as WriterEvent},
    EmitterConfig,
};

use crate::{
    crypt::ciphers::Cipher,
    db::{Database, Entry, Group, Meta, Node, Times, Value},
    xml_db::get_epoch_baseline,
};

/// Format a timestamp suitable for an XML database
pub fn format_xml_timestamp(timestamp: &chrono::NaiveDateTime) -> String {
    let timestamp = timestamp.timestamp() - get_epoch_baseline().timestamp();
    let timestamp_bytes = i64::to_le_bytes(timestamp);
    base64_engine::STANDARD.encode(timestamp_bytes)
}

pub(crate) fn dump(
    db: &Database,
    inner_cipher: &mut dyn Cipher,
) -> Result<Vec<u8>, xml::writer::Error> {
    let mut data: Vec<u8> = Vec::new();
    let mut writer = EmitterConfig::new()
        .perform_indent(false)
        .create_writer(&mut data);

    db.dump_xml(&mut writer, inner_cipher)?;

    Ok(data)
}

/// A trait that denotes an inner KeePass database object can be stored into an XML database.
///
/// Using an `xml::writer::EventWriter` and an inner cipher, emit a series of `XmlEvent`s to the
/// writer to build up the XML document.
pub(crate) trait DumpXml {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error>;
}

impl DumpXml for &chrono::NaiveDateTime {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::characters(&format_xml_timestamp(self)))
    }
}

impl DumpXml for bool {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::characters(if *self {
            "True"
        } else {
            "False"
        }))
    }
}

impl DumpXml for usize {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::characters(&format!("{}", self)))
    }
}

impl DumpXml for &str {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::characters(self))
    }
}

impl DumpXml for &String {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::characters(self))
    }
}

/// Convenience type for simplified serialization of single-value elements.
struct SimpleTag<S: AsRef<str>, D: DumpXml>(S, D);

impl<S: AsRef<str>, D: DumpXml> DumpXml for SimpleTag<S, D> {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element(self.0.as_ref()))?;
        self.1.dump_xml(writer, inner_cipher)?;
        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}

impl DumpXml for Value {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        match self {
            Value::Bytes(b) => SimpleTag("Value", std::str::from_utf8(b).expect("utf-8"))
                .dump_xml(writer, inner_cipher),
            Value::Unprotected(s) => SimpleTag("Value", s).dump_xml(writer, inner_cipher),
            Value::Protected(p) => {
                writer.write(WriterEvent::start_element("Value").attr("Protected", "True"))?;

                let encrypted_value = inner_cipher
                    .encrypt(p.unsecure())
                    .expect("Encrypt with inner cipher");

                let protected_value = base64_engine::STANDARD.encode(&encrypted_value);

                writer.write(WriterEvent::characters(&protected_value))?;

                writer.write(WriterEvent::end_element())?;
                Ok(())
            }
        }
    }
}

impl DumpXml for Database {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("KeePassFile"))?;

        self.meta.dump_xml(writer, inner_cipher)?;

        writer.write(WriterEvent::start_element("Root"))?;

        self.root.dump_xml(writer, inner_cipher)?;

        writer.write(WriterEvent::end_element())?; // Root

        writer.write(WriterEvent::end_element())?; // KeePassFile

        Ok(())
    }
}

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

impl DumpXml for Entry {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Entry"))?;

        // TODO IconId
        // TODO Times
        // TODO AutoType
        // TODO History
        // TODO ForegroundColor
        // TODO BackgroundColor

        SimpleTag("UUID", &self.uuid).dump_xml(writer, inner_cipher)?;

        SimpleTag("Tags", &self.tags.join(";")).dump_xml(writer, inner_cipher)?;

        self.times.dump_xml(writer, inner_cipher)?;

        for (field_name, field_value) in &self.fields {
            writer.write(WriterEvent::start_element("String"))?;

            SimpleTag("Key", field_name).dump_xml(writer, inner_cipher)?;
            field_value.dump_xml(writer, inner_cipher)?;

            writer.write(WriterEvent::end_element())?; // String
        }

        writer.write(WriterEvent::end_element())?; // Entry

        Ok(())
    }
}

impl DumpXml for Times {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Times"))?;
        for (time_name, time) in &self.times {
            SimpleTag(time_name, time).dump_xml(writer, inner_cipher)?;
        }

        SimpleTag("Expires", self.expires).dump_xml(writer, inner_cipher)?;
        SimpleTag("UsageCount", self.usage_count).dump_xml(writer, inner_cipher)?;

        writer.write(WriterEvent::end_element())?;

        Ok(())
    }
}
