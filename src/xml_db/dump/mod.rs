mod entry;
mod group;
mod meta;

use std::io::Write;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::{
    writer::{EventWriter, XmlEvent as WriterEvent},
    EmitterConfig,
};

use crate::{
    crypt::ciphers::Cipher,
    db::{CustomData, CustomDataItem, Database, Times},
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
    writer: &mut dyn Write,
) -> Result<(), xml::writer::Error> {
    let mut xml_writer = EmitterConfig::new()
        .perform_indent(false)
        .create_writer(writer);

    db.dump_xml(&mut xml_writer, inner_cipher)?;

    Ok(())
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

impl DumpXml for isize {
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

impl DumpXml for CustomData {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("CustomData"))?;

        for item in &self.items {
            item.dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?;

        Ok(())
    }
}

impl DumpXml for CustomDataItem {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Item"))?;

        SimpleTag("Key", &self.key).dump_xml(writer, inner_cipher)?;

        if let Some(ref value) = self.value {
            value.dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.last_modification_time {
            SimpleTag("LastModificationTime", value).dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}
