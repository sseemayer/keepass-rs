use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::writer::{EventWriter, XmlEvent as WriterEvent};

use crate::{
    crypt::ciphers::Cipher,
    xml_db::dump::{DumpXml, SimpleTag},
    Entry, Value,
};

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
