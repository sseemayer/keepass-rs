use base64::{engine::general_purpose as base64_engine, Engine as _};
use xml::writer::{EventWriter, XmlEvent as WriterEvent};

use crate::{
    compression::{Compression, GZipCompression},
    crypt::ciphers::Cipher,
    db::meta::{BinaryAttachment, BinaryAttachments, CustomIcons, Icon, MemoryProtection, Meta},
    xml_db::dump::{DumpXml, SimpleTag},
};

impl DumpXml for Meta {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Meta"))?;

        if let Some(ref value) = self.generator {
            SimpleTag("Generator", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.database_name {
            SimpleTag("DatabaseName", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.database_name_changed {
            SimpleTag("DatabaseNameChanged", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.database_description {
            SimpleTag("DatabaseDescription", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.database_description_changed {
            SimpleTag("DatabaseDescriptionChanged", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.default_username {
            SimpleTag("DefaultUserName", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.default_username_changed {
            SimpleTag("DefaultUserNameChanged", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(value) = self.maintenance_history_days {
            SimpleTag("MaintenanceHistoryDays", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.color {
            SimpleTag("Color", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.master_key_changed {
            SimpleTag("MasterKeyChanged", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(value) = self.master_key_change_rec {
            SimpleTag("MasterKeyChangeRec", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(value) = self.master_key_change_force {
            SimpleTag("MasterKeyChangeForce", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.memory_protection {
            value.dump_xml(writer, inner_cipher)?;
        }

        self.custom_icons.dump_xml(writer, inner_cipher)?;

        if let Some(value) = self.recyclebin_enabled {
            SimpleTag("RecycleBinEnabled", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.recyclebin_uuid {
            SimpleTag("RecycleBinUUID", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.recyclebin_changed {
            SimpleTag("RecycleBinChanged", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.entry_templates_group {
            SimpleTag("EntryTemplatesGroup", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.entry_templates_group_changed {
            SimpleTag("EntryTemplatesGroupChanged", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.last_selected_group {
            SimpleTag("LastSelectedGroup", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.last_top_visible_group {
            SimpleTag("LastTopVisibleGroup", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(value) = self.history_max_items {
            SimpleTag("HistoryMaxItems", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(value) = self.history_max_size {
            SimpleTag("HistoryMaxSize", value).dump_xml(writer, inner_cipher)?;
        }

        if let Some(ref value) = self.settings_changed {
            SimpleTag("SettingsChanged", value).dump_xml(writer, inner_cipher)?;
        }

        self.binaries.dump_xml(writer, inner_cipher)?;

        self.custom_data.dump_xml(writer, inner_cipher)?;

        writer.write(WriterEvent::end_element())?;

        Ok(())
    }
}

impl DumpXml for MemoryProtection {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("MemoryProtection"))?;

        SimpleTag("ProtectTitle", self.protect_title).dump_xml(writer, inner_cipher)?;
        SimpleTag("ProtectUserName", self.protect_username).dump_xml(writer, inner_cipher)?;
        SimpleTag("ProtectPassword", self.protect_password).dump_xml(writer, inner_cipher)?;
        SimpleTag("ProtectURL", self.protect_url).dump_xml(writer, inner_cipher)?;
        SimpleTag("ProtectNotes", self.protect_notes).dump_xml(writer, inner_cipher)?;

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}

impl DumpXml for BinaryAttachments {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Binaries"))?;

        for bin in &self.binaries {
            bin.dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}

impl DumpXml for BinaryAttachment {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        _inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        let start_tag = WriterEvent::start_element("Binary");

        let start_tag = if let Some(ref id) = self.identifier {
            start_tag.attr("ID", id)
        } else {
            start_tag
        };

        let start_tag = if self.compressed {
            start_tag.attr("Compressed", "True")
        } else {
            start_tag
        };

        writer.write(start_tag)?;

        let data = if self.compressed {
            GZipCompression.compress(&self.content)?
        } else {
            self.content.clone()
        };

        let buf = base64_engine::STANDARD.encode(data);

        writer.write(WriterEvent::characters(&buf))?;

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}

impl DumpXml for CustomIcons {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("CustomIcons"))?;

        for icon in &self.icons {
            icon.dump_xml(writer, inner_cipher)?;
        }

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}

impl DumpXml for Icon {
    fn dump_xml<E: std::io::Write>(
        &self,
        writer: &mut EventWriter<E>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<(), xml::writer::Error> {
        writer.write(WriterEvent::start_element("Icon"))?;

        SimpleTag("UUID", &self.uuid).dump_xml(writer, inner_cipher)?;

        let buf = base64_engine::STANDARD.encode(&self.data);
        SimpleTag("Data", &buf).dump_xml(writer, inner_cipher)?;

        writer.write(WriterEvent::end_element())?;
        Ok(())
    }
}
