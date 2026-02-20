//! XML (de)serialization for KeePass databases.
//!
//! This module provides types that mirror the ones in `crate::db`, but are tailored to closely fit
//! the XMl structure of KeePass databases for easy `#[derive(Serialize, Deserialize)]`.
//!
//! See <https://keepass.info/help/download/KDBX_XML.xsd> for an XML schema.

pub mod custom_serde;
pub mod entry;
pub mod group;
pub mod meta;
pub mod times;
pub mod timestamp;

use serde::{Deserialize, Serialize, Serializer};

use base64::{engine::general_purpose as base64_engine, Engine as _};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    crypt::ciphers::Cipher,
    format::xml_db::{
        custom_serde::cs_opt_string, entry::UnprotectError, group::Group, meta::Meta, timestamp::Timestamp,
    },
};
#[cfg(feature = "save_kdbx4")]
use crate::{crypt::CryptographyError, db::DatabaseSaveError};

pub fn parse_xml(
    data: &[u8],
    header_attachments: &[crate::db::Attachment],
    inner_decryptor: &mut dyn Cipher,
) -> Result<crate::db::Database, ParseXmlError> {
    let kdbx: KeePassFile = quick_xml::de::from_reader(data)?;
    Ok(kdbx.xml_to_db(inner_decryptor, header_attachments)?)
}

#[derive(Debug, Error)]
pub enum ParseXmlError {
    #[error("Error parsing XML inside KDBX: {0}")]
    Xml(#[from] quick_xml::DeError),

    #[error("Error unprotecting entry: {0}")]
    Unprotect(#[from] UnprotectError),
}

#[cfg(feature = "save_kdbx4")]
pub fn to_xml(
    db: &crate::db::Database,
    inner_encryptor: &mut dyn Cipher,
) -> Result<(Vec<u8>, Vec<crate::db::Attachment>), DatabaseSaveError> {
    let mut attachments = Vec::new();

    let kdbx = KeePassFile::db_to_xml(db, inner_encryptor, &mut attachments)?;
    let xml = quick_xml::se::to_string_with_root("KeePassFile", &kdbx)?
        .as_bytes()
        .to_vec();

    Ok((xml, attachments))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeePassFile {
    meta: Meta,
    root: Root,
}

impl KeePassFile {
    /// Convert from XML representation to database representation.
    fn xml_to_db(
        mut self,
        inner_decryptor: &mut dyn Cipher,
        header_attachments: &[crate::db::Attachment],
    ) -> Result<crate::db::Database, UnprotectError> {
        let mut db = crate::db::Database::new(Default::default());
        db.root.uuid = self.root.group.uuid.0;

        let mut attachments = header_attachments.to_vec();
        if let Some(binaries) = self.meta.binaries.take() {
            for binary in binaries.binaries {
                attachments.push(binary.xml_to_db(inner_decryptor));
            }
        }

        let custom_icons = self.meta.custom_icons.take();
        let custom_icons: HashMap<Uuid, Vec<u8>> = custom_icons
            .map(|ci| {
                ci.icons
                    .into_iter()
                    .map(|icon| (icon.uuid.0, icon.data))
                    .collect()
            })
            .unwrap_or_default();

        db.meta = self.meta.into();

        db.deleted_objects = self
            .root
            .deleted_objects
            .map(|del_objs| {
                del_objs
                    .objects
                    .into_iter()
                    .map(|obj| (obj.uuid.0, obj.deletion_time.map(|ts| ts.time)))
                    .collect()
            })
            .unwrap_or_default();

        self.root
            .group
            .xml_to_db_handle(&mut db.root, &attachments, &custom_icons, inner_decryptor)?;

        Ok(db)
    }

    /// Convert from database representation to XML representation.
    #[cfg(feature = "save_kdbx4")]
    fn db_to_xml(
        db: &crate::db::Database,
        inner_cipher: &mut dyn Cipher,
        attachments: &mut Vec<crate::db::Attachment>,
    ) -> Result<Self, CryptographyError> {
        use crate::format::xml_db::meta::Icon;

        let mut custom_icons = HashMap::new();

        let group = Group::db_to_xml(&db.root, inner_cipher, attachments, &mut custom_icons)?;

        let mut meta: Meta = db.meta.clone().into();
        meta.custom_icons
            .get_or_insert_default()
            .icons
            .extend(custom_icons.into_iter().map(|(uuid, data)| Icon {
                uuid: UUID(uuid),
                data,
            }));

        let deleted_objects = if db.deleted_objects.is_empty() {
            None
        } else {
            Some(DeletedObjects {
                objects: db
                    .deleted_objects
                    .iter()
                    .map(|(uuid, deletion_time)| DeletedObject {
                        uuid: UUID(*uuid),
                        deletion_time: deletion_time.map(Timestamp::new_iso8601),
                    })
                    .collect(),
            })
        };

        Ok(KeePassFile {
            meta,
            root: Root {
                group,
                deleted_objects,
            },
        })
    }
}

/// A UUID deserialized from a Base64 string.
#[allow(clippy::upper_case_acronyms)] // Keep the name consistent with KeePass XML schema
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UUID(Uuid);

impl<'de> Deserialize<'de> for UUID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;

        let v = base64_engine::STANDARD
            .decode(input)
            .map_err(serde::de::Error::custom)?;

        let uuid = Uuid::from_slice(&v).map_err(serde::de::Error::custom)?;
        Ok(UUID(uuid))
    }
}

impl Serialize for UUID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let b64 = base64_engine::STANDARD.encode(self.0.as_bytes());
        serializer.serialize_str(&b64)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Root {
    #[serde(rename = "Group")]
    pub group: Group,

    #[serde(default, rename = "DeletedObjects")]
    pub deleted_objects: Option<DeletedObjects>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeletedObjects {
    #[serde(default, rename = "DeletedObject")]
    pub objects: Vec<DeletedObject>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeletedObject {
    #[serde(rename = "UUID")]
    uuid: UUID,

    #[serde(default, with = "cs_opt_string")]
    deletion_time: Option<Timestamp>,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Test<T>(T);

    #[test]
    fn test_deserialize_uuid() {
        let uuid_str = "AAECAwQFBgcICQoLDA0ODw==";
        let uuid: UUID = quick_xml::de::from_str(&format!("{}", uuid_str)).unwrap();
        assert_eq!(
            uuid.0.as_bytes(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        );
    }

    #[test]
    fn test_serialize_uuid() {
        let uuid = UUID(Uuid::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]));
        let serialized = quick_xml::se::to_string(&Test(uuid)).unwrap();
        assert_eq!(serialized, "<Test>AAECAwQFBgcICQoLDA0ODw==</Test>");
    }
}
