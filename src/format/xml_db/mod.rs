//! XML (de)serialization for KeePass databases.
//!
//! This module provides types that mirror the ones in `crate::db`, but are tailored to closely fit
//! the XMl structure of KeePass databases for easy `#[derive(Serialize, Deserialize)]`.
//!
//! The `XmlBridge` trait provides conversion methods between these XML-specific types and the
//! user-facing types in `crate::db`.
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
use uuid::Uuid;

use crate::{
    crypt::ciphers::Cipher,
    format::xml_db::{
        custom_serde::cs_opt_string,
        group::Group,
        meta::{Icon, Meta},
        timestamp::Timestamp,
    },
};

pub fn parse_xml(
    data: &[u8],
    header_attachments: &[crate::db::Attachment],
    inner_decryptor: &mut dyn Cipher,
) -> Result<crate::db::Database, quick_xml::DeError> {
    let kdbx: KeePassFile = quick_xml::de::from_reader(data)?;
    Ok(kdbx.xml_to_db(inner_decryptor, header_attachments))
}

#[cfg(feature = "save_kdbx4")]
pub fn to_xml(
    db: &crate::db::Database,
    inner_encryptor: &mut dyn Cipher,
) -> Result<Vec<u8>, quick_xml::SeError> {
    let kdbx = KeePassFile::db_to_xml(db, inner_encryptor);
    Ok(quick_xml::se::to_string_with_root("KeePassFile", &kdbx)?
        .as_bytes()
        .to_vec())
}

/// Bridge between the XML representation of a KeePass database and the user-facing types in `crate::db`.
///
/// The trait should be implemented for types in `crate::format::xml_db`, and `DbType` should be
/// the corresponding type in `crate::db`.
pub trait XmlBridge {
    type DbType;

    fn xml_to_db(
        self,
        inner_decryptor: &mut dyn Cipher,
        header_attachments: &[crate::db::Attachment],
    ) -> Self::DbType;

    #[cfg(feature = "save_kdbx4")]
    fn db_to_xml(db: &Self::DbType, inner_encryptor: &mut dyn Cipher) -> Self;
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeePassFile {
    meta: Meta,
    root: Root,
}

impl XmlBridge for KeePassFile {
    type DbType = crate::db::Database;

    fn xml_to_db(
        mut self,
        inner_decryptor: &mut dyn Cipher,
        header_attachments: &[crate::db::Attachment],
    ) -> Self::DbType {
        let mut db = crate::db::Database::new();
        let mut attachments = header_attachments.to_vec();

        let custom_icons = self.meta.custom_icons.take();

        if let Some(binaries) = self.meta.binaries.take() {
            for binary in binaries.binaries {
                let attachment = binary.xml_to_db(inner_decryptor, header_attachments);
                attachments.push(attachment);
            }
        }

        db.meta = Meta::xml_to_db(self.meta, inner_decryptor, &attachments);

        db.custom_icons = custom_icons
            .map(|ci| {
                ci.icons
                    .into_iter()
                    .map(|icon| Icon::xml_to_db(icon, inner_decryptor, &attachments))
                    .collect()
            })
            .unwrap_or_default();

        self.root.group.xml_to_db_handle(db.root_mut(), &attachments);

        db
    }

    #[cfg(feature = "save_kdbx4")]
    fn db_to_xml(_: &Self::DbType, _: &mut dyn Cipher) -> Self {
        todo!()
    }
}

/// A UUID deserialized from a Base64 string.
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

    #[serde(rename = "DeletedObjects")]
    pub deleted_objects: Option<DeletedObjects>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeletedObjects {
    #[serde(rename = "DeletedObject")]
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
