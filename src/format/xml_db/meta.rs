use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose as base64_engine, Engine as _};

use crate::{
    compression::Compression,
    db::Color,
    format::xml_db::{
        custom_serde::{cs_base64, cs_opt_bool, cs_opt_fromstr, cs_opt_string},
        timestamp::Timestamp,
        UUID,
    },
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Meta {
    #[serde(default, with = "cs_opt_string")]
    generator: Option<String>,

    #[serde(default, with = "cs_opt_string")]
    database_name: Option<String>,

    #[serde(default, with = "cs_opt_string")]
    database_name_changed: Option<Timestamp>,

    #[serde(default, with = "cs_opt_string")]
    database_description: Option<String>,

    #[serde(default, with = "cs_opt_string")]
    database_description_changed: Option<Timestamp>,

    #[serde(default, with = "cs_opt_string")]
    default_username: Option<String>,

    #[serde(default, with = "cs_opt_string")]
    default_username_changed: Option<Timestamp>,

    #[serde(default, with = "cs_opt_fromstr")]
    maintenance_history_days: Option<usize>,

    #[serde(default, with = "cs_opt_string")]
    color: Option<Color>,

    #[serde(default, with = "cs_opt_string")]
    master_key_changed: Option<Timestamp>,

    #[serde(default, with = "cs_opt_fromstr")]
    master_key_change_rec: Option<isize>,

    #[serde(default, with = "cs_opt_fromstr")]
    master_key_change_force: Option<isize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    memory_protection: Option<MemoryProtection>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_icons: Option<CustomIcons>,

    #[serde(default, with = "cs_opt_bool")]
    recycle_bin_enabled: Option<bool>,

    #[serde(default, rename = "RecycleBinUUID", with = "cs_opt_string")]
    recycle_bin_uuid: Option<UUID>,

    #[serde(default, with = "cs_opt_string")]
    recycle_bin_changed: Option<Timestamp>,

    #[serde(default, with = "cs_opt_string")]
    entry_templates_group: Option<UUID>,

    #[serde(default, with = "cs_opt_string")]
    entry_templates_group_changed: Option<Timestamp>,

    #[serde(default, with = "cs_opt_string")]
    last_selected_group: Option<UUID>,

    #[serde(default, with = "cs_opt_string")]
    last_top_visible_group: Option<UUID>,

    #[serde(default, with = "cs_opt_fromstr")]
    history_max_items: Option<usize>,

    #[serde(default, with = "cs_opt_fromstr")]
    history_max_size: Option<usize>,

    #[serde(default, with = "cs_opt_string")]
    settings_changed: Option<Timestamp>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binaries: Option<Binaries>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    custom_data: Option<CustomData>,
}

impl From<Meta> for crate::db::Meta {
    fn from(val: Meta) -> Self {
        // NOTE: custom icons and binary attachments are moved out of the Meta into the main
        // database, so they are not converted here.
        crate::db::Meta {
            generator: val.generator,
            database_name: val.database_name,
            database_name_changed: val.database_name_changed.map(|t| t.time),
            database_description: val.database_description,
            database_description_changed: val.database_description_changed.map(|t| t.time),
            default_username: val.default_username,
            default_username_changed: val.default_username_changed.map(|t| t.time),
            maintenance_history_days: val.maintenance_history_days,
            color: val.color,
            master_key_changed: val.master_key_changed.map(|t| t.time),
            master_key_change_rec: val.master_key_change_rec,
            master_key_change_force: val.master_key_change_force,
            memory_protection: val.memory_protection.map(|mp| mp.into()),
            recyclebin_enabled: val.recycle_bin_enabled,
            recyclebin_uuid: val.recycle_bin_uuid.map(|u| u.0),
            recyclebin_changed: val.recycle_bin_changed.map(|t| t.time),
            entry_templates_group: val.entry_templates_group.map(|u| u.0),
            entry_templates_group_changed: val.entry_templates_group_changed.map(|t| t.time),
            last_selected_group: val.last_selected_group.map(|u| u.0),
            last_top_visible_group: val.last_top_visible_group.map(|u| u.0),
            history_max_items: val.history_max_items,
            history_max_size: val.history_max_size,
            settings_changed: val.settings_changed.map(|t| t.time),
            custom_data: val
                .custom_data
                .map(|cd| cd.xml_to_db().into_iter().collect())
                .unwrap_or_default(),
        }
    }
}

#[cfg(feature = "save_kdbx4")]
impl From<crate::db::Meta> for Meta {
    fn from(db: crate::db::Meta) -> Self {
        Self {
            generator: db.generator.clone(),
            database_name: db.database_name.clone(),
            database_name_changed: db.database_name_changed.as_ref().map(|t| (*t).into()),
            database_description: db.database_description.clone(),
            database_description_changed: db.database_description_changed.as_ref().map(|t| (*t).into()),
            default_username: db.default_username.clone(),
            default_username_changed: db.default_username_changed.as_ref().map(|t| (*t).into()),
            maintenance_history_days: db.maintenance_history_days,
            color: db.color.clone(),
            master_key_changed: db.master_key_changed.as_ref().map(|t| (*t).into()),
            master_key_change_rec: db.master_key_change_rec,
            master_key_change_force: db.master_key_change_force,
            memory_protection: db.memory_protection.as_ref().map(|mp| mp.clone().into()),
            custom_icons: None, // Handled separately
            recycle_bin_enabled: db.recyclebin_enabled,
            recycle_bin_uuid: db.recyclebin_uuid.map(UUID),
            recycle_bin_changed: db.recyclebin_changed.as_ref().map(|t| (*t).into()),
            entry_templates_group: db.entry_templates_group.map(UUID),
            entry_templates_group_changed: db.entry_templates_group_changed.as_ref().map(|t| (*t).into()),
            last_selected_group: db.last_selected_group.map(UUID),
            last_top_visible_group: db.last_top_visible_group.map(UUID),
            history_max_items: db.history_max_items,
            history_max_size: db.history_max_size,
            settings_changed: db.settings_changed.as_ref().map(|t| (*t).into()),
            binaries: None, // Handled separately
            custom_data: Some(CustomData::db_to_xml(
                &db.custom_data
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Vec<_>>(),
            )),
        }
    }
}

// Binaries (Meta/Binaries)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Binaries {
    #[serde(rename = "Binary", default)]
    pub binaries: Vec<Binary>,
}

// <Binary ID="..." Compressed="False" Protected="False">BASE64</Binary>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Binary {
    #[serde(rename = "$value")]
    pub value: String,

    #[serde(rename = "@ID")]
    pub id: usize,

    #[serde(rename = "@Compressed", default, with = "cs_opt_bool")]
    pub compressed: Option<bool>,

    #[serde(rename = "@Protected", default, with = "cs_opt_bool")]
    pub protected: Option<bool>,
}

impl Binary {
    pub(crate) fn xml_to_db(
        self,
        inner_decryptor: &mut dyn crate::crypt::ciphers::Cipher,
        id: crate::db::AttachmentId,
    ) -> crate::db::Attachment {
        let mut data = base64_engine::STANDARD.decode(self.value).unwrap_or_default();

        if self.protected.unwrap_or(false) {
            data = inner_decryptor.decrypt(&data).unwrap_or_default();
        }

        if self.compressed.unwrap_or(false) {
            data = crate::compression::GZipCompression
                .decompress(&data)
                .unwrap_or_default();
        }

        let mut attachment = crate::db::Attachment::with_id(id);
        attachment.protected = self.protected.unwrap_or(false);
        attachment.set_data(data);

        attachment
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CustomData {
    #[serde(default, rename = "Item")]
    items: Vec<CustomDataItem>,
}

impl CustomData {
    fn xml_to_db(self) -> Vec<(String, crate::db::CustomDataItem)> {
        self.items
            .into_iter()
            .map(|item| {
                let value = item.value.into();

                let last_modification_time = item.last_modification_time.map(|t| t.into());

                (
                    item.key,
                    crate::db::CustomDataItem {
                        value: Some(value),
                        last_modification_time,
                    },
                )
            })
            .collect()
    }

    #[cfg(feature = "save_kdbx4")]
    fn db_to_xml(db: &[(String, crate::db::CustomDataItem)]) -> Self {
        let items = db
            .iter()
            .map(|(key, item)| {
                let value = item
                    .value
                    .as_ref()
                    .map(|v| v.clone().into())
                    .unwrap_or(CustomDataValue::String(String::new()));

                let last_modification_time = item.last_modification_time.as_ref().map(|t| (*t).into());

                CustomDataItem {
                    key: key.clone(),
                    value,
                    last_modification_time,
                }
            })
            .collect();

        Self { items }
    }
}

impl From<HashMap<String, crate::db::CustomDataItem>> for CustomData {
    fn from(db: HashMap<String, crate::db::CustomDataItem>) -> Self {
        let items = db
            .into_iter()
            .map(|(key, item)| {
                let value = item
                    .value
                    .as_ref()
                    .map(|v| v.clone().into())
                    .unwrap_or(CustomDataValue::String(String::new()));

                let last_modification_time = item.last_modification_time.as_ref().map(|t| (*t).into());

                CustomDataItem {
                    key,
                    value,
                    last_modification_time,
                }
            })
            .collect();

        Self { items }
    }
}

impl From<CustomData> for HashMap<String, crate::db::CustomDataItem> {
    fn from(cd: CustomData) -> Self {
        cd.items
            .into_iter()
            .map(|item| {
                let value = item.value.into();

                let last_modification_time = item.last_modification_time.map(|t| t.into());

                (
                    item.key,
                    crate::db::CustomDataItem {
                        value: Some(value),
                        last_modification_time,
                    },
                )
            })
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Item", rename_all = "PascalCase")]
struct CustomDataItem {
    key: String,
    value: CustomDataValue,

    #[serde(default, with = "cs_opt_string")]
    last_modification_time: Option<Timestamp>,
}

#[derive(Debug)]
pub enum CustomDataValue {
    String(String),
    Binary(Vec<u8>),
}

impl From<CustomDataValue> for crate::db::CustomDataValue {
    fn from(val: CustomDataValue) -> Self {
        match val {
            CustomDataValue::String(s) => crate::db::CustomDataValue::String(s),
            CustomDataValue::Binary(b) => crate::db::CustomDataValue::Binary(b),
        }
    }
}

impl From<crate::db::CustomDataValue> for CustomDataValue {
    fn from(db: crate::db::CustomDataValue) -> Self {
        match db {
            crate::db::CustomDataValue::String(s) => CustomDataValue::String(s),
            crate::db::CustomDataValue::Binary(b) => CustomDataValue::Binary(b),
        }
    }
}

impl<'de> Deserialize<'de> for CustomDataValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Try to decode as base64, if it fails, treat it as a regular string
        match base64_engine::STANDARD.decode(&s) {
            Ok(v) => Ok(CustomDataValue::Binary(v)),
            Err(_) => Ok(CustomDataValue::String(s)),
        }
    }
}

impl Serialize for CustomDataValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CustomDataValue::String(s) => serializer.serialize_str(s),
            CustomDataValue::Binary(b) => {
                let b64 = base64_engine::STANDARD.encode(b);
                serializer.serialize_str(&b64)
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MemoryProtection {
    #[serde(default, with = "cs_opt_bool")]
    protect_title: Option<bool>,

    #[serde(default, with = "cs_opt_bool")]
    protect_username: Option<bool>,

    #[serde(default, with = "cs_opt_bool")]
    protect_password: Option<bool>,

    #[serde(default, with = "cs_opt_bool", rename = "ProtectURL")]
    protect_url: Option<bool>,

    #[serde(default, with = "cs_opt_bool")]
    protect_notes: Option<bool>,
}

impl From<MemoryProtection> for crate::db::MemoryProtection {
    fn from(val: MemoryProtection) -> Self {
        crate::db::MemoryProtection {
            protect_title: val.protect_title.unwrap_or(false),
            protect_username: val.protect_username.unwrap_or(false),
            protect_password: val.protect_password.unwrap_or(true),
            protect_url: val.protect_url.unwrap_or(false),
            protect_notes: val.protect_notes.unwrap_or(false),
        }
    }
}

impl From<crate::db::MemoryProtection> for MemoryProtection {
    fn from(db: crate::db::MemoryProtection) -> Self {
        Self {
            protect_title: Some(db.protect_title),
            protect_username: Some(db.protect_username),
            protect_password: Some(db.protect_password),
            protect_url: Some(db.protect_url),
            protect_notes: Some(db.protect_notes),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CustomIcons {
    #[serde(rename = "Icon", default)]
    pub icons: Vec<Icon>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Icon {
    #[serde(rename = "UUID")]
    pub uuid: UUID,

    #[serde(with = "cs_base64")]
    data: Vec<u8>,
}

impl From<Icon> for crate::db::Icon {
    fn from(xml: Icon) -> Self {
        Self {
            id: crate::db::IconId::from_uuid(xml.uuid.0),
            data: xml.data,
        }
    }
}

impl From<crate::db::Icon> for Icon {
    fn from(db: crate::db::Icon) -> Self {
        Self {
            uuid: UUID(db.id.to_uuid()),
            data: db.data,
        }
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use chrono::NaiveDateTime;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn test_serialize_custom_data() {
        let cd = CustomData {
            items: vec![
                CustomDataItem {
                    key: "example_key".to_string(),
                    value: CustomDataValue::String("example_value".to_string()),
                    last_modification_time: Some(Timestamp::new_base64(
                        NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
                    )),
                },
                CustomDataItem {
                    key: "binary_key".to_string(),
                    value: CustomDataValue::Binary(vec![1, 2, 3, 4, 5]),
                    last_modification_time: None,
                },
            ],
        };

        let serialized = quick_xml::se::to_string(&cd).unwrap();

        assert_eq!(
            serialized,
            "<CustomData><Item><Key>example_key</Key><Value>example_value</Value><LastModificationTime>cKSw3A4AAAA=</LastModificationTime></Item><Item><Key>binary_key</Key><Value>AQIDBAU=</Value><LastModificationTime/></Item></CustomData>"
        );
        assert!(serialized.contains("<Key>example_key</Key>"));
        assert!(serialized.contains("<Value>example_value</Value>"));
        assert!(serialized.contains("<Key>binary_key</Key>"));
        assert!(serialized.contains("<Value>AQIDBAU=</Value>")); // Base64 for [1,2,3,4,5]
    }

    #[test]
    fn test_deserialize_custom_data() {
        let xml = r#"<CustomData>
            <Item>
                <Key>example_key</Key>
                <Value>example_value</Value>
                <LastModificationTime>cKSw3A4AAAA=</LastModificationTime>
            </Item>
            <Item>
                <Key>binary_key</Key>
                <Value>AQIDBAU=</Value>
                <LastModificationTime>2023-10-05T12:34:56Z</LastModificationTime>
            </Item>
        </CustomData>"#;
        let cd: CustomData = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(cd.items.len(), 2);
        assert_eq!(cd.items[0].key, "example_key");
        match &cd.items[0].value {
            CustomDataValue::String(s) => assert_eq!(s, "example_value"),
            _ => panic!("Expected string value"),
        }
        assert_eq!(cd.items[1].key, "binary_key");
        match &cd.items[1].value {
            CustomDataValue::Binary(b) => assert_eq!(b, &vec![1, 2, 3, 4, 5]),
            _ => panic!("Expected binary value"),
        }
    }

    #[test]
    fn test_serialize_memory_protection() {
        let mp = MemoryProtection {
            protect_title: Some(true),
            protect_username: Some(false),
            protect_password: Some(true),
            protect_url: Some(false),
            protect_notes: Some(true),
        };

        let serialized = quick_xml::se::to_string(&mp).unwrap();
        assert_eq!(serialized, "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectUsername>False</ProtectUsername><ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>True</ProtectNotes></MemoryProtection>");
    }

    #[test]
    fn test_deserialize_memory_protection() {
        let mp: MemoryProtection = quick_xml::de::from_str( "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectUsername>False</ProtectUsername><ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>True</ProtectNotes></MemoryProtection>").unwrap();
        assert_eq!(mp.protect_title, Some(true));
        assert_eq!(mp.protect_username, Some(false));
        assert_eq!(mp.protect_password, Some(true));
        assert_eq!(mp.protect_url, Some(false));
        assert_eq!(mp.protect_notes, Some(true));
    }

    #[test]
    fn test_serialize_icon() {
        let icon = Icon {
            uuid: UUID(Uuid::from_bytes([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            ])),
            data: vec![1, 2, 3, 4, 5],
        };

        let serialized = quick_xml::se::to_string(&icon).unwrap();
        assert_eq!(
            serialized,
            "<Icon><UUID>AAECAwQFBgcICQoLDA0ODw==</UUID><Data>AQIDBAU=</Data></Icon>"
        );
    }

    #[test]
    fn test_deserialize_icon() {
        let xml = r#"<Icon>
            <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            <Data>AQIDBAU=</Data>
        </Icon>"#;
        let icon: Icon = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(
            icon.uuid.0.as_bytes(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        );
        assert_eq!(icon.data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_serialize_meta() {
        let meta = Meta {
            generator: Some("TestGenerator".to_string()),
            database_name: Some("TestDB".to_string()),
            database_name_changed: Some(Timestamp::new_iso8601(
                NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
            )),
            database_description: Some("A test database".to_string()),
            database_description_changed: Some(Timestamp::new_base64(
                NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
            )),
            default_username: Some("admin".to_string()),
            default_username_changed: Some(Timestamp::new_iso8601(
                NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
            )),
            maintenance_history_days: Some(30),
            color: Some(Color { r: 255, g: 0, b: 0 }),
            master_key_changed: Some(Timestamp::new_base64(
                NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
            )),
            master_key_change_rec: Some(-1),
            master_key_change_force: Some(42),
            memory_protection: Some(MemoryProtection {
                protect_title: Some(true),
                protect_username: Some(false),
                protect_password: Some(true),
                protect_url: Some(false),
                protect_notes: Some(true),
            }),
            custom_icons: Some(CustomIcons {
                icons: vec![Icon {
                    uuid: UUID(Uuid::from_bytes([
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                        0x0e, 0x0f,
                    ])),
                    data: vec![1, 2, 3, 4, 5],
                }],
            }),
            recycle_bin_enabled: Some(true),
            recycle_bin_uuid: Some(UUID(Uuid::from_bytes([
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            ]))),
            recycle_bin_changed: Some(Timestamp::new_iso8601(
                NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
            )),
            entry_templates_group: Some(UUID(Uuid::from_bytes([
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            ]))),
            entry_templates_group_changed: Some(Timestamp::new_base64(
                NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
            )),
            last_selected_group: Some(UUID(Uuid::from_bytes([
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
            ]))),
            last_top_visible_group: Some(UUID(Uuid::from_bytes([
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
            ]))),
            history_max_items: Some(10),
            history_max_size: Some(1048576),
            settings_changed: Some(Timestamp::new_iso8601(
                NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
            )),
            binaries: Some(Binaries {
                binaries: vec![
                    Binary {
                        id: 0,
                        value: base64_engine::STANDARD.encode(&[1, 2, 3, 4, 5]),
                        compressed: Some(false),
                        protected: Some(false),
                    },
                    Binary {
                        id: 1,
                        value: base64_engine::STANDARD.encode(&[10, 20, 30, 40, 50]),
                        compressed: Some(true),
                        protected: Some(true),
                    },
                ],
            }),
            custom_data: Some(CustomData {
                items: vec![
                    CustomDataItem {
                        key: "example_key".to_string(),
                        value: CustomDataValue::String("example_value".to_string()),
                        last_modification_time: Some(Timestamp::new_base64(
                            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
                        )),
                    },
                    CustomDataItem {
                        key: "binary_key".to_string(),
                        value: CustomDataValue::Binary(vec![1, 2, 3, 4, 5]),
                        last_modification_time: Some(Timestamp::new_iso8601(
                            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
                        )),
                    },
                ],
            }),
        };
        let serialized = quick_xml::se::to_string(&meta).unwrap();
        println!("{}", serialized);
        assert!(serialized.contains("<Generator>TestGenerator</Generator>"));
        assert!(serialized.contains("<DatabaseName>TestDB</DatabaseName>"));
        assert!(serialized.contains("<DatabaseNameChanged>2023-10-05T12:34:56Z</DatabaseNameChanged>"));
        assert!(serialized.contains("<DatabaseDescription>A test database</DatabaseDescription>"));
        assert!(serialized.contains("<DatabaseDescriptionChanged>cKSw3A4AAAA=</DatabaseDescriptionChanged>"));
        assert!(serialized.contains("<DefaultUsername>admin</DefaultUsername>"));
        assert!(serialized.contains("<DefaultUsernameChanged>2023-10-05T12:34:56Z</DefaultUsernameChanged>"));
        assert!(serialized.contains("<MaintenanceHistoryDays>30</MaintenanceHistoryDays>"));
        assert!(serialized.contains("<Color>#FF0000</Color>"));
        assert!(serialized.contains("<MasterKeyChanged>cKSw3A4AAAA=</MasterKeyChanged>"));
        assert!(serialized.contains("<MasterKeyChangeRec>-1</MasterKeyChangeRec>"));
        assert!(serialized.contains("<MasterKeyChangeForce>42</MasterKeyChangeForce>"));
        assert!(serialized.contains("<MemoryProtection>"));
        assert!(serialized.contains("<CustomIcons>"));
        assert!(serialized.contains("<RecycleBinEnabled>True</RecycleBinEnabled>"));
        assert!(serialized.contains("<RecycleBinUUID>EBESExQVFhcYGRobHB0eHw==</RecycleBinUUID>"));
        assert!(serialized.contains("<RecycleBinChanged>2023-10-05T12:34:56Z</RecycleBinChanged>"));
        assert!(serialized.contains("<EntryTemplatesGroup>ICEiIyQlJicoKSorLC0uLw==</EntryTemplatesGroup>"));
        assert!(serialized.contains("<EntryTemplatesGroupChanged>cKSw3A4AAAA=</EntryTemplatesGroupChanged>"));
        assert!(serialized.contains("<LastSelectedGroup>MDEyMzQ1Njc4OTo7PD0+Pw==</LastSelectedGroup>"));
        assert!(serialized.contains("<LastTopVisibleGroup>QEFCQ0RFRkdISUpLTE1OTw==</LastTopVisibleGroup>"));
        assert!(serialized.contains("<HistoryMaxItems>10</HistoryMaxItems>"));
        assert!(serialized.contains("<HistoryMaxSize>1048576</HistoryMaxSize>"));
        assert!(serialized.contains("<SettingsChanged>2023-10-05T12:34:56Z</SettingsChanged>"));
        assert!(serialized.contains("<Binaries>"));
        assert!(serialized.contains(r#"<Binary ID="0" Compressed="False" Protected="False">AQIDBAU=</Binary>"#));
        assert!(serialized.contains(r#"<Binary ID="1" Compressed="True" Protected="True">ChQeKDI=</Binary>"#));
        assert!(serialized.contains("<CustomData>"));
    }

    #[test]
    fn test_deserialize_meta() {
        let xml = r#"<Meta>
            <Generator>TestGenerator</Generator>
            <DatabaseName>TestDB</DatabaseName>
            <DatabaseNameChanged>2023-10-05T12:34:56Z</DatabaseNameChanged>
            <DatabaseDescription>A test database</DatabaseDescription>
            <DatabaseDescriptionChanged>cKSw3A4AAAA=</DatabaseDescriptionChanged>
            <DefaultUsername>admin</DefaultUsername>
            <DefaultUsernameChanged>2023-10-05T12:34:56Z</DefaultUsernameChanged>
            <MaintenanceHistoryDays>30</MaintenanceHistoryDays>
            <Color>#FF0000</Color>
            <MasterKeyChanged>cKSw3A4AAAA=</MasterKeyChanged>
            <MasterKeyChangeRec>-1</MasterKeyChangeRec>
            <MasterKeyChangeForce>42</MasterKeyChangeForce>
            <MemoryProtection>
                <ProtectTitle>True</ProtectTitle>
                <ProtectUsername>False</ProtectUsername>
                <ProtectPassword>True</ProtectPassword>
                <ProtectURL>False</ProtectURL>
                <ProtectNotes>True</ProtectNotes>
            </MemoryProtection>
            <CustomIcons>
                <Icon>
                    <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
                    <Data>AQIDBAU=</Data>
                </Icon>
            </CustomIcons>
            <RecycleBinEnabled>True</RecycleBinEnabled>
            <RecycleBinUUID>EBESExQVFhcYGRobHB0eHw==</RecycleBinUUID>
            <RecycleBinChanged>2023-10-05T12:34:56Z</RecycleBinChanged>
            <EntryTemplatesGroup>ICEiIyQlJicoKSorLC0uLw==</EntryTemplatesGroup>
            <EntryTemplatesGroupChanged>cKSw3A4AAAA=</EntryTemplatesGroupChanged>
            <LastSelectedGroup>MDEyMzQ1Njc4OTo7PD0+Pw==</LastSelectedGroup>
            <LastTopVisibleGroup>QEFCQ0RFRkdISUpLTE1OTw==</LastTopVisibleGroup>
            <HistoryMaxItems>10</HistoryMaxItems>
            <HistoryMaxSize>1048576</HistoryMaxSize>
            <SettingsChanged>2023-10-05T12:34:56Z</SettingsChanged>
            <Binaries>
                <Binary ID="0" Compressed="False" Protected="False">AQIDBAU=</Binary>
                <Binary ID="1" Compressed="True" Protected="True">ChQeKDI=</Binary>
            </Binaries>
            <CustomData>
                <Item>
                    <Key>example_key</Key>
                    <Value>example_value</Value>
                    <LastModificationTime>cKSw3A4AAAA=</LastModificationTime>
                </Item>
                <Item>
                    <Key>binary_key</Key>
                    <Value>AQIDBAU=</Value>
                    <LastModificationTime>2023-10-05T12:34:56Z</LastModificationTime>
                </Item>
            </CustomData>
        </Meta>"#;

        let meta: Meta = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(meta.generator.unwrap(), "TestGenerator");
        assert_eq!(meta.database_name.unwrap(), "TestDB");
        assert_eq!(
            meta.database_name_changed.unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
        assert_eq!(meta.database_description.unwrap(), "A test database");
        assert_eq!(
            meta.database_description_changed.unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
        assert_eq!(meta.default_username.unwrap(), "admin");
        assert_eq!(
            meta.default_username_changed.unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
        assert_eq!(meta.maintenance_history_days.unwrap(), 30);
        assert_eq!(meta.color.unwrap(), Color { r: 255, g: 0, b: 0 });
        assert_eq!(
            meta.master_key_changed.unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
        assert_eq!(meta.master_key_change_rec.unwrap(), -1);
        assert_eq!(meta.master_key_change_force.unwrap(), 42);
        let mp = meta.memory_protection.unwrap();
        assert_eq!(mp.protect_title, Some(true));
        assert_eq!(mp.protect_username, Some(false));
        assert_eq!(mp.protect_password, Some(true));
        assert_eq!(mp.protect_url, Some(false));
        assert_eq!(mp.protect_notes, Some(true));
        let icons = meta.custom_icons.unwrap();
        assert_eq!(icons.icons.len(), 1);
        assert_eq!(
            icons.icons[0].uuid.0.as_bytes(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        );
        assert_eq!(icons.icons[0].data, vec![1, 2, 3, 4, 5]);
        assert_eq!(meta.recycle_bin_enabled.unwrap(), true);
        assert_eq!(
            meta.recycle_bin_uuid.unwrap().0.as_bytes(),
            &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
        );
        assert_eq!(
            meta.recycle_bin_changed.unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
        assert_eq!(
            meta.entry_templates_group.unwrap().0.as_bytes(),
            &[0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f]
        );
        assert_eq!(
            meta.entry_templates_group_changed.unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
        assert_eq!(
            meta.last_selected_group.unwrap().0.as_bytes(),
            &[0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]
        );
        assert_eq!(
            meta.last_top_visible_group.unwrap().0.as_bytes(),
            &[0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f]
        );
        assert_eq!(meta.history_max_items.unwrap(), 10);
        assert_eq!(meta.history_max_size.unwrap(), 1048576);
        assert_eq!(
            meta.settings_changed.unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );

        let binaries = meta.binaries.unwrap();
        assert_eq!(binaries.binaries.len(), 2);
        assert_eq!(binaries.binaries[0].id, 0);
        assert_eq!(binaries.binaries[0].compressed, Some(false));
        assert_eq!(binaries.binaries[0].protected, Some(false));
        assert_eq!(
            binaries.binaries[0].value,
            base64_engine::STANDARD.encode(&[1, 2, 3, 4, 5])
        );
        assert_eq!(binaries.binaries[1].id, 1);
        assert_eq!(binaries.binaries[1].compressed, Some(true));
        assert_eq!(binaries.binaries[1].protected, Some(true));
        assert_eq!(
            binaries.binaries[1].value,
            base64_engine::STANDARD.encode(&[10, 20, 30, 40, 50])
        );

        let cd = meta.custom_data.unwrap();
        assert_eq!(cd.items.len(), 2);
        assert_eq!(cd.items[0].key, "example_key");
        match &cd.items[0].value {
            CustomDataValue::String(s) => assert_eq!(s, "example_value"),
            _ => panic!("Expected string value"),
        }
        assert_eq!(
            cd.items[0].last_modification_time.as_ref().unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
        assert_eq!(cd.items[1].key, "binary_key");
        match &cd.items[1].value {
            CustomDataValue::Binary(b) => assert_eq!(b, &vec![1, 2, 3, 4, 5]),
            _ => panic!("Expected binary value"),
        }
        assert_eq!(
            cd.items[1].last_modification_time.as_ref().unwrap().time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
    }
}
