use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose as base64_engine, Engine as _};

use crate::{
    db::Color,
    format::xml_db::{
        custom_serde::{base64 as cs_base64, bool as cs_bool},
        timestamp::Timestamp,
        UUID,
    },
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Meta {
    generator: Option<String>,
    database_name: Option<String>,
    database_name_changed: Timestamp,
    database_description: Option<String>,
    database_description_changed: Timestamp,
    default_username: Option<String>,
    default_username_changed: Timestamp,
    maintenance_history_days: Option<u32>,
    color: Option<Color>,
    master_key_changed: Timestamp,
    master_key_change_rec: Option<bool>,
    master_key_change_force: Option<bool>,
    memory_protection: Option<MemoryProtection>,
    custom_icons: Option<Vec<Icon>>,
    recycle_bin_enabled: Option<bool>,
    recycle_bin_uuid: Option<UUID>,
    recycle_bin_changed: Option<Timestamp>,
    entry_templates_group: Option<UUID>,
    entry_templates_group_changed: Option<Timestamp>,
    last_selected_group: Option<UUID>,
    last_top_visible_group: Option<UUID>,
    history_max_items: Option<u32>,
    history_max_size: Option<u64>,
    setings_changed: Option<Timestamp>,
    custom_data: Option<CustomData>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CustomData {
    #[serde(rename = "Item")]
    items: Vec<CustomDataItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Item", rename_all = "PascalCase")]
struct CustomDataItem {
    key: String,
    value: CustomDataValue,
    last_modification_time: Timestamp,
}

#[derive(Debug)]
pub enum CustomDataValue {
    String(String),
    Binary(Vec<u8>),
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
    #[serde(with = "cs_bool")]
    protect_title: bool,

    #[serde(with = "cs_bool")]
    protect_username: bool,

    #[serde(with = "cs_bool")]
    protect_password: bool,

    #[serde(with = "cs_bool", rename = "ProtectURL")]
    protect_url: bool,

    #[serde(with = "cs_bool")]
    protect_notes: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Icon {
    #[serde(rename = "UUID")]
    uuid: UUID,

    #[serde(with = "cs_base64")]
    data: Vec<u8>,
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use chrono::NaiveDateTime;
    use uuid::Uuid;

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Test<T>(T);

    #[test]
    fn test_serialize_custom_data() {
        let cd = CustomData {
            items: vec![
                CustomDataItem {
                    key: "example_key".to_string(),
                    value: CustomDataValue::String("example_value".to_string()),
                    last_modification_time: Timestamp::new_base64(
                        NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
                    ),
                },
                CustomDataItem {
                    key: "binary_key".to_string(),
                    value: CustomDataValue::Binary(vec![1, 2, 3, 4, 5]),
                    last_modification_time: Timestamp::new_iso8601(
                        NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap(),
                    ),
                },
            ],
        };

        let serialized = quick_xml::se::to_string(&cd).unwrap();

        assert_eq!(
            serialized,
            "<CustomData><Item><Key>example_key</Key><Value>example_value</Value><LastModificationTime>cKSw3A4AAAA=</LastModificationTime></Item><Item><Key>binary_key</Key><Value>AQIDBAU=</Value><LastModificationTime>2023-10-05T12:34:56Z</LastModificationTime></Item></CustomData>"
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
            protect_title: true,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: true,
        };

        let serialized = quick_xml::se::to_string(&mp).unwrap();
        assert_eq!(serialized, "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectUsername>False</ProtectUsername><ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>True</ProtectNotes></MemoryProtection>");
    }

    #[test]
    fn test_deserialize_memory_protection() {
        let mp: MemoryProtection = quick_xml::de::from_str( "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectUsername>False</ProtectUsername><ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>True</ProtectNotes></MemoryProtection>").unwrap();
        assert!(mp.protect_title);
        assert!(!mp.protect_username);
        assert!(mp.protect_password);
        assert!(!mp.protect_url);
        assert!(mp.protect_notes);
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
}
