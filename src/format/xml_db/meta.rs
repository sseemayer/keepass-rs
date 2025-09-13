use serde::{Deserialize, Serialize};

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
    items: Vec<CustomDataItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename = "Icon", rename_all = "PascalCase")]
struct CustomDataItem {
    key: String,
    value: CustomDataValue,
    last_modification_time: Timestamp,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CustomDataValue {
    String(String),
    Binary(Vec<u8>),
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

    #[serde(with = "cs_bool")]
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

    use uuid::Uuid;

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Test<T>(T);

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
        assert_eq!(
            serialized,
            "<MemoryProtection><ProtectTitle>True</ProtectTitle><ProtectUsername>False</ProtectUsername><ProtectPassword>True</ProtectPassword><ProtectUrl>False</ProtectUrl><ProtectNotes>True</ProtectNotes></MemoryProtection>"
        );
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
