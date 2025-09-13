use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose as base64_engine, Engine as _};

use crate::{
    db::Color,
    format::xml_db::{
        custom_serde::{cs_base64, cs_bool, cs_opt_bool, cs_opt_string as cs_opt},
        timestamp::Timestamp,
        UUID,
    },
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Meta {
    generator: Option<String>,
    #[serde(default)]
    database_name: Option<String>,

    #[serde(default)]
    database_name_changed: Option<Timestamp>,

    #[serde(default)]
    database_description: Option<String>,

    #[serde(default)]
    database_description_changed: Option<Timestamp>,

    #[serde(default)]
    default_username: Option<String>,

    #[serde(default)]
    default_username_changed: Option<Timestamp>,

    #[serde(default)]
    maintenance_history_days: Option<u32>,

    #[serde(default)]
    color: Option<Color>,

    #[serde(default)]
    master_key_changed: Option<Timestamp>,

    #[serde(default)]
    master_key_change_rec: Option<i32>,

    #[serde(default)]
    master_key_change_force: Option<i32>,

    #[serde(default)]
    memory_protection: Option<MemoryProtection>,

    #[serde(default)]
    custom_icons: Option<Vec<Icon>>,

    #[serde(with = "cs_opt_bool")]
    recycle_bin_enabled: Option<bool>,

    #[serde(rename = "RecycleBinUUID")]
    recycle_bin_uuid: Option<UUID>,

    #[serde(default)]
    recycle_bin_changed: Option<Timestamp>,

    #[serde(default)]
    entry_templates_group: Option<UUID>,

    #[serde(default)]
    entry_templates_group_changed: Option<Timestamp>,

    #[serde(default)]
    last_selected_group: Option<UUID>,

    #[serde(default)]
    last_top_visible_group: Option<UUID>,

    #[serde(default)]
    history_max_items: Option<u32>,

    #[serde(default)]
    history_max_size: Option<u64>,

    #[serde(default)]
    settings_changed: Option<Timestamp>,

    #[serde(default)]
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
                protect_title: true,
                protect_username: false,
                protect_password: true,
                protect_url: false,
                protect_notes: true,
            }),
            custom_icons: Some(vec![Icon {
                uuid: UUID(Uuid::from_bytes([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                    0x0f,
                ])),
                data: vec![1, 2, 3, 4, 5],
            }]),
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
            custom_data: Some(CustomData {
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
        assert!(serialized.contains("<CustomData>"));
    }

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
        assert!(mp.protect_title);
        assert!(!mp.protect_username);
        assert!(mp.protect_password);
        assert!(!mp.protect_url);
        assert!(mp.protect_notes);
        let icons = meta.custom_icons.unwrap();
        assert_eq!(icons.len(), 1);
        assert_eq!(
            icons[0].uuid.0.as_bytes(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        );
        assert_eq!(icons[0].data, vec![1, 2, 3, 4, 5]);
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
        let cd = meta.custom_data.unwrap();
        assert_eq!(cd.items.len(), 2);
        assert_eq!(cd.items[0].key, "example_key");
        match &cd.items[0].value {
            CustomDataValue::String(s) => assert_eq!(s, "example_value"),
            _ => panic!("Expected string value"),
        }
        assert_eq!(
            cd.items[0].last_modification_time.time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
        assert_eq!(cd.items[1].key, "binary_key");
        match &cd.items[1].value {
            CustomDataValue::Binary(b) => assert_eq!(b, &vec![1, 2, 3, 4, 5]),
            _ => panic!("Expected binary value"),
        }
        assert_eq!(
            cd.items[1].last_modification_time.time,
            NaiveDateTime::from_str("2023-10-05T12:34:56").unwrap()
        );
    }
}
