use serde::{Deserialize, Serialize};

use crate::{
    db::Color,
    format::xml_db::{
        custom_serde::{cs_bool, cs_opt_fromstr, cs_opt_string},
        times::Times,
        UUID,
    },
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Entry {
    #[serde(rename = "UUID")]
    pub uuid: UUID,

    #[serde(default, rename = "IconID", with = "cs_opt_fromstr")]
    pub icon_id: Option<u32>,

    #[serde(default, with = "cs_opt_string")]
    pub foreground_color: Option<Color>,

    #[serde(default, with = "cs_opt_string")]
    pub background_color: Option<Color>,

    #[serde(default, rename = "OverrideURL", with = "cs_opt_string")]
    pub override_url: Option<String>,

    #[serde(default, with = "cs_opt_string")]
    pub tags: Option<String>,

    #[serde(default)]
    pub times: Option<Times>,

    #[serde(default, rename = "String")]
    pub string_fields: Vec<StringField>,

    #[serde(default, rename = "Binary")]
    pub binary_fields: Vec<BinaryField>,

    #[serde(default)]
    pub auto_type: Option<AutoType>,

    #[serde(default)]
    pub history: Option<History>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StringField {
    pub key: String,
    pub value: StringValue,
}

#[derive(Debug, Deserialize)]
pub struct StringValue {
    #[serde(default, rename = "@Protected", with = "cs_bool")]
    protected: bool,

    #[serde(default, rename = "$value")]
    value: Option<String>,
}

impl Serialize for StringValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        if self.protected {
            let mut state = serializer.serialize_struct("StringValue", 2)?;
            state.serialize_field("@Protected", if self.protected { "True" } else { "False" })?;

            if let Some(ref val) = self.value {
                state.serialize_field("$value", val)?;
            } else {
                state.serialize_field("$value", "")?;
            }
            state.end()
        } else {
            let mut state = serializer.serialize_struct("StringValue", 1)?;

            if let Some(ref val) = self.value {
                state.serialize_field("$value", val)?;
            } else {
                state.serialize_field("$value", "")?;
            }
            state.end()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BinaryField {
    pub key: String,
    pub value: BinaryValue,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BinaryValue {
    #[serde(rename = "@Ref")]
    pub value_ref: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AutoType {
    #[serde(default, with = "cs_bool")]
    pub enabled: bool,
    pub data_transfer_obfuscation: Option<String>,
    pub default_sequence: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct History {
    #[serde(default, rename = "Entry")]
    pub entries: Vec<Entry>,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct Test<T>(T);

    #[test]
    fn test_deserialize_string_field() {
        let xml = r#"<String>
            <Key>Title</Key>
            <Value>Example Title</Value>
        </String>"#;

        let deserialized: Test<StringField> = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(deserialized.0.key, "Title");
        assert_eq!(deserialized.0.value.value.unwrap(), "Example Title");
        assert_eq!(deserialized.0.value.protected, false);

        let xml_protected = r#"<String>
            <Key>Password</Key>
            <Value Protected="True">cGFzc3dvcmQ=</Value>
        </String>"#;

        let deserialized_protected: Test<StringField> = quick_xml::de::from_str(xml_protected).unwrap();
        assert_eq!(deserialized_protected.0.key, "Password");
        assert_eq!(deserialized_protected.0.value.value.unwrap(), "cGFzc3dvcmQ=");
        assert_eq!(deserialized_protected.0.value.protected, true);
    }

    #[test]
    fn test_serialize_string_field() {
        let string_field = StringField {
            key: "Username".to_string(),
            value: StringValue {
                protected: false,
                value: Some("user123".to_string()),
            },
        };

        let serialized = quick_xml::se::to_string(&Test(string_field)).unwrap();
        assert_eq!(
            serialized,
            r#"<Test><Key>Username</Key><Value>user123</Value></Test>"#
        );

        let string_field_protected = StringField {
            key: "Password".to_string(),
            value: StringValue {
                protected: true,
                value: Some("cGFzc3dvcmQ=".to_string()),
            },
        };

        let serialized_protected = quick_xml::se::to_string(&Test(string_field_protected)).unwrap();
        assert_eq!(
            serialized_protected,
            r#"<Test><Key>Password</Key><Value Protected="True">cGFzc3dvcmQ=</Value></Test>"#
        );
    }

    #[test]
    fn test_deserialize_binary_field() {
        let xml = r#"<Binary>
            <Key>Attachment</Key>
            <Value Ref="1"/>
        </Binary>"#;

        let deserialized: Test<BinaryField> = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(deserialized.0.key, "Attachment");
        assert_eq!(deserialized.0.value.value_ref, 1);
    }

    #[test]
    fn test_serialize_binary_field() {
        let binary_field = BinaryField {
            key: "Attachment".to_string(),
            value: BinaryValue { value_ref: 1 },
        };
        let serialized = quick_xml::se::to_string(&Test(binary_field)).unwrap();
        assert_eq!(
            serialized,
            r#"<Test><Key>Attachment</Key><Value Ref="1"/></Test>"#
        );
    }

    #[test]
    fn test_deserialize_autotype() {
        let xml = r#"<AutoType>
            <Enabled>True</Enabled>
            <DataTransferObfuscation>0</DataTransferObfuscation>
            <DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence>
        </AutoType>"#;

        let deserialized: Test<AutoType> = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(deserialized.0.enabled, true);
        assert_eq!(deserialized.0.data_transfer_obfuscation.unwrap(), "0");
        assert_eq!(
            deserialized.0.default_sequence.unwrap(),
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
    }

    #[test]
    fn test_serialize_autotype() {
        let autotype = AutoType {
            enabled: true,
            data_transfer_obfuscation: Some("0".to_string()),
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string()),
        };

        let serialized = quick_xml::se::to_string(&Test(autotype)).unwrap();
        assert_eq!(
            serialized,
            r#"<Test><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence></Test>"#
        );
    }

    #[test]
    fn test_deserialize_entry() {
        let xml = r#"<Entry>
            <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            <IconID>1</IconID>
            <ForegroundColor>#FF0000</ForegroundColor>
            <BackgroundColor>#00FF00</BackgroundColor>
            <OverrideURL>https://example.com</OverrideURL>
            <Tags>tag1;tag2</Tags>
            <Times>
                <CreationTime>2023-10-05T12:34:56Z</CreationTime>
                <LastModificationTime>2023-10-06T12:34:56Z</LastModificationTime>
                <LastAccessTime>2023-10-07T12:34:56Z</LastAccessTime>
                <ExpiryTime>2024-10-05T12:34:56Z</ExpiryTime>
                <Expires>True</Expires>
                <UsageCount>5</UsageCount>
                <LocationChanged>2023-10-08T12:34:56Z</LocationChanged>
            </Times>
            <String>
                <Key>Title</Key>
                <Value>Example Title</Value>
            </String>
            <Binary>
                <Key>Attachment</Key>
                <Value Ref="1"/>
            </Binary>
            <AutoType>
                <Enabled>True</Enabled>
                <DataTransferObfuscation>0</DataTransferObfuscation>
                <DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence>
            </AutoType>
        </Entry>"#;

        let deserialized: Test<Entry> = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(
            deserialized.0.uuid.0.as_bytes(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        );
        assert_eq!(deserialized.0.icon_id.unwrap(), 1);
        assert_eq!(deserialized.0.foreground_color.unwrap().to_string(), "#FF0000");
        assert_eq!(deserialized.0.background_color.unwrap().to_string(), "#00FF00");
        assert_eq!(deserialized.0.override_url.unwrap(), "https://example.com");
        assert_eq!(deserialized.0.tags.unwrap(), "tag1;tag2");
        assert_eq!(deserialized.0.string_fields.len(), 1);
        assert_eq!(deserialized.0.string_fields[0].key, "Title");
        assert_eq!(
            deserialized.0.string_fields[0].value.value.as_ref().unwrap(),
            "Example Title"
        );
        assert_eq!(deserialized.0.binary_fields.len(), 1);
        assert_eq!(deserialized.0.binary_fields[0].key, "Attachment");
        assert_eq!(deserialized.0.binary_fields[0].value.value_ref, 1);
        assert!(deserialized.0.auto_type.is_some());
        let autotype = deserialized.0.auto_type.unwrap();
        assert_eq!(autotype.enabled, true);
        assert_eq!(autotype.data_transfer_obfuscation.unwrap(), "0");
        assert_eq!(
            autotype.default_sequence.unwrap(),
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );

        assert!(deserialized.0.history.is_none());
    }

    #[test]
    fn test_deserialize_entry_minimal() {
        let xml = r#"<Entry>
            <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            <IconID/>
            <ForegroundColor/>
            <BackgroundColor/>
            <OverrideURL/>
            <Tags/>
            <Times/>
            <AutoType/>
        </Entry>"#;

        let deserialized: Test<Entry> = quick_xml::de::from_str(xml).unwrap();

        println!("{:#?}", deserialized);

        assert!(deserialized.0.icon_id.is_none());
        assert!(deserialized.0.foreground_color.is_none());
        assert!(deserialized.0.background_color.is_none());
        assert!(deserialized.0.override_url.is_none());
        assert!(deserialized.0.tags.is_none());
        assert!(deserialized.0.string_fields.is_empty());
        assert!(deserialized.0.binary_fields.is_empty());
    }
}
