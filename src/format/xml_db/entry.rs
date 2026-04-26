use std::collections::HashMap;

use base64::{engine::general_purpose as base64_engine, Engine as _};
use thiserror::Error;

use serde::{Deserialize, Serialize};

use crate::{
    crypt::{ciphers::Cipher, CryptographyError},
    db::{AttachmentId, Color, EntryId},
    format::xml_db::{
        custom_serde::{cs_bool, cs_opt_fromstr, cs_opt_intbool, cs_opt_string},
        meta::CustomData,
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
    pub icon_id: Option<usize>,

    #[serde(default, rename = "CustomIconUUID", skip_serializing_if = "Option::is_none")]
    pub custom_icon_uuid: Option<UUID>,

    #[serde(default, with = "cs_opt_string")]
    pub foreground_color: Option<Color>,

    #[serde(default, with = "cs_opt_string")]
    pub background_color: Option<Color>,

    #[serde(default, rename = "OverrideURL", with = "cs_opt_string")]
    pub override_url: Option<String>,

    #[serde(default, with = "cs_opt_string")]
    pub tags: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub times: Option<Times>,

    #[serde(default, rename = "String")]
    pub string_fields: Vec<StringField>,

    #[serde(default, rename = "Binary")]
    pub binary_fields: Vec<BinaryField>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_type: Option<AutoType>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<History>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<CustomData>,
}

impl Entry {
    pub(crate) fn xml_to_db_handle(
        self,
        mut target: crate::db::EntryMut,
        attachments: &HashMap<crate::db::AttachmentId, crate::db::Attachment>,
        custom_icons: &HashMap<crate::db::CustomIconId, crate::db::CustomIcon>,
        inner_decryptor: &mut dyn Cipher,
    ) -> Result<(), UnprotectError> {
        target.icon = if let Some(ci) = self.custom_icon_uuid.and_then(|ci| {
            let icon_id = crate::db::CustomIconId::from_uuid(ci.0);
            custom_icons.contains_key(&icon_id).then_some(icon_id)
        }) {
            Some(crate::db::Icon::Custom(ci))
        } else {
            self.icon_id.map(crate::db::Icon::BuiltIn)
        };

        target.foreground_color = self.foreground_color;
        target.background_color = self.background_color;
        target.override_url = self.override_url;
        target.tags = self
            .tags
            .map(|t| t.split(',').map(|s| s.to_string()).collect())
            .unwrap_or_default();

        target.times = self.times.map(|t| t.into()).unwrap_or_default();

        for field in self.string_fields {
            if let Some(fval) = &field.value.value {
                let value = if field.value.protected {
                    let fval = base64_engine::STANDARD.decode(fval)?;
                    let fval = inner_decryptor.decrypt(&fval)?;
                    let fval = String::from_utf8_lossy(&fval).to_string();

                    crate::db::Value::protected(fval)
                } else {
                    crate::db::Value::unprotected(fval)
                };
                target.fields.insert(field.key, value);
            }
        }

        for field in self.binary_fields {
            let id = AttachmentId::new(field.value.value_ref);
            if attachments.contains_key(&id) {
                target.attachments.insert(field.key.clone(), id);
            }
        }

        target.autotype = self.auto_type.map(|at| at.into());

        if let Some(h) = self.history {
            target.history = Some(crate::db::History { entries: Vec::new() });

            for (i, e) in h.entries.into_iter().enumerate() {
                let mut he = crate::db::Entry::with_id(EntryId::from_uuid(e.uuid.0), target.parent);
                he.history = None; // history entries cannot have their own history
                target.history.as_mut().unwrap().entries.push(he);

                e.xml_to_db_handle(
                    target.historical(i).unwrap(),
                    attachments,
                    custom_icons,
                    inner_decryptor,
                )?;
            }
        }

        if let Some(cd) = self.custom_data {
            target.custom_data = cd.into();
        }

        Ok(())
    }

    #[cfg(feature = "save_kdbx4")]
    pub(crate) fn db_to_xml(
        db: crate::db::EntryRef,
        inner_encryptor: &mut dyn Cipher,
    ) -> Result<Self, CryptographyError> {
        let (icon_id, custom_icon_uuid) = match db.icon {
            Some(crate::db::Icon::Custom(cid)) => (None, Some(UUID(cid.uuid()))),
            Some(crate::db::Icon::BuiltIn(i)) => (Some(i), None),
            _ => (None, None),
        };

        let mut string_fields = Vec::with_capacity(db.fields.len());
        for (k, v) in &db.fields {
            let value = if v.is_protected() {
                let encrypted = inner_encryptor.encrypt(v.get().as_bytes())?;
                let encoded = base64_engine::STANDARD.encode(&encrypted);

                StringValue {
                    protected: true,
                    value: Some(encoded),
                }
            } else {
                StringValue {
                    protected: false,
                    value: Some(v.as_str().to_string()),
                }
            };

            string_fields.push(StringField {
                key: k.clone(),
                value,
            });
        }

        let mut binary_fields = Vec::with_capacity(db.attachments.len());
        for (key, attachment) in &db.attachments {
            binary_fields.push(BinaryField {
                key: key.clone(),
                value: BinaryValue {
                    value_ref: attachment.id(),
                },
            });
        }

        let history = if let Some(h) = db.history.as_ref() {
            let entries = (0..h.entries.len())
                .map(|i| Entry::db_to_xml(db.historical(i).unwrap(), inner_encryptor))
                .collect::<Result<Vec<_>, CryptographyError>>()?;

            Some(History { entries })
        } else {
            None
        };

        let custom_data: Option<CustomData> = if db.custom_data.is_empty() {
            None
        } else {
            Some(db.custom_data.clone().into())
        };

        Ok(Entry {
            uuid: UUID(db.id().uuid()),
            icon_id,
            custom_icon_uuid,
            foreground_color: db.foreground_color.clone(),
            background_color: db.background_color.clone(),
            override_url: db.override_url.clone(),
            tags: db.tags.iter().cloned().reduce(|a, b| format!("{a},{b}")),
            times: Some(db.times.clone().into()),
            string_fields,
            binary_fields,
            auto_type: db.autotype.as_ref().map(|at| at.clone().into()),
            history,
            custom_data,
        })
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UnprotectError {
    #[error("Error base64 decoding protected value: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Error decrypting protected value: {0}")]
    Decrypt(#[from] CryptographyError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
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

    #[serde(default, rename = "$value", with = "cs_opt_string")]
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

    #[serde(default, with = "cs_opt_intbool")]
    pub data_transfer_obfuscation: Option<bool>,

    #[serde(default, with = "cs_opt_string")]
    pub default_sequence: Option<String>,

    #[serde(rename = "Association", default)]
    pub associations: Vec<AutoTypeAssociation>,
}

impl From<AutoType> for crate::db::AutoType {
    fn from(value: AutoType) -> Self {
        crate::db::AutoType {
            enabled: value.enabled,
            default_sequence: value.default_sequence,
            data_transfer_obfuscation: value.data_transfer_obfuscation,
            associations: value.associations.into_iter().map(|a| a.into()).collect(),
        }
    }
}

impl From<crate::db::AutoType> for AutoType {
    fn from(value: crate::db::AutoType) -> Self {
        Self {
            enabled: value.enabled,
            data_transfer_obfuscation: value.data_transfer_obfuscation,
            default_sequence: value.default_sequence,
            associations: value.associations.into_iter().map(|a| a.into()).collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AutoTypeAssociation {
    pub window: String,
    pub keystroke_sequence: String,
}

impl From<AutoTypeAssociation> for crate::db::AutoTypeAssociation {
    fn from(val: AutoTypeAssociation) -> Self {
        crate::db::AutoTypeAssociation {
            window: val.window,
            sequence: val.keystroke_sequence,
        }
    }
}

impl From<crate::db::AutoTypeAssociation> for AutoTypeAssociation {
    fn from(value: crate::db::AutoTypeAssociation) -> Self {
        Self {
            window: value.window,
            keystroke_sequence: value.sequence,
        }
    }
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
        assert_eq!(deserialized.0.data_transfer_obfuscation.unwrap(), false);
        assert_eq!(
            deserialized.0.default_sequence.unwrap(),
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
    }

    #[test]
    fn test_serialize_autotype() {
        let autotype = AutoType {
            enabled: true,
            data_transfer_obfuscation: Some(false),
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string()),
            associations: vec![AutoTypeAssociation {
                window: "Example Window".to_string(),
                keystroke_sequence: "{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string(),
            }],
        };

        let serialized = quick_xml::se::to_string(&Test(autotype)).unwrap();
        assert_eq!(
            serialized,
            r#"<Test><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation><DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence><Association><Window>Example Window</Window><KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</KeystrokeSequence></Association></Test>"#
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
        assert_eq!(autotype.data_transfer_obfuscation.unwrap(), false);
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
