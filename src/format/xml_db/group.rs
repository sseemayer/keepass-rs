use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[cfg(feature = "save_kdbx4")]
use crate::crypt::CryptographyError;
use crate::{
    crypt::ciphers::Cipher,
    db::{EntryId, GroupId},
    format::xml_db::{
        custom_serde::{cs_opt_bool, cs_opt_fromstr, cs_opt_string},
        entry::{Entry, UnprotectError},
        times::Times,
        UUID,
    },
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Group {
    #[serde(rename = "UUID")]
    pub uuid: UUID,

    pub name: String,

    #[serde(default, with = "cs_opt_string")]
    pub notes: Option<String>,

    #[serde(default, rename = "IconID", with = "cs_opt_fromstr")]
    pub icon_id: Option<usize>,

    #[serde(default, rename = "CustomIconUUID", skip_serializing_if = "Option::is_none")]
    pub custom_icon_uuid: Option<UUID>,

    #[serde(default)]
    pub times: Option<Times>,

    #[serde(default, with = "cs_opt_bool")]
    pub is_expanded: Option<bool>,

    #[serde(default, with = "cs_opt_string")]
    pub default_auto_type_sequence: Option<String>,

    #[serde(default, with = "cs_opt_bool")]
    pub enable_auto_type: Option<bool>,

    #[serde(default, with = "cs_opt_bool")]
    pub enable_searching: Option<bool>,

    #[serde(default, with = "cs_opt_string")]
    pub last_top_visible_entry: Option<UUID>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<crate::format::xml_db::meta::CustomData>,

    #[serde(default, rename = "$value")]
    pub children: Vec<GroupOrEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum GroupOrEntry {
    Group(Group),
    Entry(Entry),
}

impl Group {
    pub(crate) fn xml_to_db_handle(
        self,
        mut target: crate::db::GroupMut<'_>,
        attachments: &HashMap<crate::db::AttachmentId, crate::db::Attachment>,
        custom_icons: &HashMap<crate::db::CustomIconId, crate::db::CustomIcon>,
        inner_decryptor: &mut dyn Cipher,
    ) -> Result<(), UnprotectError> {
        target.name = self.name;
        target.notes = self.notes;

        target.icon = if let Some(ci) = self.custom_icon_uuid.and_then(|ci| {
            let icon_id = crate::db::CustomIconId::from_uuid(ci.0);
            custom_icons.contains_key(&icon_id).then_some(icon_id)
        }) {
            Some(crate::db::Icon::Custom(ci))
        } else {
            self.icon_id.map(crate::db::Icon::BuiltIn)
        };

        target.times = self.times.map(|t| t.into()).unwrap_or_default();
        target.is_expanded = self.is_expanded.unwrap_or_default();
        target.default_autotype_sequence = self.default_auto_type_sequence;
        target.enable_autotype = self.enable_auto_type;
        target.enable_searching = self.enable_searching;
        target.last_top_visible_entry = self.last_top_visible_entry.map(|u| EntryId::from_uuid(u.0));

        if let Some(cd) = self.custom_data {
            target.custom_data = cd.into();
        }

        for child in self.children {
            match child {
                GroupOrEntry::Group(g) => {
                    let new_group = target.add_group_with_id(GroupId::from_uuid(g.uuid.0));
                    g.xml_to_db_handle(new_group, attachments, custom_icons, inner_decryptor)?;
                }
                GroupOrEntry::Entry(e) => {
                    let new_entry = target.add_entry_with_id(EntryId::from_uuid(e.uuid.0));
                    e.xml_to_db_handle(new_entry, attachments, custom_icons, inner_decryptor)?;
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "save_kdbx4")]
    pub(crate) fn db_to_xml(
        source: crate::db::GroupRef<'_>,
        inner_cipher: &mut dyn Cipher,
    ) -> Result<Self, CryptographyError> {
        let mut children = Vec::new();

        for g in source.groups() {
            children.push(GroupOrEntry::Group(Group::db_to_xml(g, inner_cipher)?));
        }

        for e in source.entries() {
            children.push(GroupOrEntry::Entry(Entry::db_to_xml(e, inner_cipher)?));
        }

        let custom_data: Option<crate::format::xml_db::meta::CustomData> = if source.custom_data.is_empty() {
            None
        } else {
            Some(source.custom_data.clone().into())
        };

        let (icon_id, custom_icon_uuid) = match source.icon {
            Some(crate::db::Icon::Custom(cid)) => (None, Some(UUID(cid.uuid()))),
            Some(crate::db::Icon::BuiltIn(i)) => (Some(i), None),
            _ => (None, None),
        };

        Ok(Group {
            uuid: UUID(source.id().uuid()),
            name: source.name.clone(),
            notes: source.notes.clone(),
            icon_id,
            custom_icon_uuid,
            times: Some(source.times.clone().into()),
            is_expanded: Some(source.is_expanded),
            default_auto_type_sequence: source.default_autotype_sequence.clone(),
            enable_auto_type: source.enable_autotype,
            enable_searching: source.enable_searching,
            last_top_visible_entry: source.last_top_visible_entry.map(|eid| UUID(eid.uuid())),
            custom_data,
            children,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Test<T>(T);

    #[test]
    fn test_deserialize_group() {
        let xml = r#"<Group>
            <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            <Name>Example Group</Name>
            <Notes>This is a test group.</Notes>
            <IconID>48</IconID>
            <CustomIconUUID>oaKjpLGywcLR0tPU1dbX2A==</CustomIconUUID>
            <Times>
                <CreationTime>2023-10-05T12:34:56Z</CreationTime>
                <LastModificationTime>2023-10-06T12:34:56Z</LastModificationTime>
                <LastAccessTime>2023-10-07T12:34:56Z</LastAccessTime>
                <ExpiryTime>2023-12-31T23:59:59Z</ExpiryTime>
                <Expires>True</Expires>
                <UsageCount>42</UsageCount>
                <LocationChanged>2023-10-08T12:34:56Z</LocationChanged>
            </Times>
            <IsExpanded>True</IsExpanded>
            <DefaultAutoTypeSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultAutoTypeSequence>
            <EnableAutoType>True</EnableAutoType>
            <EnableSearching>False</EnableSearching>
            <LastTopVisibleEntry>AAECAwQFBgcICQoLDA0ODw==</LastTopVisibleEntry>
            <CustomData>
                <Item>
                    <Key>example_key</Key>
                    <Value>example_value</Value>
                </Item>
            </CustomData>
            <Group>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
                <Name>Sub Group</Name>
                <IsExpanded>False</IsExpanded>
            </Group>
            <Entry>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            </Entry>
            <Group>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
                <Name>Another Sub Group</Name>
            </Group>
            <Entry>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            </Entry>
        </Group>"#;

        let group: Test<Group> = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(group.0.uuid.0.to_string(), "00010203-0405-0607-0809-0a0b0c0d0e0f");
        assert_eq!(group.0.name, "Example Group");
        assert_eq!(group.0.notes.unwrap(), "This is a test group.");
        assert_eq!(group.0.icon_id.unwrap(), 48);
        assert_eq!(
            group.0.custom_icon_uuid.unwrap().0.to_string(),
            "a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8"
        );
        assert_eq!(group.0.is_expanded, Some(true));
        assert_eq!(
            group.0.default_auto_type_sequence.unwrap(),
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
        assert_eq!(group.0.enable_auto_type.unwrap(), true);
        assert_eq!(group.0.enable_searching.unwrap(), false);
        assert_eq!(group.0.custom_data.is_some(), true);
        assert_eq!(group.0.children.len(), 4);
    }
}
