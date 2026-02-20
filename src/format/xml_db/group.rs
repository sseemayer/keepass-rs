use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "save_kdbx4")]
use crate::crypt::CryptographyError;
use crate::{
    crypt::ciphers::Cipher,
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
        target: &mut crate::db::Group,
        header_attachments: &[crate::db::Attachment],
        custom_icons: &HashMap<Uuid, Vec<u8>>,
        inner_decryptor: &mut dyn Cipher,
    ) -> Result<(), UnprotectError> {
        target.name = self.name;
        target.notes = self.notes;
        target.icon_id = self.icon_id;
        target.times = self.times.map(|t| t.into()).unwrap_or_default();
        target.is_expanded = self.is_expanded.unwrap_or_default();
        target.default_autotype_sequence = self.default_auto_type_sequence;
        target.enable_autotype = self.enable_auto_type;
        target.enable_searching = self.enable_searching;
        target.last_top_visible_entry = self.last_top_visible_entry.map(|u| u.0);

        for child in self.children {
            match child {
                GroupOrEntry::Group(g) => {
                    let mut new_group = crate::db::Group {
                        uuid: g.uuid.0,
                        ..Default::default()
                    };

                    g.xml_to_db_handle(&mut new_group, header_attachments, custom_icons, inner_decryptor)?;
                    target.groups.push(new_group);
                }
                GroupOrEntry::Entry(e) => {
                    let mut new_entry = crate::db::Entry {
                        uuid: e.uuid.0,
                        ..Default::default()
                    };
                    e.xml_to_db_handle(&mut new_entry, header_attachments, custom_icons, inner_decryptor)?;
                    target.entries.push(new_entry);
                }
            }
        }

        Ok(())
    }

    #[cfg(feature = "save_kdbx4")]
    pub(crate) fn db_to_xml(
        source: &crate::db::Group,
        inner_cipher: &mut dyn Cipher,
        attachments: &mut Vec<crate::db::Attachment>,
        custom_icons: &mut HashMap<Uuid, Vec<u8>>,
    ) -> Result<Self, CryptographyError> {
        let mut children = Vec::new();

        for g in &source.groups {
            children.push(GroupOrEntry::Group(Group::db_to_xml(
                g,
                inner_cipher,
                attachments,
                custom_icons,
            )?));
        }

        for e in &source.entries {
            children.push(GroupOrEntry::Entry(Entry::db_to_xml(
                e,
                inner_cipher,
                attachments,
                custom_icons,
            )?));
        }

        Ok(Group {
            uuid: UUID(source.uuid),
            name: source.name.clone(),
            notes: source.notes.clone(),
            icon_id: source.icon_id,
            times: Some(source.times.clone().into()),
            is_expanded: Some(source.is_expanded),
            default_auto_type_sequence: source.default_autotype_sequence.clone(),
            enable_auto_type: source.enable_autotype,
            enable_searching: source.enable_searching,
            last_top_visible_entry: source.last_top_visible_entry.map(|eid| UUID(eid)),
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
        assert_eq!(group.0.is_expanded, Some(true));
        assert_eq!(
            group.0.default_auto_type_sequence.unwrap(),
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
        assert_eq!(group.0.enable_auto_type.unwrap(), true);
        assert_eq!(group.0.enable_searching.unwrap(), false);
        assert_eq!(group.0.children.len(), 4);
    }
}
