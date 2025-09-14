use serde::{Deserialize, Serialize};

use crate::format::xml_db::{
    custom_serde::{cs_bool, cs_opt_bool, cs_opt_fromstr, cs_opt_string},
    entry::Entry,
    times::Times,
    UUID,
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

    #[serde(with = "cs_bool")]
    pub is_expanded: bool,

    #[serde(default, with = "cs_opt_string")]
    pub default_auto_type_sequence: Option<String>,

    #[serde(default, with = "cs_opt_bool")]
    pub enable_auto_type: Option<bool>,

    #[serde(default, with = "cs_opt_bool")]
    pub enable_searching: Option<bool>,

    #[serde(default, with = "cs_opt_string")]
    pub last_top_visible_entry: Option<UUID>,

    #[serde(default, rename = "Group")]
    pub groups: Vec<Group>,

    #[serde(default, rename = "Entry")]
    pub entries: Vec<Entry>,
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
            <Entry>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            </Entry>
        </Group>"#;

        let group: Test<Group> = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(group.0.uuid.0.to_string(), "00010203-0405-0607-0809-0a0b0c0d0e0f");
        assert_eq!(group.0.name, "Example Group");
        assert_eq!(group.0.notes.unwrap(), "This is a test group.");
        assert_eq!(group.0.icon_id.unwrap(), 48);
        assert_eq!(group.0.is_expanded, true);
        assert_eq!(
            group.0.default_auto_type_sequence.unwrap(),
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
        assert_eq!(group.0.enable_auto_type.unwrap(), true);
        assert_eq!(group.0.enable_searching.unwrap(), false);
        assert_eq!(group.0.entries.len(), 2);
        assert_eq!(group.0.groups.len(), 1);
    }
}
