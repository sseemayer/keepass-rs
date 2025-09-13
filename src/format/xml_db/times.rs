use serde::{Deserialize, Serialize};

use crate::format::xml_db::{
    custom_serde::{cs_opt_bool, cs_opt_string as cs_opt},
    timestamp::Timestamp,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Times {
    #[serde(default)]
    pub creation_time: Option<Timestamp>,
    #[serde(default)]
    pub last_modification_time: Option<Timestamp>,
    #[serde(default)]
    pub last_access_time: Option<Timestamp>,
    #[serde(default)]
    pub expiry_time: Option<Timestamp>,

    #[serde(default, with = "cs_opt_bool")]
    pub expires: Option<bool>,
    #[serde(default)]
    pub usage_count: Option<u32>,

    #[serde(default)]
    pub location_changed: Option<Timestamp>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Test<T>(T);

    #[test]
    fn test_deserialize_times() {
        let xml = r#"<Times>
            <CreationTime>2023-10-05T12:34:56Z</CreationTime>
            <LastModificationTime>2023-10-06T12:34:56Z</LastModificationTime>
            <LastAccessTime>2023-10-07T12:34:56Z</LastAccessTime>
            <ExpiryTime>2023-12-31T23:59:59Z</ExpiryTime>
            <Expires>True</Expires>
            <UsageCount>42</UsageCount>
            <LocationChanged>2023-10-08T12:34:56Z</LocationChanged>
        </Times>"#;
        let times: Times = quick_xml::de::from_str(xml).unwrap();
        assert_eq!(times.usage_count, Some(42));
        assert_eq!(times.expires, Some(true));

        assert_eq!(
            times.creation_time.unwrap().time,
            chrono::NaiveDateTime::parse_from_str("2023-10-05T12:34:56", "%Y-%m-%dT%H:%M:%S").unwrap()
        );

        assert_eq!(
            times.last_modification_time.unwrap().time,
            chrono::NaiveDateTime::parse_from_str("2023-10-06T12:34:56", "%Y-%m-%dT%H:%M:%S").unwrap()
        );

        assert_eq!(
            times.last_access_time.unwrap().time,
            chrono::NaiveDateTime::parse_from_str("2023-10-07T12:34:56", "%Y-%m-%dT%H:%M:%S").unwrap()
        );

        assert_eq!(
            times.expiry_time.unwrap().time,
            chrono::NaiveDateTime::parse_from_str("2023-12-31T23:59:59", "%Y-%m-%dT%H:%M:%S").unwrap()
        );

        assert_eq!(
            times.location_changed.unwrap().time,
            chrono::NaiveDateTime::parse_from_str("2023-10-08T12:34:56", "%Y-%m-%dT%H:%M:%S").unwrap()
        );
    }
}
