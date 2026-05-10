use serde::{Deserialize, Serialize};

use crate::format::xml_db::{
    custom_serde::{cs_opt_bool, cs_opt_fromstr, cs_opt_string},
    timestamp::Timestamp,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Times {
    #[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<Timestamp>,
    #[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
    pub last_modification_time: Option<Timestamp>,
    #[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
    pub last_access_time: Option<Timestamp>,
    #[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<Timestamp>,

    #[serde(default, with = "cs_opt_bool", skip_serializing_if = "Option::is_none")]
    pub expires: Option<bool>,
    #[serde(default, with = "cs_opt_fromstr", skip_serializing_if = "Option::is_none")]
    pub usage_count: Option<usize>,

    #[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
    pub location_changed: Option<Timestamp>,
}

impl From<Times> for crate::db::Times {
    fn from(t: Times) -> Self {
        crate::db::Times {
            creation: t.creation_time.as_ref().map(|ts| ts.time),
            last_modification: t.last_modification_time.as_ref().map(|ts| ts.time),
            last_access: t.last_access_time.as_ref().map(|ts| ts.time),
            expiry: t.expiry_time.as_ref().map(|ts| ts.time),
            location_changed: t.location_changed.as_ref().map(|ts| ts.time),
            expires: t.expires,
            usage_count: t.usage_count,
        }
    }
}

impl From<crate::db::Times> for Times {
    fn from(t: crate::db::Times) -> Self {
        Times {
            creation_time: t.creation.map(|time| time.into()),
            last_modification_time: t.last_modification.map(|time| time.into()),
            last_access_time: t.last_access.map(|time| time.into()),
            expiry_time: t.expiry.map(|time| time.into()),
            location_changed: t.location_changed.map(|time| time.into()),
            expires: t.expires,
            usage_count: t.usage_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
