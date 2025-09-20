use serde::{Deserialize, Serialize};

use crate::format::xml_db::{
    custom_serde::{cs_opt_bool, cs_opt_fromstr, cs_opt_string},
    timestamp::{Timestamp, TimestampMode},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Times {
    #[serde(default, with = "cs_opt_string")]
    pub creation_time: Option<Timestamp>,
    #[serde(default, with = "cs_opt_string")]
    pub last_modification_time: Option<Timestamp>,
    #[serde(default, with = "cs_opt_string")]
    pub last_access_time: Option<Timestamp>,
    #[serde(default, with = "cs_opt_string")]
    pub expiry_time: Option<Timestamp>,

    #[serde(default, with = "cs_opt_bool")]
    pub expires: Option<bool>,
    #[serde(default, with = "cs_opt_fromstr")]
    pub usage_count: Option<usize>,

    #[serde(default, with = "cs_opt_string")]
    pub location_changed: Option<Timestamp>,
}

impl Into<crate::db::Times> for Times {
    fn into(self) -> crate::db::Times {
        crate::db::Times {
            creation: self.creation_time.as_ref().map(|t| t.time),
            last_modification: self.last_modification_time.as_ref().map(|t| t.time),
            last_access: self.last_access_time.as_ref().map(|t| t.time),
            expiry: self.expiry_time.as_ref().map(|t| t.time),
            location_changed: self.location_changed.as_ref().map(|t| t.time),
            expires: self.expires,
            usage_count: self.usage_count,
        }
    }
}

impl From<crate::db::Times> for Times {
    fn from(t: crate::db::Times) -> Self {
        // Use ISO 8601 format for all timestamps
        // NOTE: we could store this in the Times struct to improve round-tripping
        let mode = TimestampMode::Iso8601;

        Times {
            creation_time: t.creation.map(|time| Timestamp { mode, time }),
            last_modification_time: t.last_modification.map(|time| Timestamp { mode, time }),
            last_access_time: t.last_access.map(|time| Timestamp { mode, time }),
            expiry_time: t.expiry.map(|time| Timestamp { mode, time }),
            location_changed: t.location_changed.map(|time| Timestamp { mode, time }),
            expires: t.expires,
            usage_count: t.usage_count,
        }
    }
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
