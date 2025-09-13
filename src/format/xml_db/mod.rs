use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

use base64::{engine::general_purpose as base64_engine, Engine as _};
use uuid::Uuid;

use crate::db::Color;

#[derive(Debug, Serialize, Deserialize)]
struct KeePassFile {
    meta: Meta,
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    generator: Option<String>,
    database_name: Option<String>,
    database_name_changed: Timestamp,
    database_description: Option<String>,
    database_description_changed: Timestamp,
    default_username: Option<String>,
    default_username_changed: Timestamp,
    maintenance_history_days: Option<u32>,
    color: Option<Color>,
}

#[derive(Debug)]
enum TimestampMode {
    Base64,
    Iso8601,
}

/// In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00.
/// This function returns the epoch baseline used by KDBX for date serialization.
pub fn get_epoch_baseline() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap()
}

#[derive(Debug)]
struct Timestamp {
    mode: TimestampMode,
    time: NaiveDateTime,
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let t = String::deserialize(deserializer)?;

        match chrono::NaiveDateTime::parse_from_str(&t, "%Y-%m-%dT%H:%M:%SZ") {
            // Prior to KDBX4 file format, timestamps were stored as ISO 8601 strings
            Ok(ndt) => Ok(Timestamp {
                mode: TimestampMode::Iso8601,
                time: ndt,
            }),

            // If we don't have a valid ISO 8601 string, assume we have found a Base64 encoded int.
            _ => {
                let v = base64_engine::STANDARD
                    .decode(t)
                    .map_err(serde::de::Error::custom)?;

                // Cast the decoded base64 Vec into the array expected by i64::from_le_bytes
                let mut a: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
                a.copy_from_slice(&v[0..8]);
                let ndt = get_epoch_baseline() + chrono::Duration::seconds(i64::from_le_bytes(a));

                Ok(Timestamp {
                    mode: TimestampMode::Base64,
                    time: ndt,
                })
            }
        }
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.mode {
            TimestampMode::Iso8601 => {
                let s = self.time.format("%Y-%m-%dT%H:%M:%SZ").to_string();
                serializer.serialize_str(&s)
            }
            TimestampMode::Base64 => {
                let duration = self.time - get_epoch_baseline();
                let seconds = duration.num_seconds();
                let b = seconds.to_le_bytes();
                let b64 = base64_engine::STANDARD.encode(b);
                serializer.serialize_str(&b64)
            }
        }
    }
}

/// A UUID deserialized from a Base64 string.
struct UUID(Uuid);

impl<'de> Deserialize<'de> for UUID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;

        let v = base64_engine::STANDARD
            .decode(input)
            .map_err(serde::de::Error::custom)?;

        let uuid = Uuid::from_slice(&v).map_err(serde::de::Error::custom)?;
        Ok(UUID(uuid))
    }
}

impl Serialize for UUID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let b64 = base64_engine::STANDARD.encode(self.0.as_bytes());
        serializer.serialize_str(&b64)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Test<T>(T);

    #[test]
    fn test_deserialize_uuid() {
        let uuid_str = "AAECAwQFBgcICQoLDA0ODw=="; // Base64 for 0xdeadbeef
        let uuid: UUID = quick_xml::de::from_str(&format!("{}", uuid_str)).unwrap();
        assert_eq!(
            uuid.0.as_bytes(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
        );
    }

    #[test]
    fn test_serialize_uuid() {
        let uuid = UUID(Uuid::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ]));
        let serialized = quick_xml::se::to_string(&Test(uuid)).unwrap();
        assert_eq!(serialized, "<Test>AAECAwQFBgcICQoLDA0ODw==</Test>");
    }

    #[test]
    fn test_deserialize_timestamp_iso8601() {
        let ts_str = "2023-10-05T12:34:56Z";
        let ts: Timestamp = quick_xml::de::from_str(&format!("{}", ts_str)).unwrap();
        assert_eq!(
            ts.time,
            NaiveDateTime::parse_from_str("2023-10-05T12:34:56", "%Y-%m-%dT%H:%M:%S").unwrap()
        );
        match ts.mode {
            TimestampMode::Iso8601 => (),
            _ => panic!("Expected Iso8601 mode"),
        }
    }

    #[test]
    fn test_deserialize_timestamp_base64() {
        let ts_str = "AQAAAAAAAAA="; // Base64 for 1 second since epoch
        let ts: Timestamp = quick_xml::de::from_str(&format!("{}", ts_str)).unwrap();
        assert_eq!(ts.time, get_epoch_baseline() + chrono::Duration::seconds(1));
        match ts.mode {
            TimestampMode::Base64 => (),
            _ => panic!("Expected Base64 mode"),
        }
    }

    #[test]
    fn test_serialize_timestamp_iso8601() {
        let ts = Timestamp {
            mode: TimestampMode::Iso8601,
            time: NaiveDateTime::parse_from_str("2023-10-05T12:34:56", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };
        let serialized = quick_xml::se::to_string(&Test(ts)).unwrap();
        assert_eq!(serialized, "<Test>2023-10-05T12:34:56Z</Test>");
    }

    #[test]
    fn test_serialize_timestamp_base64() {
        let ts = Timestamp {
            mode: TimestampMode::Base64,
            time: get_epoch_baseline() + chrono::Duration::seconds(1),
        };

        let serialized = quick_xml::se::to_string(&Test(ts)).unwrap();
        assert_eq!(serialized, "<Test>AQAAAAAAAAA=</Test>");
    }
}
