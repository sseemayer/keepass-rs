use base64::{engine::general_purpose as base64_engine, Engine as _};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize, Serializer};

use crate::format::xml_db::XmlBridge;

/// In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00.
/// This function returns the epoch baseline used by KDBX for date serialization.
pub fn get_epoch_baseline() -> chrono::NaiveDateTime {
    chrono::NaiveDateTime::parse_from_str("0001-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap()
}

#[derive(Debug, Clone, Copy)]
pub enum TimestampMode {
    Base64,
    Iso8601,
}

#[derive(Debug)]
pub struct Timestamp {
    pub mode: TimestampMode,
    pub time: NaiveDateTime,
}

impl Timestamp {
    pub fn new_base64(time: NaiveDateTime) -> Self {
        Timestamp {
            mode: TimestampMode::Base64,
            time,
        }
    }

    pub fn new_iso8601(time: NaiveDateTime) -> Self {
        Timestamp {
            mode: TimestampMode::Iso8601,
            time,
        }
    }
}

impl XmlBridge for Timestamp {
    type DbType = NaiveDateTime;

    fn xml_to_db(
        self,
        _inner_decryptor: &dyn crate::crypt::ciphers::Cipher,
        _: &[crate::db::Attachment],
    ) -> Self::DbType {
        self.time
    }

    #[cfg(feature = "save_kdbx4")]
    fn db_to_xml(db: &Self::DbType, _inner_encryptor: &dyn crate::crypt::ciphers::Cipher) -> Self {
        Timestamp {
            // NOTE: always use ISO8601 for serialization. We could remember the original format to
            // have more faithful round-tripping
            mode: TimestampMode::Iso8601,
            time: *db,
        }
    }
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
        S: Serializer,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct Test<T>(T);

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
