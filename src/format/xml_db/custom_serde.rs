//! Custom serde (de)serializers for specific data formats in KeePass XML flavor.

/// base64-encoded binary data
pub mod base64 {
    use base64::{engine::general_purpose as base64_engine, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&base64_engine::STANDARD.encode(data))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;

        base64_engine::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// "True"/"False" boolean strings
pub mod bool {

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &bool, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(if *data { "True" } else { "False" })
    }

    pub fn deserialize<'de, D>(d: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;

        match s.as_str() {
            "True" => Ok(true),
            "False" => Ok(false),
            _ => Err(serde::de::Error::custom(format!("Invalid boolean string: {}", s))),
        }
    }
}

/// Optional "True"/"False" boolean strings
pub mod opt_bool {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &Option<bool>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(b) => s.serialize_str(if *b { "True" } else { "False" }),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(d)?;

        match opt {
            Some(s) => match s.as_str() {
                "True" => Ok(Some(true)),
                "False" => Ok(Some(false)),
                _ => Err(serde::de::Error::custom(format!("Invalid boolean string: {}", s))),
            },
            None => Ok(None),
        }
    }
}
