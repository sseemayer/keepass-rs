//! Custom serde (de)serializers for specific data formats in KeePass XML flavor.

/// base64-encoded binary data
pub mod cs_base64 {
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
pub mod cs_bool {

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

        match s.as_str().to_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(serde::de::Error::custom(format!("Invalid boolean string: {}", s))),
        }
    }
}

/// Optional "True"/"False" boolean strings. Explicit "null" string if None for KeepasXC compat
pub mod cs_opt_bool {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &Option<bool>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(b) => s.serialize_str(if *b { "True" } else { "False" }),
            None => s.serialize_str("null"),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(d)?;

        match opt {
            Some(s) => {
                if s.trim().is_empty() {
                    Ok(None)
                } else {
                    match s.to_lowercase().as_str() {
                        "true" | "1" => Ok(Some(true)),
                        "false" | "0" => Ok(Some(false)),
                        "null" => Ok(None),
                        _ => Err(serde::de::Error::custom(format!("Invalid boolean string: {}", s))),
                    }
                }
            }
            None => Ok(None),
        }
    }
}

/// Optional boolean serialized as the integer "0"/"1". None maps to "0".
pub mod cs_opt_intbool {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &Option<bool>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(b) => s.serialize_str(if *b { "1" } else { "0" }),
            None => s.serialize_str("0"),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            Some(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    Ok(None)
                } else {
                    match trimmed {
                        "1" | "true" | "True" => Ok(Some(true)),
                        "0" | "false" | "False" => Ok(Some(false)),
                        _ => Err(serde::de::Error::custom(format!(
                            "Invalid integer-bool string: {s}"
                        ))),
                    }
                }
            }
            None => Ok(None),
        }
    }
}

/// Optional value that implements FromStr that may be missing empty, e.g. numbers
pub mod cs_opt_fromstr {
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, T>(data: &Option<T>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        match data {
            Some(v) => s.serialize_some(v),
            None => s.serialize_str(""), // this will make quick-xml serialize as <Tag></Tag>
        }
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: FromStr,
        <T as FromStr>::Err: std::fmt::Display,
    {
        if let Some(s) = Option::<String>::deserialize(d)? {
            if s.trim().is_empty() {
                Ok(None)
            } else {
                let n: T = s
                    .parse()
                    .map_err(|e| serde::de::Error::custom(format!("error parsing: {}", e)))?;
                Ok(Some(n))
            }
        } else {
            Ok(None)
        }
    }
}

/// Optional stringly value that may be missing or empty
/// (e.g. `<Name></Name>` or `<Name/>`)
pub mod cs_opt_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, T>(data: &Option<T>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        match data {
            Some(v) => s.serialize_some(v),
            None => s.serialize_str(""), // this will make quick-xml serialize as <Tag></Tag>
        }
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        if let Some(s) = Option::<String>::deserialize(d)? {
            if s.trim().is_empty() {
                Ok(None)
            } else {
                let v = T::deserialize(serde::de::IntoDeserializer::<D::Error>::into_deserializer(s))
                    .map_err(serde::de::Error::custom)?;
                Ok(Some(v))
            }
        } else {
            Ok(None)
        }
    }
}
