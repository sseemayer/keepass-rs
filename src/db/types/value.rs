use secrecy::{ExposeSecret, SecretBox};

#[derive(Debug)]
pub enum Value {
    /// unprotected binary data
    Bytes(Vec<u8>),

    /// unprotected text data
    String(String),

    /// protected binary data
    PBytes(SecretBox<Vec<u8>>),

    /// protected text data
    PString(SecretBox<String>),
}

impl Value {
    /// Create a new unprotected binary data value
    pub fn bytes(data: impl Into<Vec<u8>>) -> Self {
        Value::Bytes(data.into())
    }

    /// Create a new unprotected text data value
    pub fn string(data: impl Into<String>) -> Self {
        Value::String(data.into())
    }

    /// Create a new protected binary data value
    pub fn protected_bytes(data: impl Into<Vec<u8>>) -> Self {
        Value::PBytes(SecretBox::new(Box::new(data.into())))
    }

    /// Create a new protected text data value
    pub fn protected_string(data: impl Into<String>) -> Self {
        Value::PString(SecretBox::new(Box::new(data.into())))
    }

    /// Returns true if the value is protected (either PBytes or PString)
    pub fn is_protected(&self) -> bool {
        matches!(self, Value::PBytes(_) | Value::PString(_))
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Value::Bytes(data) => data.is_empty(),
            Value::String(data) => data.is_empty(),
            Value::PBytes(data) => data.expose_secret().is_empty(),
            Value::PString(data) => data.expose_secret().is_empty(),
        }
    }

    /// Returns the value as a byte slice, if it is either Bytes or PBytes
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(data) => Some(data),
            Value::PBytes(data) => Some(data.expose_secret()),
            _ => None,
        }
    }

    /// Returns the value as a string slice, if it is either String or PString
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Value::String(data) => Some(data),
            Value::PString(data) => Some(data.expose_secret()),
            _ => None,
        }
    }
}

impl Clone for Value {
    fn clone(&self) -> Self {
        match self {
            Value::Bytes(data) => Value::Bytes(data.clone()),
            Value::String(data) => Value::String(data.clone()),
            Value::PBytes(data) => Value::PBytes(SecretBox::new(Box::new(data.expose_secret().clone()))),
            Value::PString(data) => Value::PString(SecretBox::new(Box::new(data.expose_secret().clone()))),
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::PBytes(a), Value::PBytes(b)) => a.expose_secret() == b.expose_secret(),
            (Value::PString(a), Value::PString(b)) => a.expose_secret() == b.expose_secret(),
            _ => false,
        }
    }
}

impl Eq for Value {}

#[cfg(feature = "serialization")]
impl serde::Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Value::Bytes(data) => serializer.serialize_bytes(data),
            Value::String(data) => serializer.serialize_str(data),
            Value::PBytes(data) => serializer.serialize_bytes(data.expose_secret()),
            Value::PString(data) => serializer.serialize_str(data.expose_secret()),
        }
    }
}
