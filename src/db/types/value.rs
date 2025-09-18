use secrecy::{ExposeSecret, SecretBox};

#[derive(Debug)]
pub enum Value {
    /// unprotected text data
    String(String),

    /// protected text data
    PString(SecretBox<String>),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::String(data) => write!(f, "{}", data),
            Value::PString(_) => write!(f, "[redacted]"),
        }
    }
}

impl Value {
    /// Create a new unprotected text data value
    pub fn string(data: impl Into<String>) -> Self {
        Value::String(data.into())
    }

    /// Create a new protected text data value
    pub fn protected_string(data: impl Into<String>) -> Self {
        Value::PString(SecretBox::new(Box::new(data.into())))
    }

    /// Returns true if the value is protected (either PBytes or PString)
    pub fn is_protected(&self) -> bool {
        matches!(self, Value::PString(_))
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Value::String(data) => data.is_empty(),
            Value::PString(data) => data.expose_secret().is_empty(),
        }
    }

    /// Returns the value as a string slice
    pub fn as_str(&self) -> &str {
        match self {
            Value::String(data) => data,
            Value::PString(data) => data.expose_secret(),
        }
    }
}

impl Clone for Value {
    fn clone(&self) -> Self {
        match self {
            Value::String(data) => Value::String(data.clone()),
            Value::PString(data) => Value::PString(SecretBox::new(Box::new(data.expose_secret().clone()))),
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::String(a), Value::String(b)) => a == b,
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
            Value::String(data) => serializer.serialize_str(data),
            Value::PString(data) => serializer.serialize_str(data.expose_secret()),
        }
    }
}
