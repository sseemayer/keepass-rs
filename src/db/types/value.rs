use std::{fmt::Display, ops::Deref};

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

/// Value in an [Entry][crate::db::Entry]'s fields or an [Attachment][crate::db::Attachment]'s data
///
/// Can be either unprotected or protected
#[derive(Debug)]
pub enum Value<T: Zeroize> {
    /// unprotected data
    Unprotected(T),

    /// protected data
    Protected(SecretBox<T>),
}

impl<T: Zeroize + Display> std::fmt::Display for Value<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Unprotected(data) => write!(f, "{}", data),
            Value::Protected(_) => write!(f, "[redacted]"),
        }
    }
}

impl<T: Zeroize + Default> Default for Value<T> {
    fn default() -> Self {
        Value::Unprotected(Default::default())
    }
}

impl<T: Zeroize> Value<T> {
    /// Create a new unprotected value
    pub fn unprotected(data: impl Into<T>) -> Self {
        Value::Unprotected(data.into())
    }

    /// Create a new protected text data value
    pub fn protected(data: impl Into<T>) -> Self {
        Value::Protected(SecretBox::new(Box::new(data.into())))
    }

    /// Returns true if the value is protected (either PBytes or PString)
    pub fn is_protected(&self) -> bool {
        matches!(self, Value::Protected(_))
    }

    /// Returns the value as a string slice
    pub fn get(&self) -> &T {
        match self {
            Value::Unprotected(data) => data,
            Value::Protected(data) => data.expose_secret(),
        }
    }
}

impl<T: Zeroize + Clone> Clone for Value<T> {
    fn clone(&self) -> Self {
        match self {
            Value::Unprotected(data) => Value::Unprotected(data.clone()),
            Value::Protected(data) => Value::Protected(SecretBox::new(Box::new(data.expose_secret().clone()))),
        }
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Value<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Unprotected(a), Value::Unprotected(b)) => a == b,
            (Value::Protected(a), Value::Protected(b)) => a.expose_secret() == b.expose_secret(),
            _ => false,
        }
    }
}

impl<T: Zeroize + Eq> Eq for Value<T> {}

impl<T: Zeroize> Deref for Value<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

#[cfg(feature = "serialization")]
impl<T: Zeroize + serde::Serialize> serde::Serialize for Value<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Value::Unprotected(data) => data.serialize(serializer),
            Value::Protected(data) => data.expose_secret().serialize(serializer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Value;

    #[test]
    fn test_value() {
        let unprotected: Value<String> = Value::unprotected("test");
        let protected: Value<String> = Value::protected("test");
        assert!(!unprotected.is_protected());
        assert!(protected.is_protected());
        assert!(!unprotected.is_empty());
        assert!(!protected.is_empty());

        assert_eq!(unprotected.get(), "test");
        assert_eq!(protected.get(), "test");

        assert_eq!(format!("{}", unprotected), "test");
        assert_eq!(format!("{}", protected), "[redacted]");

        assert_ne!(unprotected, protected);
    }
}
