use std::str::FromStr;

use thiserror::Error;

/// A color value for the Database, or Entry
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[cfg(feature = "serialization")]
impl serde::Serialize for Color {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl FromStr for Color {
    type Err = ParseColorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('#') || s.len() != 7 {
            return Err(ParseColorError(s.to_string()));
        }

        let v =
            u64::from_str_radix(s.trim_start_matches('#'), 16).map_err(|_e| ParseColorError(s.to_string()))?;

        let r = ((v >> 16) & 0xff) as u8;
        let g = ((v >> 8) & 0xff) as u8;
        let b = (v & 0xff) as u8;

        Ok(Self { r, g, b })
    }
}

/// Error parsing a color code
#[derive(Debug, Error)]
#[error("Cannot parse color: '{}'", _0)]
pub struct ParseColorError(pub String);

impl std::fmt::Display for Color {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }
}
