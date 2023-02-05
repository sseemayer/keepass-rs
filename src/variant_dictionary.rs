use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use std::{collections::HashMap, io::Write};
use thiserror::Error;

use crate::io::WriteLengthTaggedExt;

pub const VARIANT_DICTIONARY_VERSION: u16 = 0x100;
pub const VARIANT_DICTIONARY_END: u8 = 0x0;

pub const U32_TYPE_ID: u8 = 0x04;
pub const U64_TYPE_ID: u8 = 0x05;
pub const BOOL_TYPE_ID: u8 = 0x08;
pub const I32_TYPE_ID: u8 = 0x0c;
pub const I64_TYPE_ID: u8 = 0x0d;
pub const STR_TYPE_ID: u8 = 0x18;
pub const BYTES_TYPE_ID: u8 = 0x42;

#[derive(Debug)]
pub(crate) struct VariantDictionary {
    pub data: HashMap<String, VariantDictionaryValue>,
}

#[derive(Debug, Error)]
pub enum VariantDictionaryError {
    #[error("Invalid variant dictionary version: {}", version)]
    InvalidVersion { version: u16 },

    #[error("Invalid value type: {}", value_type)]
    InvalidValueType { value_type: u8 },

    #[error("Missing key: {}", key)]
    MissingKey { key: String },

    #[error("Mistyped value: {}", key)]
    Mistyped { key: String },

    #[error("VariantDictionary did not end with null byte, when it should")]
    NotTerminated,
}

impl VariantDictionary {
    pub(crate) fn parse(buffer: &[u8]) -> Result<VariantDictionary, VariantDictionaryError> {
        let version = LittleEndian::read_u16(&buffer[0..2]);

        if version != VARIANT_DICTIONARY_VERSION {
            return Err(VariantDictionaryError::InvalidVersion { version });
        }

        let mut pos = 2;
        let mut data = HashMap::new();

        while pos < buffer.len() - 9 {
            let value_type = buffer[pos];
            pos += 1;

            let key_length = LittleEndian::read_u32(&buffer[pos..(pos + 4)]) as usize;
            pos += 4;

            let key = String::from_utf8_lossy(&buffer[pos..(pos + key_length)]).to_string();
            pos += key_length;

            let value_length = LittleEndian::read_u32(&buffer[pos..(pos + 4)]) as usize;
            pos += 4;

            let value_buffer = &buffer[pos..(pos + value_length)];
            pos += value_length;

            let value = match value_type {
                U32_TYPE_ID => VariantDictionaryValue::UInt32(LittleEndian::read_u32(value_buffer)),
                U64_TYPE_ID => VariantDictionaryValue::UInt64(LittleEndian::read_u64(value_buffer)),
                BOOL_TYPE_ID => VariantDictionaryValue::Bool(value_buffer != [0]),
                I32_TYPE_ID => VariantDictionaryValue::Int32(LittleEndian::read_i32(value_buffer)),
                I64_TYPE_ID => VariantDictionaryValue::Int64(LittleEndian::read_i64(value_buffer)),
                STR_TYPE_ID => VariantDictionaryValue::String(
                    String::from_utf8_lossy(value_buffer).to_string(),
                ),
                BYTES_TYPE_ID => VariantDictionaryValue::ByteArray(value_buffer.to_vec()),
                _ => {
                    return Err(VariantDictionaryError::InvalidValueType { value_type });
                }
            };

            data.insert(key, value);
        }

        if buffer[pos] != VARIANT_DICTIONARY_END {
            // even though we can determine when to stop parsing a VariantDictionary by where we
            // are in the buffer, there should always be a value_type = 0 entry to denote that a
            // VariantDictionary is finished
            return Err(VariantDictionaryError::NotTerminated);
        }

        Ok(VariantDictionary { data })
    }

    pub(crate) fn dump(&self, writer: &mut dyn Write) -> Result<(), std::io::Error> {
        writer.write_u16::<LittleEndian>(VARIANT_DICTIONARY_VERSION)?;

        for (field_name, field_value) in &self.data {
            match field_value {
                VariantDictionaryValue::UInt32(value) => {
                    writer.write_u8(U32_TYPE_ID)?;
                    writer.write_with_len(field_name.as_bytes())?;
                    writer.write_u32::<LittleEndian>(4)?;
                    writer.write_u32::<LittleEndian>(*value)?;
                }
                VariantDictionaryValue::UInt64(value) => {
                    writer.write_u8(U64_TYPE_ID)?;
                    writer.write_with_len(field_name.as_bytes())?;
                    writer.write_u32::<LittleEndian>(8)?;
                    writer.write_u64::<LittleEndian>(*value)?;
                }
                VariantDictionaryValue::Bool(value) => {
                    writer.write_u8(BOOL_TYPE_ID)?;
                    writer.write_with_len(field_name.as_bytes())?;
                    writer.write_u32::<LittleEndian>(1)?;
                    writer.write_u8(if *value { 1 } else { 0 })?;
                }
                VariantDictionaryValue::Int32(value) => {
                    writer.write_u8(I32_TYPE_ID)?;
                    writer.write_with_len(field_name.as_bytes())?;
                    writer.write_u32::<LittleEndian>(4)?;
                    writer.write_i32::<LittleEndian>(*value)?;
                }
                VariantDictionaryValue::Int64(value) => {
                    writer.write_u8(I64_TYPE_ID)?;
                    writer.write_with_len(field_name.as_bytes())?;
                    writer.write_u32::<LittleEndian>(8)?;
                    writer.write_i64::<LittleEndian>(*value)?;
                }
                VariantDictionaryValue::String(value) => {
                    writer.write_u8(STR_TYPE_ID)?;
                    writer.write_with_len(field_name.as_bytes())?;
                    writer.write_with_len(value.as_bytes())?;
                }
                VariantDictionaryValue::ByteArray(value) => {
                    writer.write_u8(BYTES_TYPE_ID)?;
                    writer.write_with_len(field_name.as_bytes())?;
                    writer.write_with_len(value)?;
                }
            };
        }

        // signify end of variant dictionary
        writer.write_u8(VARIANT_DICTIONARY_END)?;
        Ok(())
    }

    pub(crate) fn get<'a, T: 'a>(&'a self, key: &str) -> Result<&'a T, VariantDictionaryError>
    where
        &'a VariantDictionaryValue: Into<Option<&'a T>>,
    {
        let vdv = self
            .data
            .get(key)
            .ok_or_else(|| VariantDictionaryError::MissingKey {
                key: key.to_owned(),
            })?;

        vdv.into().ok_or_else(|| VariantDictionaryError::Mistyped {
            key: key.to_owned(),
        })
    }
}

#[derive(Debug)]
pub(crate) enum VariantDictionaryValue {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(Vec<u8>),
}

impl<'a> Into<Option<&'a u32>> for &'a VariantDictionaryValue {
    fn into(self) -> Option<&'a u32> {
        match self {
            VariantDictionaryValue::UInt32(v) => Some(v),
            _ => None,
        }
    }
}

impl<'a> Into<Option<&'a u64>> for &'a VariantDictionaryValue {
    fn into(self) -> Option<&'a u64> {
        match self {
            VariantDictionaryValue::UInt64(v) => Some(v),
            _ => None,
        }
    }
}

impl<'a> Into<Option<&'a bool>> for &'a VariantDictionaryValue {
    fn into(self) -> Option<&'a bool> {
        match self {
            VariantDictionaryValue::Bool(v) => Some(v),
            _ => None,
        }
    }
}

impl<'a> Into<Option<&'a i32>> for &'a VariantDictionaryValue {
    fn into(self) -> Option<&'a i32> {
        match self {
            VariantDictionaryValue::Int32(v) => Some(v),
            _ => None,
        }
    }
}

impl<'a> Into<Option<&'a i64>> for &'a VariantDictionaryValue {
    fn into(self) -> Option<&'a i64> {
        match self {
            VariantDictionaryValue::Int64(v) => Some(v),
            _ => None,
        }
    }
}

impl<'a> Into<Option<&'a String>> for &'a VariantDictionaryValue {
    fn into(self) -> Option<&'a String> {
        match self {
            VariantDictionaryValue::String(v) => Some(v),
            _ => None,
        }
    }
}

impl<'a> Into<Option<&'a Vec<u8>>> for &'a VariantDictionaryValue {
    fn into(self) -> Option<&'a Vec<u8>> {
        match self {
            VariantDictionaryValue::ByteArray(v) => Some(v),
            _ => None,
        }
    }
}
