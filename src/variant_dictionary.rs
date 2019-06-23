use crate::result::{DatabaseIntegrityError, Error, Result};
use byteorder::{ByteOrder, LittleEndian};

use std::collections::HashMap;

#[derive(Debug)]
pub(crate) struct VariantDictionary {
    data: HashMap<String, VariantDictionaryValue>,
}

impl VariantDictionary {
    pub(crate) fn parse(buffer: &[u8]) -> Result<VariantDictionary> {
        let version = LittleEndian::read_u16(&buffer[0..2]);

        if version != 0x100 {
            return Err(DatabaseIntegrityError::InvalidVariantDictionaryVersion { version }.into());
        }

        let mut pos = 2;
        let mut data = HashMap::new();

        while pos < buffer.len() - 9 {
            let value_type = buffer[pos];
            pos += 1;

            let key_length = LittleEndian::read_u32(&buffer[pos..(pos + 4)]) as usize;
            pos += 4;

            let key = std::str::from_utf8(&buffer[pos..(pos + key_length)])
                .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
                .to_owned();
            pos += key_length;

            let value_length = LittleEndian::read_u32(&buffer[pos..(pos + 4)]) as usize;
            pos += 4;

            let value_buffer = &buffer[pos..(pos + value_length)];
            pos += value_length;

            let value = match value_type {
                0x04 => VariantDictionaryValue::UInt32(LittleEndian::read_u32(value_buffer)),
                0x05 => VariantDictionaryValue::UInt64(LittleEndian::read_u64(value_buffer)),
                0x08 => VariantDictionaryValue::Bool(value_buffer != [0]),
                0x0c => VariantDictionaryValue::Int32(LittleEndian::read_i32(value_buffer)),
                0x0d => VariantDictionaryValue::Int64(LittleEndian::read_i64(value_buffer)),
                0x18 => VariantDictionaryValue::String(
                    std::str::from_utf8(value_buffer)
                        .map_err(|e| Error::from(DatabaseIntegrityError::from(e)))?
                        .into(),
                ),
                0x42 => VariantDictionaryValue::ByteArray(value_buffer.to_vec()),
                _ => {
                    return Err(DatabaseIntegrityError::InvalidVariantDictionaryValueType {
                        value_type,
                    }
                    .into());
                }
            };

            data.insert(key, value);
        }

        Ok(VariantDictionary { data })
    }

    pub(crate) fn get<T>(&self, key: &str) -> Result<T>
    where
        T: FromVariantDictionaryValue<T>,
    {
        let vdv = if let Some(v) = self.data.get(key) {
            v
        } else {
            return Err(Error::from(DatabaseIntegrityError::MissingKDFParams {
                key: key.to_owned(),
            }));
        };

        T::from_variant_dictionary_value(vdv).ok_or(
            DatabaseIntegrityError::MistypedKDFParam {
                key: key.to_owned(),
            }
            .into(),
        )
    }
}

pub(crate) trait FromVariantDictionaryValue<T> {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<T>;
}

impl FromVariantDictionaryValue<u32> for u32 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<u32> {
        if let VariantDictionaryValue::UInt32(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<u64> for u64 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<u64> {
        if let VariantDictionaryValue::UInt64(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<bool> for bool {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<bool> {
        if let VariantDictionaryValue::Bool(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<i32> for i32 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<i32> {
        if let VariantDictionaryValue::Int32(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<i64> for i64 {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<i64> {
        if let VariantDictionaryValue::Int64(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<String> for String {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<String> {
        if let VariantDictionaryValue::String(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
    }
}

impl FromVariantDictionaryValue<Vec<u8>> for Vec<u8> {
    fn from_variant_dictionary_value(vdv: &VariantDictionaryValue) -> Option<Vec<u8>> {
        if let VariantDictionaryValue::ByteArray(v) = vdv {
            Some(v.clone())
        } else {
            None
        }
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
