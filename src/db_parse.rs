use byteorder::{ByteOrder, LittleEndian};
use std;
use std::collections::HashMap;

use super::result::{ErrorKind, Result};

#[derive(Debug)]
pub enum VariantDictionaryValue<'a> {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    ByteArray(&'a [u8]),
}

/// Read KDBX4 VariantDictionary data structures
fn parse_variant_dictionary(data: &[u8]) -> Result<HashMap<String, VariantDictionaryValue>> {
    let version = &data[0];

    if version != &4u8 {
        return Err(ErrorKind::InvalidVariantDictionaryVersion.into());
    }

    let mut pos = 8;
    let mut out = HashMap::new();

    while pos < data.len() {
        let value_type = data[pos];
        pos += 1;
        println!("value_type {:x}", value_type);

        let key_length_buffer = &data[pos..(pos + 4)];
        pos += 4;
        println!("key_length_buffer {:x?}", key_length_buffer);

        let key_length = LittleEndian::read_u32(key_length_buffer);
        println!("key_length {}", key_length);

        let key_buffer = &data[pos..(pos + key_length as usize)];
        pos += key_length as usize;

        println!("Key_buffer: {:x?}", key_buffer);
        let key = std::str::from_utf8(key_buffer)?.to_owned();
        let value_length = LittleEndian::read_u32(&data[pos..(pos + 4)]) as usize;

        pos += 4;

        let value_buffer = &data[pos..(pos + value_length)];
        pos += value_length;

        let value = match value_type {
            0x04 => VariantDictionaryValue::UInt32(LittleEndian::read_u32(value_buffer)),
            0x05 => VariantDictionaryValue::UInt64(LittleEndian::read_u64(value_buffer)),
            0x08 => VariantDictionaryValue::Bool(value_buffer != [0]),
            0x0c => VariantDictionaryValue::Int32(LittleEndian::read_i32(value_buffer)),
            0x0d => VariantDictionaryValue::Int64(LittleEndian::read_i64(value_buffer)),
            0x18 => VariantDictionaryValue::String(std::str::from_utf8(value_buffer)?.into()),
            0x42 => VariantDictionaryValue::ByteArray(value_buffer),
            _ => {
                return Err(ErrorKind::InvalidVariantDictionaryValueType.into());
            }
        };

        out.insert(key, value);
    }

    Ok(out)
}
