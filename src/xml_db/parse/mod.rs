use base64::{engine::general_purpose as base64_engine, Engine as _};
use thiserror::Error;
use xml::reader::XmlEvent;

use crate::{crypt::CryptographyError, xml_db::get_epoch_baseline};

pub enum XmlParseResult {
    KeepGoing,
    Push(Box<dyn ParseXml>),
    Pop,
}

#[derive(Debug, Error)]
pub enum XmlParseError {
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),

    #[error(transparent)]
    TimestampFormat(#[from] chrono::ParseError),

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),
}

pub trait ParseXml {
    fn handle_event(
        &mut self,
        event: &XmlEvent,
        stack: &[Box<dyn ParseXml>],
    ) -> Result<XmlParseResult, XmlParseError>;
}

pub fn parse_xml_timestamp(t: &str) -> Result<chrono::NaiveDateTime, XmlParseError> {
    match chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%SZ") {
        // Prior to KDBX4 file format, timestamps were stored as ISO 8601 strings
        Ok(ndt) => Ok(ndt),
        // If we don't have a valid ISO 8601 string, assume we have found a Base64 encoded int.
        _ => {
            let v = base64_engine::STANDARD.decode(t)?;

            // Cast the decoded base64 Vec into the array expected by i64::from_le_bytes
            let mut a: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
            a.copy_from_slice(&v[0..8]);
            let ndt = get_epoch_baseline() + chrono::Duration::seconds(i64::from_le_bytes(a));
            Ok(ndt)
        }
    }
}
