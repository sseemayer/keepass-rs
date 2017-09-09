use flate2::read::GzDecoder;
use super::result::{Result};
use std::io::Read;

pub trait Decompress {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>>;
}

pub struct NoCompression;

impl Decompress for NoCompression {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        Ok(in_buffer.into_iter().cloned().collect())
    }
}

pub struct GZipCompression;

impl Decompress for GZipCompression {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        let mut decoder = GzDecoder::new(in_buffer)?;
        decoder.read_to_end(&mut res)?;
        Ok(res)
    }
}
