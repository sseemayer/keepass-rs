extern crate flate2;

use self::flate2::read::GzDecoder;

use std::io::Read;

#[derive(Debug)]
pub struct DecompressionError(String);

pub trait Decompress {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, DecompressionError>;
}

pub struct NoCompression;

impl Decompress for NoCompression {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, DecompressionError> {
        Ok(in_buffer.into_iter().cloned().collect())
    }
}

pub struct GZipCompression;

impl Decompress for GZipCompression {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, DecompressionError> {
        let mut res = Vec::new();
        let mut decoder = try!(GzDecoder::new(in_buffer)
                                   .map_err(|e| DecompressionError(e.to_string())));
        try!(decoder.read_to_end(&mut res).map_err(|e| DecompressionError(e.to_string())));
        Ok(res)
    }
}
