use flate2::read::GzDecoder;
use std::io::Read;

pub trait Decompress {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error>;
}

pub struct NoCompression;

impl Decompress for NoCompression {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        Ok(in_buffer.to_vec())
    }
}

pub struct GZipCompression;

impl Decompress for GZipCompression {
    fn decompress(&self, in_buffer: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut res = Vec::new();
        let mut decoder = GzDecoder::new(in_buffer);
        decoder.read_to_end(&mut res)?;
        Ok(res)
    }
}
