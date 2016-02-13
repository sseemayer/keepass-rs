extern crate flate2;
extern crate std;

use self::flate2::read::GzDecoder;

use std::io::Read;

#[derive(Debug)]
pub enum DecompressionError {
    Io(std::io::Error),
}

impl std::fmt::Display for DecompressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &DecompressionError::Io(ref e) => write!(f, "I/O error during decompression: {}", e),
        }
    }
}

impl std::error::Error for DecompressionError {
    fn description(&self) -> &str {
        match self {
            &DecompressionError::Io(ref e) => e.description(),
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            &DecompressionError::Io(ref e) => Some(e),
        }
    }
    
}


impl From<std::io::Error> for DecompressionError {
    fn from(e: std::io::Error) -> DecompressionError {
        DecompressionError::Io(e)
    }
}

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
        let mut decoder = try!(GzDecoder::new(in_buffer));
        try!(decoder.read_to_end(&mut res));
        Ok(res)
    }
}
