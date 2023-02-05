use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};

/// Extension trait to write a length-tagged field
pub trait WriteLengthTaggedExt: Write {
    fn write_with_len(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        self.write_u32::<LittleEndian>(data.len() as u32)?;
        self.write_all(data)?;
        Ok(())
    }
}

impl<W: Write + ?Sized> WriteLengthTaggedExt for W {}
