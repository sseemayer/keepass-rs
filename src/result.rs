error_chain! {
    foreign_links {
        Io(::std::io::Error);
        XML(::xml::reader::Error);
        UTF8(::std::str::Utf8Error);
        Argon2(::argon2::Error);
    }

    errors {
        Compression(v: String) {
            description("Decompression error"),
        }
        Crypto {
            description("Cryptography error")
            display("Cryptography error")
        }
        IncorrectKey {
            description("Incorrect key")
        }
        InvalidIdentifier {
            description("Invalid file header - not a .kdbx file?")
        }
        InvalidHeaderEntry(h: u8)  {
            description("Encountered invalid header entry")
        }
        InvalidKeyFile {
            description("Key file invalid")
        }
        IncompleteHeader {
            description("Invalid file header - missing some required entries")
        }
        InvalidOuterCipherID(cid: Vec<u8>) {
            description ("Encountered an invalid outer cipher ID")
        }
        InvalidInnerCipherID(cid: u32) {
            description ("Encountered an invalid inner cipher ID")
        }
        InvalidCompressionSuite {
            description("Encountered an invalid compression suite")
        }
        InvalidInnerRandomStreamId {
            description("Encountered an invalid inner stream cipher")
        }
        InvalidVariantDictionaryVersion {
            description("Encountered an invalid VariantDictionary version")
        }
        InvalidVariantDictionaryValueType {
            description("Encountered an invalid VariantDictionary value type")
        }
        InvalidKDBXVersion {
            description("Invalid KDBX database file version")
        }
        InvalidKdfParams {
            description("KDF parameters invalid")
        }
        HeaderHashMismatch {
            description("Header hash mismatch")
        }
        BlockHashMismatch {
            description( "Block hash verification failed"),
        }
    }

}

impl ::std::convert::From<::crypto::symmetriccipher::SymmetricCipherError> for self::Error {
    fn from(_ce: ::crypto::symmetriccipher::SymmetricCipherError) -> Self {
        self::ErrorKind::Crypto.into()
    }
}
