use secstr::SecStr;
use std::collections::HashMap;
use std::convert::TryFrom;

use hex_literal::hex;

use crate::{
    crypt, decompress,
    parse::{
        kdbx3::KDBX3Header,
        kdbx4::{KDBX4Header, KDBX4InnerHeader},
    },
    result::{DatabaseIntegrityError, Error, Result},
    variant_dictionary::VariantDictionary,
};

const _CIPHERSUITE_AES128: [u8; 16] = hex!("61ab05a1946441c38d743a563df8dd35");
const CIPHERSUITE_AES256: [u8; 16] = hex!("31c1f2e6bf714350be5805216afc5aff");
const _CIPHERSUITE_TWOFISH: [u8; 16] = hex!("ad68f29f576f4bb9a36ad47af965346c");
const _CIPHERSUITE_CHACHA20: [u8; 16] = hex!("d6038a2b8b6f4cb5a524339a31dbb59a");

#[derive(Debug)]
pub enum OuterCipherSuite {
    AES256,
}

impl OuterCipherSuite {
    pub(crate) fn get_cipher(&self, key: &[u8], iv: &[u8]) -> Result<Box<crypt::cipher::Cipher>> {
        match self {
            OuterCipherSuite::AES256 => Ok(Box::new(crypt::cipher::AES256Cipher::new(key, iv)?)),
        }
    }
}

impl TryFrom<&[u8]> for OuterCipherSuite {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<OuterCipherSuite> {
        if v == CIPHERSUITE_AES256 {
            Ok(OuterCipherSuite::AES256)
        } else {
            Err(DatabaseIntegrityError::InvalidOuterCipherID { cid: v.to_vec() }.into())
        }
    }
}

#[derive(Debug)]
pub enum InnerCipherSuite {
    Plain,
    Salsa20,
    ChaCha20,
}

impl InnerCipherSuite {
    pub(crate) fn get_cipher(&self, key: &[u8]) -> Result<Box<crypt::cipher::Cipher>> {
        match self {
            InnerCipherSuite::Plain => Ok(Box::new(crypt::cipher::PlainCipher::new(key)?)),
            InnerCipherSuite::Salsa20 => Ok(Box::new(crypt::cipher::Salsa20Cipher::new(key)?)),
            InnerCipherSuite::ChaCha20 => Ok(Box::new(crypt::cipher::ChaCha20Cipher::new(key)?)),
        }
    }
}

impl TryFrom<u32> for InnerCipherSuite {
    type Error = Error;

    fn try_from(v: u32) -> Result<InnerCipherSuite> {
        match v {
            0 => Ok(InnerCipherSuite::Plain),
            2 => Ok(InnerCipherSuite::Salsa20),
            3 => Ok(InnerCipherSuite::ChaCha20),
            _ => Err(DatabaseIntegrityError::InvalidInnerCipherID { cid: v }.into()),
        }
    }
}

#[derive(Debug)]
pub enum KdfSettings {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        memory: u64,
        salt: Vec<u8>,
        iterations: u64,
        parallelism: u32,
        version: argon2::Version,
    },
}

impl KdfSettings {
    pub(crate) fn get_kdf(&self) -> Box<crypt::kdf::Kdf> {
        match self {
            KdfSettings::Aes { seed, rounds } => Box::new(crypt::kdf::AesKdf {
                seed: seed.clone(),
                rounds: *rounds,
            }),
            KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            } => Box::new(crypt::kdf::Argon2Kdf {
                memory: *memory,
                salt: salt.clone(),
                iterations: *iterations,
                parallelism: *parallelism,
                version: *version,
            }),
        }
    }
}

const KDF_AES_KDBX3: [u8; 16] = hex!("c9d9f39a628a4460bf740d08c18a4fea");
const KDF_AES_KDBX4: [u8; 16] = hex!("7c02bb8279a74ac0927d114a00648238");
const KDF_ARGON2: [u8; 16] = hex!("ef636ddf8c29444b91f7a9a403e30a0c");

impl TryFrom<VariantDictionary> for KdfSettings {
    type Error = Error;

    fn try_from(vd: VariantDictionary) -> Result<KdfSettings> {
        let uuid: Vec<u8> = vd.get("$UUID")?;

        if uuid == KDF_ARGON2 {
            let memory: u64 = vd.get("M")?;
            let salt: Vec<u8> = vd.get("S")?;
            let iterations: u64 = vd.get("I")?;
            let parallelism: u32 = vd.get("P")?;
            let version: u32 = vd.get("V")?;

            let version = match version {
                0x10 => argon2::Version::Version10,
                0x13 => argon2::Version::Version13,
                _ => {
                    return Err(Error::from(DatabaseIntegrityError::InvalidKDFVersion {
                        version,
                    }))
                }
            };

            Ok(KdfSettings::Argon2 {
                memory,
                salt,
                iterations,
                parallelism,
                version,
            })
        } else if uuid == KDF_AES_KDBX4 || uuid == KDF_AES_KDBX3 {
            let rounds: u64 = vd.get("R")?;
            let seed: Vec<u8> = vd.get("S")?;

            Ok(KdfSettings::Aes { rounds, seed })
        } else {
            Err(DatabaseIntegrityError::InvalidKDFUUID { uuid }.into())
        }
    }
}

#[derive(Debug)]
pub enum Compression {
    None,
    GZip,
}

impl Compression {
    pub(crate) fn get_compression(&self) -> Box<decompress::Decompress> {
        match self {
            Compression::None => Box::new(decompress::NoCompression),
            Compression::GZip => Box::new(decompress::GZipCompression),
        }
    }
}

impl TryFrom<u32> for Compression {
    type Error = Error;

    fn try_from(v: u32) -> Result<Compression> {
        match v {
            0 => Ok(Compression::None),
            1 => Ok(Compression::GZip),
            _ => Err(DatabaseIntegrityError::InvalidCompressionSuite { cid: v }.into()),
        }
    }
}

#[derive(Debug)]
pub enum Header {
    KDBX3(KDBX3Header),
    KDBX4(KDBX4Header),
}

#[derive(Debug)]
pub enum InnerHeader {
    None,
    KDBX4(KDBX4InnerHeader),
}

/// A decrypted KeePass database
#[derive(Debug)]
pub struct Database {
    /// Header information of the KeePass database
    pub header: Header,

    /// Optional inner header information
    pub inner_header: InnerHeader,

    /// Root node of the KeePass database
    pub root: Group,
}

impl Database {
    /// Parse a database from a std::io::Read
    pub fn open(
        source: &mut std::io::Read,
        password: Option<&str>,
        keyfile: Option<&mut std::io::Read>,
    ) -> Result<Database> {
        let mut key_elements: Vec<Vec<u8>> = Vec::new();

        if let Some(p) = password {
            key_elements.push(
                crypt::calculate_sha256(&[p.as_bytes()])?
                    .as_slice()
                    .to_vec(),
            );
        }

        if let Some(f) = keyfile {
            key_elements.push(::keyfile::parse(f)?);
        }

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let (version, file_major_version, file_minor_version) =
            crate::parse::get_kdbx_version(data.as_ref())?;

        match file_major_version {
            3 => crate::parse::kdbx3::parse(data.as_ref(), &key_elements),
            4 => crate::parse::kdbx4::parse(data.as_ref(), &key_elements),
            _ => Err(DatabaseIntegrityError::InvalidKDBXVersion {
                version,
                file_major_version,
                file_minor_version,
            }
            .into()),
        }
    }
}

/// A database group with child groups and entries
#[derive(Debug, Default)]
pub struct Group {
    /// The name of the group
    pub name: String,

    /// The list of child groups
    pub child_groups: HashMap<String, Group>,

    /// The list of entries in this group
    pub entries: HashMap<String, Entry>,
}

impl Group {
    /// Recursively get a Group or Entry by specifying a path relative to the current Group
    /// ```
    /// use keepass::{Database, Node};
    /// use std::{fs::File, path::Path};
    ///
    /// let path = Path::new("tests/resources/test_db_with_password.kdbx");
    /// let db = Database::open(&mut File::open(path).unwrap(), Some("demopass"), None).unwrap();
    ///
    /// if let Some(Node::EntryNode(e)) = db.root.get(&["General", "Sample Entry #2"]) {
    ///     println!("User: {}", e.get_username().unwrap());
    /// }
    /// ```
    pub fn get(&self, path: &[&str]) -> Option<Node> {
        if path.len() == 0 {
            Some(Node::GroupNode(self))
        } else {
            let p = path[0];
            let l = path.len();

            if self.entries.contains_key(p) && l == 1 {
                Some(Node::EntryNode(&self.entries[p]))
            } else if self.child_groups.contains_key(p) {
                let g = &self.child_groups[p];

                if l == 1 {
                    Some(Node::GroupNode(g))
                } else {
                    let r = &path[1..];
                    g.get(r)
                }
            } else {
                None
            }
        }
    }
}

#[derive(Debug)]
pub enum Value {
    Unprotected(String),
    Protected(SecStr),
}

/// A database entry containing several key-value fields.
#[derive(Debug, Default)]
pub struct Entry {
    pub fields: HashMap<String, Value>,
    pub autotype: Option<AutoType>,
}

/// An AutoType setting associated with an Entry
#[derive(Debug, Default)]
pub struct AutoType {
    pub enabled: bool,
    pub sequence: Option<String>,
    pub associations: Vec<AutoTypeAssociation>,
}

/// A window association associated with an AutoType setting
#[derive(Debug, Default)]
pub struct AutoTypeAssociation {
    pub window: Option<String>,
    pub sequence: Option<String>,
}

pub enum Node<'a> {
    GroupNode(&'a Group),
    EntryNode(&'a Entry),
}

/// An iterator over Groups and Entries
pub struct NodeIter<'a> {
    queue: Vec<Node<'a>>,
}

impl<'a> Entry {
    /// Get a field by name, taking care of unprotecting Protected values automatically
    pub fn get(&'a self, key: &str) -> Option<&'a str> {
        match self.fields.get(key) {
            Some(&Value::Protected(ref pv)) => std::str::from_utf8(pv.unsecure()).ok(),
            Some(&Value::Unprotected(ref uv)) => Some(&uv),
            None => None,
        }
    }

    /// Convenience method for getting the value of the 'Title' field
    pub fn get_title(&'a self) -> Option<&'a str> {
        self.get("Title")
    }

    /// Convenience method for getting the value of the 'UserName' field
    pub fn get_username(&'a self) -> Option<&'a str> {
        self.get("UserName")
    }

    /// Convenience method for getting the value of the 'Password' field
    pub fn get_password(&'a self) -> Option<&'a str> {
        self.get("Password")
    }
}

impl<'a> Iterator for NodeIter<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        let res = self.queue.pop();

        if let Some(Node::GroupNode(ref g)) = res {
            self.queue
                .extend(g.entries.iter().map(|(_, e)| Node::EntryNode(&e)));
            self.queue
                .extend(g.child_groups.iter().map(|(_, g)| Node::GroupNode(&g)));
        }

        res
    }
}

impl<'a> Group {
    pub fn iter(&'a self) -> NodeIter<'a> {
        (&self).into_iter()
    }
}

impl<'a> IntoIterator for &'a Group {
    type Item = Node<'a>;
    type IntoIter = NodeIter<'a>;

    fn into_iter(self) -> NodeIter<'a> {
        NodeIter {
            queue: vec![Node::GroupNode(&self)],
        }
    }
}
