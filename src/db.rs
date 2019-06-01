use secstr::SecStr;
use std::collections::HashMap;
use std::convert::TryFrom;

use crate::{
    crypt, decompress,
    parse::kdbx3::KDBX3Header,
    result::{Error, ErrorKind, Result},
};

const CIPHERSUITE_AES256: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];

#[derive(Debug)]
pub enum OuterCipherSuite {
    AES256,
}

impl OuterCipherSuite {
    pub(crate) fn get_cipher(&self) -> Box<crypt::Cipher> {
        match self {
            OuterCipherSuite::AES256 => Box::new(crypt::AES256Cipher),
        }
    }
}

impl TryFrom<&[u8]> for OuterCipherSuite {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<OuterCipherSuite> {
        if v == CIPHERSUITE_AES256 {
            Ok(OuterCipherSuite::AES256)
        } else {
            Err(ErrorKind::InvalidCipherID.into())
        }
    }
}

#[derive(Debug)]
pub enum InnerCipherSuite {
    Plain,
    Salsa20,
}

impl InnerCipherSuite {
    pub(crate) fn get_cipher(&self) -> Box<crypt::Cipher> {
        match self {
            InnerCipherSuite::Plain => Box::new(crypt::PlainCipher),
            InnerCipherSuite::Salsa20 => Box::new(crypt::Salsa20Cipher),
        }
    }
}

impl TryFrom<u32> for InnerCipherSuite {
    type Error = Error;

    fn try_from(v: u32) -> Result<InnerCipherSuite> {
        match v {
            0 => Ok(InnerCipherSuite::Plain),
            2 => Ok(InnerCipherSuite::Salsa20),
            _ => Err(ErrorKind::InvalidCipherID.into()),
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
            _ => Err(ErrorKind::InvalidCompressionSuite.into()),
        }
    }
}

#[derive(Debug)]
pub enum Header {
    KDBX3(KDBX3Header),
}

/// A decrypted KeePass database
#[derive(Debug)]
pub struct Database {
    /// Header information of the KeePass database
    pub header: Header,

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
            key_elements.push(p.as_bytes().to_vec());
        }

        if let Some(f) = keyfile {
            key_elements.push(::keyfile::parse(f)?);
        }

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let (_, file_major_version, _) = crate::parse::get_kdbx_version(data.as_ref())?;

        match file_major_version {
            3 => crate::parse::kdbx3::parse(data.as_ref(), &key_elements),
            _ => Err(ErrorKind::InvalidKDBXVersion.into()),
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
