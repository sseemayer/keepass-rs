use secstr::SecStr;
use std::collections::{HashMap, VecDeque};
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "totp")]
use crate::otp::{TOTPError, TOTP};
use crate::{
    config::{Compression, InnerCipherSuite, KdfSettings, OuterCipherSuite},
    config::{CompressionError, InnerCipherSuiteError, KdfSettingsError, OuterCipherSuiteError},
    crypt::{calculate_sha256, CryptographyError},
    hmac_block_stream::BlockStreamError,
    keyfile::KeyfileError,
    parse::{
        kdb::KDBHeader,
        kdbx3::KDBX3Header,
        kdbx4::{BinaryAttachment, KDBX4Header, KDBX4InnerHeader},
    },
    variant_dictionary::VariantDictionaryError,
    xml_parse::XmlParseError,
};

#[derive(Debug)]
pub enum Header {
    KDB(KDBHeader),
    KDBX3(KDBX3Header),
    KDBX4(KDBX4Header),
}

#[derive(Debug)]
pub enum InnerHeader {
    None,
    KDBX4(KDBX4InnerHeader),
}

/// Identifier for KeePass 1 format.
pub const KEEPASS_1_ID: u32 = 0xb54bfb65;
/// Identifier for KeePass 2 pre-release format.
pub const KEEPASS_2_ID: u32 = 0xb54bfb66;
/// Identifier for the latest KeePass formats.
pub const KEEPASS_LATEST_ID: u32 = 0xb54bfb67;

/// A decrypted KeePass database
#[derive(Debug)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Database {
    /// Header information of the KeePass database
    #[cfg_attr(feature = "serialization", serde(skip))]
    pub header: Header,

    /// Optional inner header information
    #[cfg_attr(feature = "serialization", serde(skip))]
    pub inner_header: InnerHeader,

    /// Root node of the KeePass database
    pub root: Group,

    // Metadata of the KeePass database
    pub meta: Meta,
}

#[derive(Debug, Error)]
pub enum DatabaseKeyError {
    #[error("Incorrect key")]
    IncorrectKey,

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error(transparent)]
    Keyfile(#[from] KeyfileError),
}

#[derive(Debug, Error)]
pub enum DatabaseOpenError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Key(#[from] DatabaseKeyError),

    #[error(transparent)]
    DatabaseIntegrity(#[from] DatabaseIntegrityError),
}

#[derive(Debug, Error)]
pub enum DatabaseIntegrityError {
    #[error("Invalid KDBX identifier")]
    InvalidKDBXIdentifier,

    #[error(
        "Invalid KDBX version: {}.{}.{}",
        version,
        file_major_version,
        file_minor_version
    )]
    InvalidKDBXVersion {
        version: u32,
        file_major_version: u32,
        file_minor_version: u32,
    },

    #[error("Invalid header size: {}", size)]
    InvalidFixedHeader { size: usize },

    #[error(
        "Invalid field length for type {}: {} (expected {})",
        field_type,
        field_size,
        expected_field_size
    )]
    InvalidKDBFieldLength {
        field_type: u16,
        field_size: u32,
        expected_field_size: u32,
    },

    #[error("Missing group level")]
    MissingKDBGroupLevel,

    #[error(
        "Invalid group level {} (current level {})",
        group_level,
        current_level
    )]
    InvalidKDBGroupLevel {
        group_level: u16,
        current_level: u16,
    },

    #[error("Missing group ID")]
    MissingKDBGroupId,

    #[error("Invalid group ID {}", group_id)]
    InvalidKDBGroupId { group_id: u32 },

    #[error("Invalid group field type: {}", field_type)]
    InvalidKDBGroupFieldType { field_type: u16 },

    #[error("Invalid entry field type: {}", field_type)]
    InvalidKDBEntryFieldType { field_type: u16 },

    #[error("Incomplete group")]
    IncompleteKDBGroup,

    #[error("Incomplete entry")]
    IncompleteKDBEntry,

    #[error("Invalid fixed cipher ID: {}", cid)]
    InvalidFixedCipherID { cid: u32 },

    #[error("Header hash masmatch")]
    HeaderHashMismatch,

    #[error("Invalid outer header entry: {}", entry_type)]
    InvalidOuterHeaderEntry { entry_type: u8 },

    #[error("Incomplete outer header: Missing {}", missing_field)]
    IncompleteOuterHeader { missing_field: String },

    #[error("Invalid inner header entry: {}", entry_type)]
    InvalidInnerHeaderEntry { entry_type: u8 },

    #[error("Incomplete outer header: Missing {}", missing_field)]
    IncompleteInnerHeader { missing_field: String },

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),

    #[error(transparent)]
    Xml(#[from] XmlParseError),

    #[error(transparent)]
    OuterCipher(#[from] OuterCipherSuiteError),

    #[error(transparent)]
    InnerCipher(#[from] InnerCipherSuiteError),

    #[error(transparent)]
    Compression(#[from] CompressionError),

    #[error(transparent)]
    BlockStream(#[from] BlockStreamError),

    #[error(transparent)]
    VariantDictionary(#[from] VariantDictionaryError),

    #[error(transparent)]
    KdfSettings(#[from] KdfSettingsError),
}

#[derive(Debug, Error)]
pub enum DatabaseSaveError {
    #[error("Saving this database version is not supported")]
    UnsupportedVersion,

    #[error("Error while generating XML")]
    Xml(#[from] xml::writer::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Key(#[from] DatabaseKeyError),

    #[error(transparent)]
    Cryptography(#[from] CryptographyError),
}

impl From<CryptographyError> for DatabaseOpenError {
    fn from(e: CryptographyError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<BlockStreamError> for DatabaseOpenError {
    fn from(e: BlockStreamError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<XmlParseError> for DatabaseOpenError {
    fn from(e: XmlParseError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<InnerCipherSuiteError> for DatabaseOpenError {
    fn from(e: InnerCipherSuiteError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<OuterCipherSuiteError> for DatabaseOpenError {
    fn from(e: OuterCipherSuiteError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<KdfSettingsError> for DatabaseOpenError {
    fn from(e: KdfSettingsError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<VariantDictionaryError> for DatabaseOpenError {
    fn from(e: VariantDictionaryError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl From<CompressionError> for DatabaseOpenError {
    fn from(e: CompressionError) -> Self {
        DatabaseIntegrityError::from(e).into()
    }
}

impl Database {
    /// Parse a database from a std::io::Read
    pub fn open(
        source: &mut dyn std::io::Read,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Database, DatabaseOpenError> {
        let key_elements = Database::get_key_elements(password, keyfile)?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let (version, file_major_version, file_minor_version) =
            crate::parse::get_kdbx_version(data.as_ref())?;

        match version {
            KEEPASS_1_ID => crate::parse::kdb::parse(data.as_ref(), &key_elements),
            // KEEPASS_2_ID => alpha/beta kbd 2.x
            KEEPASS_LATEST_ID if file_major_version == 3 => {
                crate::parse::kdbx3::parse(data.as_ref(), &key_elements)
            }
            KEEPASS_LATEST_ID if file_major_version == 4 => {
                crate::parse::kdbx4::parse(data.as_ref(), &key_elements)
            }
            _ => Err(DatabaseIntegrityError::InvalidKDBXVersion {
                version,
                file_major_version: file_major_version as u32,
                file_minor_version: file_minor_version as u32,
            }
            .into()),
        }
    }

    /// Save a database to a std::io::Write
    pub(crate) fn save(
        &self,
        destination: &mut dyn std::io::Write,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<(), DatabaseSaveError> {
        let key_elements = Database::get_key_elements(password, keyfile)?;

        let data = match self.header {
            Header::KDB(_) => {
                return Err(DatabaseSaveError::UnsupportedVersion.into());
            }
            Header::KDBX3(_) => {
                return Err(DatabaseSaveError::UnsupportedVersion.into());
            }
            Header::KDBX4(_) => crate::parse::kdbx4::dump(self, &key_elements),
        }?;

        destination.write_all(&data)?;
        Ok(())
    }

    pub fn get_key_elements(
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Vec<Vec<u8>>, DatabaseKeyError> {
        let mut key_elements: Vec<Vec<u8>> = Vec::new();

        if let Some(p) = password {
            key_elements.push(calculate_sha256(&[p.as_bytes()])?.as_slice().to_vec());
        }

        if let Some(f) = keyfile {
            key_elements.push(crate::keyfile::parse(f)?);
        }

        if key_elements.is_empty() {
            return Err(DatabaseKeyError::IncorrectKey);
        }

        Ok(key_elements)
    }

    /// Helper function to load a database into its internal XML chunks
    pub fn get_xml_chunks(
        source: &mut dyn std::io::Read,
        password: Option<&str>,
        keyfile: Option<&mut dyn std::io::Read>,
    ) -> Result<Vec<Vec<u8>>, DatabaseOpenError> {
        let key_elements = Database::get_key_elements(password, keyfile)?;

        let mut data = Vec::new();
        source.read_to_end(&mut data)?;

        let (version, file_major_version, file_minor_version) =
            crate::parse::get_kdbx_version(data.as_ref())?;

        let data = match version {
            KEEPASS_1_ID => panic!("Dumping XML from KDB databases not supported"),
            // KEEPASS_2_ID => alpha/beta kbd 2.x
            KEEPASS_LATEST_ID if file_major_version == 3 => {
                crate::parse::kdbx3::decrypt_xml(data.as_ref(), &key_elements)?.1
            }
            KEEPASS_LATEST_ID if file_major_version == 4 => {
                vec![crate::parse::kdbx4::decrypt_xml(data.as_ref(), &key_elements)?.2]
            }
            _ => {
                return Err(DatabaseIntegrityError::InvalidKDBXVersion {
                    version,
                    file_major_version: file_major_version as u32,
                    file_minor_version: file_minor_version as u32,
                }
                .into())
            }
        };

        Ok(data)
    }

    pub fn new(
        outer_cipher_suite: OuterCipherSuite,
        compression: Compression,
        inner_cipher_suite: InnerCipherSuite,
        kdf_setting: KdfSettings,
        root: Group,
        binaries: Vec<BinaryAttachment>,
    ) -> std::result::Result<Database, getrandom::Error> {
        let mut outer_iv: Vec<u8> = vec![];
        outer_iv.resize(outer_cipher_suite.get_iv_size().into(), 0);
        getrandom::getrandom(&mut outer_iv)?;

        let mut inner_random_stream_key: Vec<u8> = vec![];
        inner_random_stream_key.resize(inner_cipher_suite.get_iv_size().into(), 0);
        getrandom::getrandom(&mut inner_random_stream_key)?;

        let kdf: KdfSettings;
        let mut kdf_seed: Vec<u8> = vec![];
        kdf_seed.resize(kdf_setting.seed_size().into(), 0);
        getrandom::getrandom(&mut kdf_seed)?;

        let mut master_seed: Vec<u8> = vec![];
        master_seed.resize(crate::parse::kdbx4::HEADER_MASTER_SEED_SIZE.into(), 0);
        getrandom::getrandom(&mut master_seed)?;

        // FIXME obviously this is ugly. We should be able to change
        // the seed without destructuring all the kdf enum types.
        match kdf_setting {
            KdfSettings::Aes { rounds, .. } => {
                kdf = KdfSettings::Aes {
                    seed: kdf_seed,
                    rounds,
                };
            }
            KdfSettings::Argon2 {
                iterations,
                memory,
                parallelism,
                version,
                ..
            } => {
                kdf = KdfSettings::Argon2 {
                    salt: kdf_seed,
                    iterations,
                    memory,
                    parallelism,
                    version,
                };
            }
        };

        Ok(Database {
            header: Header::KDBX4(KDBX4Header {
                version: crate::db::KEEPASS_LATEST_ID,
                file_major_version: 4,
                file_minor_version: 3,
                outer_cipher: outer_cipher_suite,
                compression,
                master_seed,
                outer_iv,
                kdf,
            }),
            inner_header: InnerHeader::KDBX4(KDBX4InnerHeader {
                inner_random_stream: inner_cipher_suite,
                inner_random_stream_key,
                binaries,
            }),
            root,
            meta: Meta::default(),
        })
    }
}

/// Database metadata
#[derive(Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Meta {
    pub recyclebin_uuid: String,
}

/// A database group with child groups and entries
#[derive(Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Group {
    /// The unique identifier of the group
    pub uuid: String,

    /// The name of the group
    pub name: String,

    /// The list of child nodes (Groups or Entries)
    pub children: Vec<Node>,

    /// The list of time fields for this group
    ///
    /// Using chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub times: HashMap<String, chrono::NaiveDateTime>,

    /// Does this group expire
    pub expires: bool,
}

impl Group {
    pub fn new(name: &str) -> Group {
        Group {
            children: vec![],
            name: name.to_string(),
            uuid: Uuid::new_v4().to_string(),
            times: HashMap::default(),
            expires: false,
        }
    }

    /// Recursively get a Group or Entry reference by specifying a path relative to the current Group
    /// ```
    /// use keepass::{Database, NodeRef};
    /// use std::{fs::File, path::Path};
    ///
    /// let path = Path::new("tests/resources/test_db_with_password.kdbx");
    /// let db = Database::open(&mut File::open(path).unwrap(), Some("demopass"), None).unwrap();
    ///
    /// if let Some(NodeRef::Entry(e)) = db.root.get(&["General", "Sample Entry #2"]) {
    ///     println!("User: {}", e.get_username().unwrap());
    /// }
    /// ```
    pub fn get<'a>(&'a self, path: &[&str]) -> Option<NodeRef<'a>> {
        if path.is_empty() {
            Some(NodeRef::Group(self))
        } else {
            if path.len() == 1 {
                let head = path[0];
                self.children.iter().find_map(|n| match n {
                    Node::Group(_) => None,
                    Node::Entry(e) => {
                        e.get_title()
                            .and_then(|t| if t == head { Some(n.to_ref()) } else { None })
                    }
                })
            } else {
                let head = path[0];
                let tail = &path[1..path.len()];

                let head_group = self.children.iter().find_map(|n| match n {
                    Node::Group(g) if g.name == head => Some(g),
                    _ => None,
                })?;

                head_group.get(tail)
            }
        }
    }

    /// Recursively get a mutable reference to a Group or Entry by specifying a path relative to
    /// the current Group
    pub fn get_mut<'a>(&'a mut self, path: &[&str]) -> Option<NodeRefMut<'a>> {
        if path.is_empty() {
            Some(NodeRefMut::Group(self))
        } else {
            if path.len() == 1 {
                let head = path[0];
                self.children
                    .iter_mut()
                    .filter(|n| match n {
                        Node::Group(g) => g.name == head,
                        Node::Entry(e) => e.get_title().map(|t| t == head).unwrap_or(false),
                    })
                    .map(|t| t.to_ref_mut())
                    .next()
            } else {
                let head = path[0];
                let tail = &path[1..path.len()];

                let head_group: &mut Group = self.children.iter_mut().find_map(|n| match n {
                    Node::Group(g) if g.name == head => Some(g),
                    _ => None,
                })?;

                head_group.get_mut(tail)
            }
        }
    }

    /// Get a timestamp field by name
    ///
    /// Returning the chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub fn get_time(&self, key: &str) -> Option<&chrono::NaiveDateTime> {
        self.times.get(key)
    }

    /// Convenience method for getting the value of the 'ExpiryTime' timestamp
    pub fn get_expiry_time(&self) -> Option<&chrono::NaiveDateTime> {
        self.get_time("ExpiryTime")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Value {
    Bytes(Vec<u8>),
    Unprotected(String),
    Protected(SecStr),
}

impl Value {
    pub fn is_empty(&self) -> bool {
        match self {
            Value::Bytes(b) => b.is_empty(),
            Value::Unprotected(u) => u.is_empty(),
            Value::Protected(p) => p.unsecure().is_empty(),
        }
    }
}

#[cfg(feature = "serialization")]
impl serde::Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Value::Bytes(b) => serializer.serialize_bytes(b),
            Value::Unprotected(u) => serializer.serialize_str(u),
            Value::Protected(p) => serializer.serialize_bytes(p.unsecure()),
        }
    }
}

/// An AutoType setting associated with an Entry
#[derive(Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AutoType {
    pub enabled: bool,
    pub sequence: Option<String>,
    pub associations: Vec<AutoTypeAssociation>,
}

/// A window association associated with an AutoType setting
#[derive(Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct AutoTypeAssociation {
    pub window: Option<String>,
    pub sequence: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum Node {
    Group(Group),
    Entry(Entry),
}

impl Node {
    pub fn to_ref<'a>(&'a self) -> NodeRef<'a> {
        self.into()
    }

    pub fn to_ref_mut<'a>(&'a mut self) -> NodeRefMut<'a> {
        self.into()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum NodeRef<'a> {
    Group(&'a Group),
    Entry(&'a Entry),
}

impl<'a> std::convert::From<&'a Node> for NodeRef<'a> {
    fn from(n: &'a Node) -> Self {
        match n {
            Node::Group(g) => NodeRef::Group(g),
            Node::Entry(e) => NodeRef::Entry(e),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum NodeRefMut<'a> {
    Group(&'a mut Group),
    Entry(&'a mut Entry),
}

impl<'a> std::convert::From<&'a mut Node> for NodeRefMut<'a> {
    fn from(n: &'a mut Node) -> Self {
        match n {
            Node::Group(g) => NodeRefMut::Group(g),
            Node::Entry(e) => NodeRefMut::Entry(e),
        }
    }
}

/// A database entry containing several key-value fields.
#[derive(Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Entry {
    pub uuid: String,
    pub fields: HashMap<String, Value>,
    pub autotype: Option<AutoType>,
    pub expires: bool,
    pub times: HashMap<String, chrono::NaiveDateTime>,
    pub tags: Vec<String>,
}
impl Entry {
    pub fn new() -> Entry {
        Entry {
            uuid: Uuid::new_v4().to_string(),
            fields: HashMap::default(),
            times: HashMap::default(),
            expires: false,
            autotype: None,
            tags: vec![],
        }
    }
}

impl<'a> Entry {
    /// Get a field by name, taking care of unprotecting Protected values automatically
    pub fn get(&'a self, key: &str) -> Option<&'a str> {
        match self.fields.get(key) {
            Some(&Value::Bytes(_)) => None,
            Some(&Value::Protected(ref pv)) => std::str::from_utf8(pv.unsecure()).ok(),
            Some(&Value::Unprotected(ref uv)) => Some(&uv),
            None => None,
        }
    }

    /// Get a bytes field by name
    pub fn get_bytes(&'a self, key: &str) -> Option<&'a [u8]> {
        match self.fields.get(key) {
            Some(&Value::Bytes(ref b)) => Some(&b),
            Some(&Value::Protected(_)) => None,
            Some(&Value::Unprotected(_)) => None,
            None => None,
        }
    }

    pub fn get_uuid(&'a self) -> &'a str {
        &self.uuid
    }

    /// Get a timestamp field by name
    ///
    /// Returning the chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub fn get_time(&self, key: &str) -> Option<&chrono::NaiveDateTime> {
        self.times.get(key)
    }

    /// Convenience method for getting the value of the 'ExpiryTime' timestamp
    /// This value is usually only meaningful/useful when expires == true
    pub fn get_expiry_time(&self) -> Option<&chrono::NaiveDateTime> {
        self.get_time("ExpiryTime")
    }

    /// Convenience method for getting a TOTP from this entry
    #[cfg(feature = "totp")]
    pub fn get_otp(&'a self) -> Result<TOTP, TOTPError> {
        self.get_raw_otp_value().ok_or(TOTPError::NoRecord)?.parse()
    }

    /// Convenience method for getting the raw value of the 'otp' field
    pub fn get_raw_otp_value(&'a self) -> Option<&'a str> {
        self.get("otp")
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

    /// Convenience method for getting the value of the 'URL' field
    pub fn get_url(&'a self) -> Option<&'a str> {
        self.get("URL")
    }
}

/// An iterator over Groups and Entries
pub struct NodeIter<'a> {
    queue: VecDeque<NodeRef<'a>>,
}

impl<'a> Iterator for NodeIter<'a> {
    type Item = NodeRef<'a>;

    fn next(&mut self) -> Option<NodeRef<'a>> {
        let head = self.queue.pop_front()?;

        if let NodeRef::Group(ref g) = head {
            self.queue.extend(g.children.iter().map(|n| n.into()))
        }

        Some(head)
    }
}

impl<'a> Group {
    pub fn iter(&'a self) -> NodeIter<'a> {
        (&self).into_iter()
    }
}

impl<'a> IntoIterator for &'a Group {
    type Item = NodeRef<'a>;
    type IntoIter = NodeIter<'a>;

    fn into_iter(self) -> NodeIter<'a> {
        let mut queue: VecDeque<NodeRef> = VecDeque::new();
        queue.push_back(NodeRef::Group(self));

        NodeIter { queue }
    }
}
