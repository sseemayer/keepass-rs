use result::Result;
use secstr::SecStr;
use std::collections::HashMap;

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

        ::db_parse::parse(source, &key_elements)
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

#[derive(Debug)]
pub struct Header {
    //https://gist.github.com/msmuenchen/9318327
    pub version: u32,
    pub file_major_version: u16,
    pub file_minor_version: u16,
    pub outer_cipher_id: Vec<u8>,
    pub compression_flag: u32,
    pub master_seed: Vec<u8>,
    pub transform_seed: Vec<u8>,
    pub transform_rounds: u64,
    pub outer_iv: Vec<u8>,
    pub protected_stream_key: Vec<u8>,
    pub stream_start: Vec<u8>,
    pub inner_cipher_id: u32,
    pub body_start: usize,
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
