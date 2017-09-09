use secstr::SecStr;
use std::collections::HashMap;
use std;

/// A decrypted KeePass database
#[derive(Debug)]
pub struct Database {
    /// Root node of the KeePass database
    pub root: Group,
}

/// A database group with child groups and entries
#[derive(Debug)]
pub struct Group {
    /// The name of the group
    pub name: String,

    /// The list of child groups
    pub child_groups: Vec<Group>,

    /// The list of entries in this group
    pub entries: Vec<Entry>,
}


#[derive(Debug)]
pub enum Value {
    Unprotected(String),
    Protected(SecStr),
}

/// A database entry containing several key-value fields.
#[derive(Debug)]
pub struct Entry {
    pub fields: HashMap<String, Value>,
}


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
}


impl Header {
    pub fn new(
        version: u32,
        file_major_version: u16,
        file_minor_version: u16,
        outer_cipher_id: Vec<u8>,
        compression_flag: u32,
        master_seed: Vec<u8>,
        transform_seed: Vec<u8>,
        transform_rounds: u64,
        outer_iv: Vec<u8>,
        protected_stream_key: Vec<u8>,
        stream_start: Vec<u8>,
        inner_cipher_id: u32,
    ) -> Self {
        Header {
            version: version,
            file_major_version: file_major_version,
            file_minor_version: file_minor_version,
            outer_cipher_id: outer_cipher_id,
            compression_flag: compression_flag,
            master_seed: master_seed,
            transform_seed: transform_seed,
            transform_rounds: transform_rounds,
            outer_iv: outer_iv,
            protected_stream_key: protected_stream_key,
            stream_start: stream_start,
            inner_cipher_id: inner_cipher_id,
        }
    }
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
            self.queue.extend(g.entries.iter().map(|e| Node::EntryNode(&e)));
            self.queue
                .extend(g.child_groups.iter().map(|g| Node::GroupNode(&g)));
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
