use std::collections::VecDeque;
use uuid::Uuid;

use crate::db::{entry::Entry, group::Group};

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) enum NodePathElement {
    #[allow(dead_code)]
    UUID(String),
    Title(String),
}

pub(crate) type NodePath = Vec<NodePathElement>;

impl NodePathElement {
    pub(crate) fn matches(&self, node: &Node) -> bool {
        let uuid = match node {
            Node::Entry(e) => e.uuid,
            Node::Group(g) => g.uuid,
        };
        let title = match node {
            Node::Entry(e) => e.get_title(),
            Node::Group(g) => Some(g.get_name()),
        };
        match self {
            NodePathElement::UUID(u) => uuid.to_string() == *u,
            NodePathElement::Title(t) => {
                if let Some(title) = title {
                    return title == *t;
                }
                return false;
            }
        }
    }

    pub(crate) fn wrap_titles(path: &[&str]) -> NodePath {
        let mut response: NodePath = vec![];
        for path_element in path {
            response.push(NodePathElement::Title(path_element.to_string()));
        }
        response
    }

    pub(crate) fn wrap_ids(uuids: &[Uuid]) -> NodePath {
        let mut response: NodePath = vec![];
        for uuid in uuids {
            response.push(NodePathElement::UUID(uuid.to_string()));
        }
        response
    }
}

/// An owned node in the database tree structure which can either be an Entry or Group
#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub enum Node {
    Group(Group),
    Entry(Entry),
}

impl Node {
    pub fn as_ref<'a>(&'a self) -> NodeRef<'a> {
        self.into()
    }

    pub fn as_mut<'a>(&'a mut self) -> NodeRefMut<'a> {
        self.into()
    }

    pub fn get_uuid(&self) -> Uuid {
        match self {
            Node::Group(g) => g.uuid,
            Node::Entry(e) => e.uuid,
        }
    }
}

impl From<Entry> for Node {
    fn from(entry: Entry) -> Self {
        Node::Entry(entry)
    }
}

impl From<Group> for Node {
    fn from(group: Group) -> Self {
        Node::Group(group)
    }
}

/// A shared reference to a node in the database tree structure which can either point to an Entry or a Group
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

/// An exclusive mutable reference to a node in the database tree structure which can either point to an Entry or a Group
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

/// An iterator over Group and Entry references
pub struct NodeIter<'a> {
    queue: VecDeque<NodeRef<'a>>,
}

impl<'a> NodeIter<'a> {
    pub fn new(queue: VecDeque<NodeRef<'a>>) -> Self {
        Self { queue }
    }
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
