use std::collections::VecDeque;

use crate::db::{entry::Entry, group::Group};

#[derive(Debug, Eq, PartialEq, Clone)]
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

/// An iterator over Groups and Entries
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
