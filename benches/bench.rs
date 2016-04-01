#![feature(test)]

extern crate keepass;
extern crate test;

use keepass::{Database, Node, OpenDBError};
use std::fs::File;
use test::{Bencher, black_box};

#[bench]
fn bench_sample(b: &mut Bencher) {

    b.iter(|| {
        // Open KeePass database
        let db = File::open(std::path::Path::new("test/sample.kdbx"))
                     .map_err(|e| OpenDBError::Io(e))
                     .and_then(|mut db_file| Database::open(&mut db_file, "demopass"))
                     .unwrap();

        let mut group_count = black_box(0);
        let mut entry_count = black_box(0);

        // Iterate over all Groups and Nodes
        for node in &db.root {
            match node {
                Node::Group(_) => group_count += 1,
                Node::Entry(_) => entry_count += 1,
            }
        }
        assert_eq!(group_count, 5);
        assert_eq!(entry_count, 5);
    });
}
