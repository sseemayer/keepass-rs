use keepass::{
    db::{Entry, Group, Node},
    Database,
};
use uuid::Uuid;

#[test]
fn test_deletion() {
    // 1. Setup
    let mut db = Database::new(Default::default());

    let mut g1 = Group::new("G1");
    let e1 = Entry::new();
    let _e1_uuid = e1.uuid;
    g1.add_child(e1);

    let mut g2 = Group::new("G2");
    let e2 = Entry::new();
    let e2_uuid = e2.uuid;
    g2.add_child(e2);
    g1.add_child(g2);

    let g1_uuid = g1.uuid;
    db.root.add_child(g1);

    let e3 = Entry::new();
    let e3_uuid = e3.uuid;
    db.root.add_child(e3);

    // 2. Test deleting a nested entry with logging
    let deleted_node = db.delete_by_uuid(&e2_uuid, true);
    assert!(deleted_node.is_some());
    if let Some(Node::Entry(e)) = deleted_node {
        assert_eq!(e.uuid, e2_uuid);
    } else {
        panic!("Expected an Entry to be deleted");
    }

    // Verify it's gone from the group
    let g1_ref = db.root.children.iter().find(|n| match n {
        Node::Group(g) => g.uuid == g1_uuid,
        _ => false,
    }).unwrap();
    if let Node::Group(g) = g1_ref {
        let g2_ref = g.children.iter().find(|n| match n {
            Node::Group(g_inner) => g_inner.name == "G2",
            _ => false,
        }).unwrap();
        if let Node::Group(g2_inner) = g2_ref {
             assert_eq!(g2_inner.children.len(), 0);
        } else {
            panic!("Expected G2 group");
        }
    } else {
        panic!("Expected G1 group");
    }


    // Verify it's in deleted_objects
    assert_eq!(db.deleted_objects.objects.len(), 1);
    assert_eq!(db.deleted_objects.objects[0].uuid, e2_uuid);

    // 3. Test deleting a group without logging
    let deleted_node = db.delete_by_uuid(&g1_uuid, false);
    assert!(deleted_node.is_some());
    if let Some(Node::Group(g)) = deleted_node {
        assert_eq!(g.uuid, g1_uuid);
        // check that it contained e1 and g2 before it was deleted
        assert_eq!(g.children.len(), 2);
    } else {
        panic!("Expected a Group to be deleted");
    }

    // Verify it's gone from the root
    assert_eq!(db.root.children.len(), 1);
    if let Some(Node::Entry(e)) = db.root.children.get(0) {
        assert_eq!(e.uuid, e3_uuid);
    } else {
        panic!("Expected E3 to be the only child of root");
    }

    // Verify deleted_objects count has not changed
    assert_eq!(db.deleted_objects.objects.len(), 1);

    // 4. Test deleting a non-existent node
    let random_uuid = Uuid::new_v4();
    let deleted_node = db.delete_by_uuid(&random_uuid, true);
    assert!(deleted_node.is_none());
    assert_eq!(db.deleted_objects.objects.len(), 1);
}
