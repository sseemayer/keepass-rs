#![forbid(unsafe_code)]

mod common;

use common::{baseline_combo, config_and_key_for, minimal_database, rich_database, round_trip_combos, Combo};
use keepass::{db::Value, Database};

fn opening_key_for(combo: &Combo) -> keepass::DatabaseKey {
    config_and_key_for(combo).1
}

fn root_child_count(db: &Database) -> usize {
    let root = db.root();
    root.entries().count() + root.groups().count()
}

#[test]
fn matrix_round_trip_minimal_database() {
    for combo in &round_trip_combos() {
        let (cfg, key) = config_and_key_for(combo);
        let db = minimal_database(cfg);
        let bytes = common::save_to_vec(&db, key);
        assert!(
            bytes.len() > 32,
            "combo {} produced suspiciously small output ({} bytes)",
            combo.label,
            bytes.len()
        );
        assert_eq!(
            &bytes[..4],
            &[0x03, 0xd9, 0xa2, 0x9a],
            "combo {} missing kdbx magic",
            combo.label
        );
        let parsed = Database::open(&mut bytes.as_slice(), opening_key_for(combo))
            .unwrap_or_else(|e| panic!("combo {} reopen failed: {:?}", combo.label, e));
        assert_eq!(root_child_count(&parsed), root_child_count(&db));
    }
}

#[test]
fn matrix_round_trip_rich_database_subset() {
    let combos = round_trip_combos();
    let subset: Vec<&Combo> = combos
        .iter()
        .filter(|c| {
            c.label.contains("aes256+gz+inner-chacha20+argon2d")
                || c.label.contains("chacha20+gz+inner-chacha20+argon2id")
                || c.label.contains("aes256+none+inner-salsa20+aeskdf")
        })
        .collect();
    for combo in &subset {
        let (cfg, key) = config_and_key_for(combo);
        let db = rich_database(cfg);
        let bytes = common::save_to_vec(&db, key);

        let parsed = Database::open(&mut bytes.as_slice(), opening_key_for(combo))
            .unwrap_or_else(|e| panic!("combo {} reopen failed: {:?}", combo.label, e));

        assert_eq!(
            parsed.root().entries().count(),
            10,
            "{} root entry count",
            combo.label
        );
        assert_eq!(
            parsed.root().groups().count(),
            1,
            "{} root group count",
            combo.label
        );
        assert_eq!(
            parsed.num_attachments(),
            3,
            "{} num_attachments mismatch",
            combo.label
        );

        let root = parsed.root();
        let entry = root
            .entries()
            .find(|e| e.attachment_by_name("small.bin").is_some())
            .unwrap_or_else(|| panic!("{}: no entry holds small.bin", combo.label));
        let small = entry.attachment_by_name("small.bin").expect("small.bin present");
        assert_eq!(small.data.get().as_slice(), b"small", "{} small.bin", combo.label);
        let noise = entry.attachment_by_name("noise.bin").expect("noise.bin present");
        assert_eq!(noise.data.get().len(), 4096, "{} noise.bin len", combo.label);
        let nonutf8 = entry
            .attachment_by_name("nonutf8.bin")
            .expect("nonutf8.bin present");
        assert_eq!(
            nonutf8.data.get().as_slice(),
            &[0xFF, 0xFE, 0xFD, 0x80, 0x81, 0x82, 0x00, 0x01],
            "{} nonutf8 bytes",
            combo.label
        );

        let names: Vec<String> = entry.attachments_named().map(|(n, _)| n.to_string()).collect();
        for n in ["small.bin", "noise.bin", "nonutf8.bin"] {
            assert!(names.contains(&n.to_string()), "{} {} name", combo.label, n);
        }

        assert!(parsed.meta.custom_data.contains_key("fixture.kind"));
        assert_eq!(parsed.meta.recyclebin_enabled, Some(true));
    }
}

#[test]
fn second_save_is_self_consistent() {
    let combo = baseline_combo();
    let (cfg, key) = config_and_key_for(&combo);
    let db = rich_database(cfg);
    let bytes_a = common::save_to_vec(&db, key);
    let parsed_a = Database::open(&mut bytes_a.as_slice(), opening_key_for(&combo)).unwrap();

    let bytes_b = common::save_to_vec(&parsed_a, opening_key_for(&combo));
    let parsed_b = Database::open(&mut bytes_b.as_slice(), opening_key_for(&combo)).unwrap();

    assert_eq!(root_child_count(&parsed_a), root_child_count(&parsed_b));
    assert_eq!(parsed_a.num_attachments(), parsed_b.num_attachments());
    assert_eq!(parsed_a.meta.database_name, parsed_b.meta.database_name);
}

#[test]
fn protected_field_decrypts_after_round_trip() {
    let combo = baseline_combo();
    let (cfg, key) = config_and_key_for(&combo);
    let db = rich_database(cfg);
    let bytes = common::save_to_vec(&db, key);
    let parsed = Database::open(&mut bytes.as_slice(), opening_key_for(&combo)).unwrap();

    let root = parsed.root();
    let entry = root
        .entries()
        .find(|e| e.get_title().is_some_and(|t| t.starts_with("entry-")))
        .expect("at least one entry-NN");
    let pw = entry.get("Password").expect("password is decryptable");
    assert!(pw.starts_with("pw-"));

    let mut found = false;
    for e in parsed.root().entries() {
        for (k, v) in &e.fields {
            if k.starts_with("custom.protected.") {
                if let Value::Protected(_) = v {
                    found = true;
                    break;
                }
            }
        }
    }
    assert!(found, "no Protected custom field round-tripped");
}
