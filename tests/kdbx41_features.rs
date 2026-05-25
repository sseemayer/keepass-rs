//! Programmatic round-trip coverage for KDBX 4.1-specific surface.
//! Each test builds a database via the public API, saves it, reopens it,
//! and asserts the 4.1 fields survive intact.

#![cfg(feature = "save_kdbx4")]
#![forbid(unsafe_code)]
#![allow(missing_docs)]

use chrono::NaiveDate;
use keepass::{
    config::{DatabaseConfig, KdfConfig},
    db::{
        AutoType, AutoTypeAssociation, Color, CustomDataItem, CustomDataValue, CustomIconId, Database, EntryId,
        GroupId, Value,
    },
    DatabaseKey,
};

const PASSWORD: &str = "demopass";

fn fast_kdbx41_config() -> DatabaseConfig {
    let mut cfg = DatabaseConfig::default();
    cfg.kdf_config = KdfConfig::Argon2 {
        iterations: 1,
        memory: 64 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    };
    cfg
}

fn save_then_open(db: &Database) -> Database {
    let mut buf = Vec::new();
    db.save(&mut buf, DatabaseKey::new().with_password(PASSWORD))
        .expect("save");
    Database::open(&mut buf.as_slice(), DatabaseKey::new().with_password(PASSWORD)).expect("open")
}

fn fixed_time() -> chrono::NaiveDateTime {
    NaiveDate::from_ymd_opt(2024, 6, 15)
        .unwrap()
        .and_hms_opt(12, 30, 45)
        .unwrap()
}

/// Build a database touching every public KDBX 4.1 field we can reach.
/// Returns the database and the id of the entry carrying the rich fields,
/// for tests that want to inspect a specific entry post-roundtrip.
fn build_kdbx41_rich_database() -> (Database, EntryId) {
    let mut db = Database::with_config(fast_kdbx41_config());

    db.meta.database_name = Some("kdbx41-features".to_string());
    db.meta.custom_data.insert(
        "meta.cd.with-time".to_string(),
        CustomDataItem {
            value: Some(CustomDataValue::String("v1".to_string())),
            last_modification_time: Some(fixed_time()),
        },
    );
    db.meta.custom_data.insert(
        "meta.cd.no-time".to_string(),
        CustomDataItem {
            value: Some(CustomDataValue::String("v2".to_string())),
            last_modification_time: None,
        },
    );

    db.deleted_objects.insert(uuid::Uuid::nil(), Some(fixed_time()));

    let entry_id = {
        let mut root = db.root_mut();
        root.name = "Root".to_string();
        root.notes = Some("notes on root".to_string());
        root.tags = vec!["root-tag".to_string(), "shared".to_string()];
        root.is_expanded = true;
        root.default_autotype_sequence = Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string());
        root.enable_autotype = Some(false);
        root.enable_searching = Some(true);
        root.custom_data.insert(
            "group.cd".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("g".to_string())),
                last_modification_time: Some(fixed_time()),
            },
        );

        let mut entry = root.add_entry();
        entry.set_unprotected("Title", "feature-bag");
        entry.set_unprotected("UserName", "alice");
        entry.set_protected("Password", "hunter2");

        entry.tags = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        entry.quality_check = false;
        entry.foreground_color = Some(Color {
            r: 0x12,
            g: 0x34,
            b: 0x56,
        });
        entry.background_color = Some(Color {
            r: 0xFE,
            g: 0xDC,
            b: 0xBA,
        });
        entry.override_url = Some("ssh://override.invalid".to_string());

        entry.autotype = Some(AutoType {
            enabled: true,
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string()),
            data_transfer_obfuscation: Some(true),
            associations: vec![
                AutoTypeAssociation {
                    window: "Login - *".to_string(),
                    sequence: "{USERNAME}{TAB}{PASSWORD}{ENTER}".to_string(),
                },
                AutoTypeAssociation {
                    window: "Sign in *".to_string(),
                    sequence: String::new(),
                },
            ],
        });

        entry.custom_data.insert(
            "entry.cd.with-time".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("e1".to_string())),
                last_modification_time: Some(fixed_time()),
            },
        );
        entry.custom_data.insert(
            "entry.cd.no-time".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("e2".to_string())),
                last_modification_time: None,
            },
        );

        entry.id()
    };

    {
        let mut root = db.root_mut();
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".to_string();
        let bin_uuid = bin.id().uuid();
        let mut deleted = bin.add_entry();
        deleted.set_unprotected("Title", "tombstone");
        db.meta.recyclebin_enabled = Some(true);
        db.meta.recyclebin_uuid = Some(bin_uuid);
    }

    (db, entry_id)
}

#[test]
fn full_database_round_trips_byte_for_field() {
    let (db, _) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    assert_eq!(parsed, db, "kdbx 4.1 rich database did not round-trip");
}

#[test]
fn entry_tags_round_trip() {
    let (db, id) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    let entry = root.entry(id).expect("entry survives");
    assert_eq!(entry.tags, vec!["a", "b", "c"]);
}

#[test]
fn entry_colors_round_trip() {
    let (db, id) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    let entry = root.entry(id).expect("entry survives");
    assert_eq!(
        entry.foreground_color,
        Some(Color {
            r: 0x12,
            g: 0x34,
            b: 0x56
        })
    );
    assert_eq!(
        entry.background_color,
        Some(Color {
            r: 0xFE,
            g: 0xDC,
            b: 0xBA
        })
    );
}

#[test]
fn entry_override_url_round_trips() {
    let (db, id) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    let entry = root.entry(id).expect("entry survives");
    assert_eq!(entry.override_url.as_deref(), Some("ssh://override.invalid"));
}

#[test]
fn entry_autotype_with_obfuscation_round_trips() {
    let (db, id) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    let entry = root.entry(id).expect("entry survives");
    let at = entry.autotype.as_ref().expect("autotype present");
    assert!(at.enabled);
    assert_eq!(at.data_transfer_obfuscation, Some(true));
    assert_eq!(at.associations.len(), 2);
    assert_eq!(at.associations[0].window, "Login - *");
}

#[test]
fn entry_custom_data_with_modification_time_round_trips() {
    let (db, id) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    let entry = root.entry(id).expect("entry survives");

    let with_time = entry
        .custom_data
        .get("entry.cd.with-time")
        .expect("with-time custom data present");
    assert_eq!(with_time.last_modification_time, Some(fixed_time()));
    assert!(matches!(
        with_time.value,
        Some(CustomDataValue::String(ref s)) if s == "e1"
    ));

    let no_time = entry
        .custom_data
        .get("entry.cd.no-time")
        .expect("no-time custom data present");
    assert_eq!(no_time.last_modification_time, None);
}

#[test]
fn group_enable_flags_round_trip() {
    let (db, _) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    assert_eq!(root.enable_autotype, Some(false));
    assert_eq!(root.enable_searching, Some(true));
}

#[test]
fn group_default_autotype_sequence_round_trips() {
    let (db, _) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    assert_eq!(
        root.default_autotype_sequence.as_deref(),
        Some("{USERNAME}{TAB}{PASSWORD}{ENTER}")
    );
}

#[test]
fn group_custom_data_with_modification_time_round_trips() {
    let (db, _) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    let cd = root
        .custom_data
        .get("group.cd")
        .expect("group custom data present");
    assert_eq!(cd.last_modification_time, Some(fixed_time()));
}

#[test]
fn meta_custom_data_with_modification_time_round_trips() {
    let (db, _) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let with_time = parsed
        .meta
        .custom_data
        .get("meta.cd.with-time")
        .expect("meta custom data present");
    assert_eq!(with_time.last_modification_time, Some(fixed_time()));
}

#[test]
fn deleted_objects_round_trip() {
    let (db, _) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let entry = parsed
        .deleted_objects
        .get(&uuid::Uuid::nil())
        .expect("deleted-object entry present");
    assert_eq!(*entry, Some(fixed_time()));
}

#[test]
fn protected_password_round_trips_and_decrypts() {
    let (db, id) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    let entry = root.entry(id).expect("entry survives");
    let pw = entry.fields.get("Password").expect("password field present");
    assert!(matches!(pw, Value::Protected(_)));
    assert_eq!(entry.get("Password"), Some("hunter2"));
}

#[test]
fn group_tags_round_trip() {
    let (db, _) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    assert_eq!(root.tags, vec!["root-tag", "shared"]);
}

#[test]
fn entry_quality_check_disabled_round_trips() {
    let (db, id) = build_kdbx41_rich_database();
    let parsed = save_then_open(&db);
    let root = parsed.root();
    let entry = root.entry(id).expect("entry survives");
    assert!(
        !entry.quality_check,
        "quality_check=false must survive round-trip"
    );
}

#[test]
fn entry_previous_parent_group_round_trips() {
    let mut db = Database::with_config(fast_kdbx41_config());

    let (source_id, entry_id): (GroupId, EntryId) = {
        let mut root = db.root_mut();
        let mut source = root.add_group();
        source.name = "Source".to_string();
        let source_id = source.id();
        let mut entry = source.add_entry();
        entry.set_unprotected("Title", "movable");
        (source_id, entry.id())
    };

    let dest_id: GroupId = {
        let mut root = db.root_mut();
        let mut dest = root.add_group();
        dest.name = "Dest".to_string();
        dest.id()
    };

    db.entry_mut(entry_id).unwrap().move_to(dest_id).unwrap();

    let parsed = save_then_open(&db);
    let entry = parsed.entry(entry_id).expect("entry survives");
    let prev = entry
        .previous_parent()
        .expect("previous_parent_group survives round-trip");
    assert_eq!(prev.id(), source_id);
}

#[test]
fn custom_icon_name_and_modification_time_round_trip() {
    let mut db = Database::with_config(fast_kdbx41_config());

    let icon_id: CustomIconId = {
        let mut root = db.root_mut();
        let icon = root.set_icon_custom_new(vec![0xFF, 0xD8, 0xFF]);
        icon.id()
    };
    {
        let mut icon = db.custom_icon_mut(icon_id).expect("icon exists");
        icon.name = Some("my-icon".to_string());
        icon.last_modification_time = Some(fixed_time());
    }

    let parsed = save_then_open(&db);
    let icon = parsed.custom_icon(icon_id).expect("icon survives round-trip");
    assert_eq!(icon.name.as_deref(), Some("my-icon"));
    assert_eq!(icon.last_modification_time, Some(fixed_time()));
}
