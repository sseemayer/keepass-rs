//! tests for cross-tool compatibility of generated databases
#![cfg(feature = "save_kdbx4")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::fs::File;
use std::io::Write as _;
use std::process::{Command, Stdio};

use common::round_trip_combos;
use keepass::{
    db::{fields, Database, EntryId},
    DatabaseKey,
};

use crate::common::MasterKey;

#[test_with::executable(kpscript)]
fn kpscript_lists_our_vault() {
    // filter out twofish since KeePass does not support it
    let combos: Vec<_> = round_trip_combos()
        .into_iter()
        .filter(|c| !c.label.contains("twofish"))
        .collect();

    for combo in combos {
        println!("Testing combo: {}", combo.label);

        let db = combo.rich_database();
        let bytes = common::save_to_vec(&db, combo.get_key());

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.kdbx");
        std::fs::write(&path, &bytes).expect("write vault");

        let mut command = Command::new("kpscript");

        let command = command
            .arg("-c:ListEntries")
            .arg(&path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let command = match combo.master_key {
            MasterKey::Password(password) => command.arg(format!("-pw:{password}")),
            MasterKey::Keyfile(keyfile_kind) => {
                let keyfile_path = dir.path().join("keyfile");
                let mut file = File::create(&keyfile_path).expect("create temp keyfile");
                file.write_all(&keyfile_kind.to_bytes()).expect("write keyfile");

                command.arg(format!("-keyfile:{}", keyfile_path.display()))
            }
            MasterKey::PasswordAndKeyfile(password, keyfile_kind) => {
                let keyfile_path = dir.path().join("keyfile");
                let mut file = File::create(&keyfile_path).expect("create temp keyfile");
                file.write_all(&keyfile_kind.to_bytes()).expect("write keyfile");

                command
                    .arg(format!("-keyfile:{}", keyfile_path.display()))
                    .arg(format!("-pw:{password}"))
            }
        };

        println!("Running command: {:?}", command);

        let out = command.output().expect("spawn KPScript");

        if !out.status.success() {
            let _ = dir.keep();
            panic!(
                "KPScript ListEntries failed: {} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("entry-"),
            "KPScript output didn't list our entries: {:?}",
            stdout
        );
    }
}

#[test_with::executable(keepassxc-cli)]
fn keepassxc_cli_lists_our_vault() {
    let combos: Vec<_> = round_trip_combos().into_iter().collect();

    for combo in combos {
        println!("Testing combo: {}", combo.label);

        let db = combo.rich_database();

        let bytes = common::save_to_vec(&db, combo.get_key());

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.kdbx");
        std::fs::write(&path, &bytes).expect("write vault");

        let mut command = Command::new("keepassxc-cli");

        let command = command
            .arg("ls")
            .arg(&path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let (command, password) = match combo.master_key {
            MasterKey::Password(password) => (command, Some(password)),
            MasterKey::Keyfile(keyfile_kind) => {
                let keyfile_path = dir.path().join("keyfile");
                let mut file = File::create(&keyfile_path).expect("create temp keyfile");
                file.write_all(&keyfile_kind.to_bytes()).expect("write keyfile");

                let command = command.arg("--key-file").arg(keyfile_path).arg("--no-password");

                (command, None)
            }
            MasterKey::PasswordAndKeyfile(password, keyfile_kind) => {
                let keyfile_path = dir.path().join("keyfile");
                let mut file = File::create(&keyfile_path).expect("create temp keyfile");
                file.write_all(&keyfile_kind.to_bytes()).expect("write keyfile");

                let command = command.arg("--key-file").arg(keyfile_path);

                (command, Some(password))
            }
        };

        if password.is_some() {
            command.stdin(Stdio::piped());
        }

        println!("Running command: {:?}", command);

        let mut child = command.spawn().expect("spawn keepassxc-cli");

        if let Some(password) = password {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(format!("{password}\n").as_bytes())
                .expect("write password");
        }

        let out = child.wait_with_output().expect("wait keepassxc-cli");
        if !out.status.success() {
            let _ = dir.keep();
            panic!(
                "keepassxc-cli ls failed: {} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("entry-"),
            "keepassxc-cli output didn't list our entries: {:?}",
            stdout
        );
    }
}

/// A database with one entry that has a history item, saved with a fast KDF.
fn database_with_history() -> (Database, EntryId) {
    let mut db = Database::new();
    db.config.kdf_config = common::fast_aes_kdf();

    let id = db
        .root_mut()
        .add_entry()
        .edit(|e| e.set_unprotected(fields::TITLE, "entry"))
        .id();

    // history items need a distinct modification time
    std::thread::sleep(std::time::Duration::from_secs(1));

    db.entry_mut(id)
        .unwrap()
        .edit_tracking(|e| e.set_unprotected(fields::USERNAME, "user"));

    (db, id)
}

/// Every timestamp of new entries and groups is written, so that readers don't have to fill in a
/// missing one.
#[test]
fn new_objects_have_all_timestamps() {
    let (db, id) = database_with_history();
    let db = common::save_then_open(&db, DatabaseKey::new().with_password(common::DEMO_PASSWORD));

    let entry = db.entry(id).unwrap();
    let history_item = entry.historical(0).unwrap();

    for times in [&entry.times, &history_item.times, &db.root().times] {
        assert!(times.creation.is_some());
        assert!(times.last_modification.is_some());
        assert!(times.last_access.is_some());
        assert_eq!(times.expiry, times.creation.expect("creation time"));
        assert!(times.location_changed.is_some());
    }
}

/// KeePassXC fills a missing timestamp with the time it parsed the file, so a missing expiry time
/// made two copies of the same database look like conflicting changes when merged.
#[test_with::executable(keepassxc-cli)]
fn keepassxc_cli_merges_copies_of_our_vault_without_conflicts() {
    let (db, _) = database_with_history();
    let bytes = common::save_to_vec(&db, DatabaseKey::new().with_password(common::DEMO_PASSWORD));

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target.kdbx");
    let source = dir.path().join("source.kdbx");
    std::fs::write(&target, &bytes).expect("write target vault");
    std::fs::write(&source, &bytes).expect("write source vault");

    let mut child = Command::new("keepassxc-cli")
        .arg("merge")
        .arg("--dry-run")
        .arg(&target)
        .arg(&source)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keepassxc-cli");

    // unlock the source more than a second after the target, so that a timestamp filled in at
    // parse time differs between the two copies
    let stdin = child.stdin.as_mut().unwrap();
    let password = format!("{}\n", common::DEMO_PASSWORD);
    stdin
        .write_all(password.as_bytes())
        .expect("write target password");
    stdin.flush().expect("flush target password");
    std::thread::sleep(std::time::Duration::from_millis(1500));
    stdin
        .write_all(password.as_bytes())
        .expect("write source password");

    let out = child.wait_with_output().expect("wait keepassxc-cli");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "keepassxc-cli merge failed: {} stderr={}",
        out.status,
        stderr
    );
    assert!(
        !stderr.contains("conflicting changes"),
        "keepassxc-cli reported conflicts: {:?}",
        stderr
    );
    assert!(
        !stdout.contains("Expiration"),
        "keepassxc-cli saw a changed expiry time: {:?}",
        stdout
    );
}
