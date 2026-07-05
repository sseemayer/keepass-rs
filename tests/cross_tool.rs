//! tests for cross-tool compatibility of generated databases
#![cfg(feature = "save_kdbx4")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::fs::File;
use std::io::Write as _;
use std::process::{Command, Stdio};

use common::round_trip_combos;

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
