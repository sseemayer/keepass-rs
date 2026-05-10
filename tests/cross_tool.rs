//! tests for cross-tool compatibility of generated databases
#![cfg(feature = "save_kdbx4")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::io::Write as _;
use std::process::{Command, Stdio};

use common::{baseline_combo, DEMO_PASSWORD};

#[test_with::executable(keepassxc-cli)]
fn keepassxc_cli_lists_our_vault() {
    let combo = baseline_combo();
    let db = combo.rich_database();
    let bytes = common::save_to_vec(&db, combo.get_key());

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fixture.kdbx");
    std::fs::write(&path, &bytes).expect("write vault");

    let mut child = Command::new("keepassxc-cli")
        .arg("ls")
        .arg(&path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keepassxc-cli");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{DEMO_PASSWORD}\n").as_bytes())
        .expect("write password");
    let out = child.wait_with_output().expect("wait keepassxc-cli");
    if !out.status.success() {
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
