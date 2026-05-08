#![forbid(unsafe_code)]

mod common;

use std::io::Write as _;
use std::process::{Command, Stdio};

use common::{baseline_combo, config_and_key_for, rich_database, DEMO_PASSWORD};

fn keepassxc_cli_present() -> bool {
    Command::new("keepassxc-cli")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn keepassxc_cli_lists_our_vault() {
    if !keepassxc_cli_present() {
        eprintln!("keepassxc-cli not on PATH — skipping");
        return;
    }

    let combo = baseline_combo();
    let (cfg, key) = config_and_key_for(&combo);
    let db = rich_database(cfg);
    let bytes = common::save_to_vec(&db, key);

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
