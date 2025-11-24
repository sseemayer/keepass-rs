#![cfg(target_arch = "wasm32")]

use keepass::{db::Database, DatabaseKey};
use wasm_bindgen_test::wasm_bindgen_test;

/// Ensure that opening an Argon2-encrypted KDBX4 database does not panic
/// when running inside a wasm32 runtime (regression test for the "support wasm" change).
#[wasm_bindgen_test]
fn open_kdbx4_argon2_in_wasm_does_not_panic() {
    // This database uses Argon2; historically, multithreaded Argon2 could
    // cause panics on wasm targets without thread support. This test ensures
    // that the wasm configuration works end-to-end.
    const DB_BYTES: &[u8] = include_bytes!("resources/test_db_kdbx4_with_password_argon2.kdbx");

    let db = Database::parse(DB_BYTES, DatabaseKey::new().with_password("demopass"))
        .expect("database should open successfully in wasm without panicking");

    // A small sanity check to confirm that parsing actually succeeded.
    assert_eq!(db.root.name, "Root");
}
