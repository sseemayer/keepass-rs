extern crate cbindgen;

use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let mut config = cbindgen::Config::default();
    config.language = cbindgen::Language::Cxx;
    config.export.include = vec![
        "DatabaseKey".to_string(),
        "Database".to_string(),
        "DatabaseConfig".to_string(),
        "KdfConfig".to_string(),
        "InnerCipherConfig".to_string(),
        "OuterCipherConfig".to_string(),
        "CompressionConfig".to_string(),
    ];

    println!("cargo:rerun-if-changed=NULL");
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("keepass.h");
}
