#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::io::Cursor;

use keepass::{
    config::{
        CompressionConfig, DatabaseConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig,
    },
    db::{CustomDataItem, CustomDataValue, Database, Value},
    DatabaseKey,
};

use rand::{rngs::StdRng, RngCore, SeedableRng};

use sha2::{Digest, Sha256};

pub const MASTER_SEED: u64 = 0xdead_beef_cafe_f00d;
pub const DEMO_PASSWORD: &str = "demopass";

fn calculate_sha256(elements: &[&[u8]]) -> Vec<u8> {
    let mut digest = Sha256::new();

    for element in elements {
        digest.update(element);
    }

    digest.finalize().to_vec()
}

#[derive(Debug, Clone)]
pub struct Combo {
    pub label: &'static str,
    pub outer_cipher: OuterCipherConfig,
    pub compression: CompressionConfig,
    pub inner_cipher: InnerCipherConfig,
    pub kdf: KdfConfig,
    pub master_key: MasterKey,
}

#[derive(Debug, Clone)]
pub enum MasterKey {
    Password(&'static str),
    Keyfile(KeyfileKind),
    PasswordAndKeyfile(&'static str, KeyfileKind),
}

#[derive(Debug, Clone)]
pub enum KeyfileKind {
    Raw32([u8; 32]),
    Hex([u8; 32]),
    XmlV1([u8; 32]),
    XmlV2([u8; 32]),
}

impl KeyfileKind {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            KeyfileKind::Raw32(k) => k.to_vec(),
            KeyfileKind::Hex(k) => hex::encode(k).into_bytes(),
            KeyfileKind::XmlV1(k) => {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine as _;
                let b64 = STANDARD.encode(k);
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n  <Meta><Version>1.00</Version></Meta>\n  <Key><Data>{b64}</Data></Key>\n</KeyFile>\n"
                )
                .into_bytes()
            }
            KeyfileKind::XmlV2(k) => {
                let hex_lo = hex::encode(k).to_uppercase();
                let line = |s: &str| -> String {
                    let mut out = String::new();
                    for (i, c) in s.chars().enumerate() {
                        if i > 0 && i % 8 == 0 {
                            out.push(' ');
                        }
                        out.push(c);
                    }
                    out
                };
                let l1 = line(&hex_lo[0..32]);
                let l2 = line(&hex_lo[32..64]);

                // hash should be the first 4 bytes of the SHA256 of the keyfile data
                let hash = calculate_sha256(&[&k[..]]);
                let hash_hex = hex::encode(&hash[0..4]).to_uppercase();

                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n  <Meta><Version>2.0</Version></Meta>\n  <Key>\n    <Data Hash=\"{hash_hex}\">\n      {l1}\n      {l2}\n    </Data>\n  </Key>\n</KeyFile>\n"
                )
                .into_bytes()
            }
        }
    }
}

pub fn seeded_rng() -> StdRng {
    StdRng::seed_from_u64(MASTER_SEED)
}

pub fn fast_argon2() -> KdfConfig {
    KdfConfig::Argon2 {
        iterations: 1,
        memory: 64 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

pub fn fast_argon2id() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 64 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

pub fn fast_aes_kdf() -> KdfConfig {
    KdfConfig::Aes { rounds: 8 }
}

pub fn round_trip_combos() -> Vec<Combo> {
    let mut combos = Vec::new();

    let outer = [
        ("aes256", OuterCipherConfig::AES256),
        ("chacha20", OuterCipherConfig::ChaCha20),
        ("twofish", OuterCipherConfig::Twofish),
    ];
    let comp = [("gz", CompressionConfig::GZip), ("none", CompressionConfig::None)];
    let inner = [
        ("inner-chacha20", InnerCipherConfig::ChaCha20),
        ("inner-salsa20", InnerCipherConfig::Salsa20),
    ];
    let kdfs = [
        ("aeskdf", fast_aes_kdf()),
        ("argon2d", fast_argon2()),
        ("argon2id", fast_argon2id()),
    ];

    for (oc_l, oc) in &outer {
        for (cm_l, cm) in &comp {
            for (ic_l, ic) in &inner {
                for (kd_l, kd) in &kdfs {
                    let label: &'static str =
                        Box::leak(format!("{oc_l}+{cm_l}+{ic_l}+{kd_l}").into_boxed_str());
                    combos.push(Combo {
                        label,
                        outer_cipher: oc.clone(),
                        compression: cm.clone(),
                        inner_cipher: ic.clone(),
                        kdf: kd.clone(),
                        master_key: MasterKey::Password(DEMO_PASSWORD),
                    });
                }
            }
        }
    }

    let mut keyfile_seed = [0u8; 32];
    let mut rng = seeded_rng();
    rng.fill_bytes(&mut keyfile_seed);
    let kinds = [
        ("kf-raw32", KeyfileKind::Raw32(keyfile_seed)),
        ("kf-hex", KeyfileKind::Hex(keyfile_seed)),
        ("kf-xmlv1", KeyfileKind::XmlV1(keyfile_seed)),
        ("kf-xmlv2", KeyfileKind::XmlV2(keyfile_seed)),
    ];
    for (kf_l, kf) in &kinds {
        let label: &'static str =
            Box::leak(format!("aes256+gz+inner-chacha20+argon2d+{kf_l}").into_boxed_str());
        combos.push(Combo {
            label,
            outer_cipher: OuterCipherConfig::AES256,
            compression: CompressionConfig::GZip,
            inner_cipher: InnerCipherConfig::ChaCha20,
            kdf: fast_argon2(),
            master_key: MasterKey::Keyfile(kf.clone()),
        });
    }

    combos.push(Combo {
        label: "aes256+gz+inner-chacha20+argon2d+pw+kf-raw32",
        outer_cipher: OuterCipherConfig::AES256,
        compression: CompressionConfig::GZip,
        inner_cipher: InnerCipherConfig::ChaCha20,
        kdf: fast_argon2(),
        master_key: MasterKey::PasswordAndKeyfile(DEMO_PASSWORD, KeyfileKind::Raw32(keyfile_seed)),
    });

    combos
}

pub fn combo_by_label(label: &str) -> Combo {
    round_trip_combos()
        .into_iter()
        .find(|c| c.label == label)
        .unwrap_or_else(|| panic!("combo {} not in matrix", label))
}

pub fn baseline_combo() -> Combo {
    combo_by_label("aes256+gz+inner-chacha20+argon2d")
}

pub fn fast_combo() -> Combo {
    combo_by_label("aes256+none+inner-chacha20+aeskdf")
}

impl Combo {
    pub fn get_config(&self) -> DatabaseConfig {
        let mut cfg = DatabaseConfig::default();
        cfg.version = DatabaseVersion::KDB4(1);
        cfg.outer_cipher_config = self.outer_cipher.clone();
        cfg.compression_config = self.compression.clone();
        cfg.inner_cipher_config = self.inner_cipher.clone();
        cfg.kdf_config = self.kdf.clone();
        cfg.public_custom_data = None;
        cfg
    }

    #[allow(clippy::expect_used)]
    pub fn get_key(&self) -> DatabaseKey {
        match &self.master_key {
            MasterKey::Password(p) => DatabaseKey::new().with_password(p),
            MasterKey::Keyfile(k) => {
                let bytes = k.to_bytes();
                DatabaseKey::new()
                    .with_keyfile(&mut Cursor::new(bytes))
                    .expect("keyfile read")
            }
            MasterKey::PasswordAndKeyfile(p, k) => {
                let bytes = k.to_bytes();
                DatabaseKey::new()
                    .with_password(p)
                    .with_keyfile(&mut Cursor::new(bytes))
                    .expect("keyfile read")
            }
        }
    }

    pub fn minimal_database(&self) -> Database {
        let mut db = Database::with_config(self.get_config());
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "only-entry");
        db
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    pub fn rich_database(&self) -> Database {
        use chrono::NaiveDate;

        let mut db = Database::with_config(self.get_config());
        db.meta.generator = Some("keepass-spec-tests".to_string());
        db.meta.database_name = Some("rich-fixture".to_string());
        db.meta.database_description = Some("test fixture".to_string());

        db.meta.custom_data.insert(
            "fixture.kind".to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String("rich".to_string())),
                last_modification_time: None,
            },
        );

        let mut first_entry_id = None;
        for i in 0..10 {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected("Title", format!("entry-{i:02}"));
            e.set_unprotected("UserName", format!("user-{i:02}"));
            e.set_protected("Password", format!("pw-{i:02}"));
            e.set_unprotected("URL", format!("https://example.invalid/{i}"));
            e.set_unprotected(format!("custom.unprotected.{i}"), format!("plain-{i}"));
            e.set_protected(format!("custom.protected.{i}"), format!("secret-{i}"));
            if i % 2 == 0 {
                e.tags = vec![format!("tag-{i}"), "fixture".to_string()];
                e.times.expires = Some(true);

                e.times.expiry = Some(
                    NaiveDate::from_ymd_opt(2099, 12, 31)
                        .unwrap()
                        .and_hms_opt(23, 59, 59)
                        .unwrap(),
                );
            }
            e.custom_data.insert(
                format!("entry.cd.{i}"),
                CustomDataItem {
                    value: Some(CustomDataValue::String(format!("cd-{i}"))),
                    last_modification_time: None,
                },
            );
            if i == 0 {
                first_entry_id = Some(e.id());
            }
        }

        let bin_uuid = {
            let mut root = db.root_mut();
            let mut rec_bin = root.add_group();
            rec_bin.name = "Recycle Bin".to_string();
            let bin_id = rec_bin.id();
            let mut rec_entry = rec_bin.add_entry();
            rec_entry.set_unprotected("Title", "deleted-entry");
            bin_id.uuid()
        };
        db.meta.recyclebin_enabled = Some(true);
        db.meta.recyclebin_uuid = Some(bin_uuid);

        let first_id = first_entry_id.expect("at least one entry created");
        let mut e = db.entry_mut(first_id).expect("first entry exists");
        e.add_attachment("small.bin", Value::Unprotected(b"small".to_vec()));
        let noise = {
            let mut buf = vec![0u8; 4 * 1024];
            let mut r = StdRng::seed_from_u64(MASTER_SEED ^ 0xA);
            r.fill_bytes(&mut buf);
            buf
        };
        e.add_attachment("noise.bin", Value::Unprotected(noise));
        e.add_attachment(
            "nonutf8.bin",
            Value::Unprotected(vec![0xFF, 0xFE, 0xFD, 0x80, 0x81, 0x82, 0x00, 0x01]),
        );

        db
    }
}

#[allow(clippy::expect_used)]
#[cfg(feature = "save_kdbx4")]
pub fn save_to_vec(db: &Database, key: DatabaseKey) -> Vec<u8> {
    let mut buf = Vec::new();
    db.save(&mut buf, key).expect("save_to_vec: save failed");
    buf
}

#[cfg(feature = "save_kdbx4")]
pub fn save_then_open(db: &Database, key: DatabaseKey) -> Database {
    let mut buf = Vec::new();
    db.save(&mut buf, key.clone()).expect("Unable to save database");
    Database::open(&mut buf.as_slice(), key).expect("Unable to open database")
}
