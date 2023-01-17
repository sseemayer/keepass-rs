#[cfg(feature = "totp")]
pub(crate) mod otp {
    use base32;
    use std::borrow::Cow;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};
    use totp_lite::{totp_custom, Sha1, Sha256, Sha512};
    use url::Url;

    const DEFAULT_PERIOD: u64 = 30;
    const DEFAULT_DIGITS: u32 = 8;

    #[derive(Debug, PartialEq, Eq)]
    pub enum TOTPAlgorithm {
        Sha1,
        Sha256,
        Sha512,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct TOTP {
        label: String,
        secret: Vec<u8>,
        issuer: String,
        period: u64,
        digits: u32,
        algorithm: TOTPAlgorithm,
    }

    pub struct OTPCode {
        pub code: String,
        pub valid_for: Duration,
        pub period: Duration,
    }

    impl std::fmt::Display for OTPCode {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(
                f,
                "Code: {}, valid for: {}/{}s",
                self.code,
                self.valid_for.as_secs(),
                self.period.as_secs(),
            )
        }
    }

    impl TOTP {
        pub fn parse_from_str(s: &str) -> Option<TOTP> {
            let parsed = Url::parse(s).unwrap();
            let query_pairs = parsed.query_pairs();

            let label: String = parsed.path().trim_start_matches("/").to_string();
            let mut secret: Option<String> = None;
            let mut issuer: Option<String> = None;
            let mut period: Option<u64> = None;
            let mut digits: Option<u32> = None;
            let mut algorithm: TOTPAlgorithm = TOTPAlgorithm::Sha1;

            for pair in query_pairs {
                let (k, v) = pair;
                match k {
                    Cow::Borrowed("secret") => secret = Some(v.into_owned()),
                    Cow::Borrowed("issuer") => issuer = Some(v.into_owned()),
                    Cow::Borrowed("period") => period = Some(v.parse::<u64>().unwrap()),
                    Cow::Borrowed("digits") => digits = Some(v.parse::<u32>().unwrap()),
                    Cow::Borrowed("algorithm") => {
                        algorithm = match v {
                            Cow::Borrowed("SHA1") => TOTPAlgorithm::Sha1,
                            Cow::Borrowed("SHA256") => TOTPAlgorithm::Sha256,
                            Cow::Borrowed("SHA512") => TOTPAlgorithm::Sha512,
                            _ => panic!("Received an unsupported algorithm for TOTP"),
                        }
                    }
                    Cow::Borrowed(_) => (),
                    Cow::Owned(_) => panic!("Somehow got an owned value"),
                }
            }

            Some(TOTP {
                label,
                secret: base32::decode(base32::Alphabet::RFC4648 { padding: true }, &secret?)?,
                issuer: issuer.unwrap(),
                period: period.unwrap_or(DEFAULT_PERIOD),
                digits: digits.unwrap_or(DEFAULT_DIGITS),
                algorithm,
            })
        }
        pub fn current_value(&self) -> OTPCode {
            let time: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let code = match self.algorithm {
                TOTPAlgorithm::Sha1 => {
                    totp_custom::<Sha1>(self.period, self.digits, &self.secret, time)
                }
                TOTPAlgorithm::Sha256 => {
                    totp_custom::<Sha256>(self.period, self.digits, &self.secret, time)
                }
                TOTPAlgorithm::Sha512 => {
                    totp_custom::<Sha512>(self.period, self.digits, &self.secret, time)
                }
            };

            let valid_for = Duration::from_secs(self.period - (time % self.period));
            return OTPCode {
                code,
                valid_for,
                period: Duration::from_secs(self.period),
            };
        }
    }

    #[cfg(test)]
    mod kdbx4_otp_tests {
        use super::TOTP;
        use crate::*;
        use std::error;
        use std::{fs::File, path::Path};

        #[test]
        fn kdbx4_entry_totp_default() -> Result<(), Box<dyn error::Error>> {
            // KDBX4 database format Base64 encodes ExpiryTime (and all other XML timestamps)
            let path = Path::new("tests/resources/test_db_kdbx4_with_totp_entry.kdbx");
            let db = Database::open(&mut File::open(path)?, Some("test"), None)?;

            // get an entry on the root node
            if let Some(NodeRef::Entry(e)) = db.root.get(&["this entry has totp"]) {
                assert_eq!(e.get_title(), Some("this entry has totp"));
                let otp_str = "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC";
                assert_eq!(e.get_raw_otp_value(), Some(otp_str));
                assert_eq!(e.get_otp(), TOTP::parse_from_str(otp_str));
                assert_eq!(e.get_otp().unwrap().current_value().code.len(), 6); // 6 digits
            } else {
                panic!("Expected an entry");
            }

            Ok(())
        }

        #[test]
        fn kdbx4_entry_totp_sha512() -> Result<(), Box<dyn error::Error>> {
            // KDBX4 database format Base64 encodes ExpiryTime (and all other XML timestamps)
            let path = Path::new("tests/resources/test_db_kdbx4_with_totp_sha512_entry.kdbx");
            let db = Database::open(&mut File::open(path)?, Some("test"), None)?;

            // get an entry on the root node
            if let Some(NodeRef::Entry(e)) = db.root.get(&["sha512 totp"]) {
                assert_eq!(e.get_title(), Some("sha512 totp"));
                let otp_str = "otpauth://totp/sha512%20totp:none?secret=GEZDGNBVGY%3D%3D%3D%3D%3D%3D&period=30&digits=6&issuer=sha512%20totp&algorithm=SHA512";
                assert_eq!(e.get_raw_otp_value(), Some(otp_str));
                assert_eq!(e.get_otp(), TOTP::parse_from_str(otp_str));
                assert_eq!(e.get_otp().unwrap().current_value().code.len(), 6); // 6 digits
            } else {
                panic!("Expected an entry");
            }

            Ok(())
        }
    }
}
