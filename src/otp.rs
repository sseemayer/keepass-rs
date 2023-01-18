use base32;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};
use thiserror::Error;
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

#[derive(Debug, Error)]
pub enum TOTPError {
    #[error(transparent)]
    UrlFormat(#[from] url::ParseError),

    #[error(transparent)]
    IntFormat(#[from] std::num::ParseIntError),

    #[error("Missing TOTP field: {}", _0)]
    MissingField(&'static str),

    #[error(transparent)]
    Time(#[from] SystemTimeError),

    #[error("Base32 decoding error")]
    Base32,

    #[error("No OTP record found")]
    NoRecord,

    #[error("Bad URL scheme: '{}'", _0)]
    BadScheme(String),

    #[error("Bad hash algorithm: '{}'", _0)]
    BadAlgorithm(String),
}

impl TOTP {
    pub fn parse_from_str(s: &str) -> Result<TOTP, TOTPError> {
        let parsed = Url::parse(s)?;

        if parsed.scheme() != "otpauth" {
            return Err(TOTPError::BadScheme(parsed.scheme().to_string()));
        }
        let query_pairs = parsed.query_pairs();

        let label: String = parsed.path().trim_start_matches("/").to_string();
        let mut secret: Option<String> = None;
        let mut issuer: Option<String> = None;
        let mut period: Option<u64> = None;
        let mut digits: Option<u32> = None;
        let mut algorithm: TOTPAlgorithm = TOTPAlgorithm::Sha1;

        for pair in query_pairs {
            let (k, v) = pair;
            match k.as_ref() {
                "secret" => secret = Some(v.to_string()),
                "issuer" => issuer = Some(v.to_string()),
                "period" => period = Some(v.parse::<u64>()?),
                "digits" => digits = Some(v.parse::<u32>()?),
                "algorithm" => {
                    algorithm = match v.as_ref() {
                        "SHA1" => TOTPAlgorithm::Sha1,
                        "SHA256" => TOTPAlgorithm::Sha256,
                        "SHA512" => TOTPAlgorithm::Sha512,
                        _ => return Err(TOTPError::BadAlgorithm(v.to_string())),
                    }
                }
                _ => {}
            }
        }

        Ok(TOTP {
            label,
            secret: base32::decode(
                base32::Alphabet::RFC4648 { padding: true },
                &secret.ok_or(TOTPError::MissingField("secret"))?,
            )
            .ok_or(TOTPError::Base32)?,
            issuer: issuer.ok_or(TOTPError::MissingField("issuer"))?,
            period: period.unwrap_or(DEFAULT_PERIOD),
            digits: digits.unwrap_or(DEFAULT_DIGITS),
            algorithm,
        })
    }
    pub fn current_value(&self) -> Result<OTPCode, SystemTimeError> {
        let time: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

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
        return Ok(OTPCode {
            code,
            valid_for,
            period: Duration::from_secs(self.period),
        });
    }
}

#[cfg(test)]
mod kdbx4_otp_tests {
    use super::{TOTPError, TOTP};
    use crate::*;
    use std::{fs::File, path::Path};

    #[test]
    fn kdbx4_entry() -> Result<(), Box<dyn std::error::Error>> {
        // KDBX4 database format Base64 encodes ExpiryTime (and all other XML timestamps)
        let path = Path::new("tests/resources/test_db_kdbx4_with_totp_entry.kdbx");
        let db = Database::open(&mut File::open(path)?, Some("test"), None)?;

        let otp_str = "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC";

        // get an entry on the root node
        if let Some(NodeRef::Entry(e)) = db.root.get(&["this entry has totp"]) {
            assert_eq!(e.get_title(), Some("this entry has totp"));
            assert_eq!(e.get_raw_otp_value(), Some(otp_str));
        } else {
            panic!("Expected an entry");
        }

        Ok(())
    }

    #[test]
    fn totp_default() -> Result<(), TOTPError> {
        let otp_str = "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC";

        let expected = TOTP {
            label: "KeePassXC:none".to_string(),
            secret: b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            issuer: "KeePassXC".to_string(),
            period: 30,
            digits: 6,
            algorithm: otp::TOTPAlgorithm::Sha1,
        };

        assert_eq!(TOTP::parse_from_str(otp_str)?, expected);

        Ok(())
    }

    #[test]
    fn totp_sha512() -> Result<(), TOTPError> {
        let otp_str = "otpauth://totp/sha512%20totp:none?secret=GEZDGNBVGY%3D%3D%3D%3D%3D%3D&period=30&digits=6&issuer=sha512%20totp&algorithm=SHA512";

        let expected = TOTP {
            label: "sha512%20totp:none".to_string(),
            secret: b"123456".to_vec(),
            issuer: "sha512 totp".to_string(),
            period: 30,
            digits: 6,
            algorithm: otp::TOTPAlgorithm::Sha512,
        };

        assert_eq!(TOTP::parse_from_str(otp_str)?, expected);

        Ok(())
    }

    #[test]
    fn totp_bad() {
        assert!(matches!(
            TOTP::parse_from_str("not a totp string"),
            Err(TOTPError::UrlFormat(_))
        ));

        assert!(matches!(
            TOTP::parse_from_str("http://totp/sha512%20totp:none?secret=GEZDGNBVGY%3D%3D%3D%3D%3D%3D&period=30&digits=6&issuer=sha512%20totp&algorithm=SHA512"),
            Err(TOTPError::BadScheme(_))
        ));

        assert!(matches!(
            TOTP::parse_from_str("otpauth://totp/sha512%20totp:none?secret=GEZDGNBVGY%3D%3D%3D%3D%3D%3D&period=30&digits=6&issuer=sha512%20totp&algorithm=SHA123"),
            Err(TOTPError::BadAlgorithm(_))
        ));

        assert!(matches!(
            TOTP::parse_from_str("otpauth://missing_fields"),
            Err(TOTPError::MissingField("secret"))
        ));
    }
}
