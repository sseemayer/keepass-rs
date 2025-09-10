use base32;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};
use thiserror::Error;
use totp_lite::{totp_custom, Sha1, Sha256, Sha512};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: u32 = 8;

/// Choices of hash algorithm for TOTP
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum TOTPAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl std::str::FromStr for TOTPAlgorithm {
    type Err = TOTPError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SHA1" => Ok(TOTPAlgorithm::Sha1),
            "SHA256" => Ok(TOTPAlgorithm::Sha256),
            "SHA512" => Ok(TOTPAlgorithm::Sha512),
            _ => Err(TOTPError::BadAlgorithm(s.to_string())),
        }
    }
}

/// Time-based one time password settings
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TOTP {
    pub label: String,
    pub issuer: Option<String>,
    pub period: u64,
    pub digits: u32,
    pub algorithm: TOTPAlgorithm,

    secret: Vec<u8>,
}

/// A generated one time password
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

/// Errors while processing a TOTP specification
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

impl std::str::FromStr for TOTP {
    type Err = TOTPError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parsed = Url::parse(s)?;

        if parsed.scheme() != "otpauth" {
            return Err(TOTPError::BadScheme(parsed.scheme().to_string()));
        }
        let query_pairs = parsed.query_pairs();

        let label: String = parsed.path().trim_start_matches("/").to_string();
        let mut secret: Option<String> = None;
        let mut issuer: Option<String> = None;
        let mut period: u64 = DEFAULT_PERIOD;
        let mut digits: u32 = DEFAULT_DIGITS;
        let mut algorithm: TOTPAlgorithm = TOTPAlgorithm::Sha1;

        for pair in query_pairs {
            let (k, v) = pair;
            match k.as_ref() {
                "secret" => secret = Some(v.to_string()),
                "issuer" => issuer = Some(v.to_string()),
                "period" => period = v.parse()?,
                "digits" => digits = v.parse()?,
                "algorithm" => algorithm = v.parse()?,
                _ => {}
            }
        }

        let secret = secret.ok_or(TOTPError::MissingField("secret"))?;

        let secret =
            base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret).ok_or(TOTPError::Base32)?;

        Ok(TOTP {
            label,
            secret,
            issuer,
            period,
            digits,
            algorithm,
        })
    }
}

impl TOTP {
    /// Get the one-time code for a specific unix timestamp
    pub fn value_at(&self, time: u64) -> OTPCode {
        let code = match self.algorithm {
            TOTPAlgorithm::Sha1 => totp_custom::<Sha1>(self.period, self.digits, &self.secret, time),
            TOTPAlgorithm::Sha256 => totp_custom::<Sha256>(self.period, self.digits, &self.secret, time),
            TOTPAlgorithm::Sha512 => totp_custom::<Sha512>(self.period, self.digits, &self.secret, time),
        };

        let valid_for = Duration::from_secs(self.period - (time % self.period));

        OTPCode {
            code,
            valid_for,
            period: Duration::from_secs(self.period),
        }
    }

    /// Get the current one-time code
    pub fn value_now(&self) -> Result<OTPCode, SystemTimeError> {
        let time: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(self.value_at(time))
    }

    pub fn get_secret(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &self.secret)
    }
}

#[cfg(test)]
mod kdbx4_otp_tests {
    use super::{TOTPAlgorithm, TOTPError, TOTP};
    use crate::{
        db::{Database, NodeRef},
        key::DatabaseKey,
    };
    use std::{fs::File, path::Path};

    #[test]
    fn kdbx4_entry() -> Result<(), Box<dyn std::error::Error>> {
        // KDBX4 database format Base64 encodes ExpiryTime (and all other XML timestamps)
        let path = Path::new("tests/resources/test_db_kdbx4_with_totp_entry.kdbx");
        let db = Database::open(&mut File::open(path)?, DatabaseKey::new().with_password("test"))?;

        let otp_str =
            "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC";

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
        let otp_str =
            "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC";

        let expected = TOTP {
            label: "KeePassXC:none".to_string(),
            secret: b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            issuer: Some("KeePassXC".to_string()),
            period: 30,
            digits: 6,
            algorithm: TOTPAlgorithm::Sha1,
        };

        assert_eq!(otp_str.parse::<TOTP>()?, expected);

        Ok(())
    }

    #[test]
    fn totp_get_secret() -> Result<(), TOTPError> {
        let otp_str =
            "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC";

        let otp = otp_str.parse::<TOTP>()?;

        assert_eq!(otp.get_secret(), "JBSWY3DPEHPK3PXP".to_string());

        Ok(())
    }

    #[test]
    fn totp_sha512() -> Result<(), TOTPError> {
        let otp_str = "otpauth://totp/sha512%20totp:none?secret=GEZDGNBVGY%3D%3D%3D%3D%3D%3D&period=30&digits=6&issuer=sha512%20totp&algorithm=SHA512";

        let expected = TOTP {
            label: "sha512%20totp:none".to_string(),
            secret: b"123456".to_vec(),
            issuer: Some("sha512 totp".to_string()),
            period: 30,
            digits: 6,
            algorithm: TOTPAlgorithm::Sha512,
        };

        assert_eq!(otp_str.parse::<TOTP>()?, expected);

        Ok(())
    }

    #[test]
    fn totp_value() {
        let totp = TOTP {
            label: "KeePassXC:none".to_string(),
            secret: b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            issuer: Some("KeePassXC".to_string()),
            period: 30,
            digits: 6,
            algorithm: TOTPAlgorithm::Sha1,
        };

        assert_eq!(totp.value_at(1234).code, "806863")
    }

    #[test]
    fn totp_bad() {
        assert!(matches!(
            "not a totp string".parse::<TOTP>(),
            Err(TOTPError::UrlFormat(_))
        ));

        assert!(matches!(
            "http://totp/sha512%20totp:none?secret=GEZDGNBVGY%3D%3D%3D%3D%3D%3D&period=30&digits=6&issuer=sha512%20totp&algorithm=SHA512".parse::<TOTP>(),
            Err(TOTPError::BadScheme(_))
        ));

        assert!(matches!(
            "otpauth://totp/sha512%20totp:none?secret=GEZDGNBVGY%3D%3D%3D%3D%3D%3D&period=30&digits=6&issuer=sha512%20totp&algorithm=SHA123".parse::<TOTP>(),
            Err(TOTPError::BadAlgorithm(_))
        ));

        assert!(matches!(
            "otpauth://missing_fields".parse::<TOTP>(),
            Err(TOTPError::MissingField("secret"))
        ));
    }

    #[test]
    fn totp_minimal() -> Result<(), TOTPError> {
        let otp_str = "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6";

        let expected = TOTP {
            label: "KeePassXC:none".to_string(),
            secret: b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            issuer: None,
            period: 30,
            digits: 6,
            algorithm: TOTPAlgorithm::Sha1,
        };

        assert_eq!(otp_str.parse::<TOTP>()?, expected);

        Ok(())
    }
}
