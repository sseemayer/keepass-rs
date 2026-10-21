use base32;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::db::Entry;

const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: u32 = 8;
const MAX_GENERATED_DIGITS: u32 = 20;

/// Choices of hash algorithm for TOTP.
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[non_exhaustive]
pub enum TOTPAlgorithm {
    /// SHA-1 hash algorithm (default).
    Sha1,
    /// SHA-256 hash algorithm.
    Sha256,
    /// SHA-512 hash algorithm.
    Sha512,
}

impl std::str::FromStr for TOTPAlgorithm {
    type Err = TOTPError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(TOTPError::BadAlgorithm(s.to_string())),
        }
    }
}

/// Time-based one-time password settings.
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TOTP {
    /// The label for this TOTP.
    pub label: String,

    /// The issuer for this TOTP, if specified.
    pub issuer: Option<String>,

    /// The period (in seconds) for which a generated code is valid.
    pub period: u64,

    /// The number of digits in the generated code.
    pub digits: u32,

    /// The hash algorithm to use when generating codes.
    pub algorithm: TOTPAlgorithm,

    /// The secret key for this TOTP, decoded from base32.
    secret: Vec<u8>,
}

/// A generated one-time password.
pub struct OTPCode {
    /// The generated code as a string of digits.
    pub code: String,

    /// The duration for which this code is still valid.
    pub valid_for: Duration,

    /// The period (in seconds) for which codes are generated for this TOTP.
    pub period: Duration,
}

impl std::fmt::Display for OTPCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Code: {}, valid for: {}/{}s",
            self.code,
            self.valid_for.as_secs(),
            self.period.as_secs(),
        )
    }
}

/// Errors while processing a TOTP specification.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TOTPError {
    /// Errors parsing the TOTP URL.
    #[error(transparent)]
    UrlFormat(#[from] url::ParseError),

    /// Errors parsing integer fields in the TOTP URL.
    #[error(transparent)]
    IntFormat(#[from] std::num::ParseIntError),

    /// A required field is missing from the TOTP URL query parameters.
    #[error("Missing TOTP field: {}", _0)]
    MissingField(&'static str),

    /// Errors related to getting system time.
    #[error(transparent)]
    Time(#[from] SystemTimeError),

    /// Errors decoding the base32-encoded secret key.
    #[error("Base32 decoding error")]
    Base32,

    /// No OTP record found in the entry.
    #[error("No OTP record found")]
    NoRecord,

    /// The URL scheme in the TOTP URL is not "otpauth".
    #[error("Bad URL scheme: '{}'", _0)]
    BadScheme(String),

    /// The hash algorithm specified in the TOTP URL is not recognized.
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

        // Preserve percent-encoding in the label, as the previous API did.
        let label = parsed.path().trim_start_matches('/').to_string();

        let mut secret: Option<String> = None;
        let mut issuer: Option<String> = None;
        let mut period = DEFAULT_PERIOD;
        let mut digits = DEFAULT_DIGITS;
        let mut algorithm = TOTPAlgorithm::Sha1;

        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "secret" => secret = Some(value.to_string()),
                "issuer" => issuer = Some(value.to_string()),
                "period" => period = value.parse()?,
                "digits" => digits = value.parse()?,
                "algorithm" => algorithm = value.parse()?,
                _ => {}
            }
        }

        let secret = secret.ok_or(TOTPError::MissingField("secret"))?;
        let secret = base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &secret)
            .ok_or(TOTPError::Base32)?;

        Ok(Self {
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
    /// Generate an OTP code using RFC 6238 dynamic truncation.
    ///
    /// The returned integer is limited to 31 bits, as required by HOTP/TOTP.
    fn generate_code(&self, time: u64, digits: u32) -> String {
        let counter = time / self.period;
        let counter_bytes = counter.to_be_bytes();

        let hash = match self.algorithm {
            TOTPAlgorithm::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(&self.secret)
                    .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            TOTPAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
                    .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            TOTPAlgorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(&self.secret)
                    .unwrap_or_else(|_| unreachable!("HMAC accepts keys of any length"));
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        let offset = (hash[hash.len() - 1] & 0x0f) as usize;

        let binary = (u32::from(hash[offset] & 0x7f) << 24)
            | (u32::from(hash[offset + 1]) << 16)
            | (u32::from(hash[offset + 2]) << 8)
            | u32::from(hash[offset + 3]);

        let code = if digits >= 10 {
            u64::from(binary)
        } else {
            u64::from(binary) % 10_u64.pow(digits)
        };

        format!("{code:0width$}", width = digits as usize)
    }

    /// Get the one-time code for a specific Unix timestamp.
    pub fn value_at(&self, time: u64) -> OTPCode {
        let period = Duration::from_secs(self.period);

        if self.period == 0 {
            return OTPCode {
                code: String::new(),
                valid_for: Duration::ZERO,
                period,
            };
        }

        let valid_for = Duration::from_secs(self.period - (time % self.period));

        if self.digits == 0 {
            return OTPCode {
                code: "0".to_string(),
                valid_for,
                period,
            };
        }

        let digits = self.digits.min(MAX_GENERATED_DIGITS);
        let code = self.generate_code(time, digits);

        OTPCode {
            code,
            valid_for,
            period,
        }
    }

    /// Get the current one-time code.
    pub fn value_now(&self) -> Result<OTPCode, SystemTimeError> {
        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        Ok(self.value_at(time))
    }

    /// Get the base32-encoded secret key for this TOTP.
    pub fn get_secret(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &self.secret)
    }
}

impl Entry {
    /// Convenience method for getting a TOTP from this entry.
    pub fn get_otp(&self) -> Result<TOTP, TOTPError> {
        self.get_raw_otp_value().ok_or(TOTPError::NoRecord)?.parse()
    }
}

#[cfg(test)]
mod kdbx4_otp_tests {
    use super::{TOTPAlgorithm, TOTPError, TOTP};
    use crate::{db::Database, key::DatabaseKey};
    use std::{fs::File, path::Path};

    #[test]
    fn kdbx4_entry() -> Result<(), Box<dyn std::error::Error>> {
        let path = Path::new("tests/resources/test_db_kdbx4_with_totp_entry.kdbx");
        let db = Database::open(
            &mut File::open(path)?,
            DatabaseKey::new().with_password("test"),
        )?;

        let otp_str =
            "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC";

        let root = db.root();
        let entry = root
            .entry_by_name("this entry has totp")
            .ok_or("Entry not found")?;

        assert_eq!(entry.get_title(), Some("this entry has totp"));
        assert_eq!(entry.get_raw_otp_value(), Some(otp_str));

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
        assert_eq!(otp.get_secret(), "JBSWY3DPEHPK3PXP");
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

        assert_eq!(totp.value_at(1234).code, "806863");
    }

    #[test]
    fn totp_zero_period() {
        let totp = TOTP {
            label: "KeePassXC:none".to_string(),
            secret: b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            issuer: Some("KeePassXC".to_string()),
            period: 0,
            digits: 6,
            algorithm: TOTPAlgorithm::Sha1,
        };

        assert_eq!(totp.value_at(1234).code, "");
    }

    #[test]
    fn totp_zero_digits() {
        let totp = TOTP {
            label: "KeePassXC:none".to_string(),
            secret: b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            issuer: Some("KeePassXC".to_string()),
            period: 30,
            digits: 0,
            algorithm: TOTPAlgorithm::Sha1,
        };

        assert_eq!(totp.value_at(1234).code, "0");
    }

    #[test]
    fn totp_ten_digits() {
        let totp = TOTP {
            label: "KeePassXC:none".to_string(),
            secret: b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            issuer: Some(TOTPAlgorithm::Sha1).map(|_| "KeePassXC".to_string()),
            period: 30,
            digits: 10,
            algorithm: TOTPAlgorithm::Sha1,
        };

        assert_eq!(totp.value_at(1234).code, "0638806863");
    }

    #[test]
    fn totp_twentyone_digits() {
        let totp = TOTP {
            label: "KeePassXC:none".to_string(),
            secret: b"Hello!\xDE\xAD\xBE\xEF".to_vec(),
            issuer: Some(TOTPAlgorithm::Sha1).map(|_| "KeePassXC".to_string()),
            period: 30,
            digits: 21,
            algorithm: TOTPAlgorithm::Sha1,
        };

        assert_eq!(totp.value_at(1234).code, "00000000000638806863");
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
