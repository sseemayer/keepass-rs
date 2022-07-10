use base32;
use std::borrow::Cow;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_lite::{totp_custom, Sha1, Sha256, Sha512};
use url::Url;

const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: u32 = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum AlgoType {
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
    algorithm: AlgoType,
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
        let mut algorithm: AlgoType = AlgoType::Sha1;

        for pair in query_pairs {
            let (k, v) = pair;
            match k {
                Cow::Borrowed("secret") => secret = Some(v.into_owned()),
                Cow::Borrowed("issuer") => issuer = Some(v.into_owned()),
                Cow::Borrowed("period") => period = Some(v.parse::<u64>().unwrap()),
                Cow::Borrowed("digits") => digits = Some(v.parse::<u32>().unwrap()),
                Cow::Borrowed("algorithm") => {
                    algorithm = match v {
                        Cow::Borrowed("SHA1") => AlgoType::Sha1,
                        Cow::Borrowed("SHA256") => AlgoType::Sha256,
                        Cow::Borrowed("SHA512") => AlgoType::Sha512,
                        _ => panic!("Received an unsupported algorithm for TOTP"),
                    }
                }
                Cow::Borrowed(_) => (),
                Cow::Owned(_) => panic!("Somehow got an owned value"),
            }
        }

        if secret.is_none() {
            return None;
        }
        if issuer.is_none() {
            return None;
        }
        Some(TOTP {
            label,
            secret: base32::decode(
                base32::Alphabet::RFC4648 { padding: true },
                &secret.unwrap(),
            )
            .unwrap(),
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
            AlgoType::Sha1 => totp_custom::<Sha1>(self.period, self.digits, &self.secret, time),
            AlgoType::Sha256 => totp_custom::<Sha256>(self.period, self.digits, &self.secret, time),
            AlgoType::Sha512 => totp_custom::<Sha512>(self.period, self.digits, &self.secret, time),
        };

        let valid_for = Duration::from_secs(self.period - (time % self.period));
        return OTPCode {
            code,
            valid_for,
            period: Duration::from_secs(self.period),
        };
    }
}
