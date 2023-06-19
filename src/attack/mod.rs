use lazy_static::lazy_static;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use rug::Integer;

mod cube_root;
mod ecm;
mod small_e;
mod small_prime;
mod wiener;

use crate::utils::phi;

pub use self::ecm::EcmAttack;
pub use cube_root::CubeRootAttack;
pub use small_e::SmallEAttack;
pub use small_prime::SmallPrimeAttack;
pub use wiener::WienerAttack;

/// Known parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    /// Modulus.
    pub n: Option<Integer>,
    /// Prime number p.
    pub p: Option<Integer>,
    /// Prime number q.
    pub q: Option<Integer>,
    /// Public exponent.
    pub e: Integer,
    /// Cipher message.
    pub c: Option<Integer>,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            n: None,
            p: None,
            q: None,
            e: 65537.into(),
            c: None,
        }
    }
}

impl Parameters {
    /// Create parameters from RSA public key PEM
    pub fn from_pub_pem(pem: &str) -> Self {
        let pub_key = RsaPublicKey::from_public_key_pem(pem).unwrap();

        Self {
            n: Some(pub_key.n().to_string().parse().unwrap()),
            e: pub_key.e().to_string().parse().unwrap(),
            ..Default::default()
        }
    }
}

/// RSA private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    /// Modulus.
    pub n: Integer,
    /// Prime numbers.
    pub factors: Vec<Integer>,
    /// Public exponent.
    pub e: Integer,
    /// Private exponent.
    pub d: Integer,
}

impl PrivateKey {
    /// Create private key from p and q
    pub fn from_p_q(p: Integer, q: Integer, e: Integer) -> Self {
        Self::from_factors(&[p, q], e)
    }

    /// Create private key from multiple factors
    pub fn from_factors(factors: &[Integer], e: Integer) -> Self {
        let n: Integer = factors.iter().product();
        let phi = phi(&factors);
        let d = e.clone().invert(&phi).unwrap();

        Self {
            n,
            factors: {
                let mut factors = factors.to_vec();
                factors.sort();
                factors
            },
            e,
            d,
        }
    }

    /// Decrypt cipher message
    pub fn decrypt(&self, c: &Integer) -> Integer {
        c.clone().pow_mod(&self.d, &self.n).unwrap()
    }
}

/// Attack error
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Missing parameters
    #[error("missing parameters")]
    MissingParameters,
    /// Unsuccessful attack
    #[error("unsuccessful attack")]
    NotFound,
}

/// Attack result
pub type AttackResult = Result<(Option<PrivateKey>, Option<Integer>), Error>;

/// Abstract attack trait
pub trait Attack {
    /// Get the attack name
    fn name(&self) -> &'static str;

    /// Run the attack
    fn run(&self, params: &Parameters) -> AttackResult;
}

lazy_static! {
    /// List of attacks
    pub static ref ATTACKS: Vec<Box<dyn Attack + Send + Sync>> = vec![
        Box::new(CubeRootAttack),
        Box::new(EcmAttack),
        Box::new(SmallEAttack),
        Box::new(SmallPrimeAttack),
        Box::new(WienerAttack),
    ];
}
