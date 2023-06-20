use lazy_static::lazy_static;
use rug::Integer;

mod cube_root;
mod ecm;
mod known_factors;
mod leaked_crt;
mod small_e;
mod small_prime;
mod wiener;

use crate::utils::phi;

pub use self::ecm::EcmAttack;
pub use cube_root::CubeRootAttack;
pub use known_factors::KnownFactorsAttack;
pub use leaked_crt::LeakedCrtAttack;
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
    /// Modulus dP (d mod p-1)
    pub dp: Option<Integer>,
    /// Modulus dQ (d mod q-1)
    pub dq: Option<Integer>,
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
            dp: None,
            dq: None,
            e: 65537.into(),
            c: None,
        }
    }
}

impl Parameters {
    /// Create parameters from public key
    pub fn from_publickey(key: &[u8]) -> Option<Self> {
        Self::from_rsa_public_pem(key).or_else(|| Self::from_x509_public_pem(key))
    }

    /// Create parameters from x509 public key
    pub fn from_rsa_public_pem(key: &[u8]) -> Option<Self> {
        let publickey = openssl::rsa::Rsa::public_key_from_pem(key)
            .or_else(|_| openssl::rsa::Rsa::public_key_from_pem_pkcs1(key))
            .ok()?;

        Some(Self {
            n: Some(publickey.n().to_string().parse().unwrap()),
            e: publickey.e().to_string().parse().unwrap(),
            ..Default::default()
        })
    }

    /// Create parameters from x509 public key
    pub fn from_x509_public_pem(key: &[u8]) -> Option<Self> {
        let publickey = openssl::x509::X509::from_pem(key).unwrap();
        let rsa = publickey.public_key().ok()?.rsa().ok()?;

        Some(Self {
            n: Some(rsa.n().to_string().parse().unwrap()),
            e: rsa.e().to_string().parse().unwrap(),
            ..Default::default()
        })
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
        let phi = phi(factors);
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

/// Solved RSA (private key, decrypted message)
pub type SolvedRsa = (Option<PrivateKey>, Option<Integer>);

/// Abstract attack trait
pub trait Attack {
    /// Get the attack name
    fn name(&self) -> &'static str;

    /// Run the attack
    fn run(&self, params: &Parameters) -> Result<SolvedRsa, Error>;
}

lazy_static! {
    /// List of attacks
    pub static ref ATTACKS: Vec<Box<dyn Attack + Send + Sync>> = vec![
        Box::new(CubeRootAttack),
        Box::new(KnownFactorsAttack),
        Box::new(LeakedCrtAttack),
        Box::new(SmallEAttack),
        Box::new(SmallPrimeAttack),
        Box::new(WienerAttack),
        Box::new(EcmAttack),
    ];
}
