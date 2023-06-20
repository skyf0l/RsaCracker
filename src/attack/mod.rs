use lazy_static::lazy_static;
use rug::Integer;

mod cube_root;
mod ecm;
mod known_factors;
mod known_phi;
mod leaked_crt_exponent;
mod pollard_p_1;
mod small_e;
mod small_prime;
mod sum_pq;
mod wiener;
mod z3;

use crate::key::PrivateKey;

pub use self::ecm::EcmAttack;
pub use self::z3::Z3Attack;
pub use cube_root::CubeRootAttack;
pub use known_factors::KnownFactorsAttack;
pub use known_phi::KnownPhiAttack;
pub use leaked_crt_exponent::LeakedCrtExponentAttack;
pub use pollard_p_1::PollardP1Attack;
pub use small_e::SmallEAttack;
pub use small_prime::SmallPrimeAttack;
pub use sum_pq::SumPQAttack;
pub use wiener::WienerAttack;

/// Known parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    /// Cipher message.
    pub c: Option<Integer>,
    /// Modulus.
    pub n: Option<Integer>,
    /// Public exponent.
    pub e: Integer,
    /// Prime number p.
    pub p: Option<Integer>,
    /// Prime number q.
    pub q: Option<Integer>,
    /// dP or dmp1 CRT exponent. (d mod p-1)
    pub dp: Option<Integer>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    pub dq: Option<Integer>,
    /// Phi or Euler's totient function of n. (p-1)(q-1)
    pub phi: Option<Integer>,
    /// The sum of the two primes p and q.
    pub sum_pq: Option<Integer>,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            n: None,
            e: 65537.into(),
            c: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            phi: None,
            sum_pq: None,
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

/// Attack error
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Missing parameters
    #[error("missing parameters")]
    MissingParameters,
    /// Unsuccessful attack
    #[error("unsuccessful attack")]
    NotFound,
    /// Ket error
    #[error(transparent)]
    Key(#[from] crate::key::KeyError),
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
        Box::new(KnownPhiAttack),
        Box::new(LeakedCrtExponentAttack),
        Box::new(PollardP1Attack),
        Box::new(SmallEAttack),
        Box::new(SmallPrimeAttack),
        Box::new(SumPQAttack),
        Box::new(WienerAttack),
        Box::new(EcmAttack),
        Box::new(Z3Attack),
    ];
}
