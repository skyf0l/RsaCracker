use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use rug::Integer;

mod small_prime;
pub use small_prime::SmallPrimeAttack;
mod cube_root;
pub use cube_root::CubeRootAttack;

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
    /// Prime number p.
    pub p: Integer,
    /// Prime number q.
    pub q: Integer,
    /// Public exponent.
    pub e: Integer,
    /// Private exponent.
    pub d: Integer,
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

/// All attacks
pub fn attacks() -> Vec<Box<dyn Attack>> {
    vec![Box::new(SmallPrimeAttack), Box::new(CubeRootAttack)]
}
