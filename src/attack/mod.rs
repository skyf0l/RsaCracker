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
    fn name() -> &'static str;

    /// Run the attack
    fn run(params: &Parameters) -> AttackResult;
}
