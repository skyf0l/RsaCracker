use rug::Integer;

mod small_prime;
pub use small_prime::SmallPrimeAttack;

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
    /// Missing modulus
    #[error("missing modulus")]
    MissingModulus,
    /// Unsuccesful attack
    #[error("unsuccesful attack")]
    NotFound,
}

/// Abstract attack trait
pub trait Attack {
    /// Get the attack name
    fn name() -> &'static str;

    /// Run the attack
    fn run(params: &Parameters) -> Result<PrivateKey, Error>;
}
