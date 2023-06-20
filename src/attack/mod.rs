use lazy_static::lazy_static;
use openssl::bn::BigNum;
use rug::Integer;

mod cube_root;
mod ecm;
mod known_factors;
mod leaked_crt_exponent;
mod pollard_p_1;
mod small_e;
mod small_prime;
mod sum_pq;
mod wiener;
mod z3;

use crate::utils::phi;

pub use self::ecm::EcmAttack;
pub use self::z3::Z3Attack;
pub use cube_root::CubeRootAttack;
pub use known_factors::KnownFactorsAttack;
pub use leaked_crt_exponent::LeakedCrtExponentAttack;
pub use pollard_p_1::PollardP1Attack;
pub use small_e::SmallEAttack;
pub use small_prime::SmallPrimeAttack;
pub use sum_pq::SumPQAttack;
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
    /// dP or dmp1 CRT exponent. (d mod p-1)
    pub dp: Option<Integer>,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    pub dq: Option<Integer>,
    /// The sum of the two primes p and q.
    pub sum_pq: Option<Integer>,
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
            sum_pq: None,
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
    /// dP or dmp1 CRT exponent. (d mod p-1)
    pub dmp1: Integer,
    /// dQ or dmq1 CRT exponent. (d mod q-1)
    pub dmq1: Integer,
    /// qInv or iqmp CRT coefficient. (q^-1 mod p)
    pub iqmp: Integer,
}

impl PrivateKey {
    /// Create private key from p and q
    pub fn from_p_q(p: Integer, q: Integer, e: Integer) -> Result<Self, Error> {
        Self::from_factors(&[p, q], e)
    }

    /// Create private key from multiple factors
    pub fn from_factors(factors: &[Integer], e: Integer) -> Result<Self, Error> {
        println!("factors: {:?}", factors);
        let n: Integer = factors.iter().product();
        let phi = phi(factors);
        let d = e
            .clone()
            .invert(&phi)
            .or(Err(Error::CannotGeneratePrivateKey))?;

        Ok(Self {
            n,
            factors: {
                let mut factors = factors.to_vec();
                factors.sort();
                factors
            },
            e,
            dmp1: d.clone() % (&factors[0] - Integer::from(1)),
            dmq1: d.clone() % (&factors[1] - Integer::from(1)),
            iqmp: factors[1].invert_ref(&factors[0]).unwrap().into(),
            d,
        })
    }

    /// Decrypt cipher message
    pub fn decrypt(&self, c: &Integer) -> Integer {
        c.clone().pow_mod(&self.d, &self.n).unwrap()
    }

    /// Convert to PEM format
    pub fn to_pem(&self) -> Option<String> {
        if self.factors.len() != 2 {
            panic!("Only keys with two factors can be converted to PEM format");
        }

        let rsa = openssl::rsa::RsaPrivateKeyBuilder::new(
            BigNum::from_dec_str(&self.n.to_string()).unwrap(),
            BigNum::from_dec_str(&self.e.to_string()).unwrap(),
            BigNum::from_dec_str(&self.d.to_string()).unwrap(),
        )
        .ok()?
        .set_factors(
            BigNum::from_dec_str(&self.factors[0].to_string()).unwrap(),
            BigNum::from_dec_str(&self.factors[1].to_string()).unwrap(),
        )
        .ok()?
        .set_crt_params(
            BigNum::from_dec_str(&self.dmp1.to_string()).unwrap(),
            BigNum::from_dec_str(&self.dmq1.to_string()).unwrap(),
            BigNum::from_dec_str(&self.iqmp.to_string()).unwrap(),
        )
        .ok()?
        .build();

        rsa.private_key_to_pem()
            .ok()
            .map(|pem| String::from_utf8(pem).unwrap())
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
    /// Cannot generate private key
    #[error("cannot generate private key")]
    CannotGeneratePrivateKey,
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
