use openssl::{bn::BigNum, rsa::RsaPrivateKeyBuilder};
use rug::Integer;

use crate::utils::phi;

/// Attack error
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Private exponent computation failed
    #[error("private exponent computation failed")]
    PrivateExponentComputationFailed,
}

/// RSA private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    /// Modulus.
    pub n: Integer,
    /// Public exponent.
    pub e: Integer,
    /// Prime numbers.
    pub factors: Vec<Integer>,
    /// Phi or Euler's totient function of n. (p-1)(q-1)
    pub phi: Integer,
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
    pub fn from_p_q(p: Integer, q: Integer, e: Integer) -> Result<Self, KeyError> {
        Self::from_factors(&[p, q], e)
    }

    /// Create private key from multiple factors
    pub fn from_factors(factors: &[Integer], e: Integer) -> Result<Self, KeyError> {
        let n: Integer = factors.iter().product();
        let phi = phi(factors);
        let d = e
            .clone()
            .invert(&phi)
            .or(Err(KeyError::PrivateExponentComputationFailed))?;

        Ok(Self {
            n,
            e,
            factors: {
                let mut factors = factors.to_vec();
                factors.sort();
                factors
            },
            d: d.clone(),
            phi,
            dmp1: d.clone() % (&factors[0] - Integer::from(1)),
            dmq1: d % (&factors[1] - Integer::from(1)),
            iqmp: factors[1].invert_ref(&factors[0]).unwrap().into(),
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

        let rsa = RsaPrivateKeyBuilder::new(
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
