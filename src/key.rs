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
    /// Prime number p.
    pub p: Integer,
    /// Prime number q.
    pub q: Integer,
    /// Other factors. (Used for multi-prime RSA)
    pub other_factors: Vec<Integer>,
    /// Private exponent.
    pub d: Integer,
}

impl PrivateKey {
    /// Create private key from p and q
    pub fn from_p_q(p: Integer, q: Integer, e: Integer) -> Result<Self, KeyError> {
        let n = Integer::from(&p * &q);
        let phi = phi(&vec![p.clone(), q.clone()]);
        let d = e
            .clone()
            .invert(&phi)
            .or(Err(KeyError::PrivateExponentComputationFailed))?;

        Ok(Self {
            n,
            e,
            p: if p > q { q.clone() } else { p.clone() },
            q: if p > q { p } else { q },
            other_factors: vec![],
            d,
        })
    }

    /// Create private key from multiple factors
    pub fn from_factors(factors: &[Integer], e: Integer) -> Result<Self, KeyError> {
        let mut factors = factors.to_vec();
        factors.sort();

        let n: Integer = factors.iter().product();
        let phi = phi(&factors);
        let d = e
            .clone()
            .invert(&phi)
            .or(Err(KeyError::PrivateExponentComputationFailed))?;

        Ok(Self {
            n,
            e,
            p: factors.remove(0),
            q: factors.remove(0),
            other_factors: factors,
            d,
        })
    }

    /// Decrypt cipher message
    pub fn decrypt(&self, c: &Integer) -> Integer {
        c.clone().pow_mod(&self.d, &self.n).unwrap()
    }

    /// Convert to PEM format
    pub fn to_pem(&self) -> Option<String> {
        if !self.other_factors.is_empty() {
            panic!("Only keys with two factors can be converted to PEM format");
        }

        let dmp1 = self.d.clone() % (&self.p - Integer::from(1));
        let dmq1 = self.d.clone() % (&self.q - Integer::from(1));
        let iqmp = Integer::from(self.q.invert_ref(&self.p).unwrap());

        let rsa = RsaPrivateKeyBuilder::new(
            BigNum::from_dec_str(&self.n.to_string()).unwrap(),
            BigNum::from_dec_str(&self.e.to_string()).unwrap(),
            BigNum::from_dec_str(&self.d.to_string()).unwrap(),
        )
        .ok()?
        .set_factors(
            BigNum::from_dec_str(&self.p.to_string()).unwrap(),
            BigNum::from_dec_str(&self.q.to_string()).unwrap(),
        )
        .ok()?
        .set_crt_params(
            BigNum::from_dec_str(&dmp1.to_string()).unwrap(),
            BigNum::from_dec_str(&dmq1.to_string()).unwrap(),
            BigNum::from_dec_str(&iqmp.to_string()).unwrap(),
        )
        .ok()?
        .build();

        rsa.private_key_to_pem()
            .ok()
            .map(|pem| String::from_utf8(pem).unwrap())
    }
}
