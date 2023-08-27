use openssl::{bn::BigNum, rsa::RsaPrivateKeyBuilder};
use rug::{integer::IsPrime, Integer};

use crate::factors::Factors;

/// Attack error
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Factors are not prime numbers
    #[error("factors are not prime numbers: {0:?}")]
    FactorsAreNotPrimeNumbers(Factors),
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
    /// Factors.
    pub factors: Factors,
    /// Private exponent.
    pub d: Integer,
    /// Phi or Euler's totient function of n. (p-1)(q-1)
    pub phi: Integer,
}

impl PrivateKey {
    /// Create private key from p and q
    pub fn from_p_q(p: Integer, q: Integer, e: Integer) -> Result<Self, KeyError> {
        Self::from_factors([p, q], e)
    }

    /// Create private key from multiple factors
    pub fn from_factors(factors: impl Into<Factors>, e: Integer) -> Result<Self, KeyError> {
        let factors = Into::<Factors>::into(factors);

        // Check if factors are prime numbers
        if factors
            .factors()
            .iter()
            .any(|f| f.is_probably_prime(30) == IsPrime::No)
        {
            return Err(KeyError::FactorsAreNotPrimeNumbers(factors));
        }

        let n: Integer = factors.product();
        let phi = factors.phi();
        let d = e
            .clone()
            .invert(&phi)
            .or(Err(KeyError::PrivateExponentComputationFailed))?;

        Ok(Self {
            n,
            e,
            factors,
            d,
            phi,
        })
    }

    /// Decrypt cipher message
    pub fn decrypt(&self, c: &Integer) -> Integer {
        c.clone().pow_mod(&self.d, &self.n).unwrap()
    }

    /// Returns P factor
    pub fn p(&self) -> Integer {
        self.factors[0].clone()
    }

    /// Returns Q factor
    pub fn q(&self) -> Integer {
        self.factors[1].clone()
    }

    /// Returns dP or dmp1 CRT exponent. (d mod p-1)
    pub fn dp(&self) -> Integer {
        self.d.clone() % (self.p() - 1)
    }

    /// Returns dQ or dmq1 CRT exponent. (d mod q-1)
    pub fn dq(&self) -> Integer {
        self.d.clone() % (self.q() - 1)
    }

    /// Returns qInv or iqmp CRT exponent. (q^-1 mod p)
    pub fn qinv(&self) -> Integer {
        self.q().invert(&self.p()).unwrap()
    }

    /// Returns pInv or ipmq CRT exponent. (p^-1 mod q)
    pub fn pinv(&self) -> Integer {
        self.p().invert(&self.q()).unwrap()
    }

    /// Convert to PEM format
    pub fn to_pem(&self, passphrase: &Option<String>) -> Option<String> {
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
            BigNum::from_dec_str(&self.p().to_string()).unwrap(),
            BigNum::from_dec_str(&self.q().to_string()).unwrap(),
        )
        .ok()?
        .set_crt_params(
            BigNum::from_dec_str(&self.dp().to_string()).unwrap(),
            BigNum::from_dec_str(&self.dq().to_string()).unwrap(),
            BigNum::from_dec_str(&self.qinv().to_string()).unwrap(),
        )
        .ok()?
        .build();

        if let Some(passphrase) = passphrase {
            rsa.private_key_to_pem_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                passphrase.as_bytes(),
            )
            .ok()
            .map(|pem| String::from_utf8(pem).unwrap())
        } else {
            rsa.private_key_to_pem()
                .ok()
                .map(|pem| String::from_utf8(pem).unwrap())
        }
    }
}
